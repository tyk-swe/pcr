// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::{IpAddr, Ipv6Addr};

use log::{debug, info, warn};
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;

use crate::domain::policy::TransmissionPolicy;
use crate::domain::spec::{DestinationSpec, PacketSpec, TargetAddress};

use super::builder::{Ipv4PacketBuilder, Ipv6PacketBuilder, PacketBuildResult, PacketBuilder};
use super::control::validate_transmission_policy;
use super::error::{PlannerError, Result};
use super::interface::{resolve_ip_addresses_with_selection, select_interface_with_reason};
use super::ipv6;
use super::layer2::{resolve_layer2_ipv4, resolve_layer2_ipv6, Layer2Resolved};
use super::payload::prepare_payload;
use super::transport::{build_transport_segment, TransportBuild};
use super::types::{
    InterfaceSelectionReason, LinkType, NetworkTarget, NetworkTransmissionPlan, PlanningMode,
    SelectionMetadata, TransmissionSummary,
};

pub(crate) fn plan_transmission_with_policy(
    spec: &PacketSpec,
    policy: TransmissionPolicy,
) -> Result<NetworkTransmissionPlan> {
    plan_transmission_with_mode(spec, PlanningMode::Live, policy)
}

pub(crate) fn plan_transmission_dry_run_with_policy(
    spec: &PacketSpec,
    policy: TransmissionPolicy,
) -> Result<NetworkTransmissionPlan> {
    plan_transmission_with_mode(spec, PlanningMode::DryRun, policy)
}

fn plan_transmission_with_mode(
    spec: &PacketSpec,
    mode: PlanningMode,
    policy: TransmissionPolicy,
) -> Result<NetworkTransmissionPlan> {
    info!("Preparing packet for {}", format_target(&spec.target));

    let selected = select_interface_with_reason(spec)?;
    plan_transmission_with_interface_and_reason(
        spec,
        selected.interface,
        selected.reason,
        mode,
        policy,
    )
}

fn plan_transmission_with_interface_and_reason(
    spec: &PacketSpec,
    interface: pnet::datalink::NetworkInterface,
    interface_reason: InterfaceSelectionReason,
    mode: PlanningMode,
    policy: TransmissionPolicy,
) -> Result<NetworkTransmissionPlan> {
    info!("Using interface {}", interface.name);

    enforce_feature_constraints(spec)?;
    validate_transmission_policy(&spec.transmit, policy)?;

    if spec.transmit.flood {
        warn_if_unbounded(spec);
    }

    let context = build_planning_context(spec, &interface)?;
    log_layer3_selection(spec);

    let layer2 = resolve_layer2_plan(spec, &interface, &context, mode)?;
    let transport = build_transport_segment(
        &spec.transport,
        &context.payload,
        context.source_ip,
        context.destination_ip,
    )?;

    let (frames, link_type, destination) =
        assemble_frames(spec, &context, layer2.as_ref(), &transport)?;
    validate_built_frames(&frames, &link_type)?;

    let mut transmit = spec.transmit.clone();

    if matches!(&link_type, LinkType::Ipv4 | LinkType::Ipv6) && !transmit.is_layer3() {
        if matches!(&link_type, LinkType::Ipv6) && !spec.ipv6.exthdrs.is_empty() {
            return Err(PlannerError::Ipv6ExtensionHeaderLayer3Mismatch.into());
        }

        info!(
            "Falling back to {:?} layer-3 transmission after link-layer resolution failed",
            link_type
        );
        transmit.auto_layer3 = true;
    }

    let TransportBuild {
        bytes: _,
        protocol,
        label,
    } = transport;
    let summary = build_summary(&context, &frames, label);

    let plan = NetworkTransmissionPlan {
        frames,
        link_type,
        transmit,
        destination,
        selection: SelectionMetadata {
            selected_interface: interface.name.clone(),
            interface_reason,
            source_ip: context.source_ip,
            source_reason: context.source_reason,
            destination_ip: context.destination_ip,
            destination_reason: context.destination_reason,
        },
        interface,
        protocol,
        summary,
        logging: spec.logging.clone(),
        mode,
        policy,
    };

    debug!(
        "Prepared frame(s): transport={} payload={} bytes frames={} largest_frame={} bytes link_type={:?} mode={:?}",
        plan.summary.transport,
        plan.summary.payload_len,
        plan.summary.frame_count,
        plan.summary.largest_frame_len,
        plan.link_type,
        plan.mode
    );

    Ok(plan)
}

fn warn_if_unbounded(plan: &PacketSpec) {
    if plan.transmit.count.is_none() && !plan.transmit.loop_send {
        warn!("--flood enabled without explicit count; be cautious with raw socket permissions");
    }
}

fn enforce_feature_constraints(spec: &PacketSpec) -> Result<()> {
    #[cfg(feature = "pcap")]
    let _ = spec;
    #[cfg(not(feature = "pcap"))]
    if spec.logging.pcap_write.is_some() {
        return Err(PlannerError::PcapFeatureRequired.into());
    }

    Ok(())
}

fn log_layer3_selection(spec: &PacketSpec) {
    if spec.transmit.auto_layer3 {
        info!(
            "Auto-selected IPv6 layer-3 transmission (no destination MAC and --ipv6-nd not requested)"
        );
    }
}

struct PlanningContext {
    payload: Vec<u8>,
    source_ip: IpAddr,
    source_reason: super::types::SourceSelectionReason,
    destination_ip: IpAddr,
    destination_reason: super::types::DestinationSelectionReason,
    ipv6_first_hop: Option<Ipv6Addr>,
}

fn build_planning_context(
    spec: &PacketSpec,
    interface: &pnet::datalink::NetworkInterface,
) -> Result<PlanningContext> {
    let payload = prepare_payload(&spec.payload.source)?;
    let ip_selection = resolve_ip_addresses_with_selection(spec, interface)?;
    let source_ip = ip_selection.source_ip;
    let destination_ip = ip_selection.destination_ip;
    let ipv6_first_hop = match destination_ip {
        IpAddr::V6(dst) => Some(ipv6::routing_initial_destination(&spec.ipv6.exthdrs, dst)),
        _ => None,
    };

    Ok(PlanningContext {
        payload,
        source_ip,
        source_reason: ip_selection.source_reason,
        destination_ip,
        destination_reason: ip_selection.destination_reason,
        ipv6_first_hop,
    })
}

fn resolve_layer2_plan(
    spec: &PacketSpec,
    interface: &pnet::datalink::NetworkInterface,
    context: &PlanningContext,
    mode: PlanningMode,
) -> Result<Option<Layer2Resolved>> {
    if spec.transmit.is_layer3() {
        return Ok(None);
    }

    match (context.source_ip, context.destination_ip) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => resolve_layer2_ipv4(spec, interface, src, dst, mode),
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            let first_hop = context.ipv6_first_hop.unwrap_or(dst);
            resolve_layer2_ipv6(spec, interface, src, first_hop, mode)
        }
        _ => Err(PlannerError::IpVersionMismatch.into()),
    }
}

fn assemble_frames(
    spec: &PacketSpec,
    context: &PlanningContext,
    layer2: Option<&Layer2Resolved>,
    transport: &TransportBuild,
) -> Result<(Vec<Vec<u8>>, LinkType, NetworkTarget)> {
    let result = match (context.source_ip, context.destination_ip) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => Ipv4PacketBuilder {
            source: src,
            destination: dst,
        }
        .build(spec, transport, layer2),
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            let first_hop = context.ipv6_first_hop.unwrap_or(dst);
            Ipv6PacketBuilder {
                source: src,
                destination: dst,
                first_hop,
            }
            .build(spec, transport, layer2)
        }
        _ => Err(PlannerError::IpVersionMismatch.into()),
    }?;

    Ok(convert_build_result(result))
}

fn convert_build_result(result: PacketBuildResult) -> (Vec<Vec<u8>>, LinkType, NetworkTarget) {
    (result.frames, result.link_type, result.target)
}

fn validate_built_frames(frames: &[Vec<u8>], link_type: &LinkType) -> Result<()> {
    if frames.is_empty() {
        return Err(PlannerError::EmptyFramePlan.into());
    }

    for frame in frames {
        let valid = match link_type {
            LinkType::Ipv4 => Ipv4Packet::new(frame)
                .map(|packet| packet.get_version() == 4)
                .unwrap_or(false),
            LinkType::Ipv6 => Ipv6Packet::new(frame)
                .map(|packet| packet.get_version() == 6)
                .unwrap_or(false),
            LinkType::Ethernet => EthernetPacket::new(frame).is_some(),
        };

        if !valid {
            return Err(PlannerError::InvalidBuiltFrame {
                link_type: link_type.as_str(),
            }
            .into());
        }
    }

    Ok(())
}

fn build_summary(
    context: &PlanningContext,
    frames: &[Vec<u8>],
    transport_label: &'static str,
) -> TransmissionSummary {
    let largest_frame_len = frames.iter().map(|frame| frame.len()).max().unwrap_or(0);
    TransmissionSummary {
        payload_len: context.payload.len(),
        largest_frame_len,
        frame_count: frames.len(),
        transport: transport_label,
    }
}

fn format_target(target: &DestinationSpec) -> String {
    target
        .address
        .as_ref()
        .map(TargetAddress::to_string)
        .unwrap_or_else(|| "<unspecified destination>".to_string())
}

#[cfg(test)]
mod tests {
    use super::super::error::SenderError;
    use super::*;
    #[cfg(not(feature = "pcap"))]
    use crate::domain::spec::LoggingSpec;
    use pnet::packet::ethernet::MutableEthernetPacket;
    use pnet::packet::ipv4::MutableIpv4Packet;
    use pnet::packet::ipv6::MutableIpv6Packet;
    #[cfg(not(feature = "pcap"))]
    use std::path::PathBuf;

    fn ipv4_frame() -> Vec<u8> {
        let mut bytes = vec![0u8; 20];
        MutableIpv4Packet::new(&mut bytes).unwrap().set_version(4);
        bytes
    }

    fn ipv6_frame() -> Vec<u8> {
        let mut bytes = vec![0u8; 40];
        MutableIpv6Packet::new(&mut bytes).unwrap().set_version(6);
        bytes
    }

    fn ethernet_frame() -> Vec<u8> {
        let mut bytes = vec![0u8; 14];
        MutableEthernetPacket::new(&mut bytes).unwrap();
        bytes
    }

    fn context(payload: Vec<u8>) -> PlanningContext {
        PlanningContext {
            payload,
            source_ip: "192.0.2.5".parse().unwrap(),
            source_reason: super::super::types::SourceSelectionReason::ExplicitSourceIp,
            destination_ip: "192.0.2.10".parse().unwrap(),
            destination_reason: super::super::types::DestinationSelectionReason::TargetLiteral,
            ipv6_first_hop: None,
        }
    }

    #[test]
    fn format_target_reports_unspecified_destination() {
        assert_eq!(
            format_target(&DestinationSpec::default()),
            "<unspecified destination>"
        );
    }

    #[test]
    fn format_target_uses_target_address_display() {
        let target = DestinationSpec {
            address: Some(TargetAddress::Ip("192.0.2.10".parse().unwrap())),
            interface: None,
        };

        assert_eq!(format_target(&target), "192.0.2.10");
    }

    #[test]
    fn build_summary_uses_payload_len_frame_count_and_largest_frame() {
        let summary = build_summary(&context(vec![1, 2, 3]), &[vec![0; 4], vec![0; 9]], "udp");

        assert_eq!(summary.payload_len, 3);
        assert_eq!(summary.frame_count, 2);
        assert_eq!(summary.largest_frame_len, 9);
        assert_eq!(summary.transport, "udp");
    }

    #[test]
    fn validate_built_frames_rejects_empty_plan() {
        let err = validate_built_frames(&[], &LinkType::Ipv4).unwrap_err();

        assert!(matches!(
            err,
            SenderError::Planner(PlannerError::EmptyFramePlan)
        ));
    }

    #[test]
    fn validate_built_frames_accepts_matching_link_types() {
        validate_built_frames(&[ipv4_frame()], &LinkType::Ipv4).unwrap();
        validate_built_frames(&[ipv6_frame()], &LinkType::Ipv6).unwrap();
        validate_built_frames(&[ethernet_frame()], &LinkType::Ethernet).unwrap();
    }

    #[test]
    fn validate_built_frames_rejects_ip_version_mismatch() {
        let err = validate_built_frames(&[ipv6_frame()], &LinkType::Ipv4).unwrap_err();

        assert!(matches!(
            err,
            SenderError::Planner(PlannerError::InvalidBuiltFrame { link_type: "ipv4" })
        ));
    }

    #[cfg(not(feature = "pcap"))]
    #[test]
    fn enforce_feature_constraints_rejects_pcap_write_without_feature() {
        let spec = PacketSpec {
            logging: LoggingSpec {
                pcap_write: Some(PathBuf::from("out.pcap")),
                ..Default::default()
            },
            ..Default::default()
        };

        let err = enforce_feature_constraints(&spec).unwrap_err();

        assert!(matches!(
            err,
            SenderError::Planner(PlannerError::PcapFeatureRequired)
        ));
    }

    #[test]
    fn enforce_feature_constraints_accepts_default_logging() {
        let spec = PacketSpec::default();

        enforce_feature_constraints(&spec).unwrap();
    }
}
