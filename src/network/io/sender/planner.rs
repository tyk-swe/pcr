use std::net::{IpAddr, Ipv6Addr};

use log::{debug, info, warn};

use crate::engine::spec::{DestinationSpec, PacketSpec, TargetAddress};

use super::builder::{Ipv4PacketBuilder, Ipv6PacketBuilder, PacketBuildResult, PacketBuilder};
use super::control::{validate_transmission_policy, TransmissionPolicy};
use super::error::{PlannerError, Result};
use super::interface::{resolve_ip_addresses, select_interface};
use super::ipv6;
use super::layer2::{resolve_layer2_ipv4, resolve_layer2_ipv6, Layer2Resolved};
use super::metrics::emit_metrics_snapshot;
use super::payload::prepare_payload;
use super::transport::{build_transport_segment, TransportBuild};
use super::types::{LinkType, NetworkTarget, PlanningMode, TransmissionPlan, TransmissionSummary};

pub fn plan_transmission(spec: &PacketSpec) -> Result<TransmissionPlan> {
    plan_transmission_with_policy(spec, TransmissionPolicy::default())
}

pub fn plan_transmission_dry_run(spec: &PacketSpec) -> Result<TransmissionPlan> {
    plan_transmission_dry_run_with_policy(spec, TransmissionPolicy::new(false, true))
}

pub fn plan_transmission_with_policy(
    spec: &PacketSpec,
    policy: TransmissionPolicy,
) -> Result<TransmissionPlan> {
    plan_transmission_with_mode(spec, PlanningMode::Live, policy)
}

pub fn plan_transmission_dry_run_with_policy(
    spec: &PacketSpec,
    policy: TransmissionPolicy,
) -> Result<TransmissionPlan> {
    plan_transmission_with_mode(spec, PlanningMode::DryRun, policy)
}

fn plan_transmission_with_mode(
    spec: &PacketSpec,
    mode: PlanningMode,
    policy: TransmissionPolicy,
) -> Result<TransmissionPlan> {
    info!("Preparing packet for {}", format_target(&spec.target));

    let interface = select_interface(spec)?;
    plan_transmission_with_interface_and_policy(spec, interface, mode, policy)
}

/// Plan transmission with selected interface.
pub fn plan_transmission_with_interface(
    spec: &PacketSpec,
    interface: pnet::datalink::NetworkInterface,
    mode: PlanningMode,
) -> Result<TransmissionPlan> {
    let policy = TransmissionPolicy::new(false, mode == PlanningMode::DryRun);
    plan_transmission_with_interface_and_policy(spec, interface, mode, policy)
}

pub fn plan_transmission_with_interface_and_policy(
    spec: &PacketSpec,
    interface: pnet::datalink::NetworkInterface,
    mode: PlanningMode,
    policy: TransmissionPolicy,
) -> Result<TransmissionPlan> {
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

    let plan = TransmissionPlan {
        frames,
        link_type,
        transmit,
        destination,
        interface,
        protocol,
        summary,
        logging: spec.logging.clone(),
        mode,
        policy,
    };

    if mode == PlanningMode::Live {
        emit_metrics_snapshot(&plan)?;
    }

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
    destination_ip: IpAddr,
    ipv6_first_hop: Option<Ipv6Addr>,
}

fn build_planning_context(
    spec: &PacketSpec,
    interface: &pnet::datalink::NetworkInterface,
) -> Result<PlanningContext> {
    let payload = prepare_payload(&spec.payload.source)?;
    let (source_ip, destination_ip) = resolve_ip_addresses(spec, interface)?;
    let ipv6_first_hop = match destination_ip {
        IpAddr::V6(dst) => Some(ipv6::routing_initial_destination(&spec.ipv6.exthdrs, dst)),
        _ => None,
    };

    Ok(PlanningContext {
        payload,
        source_ip,
        destination_ip,
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
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn format_target_shows_unspecified_when_no_address() {
        let target = DestinationSpec {
            address: None,
            interface: None,
        };
        assert_eq!(format_target(&target), "<unspecified destination>");
    }

    #[test]
    fn format_target_shows_ip_address() {
        let target = DestinationSpec {
            address: Some(TargetAddress::Ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)))),
            interface: None,
        };
        assert_eq!(format_target(&target), "192.168.1.1");
    }

    #[test]
    fn format_target_shows_hostname() {
        let target = DestinationSpec {
            address: Some(TargetAddress::Host("example.com".to_string())),
            interface: None,
        };
        assert_eq!(format_target(&target), "example.com");
    }

    #[test]
    fn format_target_shows_ipv6_address() {
        let target = DestinationSpec {
            address: Some(TargetAddress::Ip(IpAddr::V6(Ipv6Addr::new(
                0x2001, 0xdb8, 0, 0, 0, 0, 0, 1,
            )))),
            interface: None,
        };
        assert_eq!(format_target(&target), "2001:db8::1");
    }

    #[test]
    fn format_target_with_interface_specified() {
        let target = DestinationSpec {
            address: None,
            interface: Some("eth0".to_string()),
        };
        assert_eq!(format_target(&target), "<unspecified destination>");
    }

    #[test]
    fn build_summary_with_single_frame() {
        let context = PlanningContext {
            payload: vec![1, 2, 3, 4],
            source_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            destination_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)),
            ipv6_first_hop: None,
        };
        let frames = vec![vec![0; 64]];
        let label = "tcp";

        let summary = build_summary(&context, &frames, label);

        assert_eq!(summary.payload_len, 4);
        assert_eq!(summary.largest_frame_len, 64);
        assert_eq!(summary.frame_count, 1);
        assert_eq!(summary.transport, "tcp");
    }

    #[test]
    fn build_summary_with_multiple_frames() {
        let context = PlanningContext {
            payload: vec![1, 2, 3, 4, 5, 6, 7, 8],
            source_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            destination_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            ipv6_first_hop: None,
        };
        let frames = vec![vec![0; 100], vec![0; 150], vec![0; 80]];
        let label = "udp";

        let summary = build_summary(&context, &frames, label);

        assert_eq!(summary.payload_len, 8);
        assert_eq!(summary.largest_frame_len, 150);
        assert_eq!(summary.frame_count, 3);
        assert_eq!(summary.transport, "udp");
    }

    #[test]
    fn build_summary_with_empty_payload() {
        let context = PlanningContext {
            payload: vec![],
            source_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            destination_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            ipv6_first_hop: None,
        };
        let frames = vec![vec![0; 40]];
        let label = "icmp";

        let summary = build_summary(&context, &frames, label);

        assert_eq!(summary.payload_len, 0);
        assert_eq!(summary.largest_frame_len, 40);
        assert_eq!(summary.frame_count, 1);
        assert_eq!(summary.transport, "icmp");
    }

    #[test]
    fn build_summary_with_no_frames() {
        let context = PlanningContext {
            payload: vec![1, 2, 3],
            source_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            destination_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)),
            ipv6_first_hop: None,
        };
        let frames: Vec<Vec<u8>> = vec![];
        let label = "tcp";

        let summary = build_summary(&context, &frames, label);

        assert_eq!(summary.payload_len, 3);
        assert_eq!(summary.largest_frame_len, 0);
        assert_eq!(summary.frame_count, 0);
        assert_eq!(summary.transport, "tcp");
    }

    #[test]
    fn build_summary_with_varying_frame_sizes() {
        let context = PlanningContext {
            payload: vec![0xFF; 1000],
            source_ip: IpAddr::V6(Ipv6Addr::LOCALHOST),
            destination_ip: IpAddr::V6(Ipv6Addr::LOCALHOST),
            ipv6_first_hop: Some(Ipv6Addr::LOCALHOST),
        };
        let frames = vec![
            vec![0; 40],
            vec![0; 1500],
            vec![0; 200],
            vec![0; 800],
            vec![0; 64],
        ];
        let label = "icmpv6";

        let summary = build_summary(&context, &frames, label);

        assert_eq!(summary.payload_len, 1000);
        assert_eq!(summary.largest_frame_len, 1500);
        assert_eq!(summary.frame_count, 5);
        assert_eq!(summary.transport, "icmpv6");
    }

    #[test]
    fn convert_build_result_extracts_all_fields() {
        use super::super::types::{LinkType, NetworkTarget};

        let result = PacketBuildResult {
            frames: vec![vec![1, 2, 3], vec![4, 5, 6]],
            link_type: LinkType::Ethernet,
            target: NetworkTarget::Ipv4(Ipv4Addr::new(192, 168, 1, 1)),
        };

        let (frames, link_type, target) = convert_build_result(result);

        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0], vec![1, 2, 3]);
        assert_eq!(frames[1], vec![4, 5, 6]);
        assert!(matches!(link_type, LinkType::Ethernet));
        assert!(matches!(target, NetworkTarget::Ipv4(_)));
    }

    #[test]
    fn format_target_with_ipv6_loopback() {
        let target = DestinationSpec {
            address: Some(TargetAddress::Ip(IpAddr::V6(Ipv6Addr::LOCALHOST))),
            interface: None,
        };
        assert_eq!(format_target(&target), "::1");
    }

    #[test]
    fn format_target_with_ipv4_loopback() {
        let target = DestinationSpec {
            address: Some(TargetAddress::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST))),
            interface: None,
        };
        assert_eq!(format_target(&target), "127.0.0.1");
    }

    #[test]
    fn format_target_with_broadcast_address() {
        let target = DestinationSpec {
            address: Some(TargetAddress::Ip(IpAddr::V4(Ipv4Addr::BROADCAST))),
            interface: None,
        };
        assert_eq!(format_target(&target), "255.255.255.255");
    }

    #[test]
    fn format_target_with_unspecified_ipv6() {
        let target = DestinationSpec {
            address: Some(TargetAddress::Ip(IpAddr::V6(Ipv6Addr::UNSPECIFIED))),
            interface: None,
        };
        assert_eq!(format_target(&target), "::");
    }
}
