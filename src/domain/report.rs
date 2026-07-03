// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use crate::domain::spec::TransmissionSpec;
use crate::domain::transmission::{
    emission_accounting, SendControlError, TransmissionLinkType, TransmissionPlan,
    TransmissionTarget,
};

#[derive(Debug, Clone)]
pub(crate) struct PreflightView {
    pub destination: String,
    pub selected_destination_ip: String,
    pub destination_reason: &'static str,
    pub destination_family: &'static str,
    pub interface: String,
    pub interface_reason: &'static str,
    pub source_ip: String,
    pub source_reason: &'static str,
    pub mode: &'static str,
    pub transport: &'static str,
    pub count: Option<u64>,
    pub attempts: Option<u64>,
    pub units_per_attempt: u64,
    pub total_emitted_units: Option<u64>,
    pub send_mode: &'static str,
    pub transmit: TransmissionSpec,
}

impl PreflightView {
    pub(crate) fn from_transmission_plan(
        plan: &TransmissionPlan,
    ) -> Result<Self, SendControlError> {
        let accounting =
            emission_accounting(&plan.transmit, plan.policy, plan.summary.frame_count as u64)?;
        let send_mode = if accounting.attempts.is_some() {
            "finite"
        } else {
            "unbounded"
        };

        Ok(Self {
            destination: planned_destination(plan),
            selected_destination_ip: plan.selection.destination_ip.to_string(),
            destination_reason: plan.selection.destination_reason.as_str(),
            destination_family: planned_destination_family(plan),
            interface: plan.interface_name.clone(),
            interface_reason: plan.selection.interface_reason.as_str(),
            source_ip: plan.selection.source_ip.to_string(),
            source_reason: plan.selection.source_reason.as_str(),
            mode: planned_mode(plan),
            transport: plan.summary.transport,
            count: accounting.attempts,
            attempts: accounting.attempts,
            units_per_attempt: accounting.units_per_attempt,
            total_emitted_units: accounting.total_emitted_units,
            send_mode,
            transmit: plan.transmit.clone(),
        })
    }
}

fn planned_destination_family(plan: &TransmissionPlan) -> &'static str {
    match &plan.destination {
        TransmissionTarget::Ipv4(_) => "IPv4",
        TransmissionTarget::Ipv6(_) => "IPv6",
    }
}

fn planned_destination(plan: &TransmissionPlan) -> String {
    match &plan.destination {
        TransmissionTarget::Ipv4(addr) => addr.to_string(),
        TransmissionTarget::Ipv6(addr) => addr.to_string(),
    }
}

fn planned_mode(plan: &TransmissionPlan) -> &'static str {
    if plan.transmit.is_layer3()
        || matches!(
            &plan.link_type,
            TransmissionLinkType::Ipv4 | TransmissionLinkType::Ipv6
        )
    {
        "L3"
    } else {
        "L2"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::policy::TransmissionPolicy;
    use crate::domain::spec::LoggingSpec;
    use crate::domain::transmission::{
        DestinationSelectionReason, InterfaceSelectionReason, PlanningMode, SourceSelectionReason,
        TransmissionProtocol, TransmissionSelection, TransmissionSummary,
    };
    use std::net::{IpAddr, Ipv4Addr};

    fn ipv4_plan(link_type: TransmissionLinkType, transmit: TransmissionSpec) -> TransmissionPlan {
        plan(
            link_type,
            TransmissionTarget::Ipv4(Ipv4Addr::new(192, 0, 2, 10)),
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 5)),
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
            transmit,
            TransmissionPolicy::default(),
        )
    }

    fn ipv6_plan(link_type: TransmissionLinkType, transmit: TransmissionSpec) -> TransmissionPlan {
        plan(
            link_type,
            TransmissionTarget::Ipv6("2001:db8::10".parse().unwrap()),
            IpAddr::V6("2001:db8::5".parse().unwrap()),
            IpAddr::V6("2001:db8::10".parse().unwrap()),
            transmit,
            TransmissionPolicy::default(),
        )
    }

    fn plan(
        link_type: TransmissionLinkType,
        destination: TransmissionTarget,
        source_ip: IpAddr,
        destination_ip: IpAddr,
        transmit: TransmissionSpec,
        policy: TransmissionPolicy,
    ) -> TransmissionPlan {
        TransmissionPlan {
            frames: vec![vec![0; 4], vec![0; 9]],
            link_type,
            transmit,
            destination,
            interface_name: "eth-test".to_string(),
            selection: TransmissionSelection {
                selected_interface: "eth-test".to_string(),
                interface_reason: InterfaceSelectionReason::ExplicitInterface,
                source_ip,
                source_reason: SourceSelectionReason::ExplicitSourceIp,
                destination_ip,
                destination_reason: DestinationSelectionReason::TargetLiteral,
            },
            protocol: TransmissionProtocol(17),
            summary: TransmissionSummary {
                payload_len: 3,
                largest_frame_len: 9,
                frame_count: 2,
                transport: "udp",
            },
            logging: LoggingSpec::default(),
            mode: PlanningMode::DryRun,
            policy,
        }
    }

    #[test]
    fn preflight_view_preserves_ipv4_destination_selection_and_summary() {
        let view = PreflightView::from_transmission_plan(&ipv4_plan(
            TransmissionLinkType::Ethernet,
            TransmissionSpec::default(),
        ))
        .unwrap();

        assert_eq!(view.destination, "192.0.2.10");
        assert_eq!(view.selected_destination_ip, "192.0.2.10");
        assert_eq!(view.destination_reason, "target_literal");
        assert_eq!(view.destination_family, "IPv4");
        assert_eq!(view.interface, "eth-test");
        assert_eq!(view.interface_reason, "explicit_interface");
        assert_eq!(view.source_ip, "192.0.2.5");
        assert_eq!(view.source_reason, "explicit_source_ip");
        assert_eq!(view.transport, "udp");
    }

    #[test]
    fn preflight_view_reports_ethernet_plan_as_layer2() {
        let view = PreflightView::from_transmission_plan(&ipv4_plan(
            TransmissionLinkType::Ethernet,
            TransmissionSpec::default(),
        ))
        .unwrap();

        assert_eq!(view.mode, "L2");
    }

    #[test]
    fn preflight_view_reports_layer3_when_transmit_or_link_type_is_layer3() {
        let forced = PreflightView::from_transmission_plan(&ipv4_plan(
            TransmissionLinkType::Ethernet,
            TransmissionSpec {
                force_layer3: true,
                ..Default::default()
            },
        ))
        .unwrap();
        let link_type = PreflightView::from_transmission_plan(&ipv4_plan(
            TransmissionLinkType::Ipv4,
            TransmissionSpec::default(),
        ))
        .unwrap();

        assert_eq!(forced.mode, "L3");
        assert_eq!(link_type.mode, "L3");
    }

    #[test]
    fn preflight_view_preserves_ipv6_destination_family() {
        let view = PreflightView::from_transmission_plan(&ipv6_plan(
            TransmissionLinkType::Ipv6,
            TransmissionSpec::default(),
        ))
        .unwrap();

        assert_eq!(view.destination, "2001:db8::10");
        assert_eq!(view.selected_destination_ip, "2001:db8::10");
        assert_eq!(view.destination_family, "IPv6");
        assert_eq!(view.mode, "L3");
    }

    #[test]
    fn preflight_view_accounts_for_finite_count() {
        let view = PreflightView::from_transmission_plan(&ipv4_plan(
            TransmissionLinkType::Ethernet,
            TransmissionSpec {
                count: Some(3),
                ..Default::default()
            },
        ))
        .unwrap();

        assert_eq!(view.send_mode, "finite");
        assert_eq!(view.count, Some(3));
        assert_eq!(view.attempts, Some(3));
        assert_eq!(view.units_per_attempt, 2);
        assert_eq!(view.total_emitted_units, Some(6));
    }

    #[test]
    fn preflight_view_accounts_for_unbounded_flood() {
        let mut plan = ipv4_plan(
            TransmissionLinkType::Ethernet,
            TransmissionSpec {
                flood: true,
                ..Default::default()
            },
        );
        plan.policy = TransmissionPolicy {
            allow_unbounded_sends: true,
            ..Default::default()
        };

        let view = PreflightView::from_transmission_plan(&plan).unwrap();

        assert_eq!(view.send_mode, "unbounded");
        assert_eq!(view.count, None);
        assert_eq!(view.total_emitted_units, None);
    }

    #[test]
    fn preflight_view_clones_transmit_spec() {
        let transmit = TransmissionSpec {
            count: Some(5),
            force_layer3: true,
            ..Default::default()
        };
        let view = PreflightView::from_transmission_plan(&ipv4_plan(
            TransmissionLinkType::Ethernet,
            transmit,
        ))
        .unwrap();

        assert_eq!(view.transmit.count, Some(5));
        assert!(view.transmit.force_layer3);
    }

    #[test]
    fn preflight_view_propagates_emitted_unit_overflow() {
        let err = PreflightView::from_transmission_plan(&ipv4_plan(
            TransmissionLinkType::Ethernet,
            TransmissionSpec {
                count: Some(u64::MAX),
                ..Default::default()
            },
        ))
        .unwrap_err();

        assert_eq!(
            err,
            SendControlError::EmittedUnitsOverflow {
                attempts: u64::MAX,
                units_per_attempt: 2
            }
        );
    }
}
