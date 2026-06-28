// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use crate::engine::spec::{PacketSpec, TransmissionSpec};
use crate::engine::EngineConfig;
use crate::network::io::sender::{
    determine_send_mode, LinkType, NetworkTarget, SendMode, SenderResult, TransmissionPlan,
};
use crate::output::OutputController;

#[derive(Debug, Clone)]
pub struct PreflightView {
    pub destination: String,
    pub destination_family: &'static str,
    pub interface: String,
    pub mode: &'static str,
    pub transport: &'static str,
    pub count: Option<u64>,
    pub send_mode: &'static str,
    pub frame_count: usize,
    pub largest_frame_len: usize,
    pub transmit: TransmissionSpec,
}

impl PreflightView {
    pub(crate) fn try_from_plan(plan: &TransmissionPlan) -> SenderResult<Self> {
        let (count, send_mode) = match determine_send_mode(&plan.transmit, plan.policy)? {
            SendMode::Finite(count) => (Some(count), "finite"),
            SendMode::Infinite => (None, "unbounded"),
        };

        Ok(Self {
            destination: planned_destination(plan),
            destination_family: planned_destination_family(plan),
            interface: plan.interface.name.clone(),
            mode: planned_mode(plan),
            transport: plan.summary.transport,
            count,
            send_mode,
            frame_count: plan.summary.frame_count,
            largest_frame_len: plan.summary.largest_frame_len,
            transmit: plan.transmit.clone(),
        })
    }
}

impl OutputController {
    pub fn emit_preflight_summary(
        &self,
        spec: &PacketSpec,
        plan: &TransmissionPlan,
        _config: &EngineConfig,
    ) -> anyhow::Result<()> {
        let view = PreflightView::try_from_plan(plan)?;
        self.emit_preflight_view_summary(spec, &view)
    }
}

fn planned_destination_family(plan: &TransmissionPlan) -> &'static str {
    match &plan.destination {
        NetworkTarget::Ipv4(_) => "IPv4",
        NetworkTarget::Ipv6(_) => "IPv6",
    }
}

fn planned_destination(plan: &TransmissionPlan) -> String {
    match &plan.destination {
        NetworkTarget::Ipv4(addr) => addr.to_string(),
        NetworkTarget::Ipv6(addr) => addr.to_string(),
    }
}

fn planned_mode(plan: &TransmissionPlan) -> &'static str {
    if plan.transmit.is_layer3() || matches!(&plan.link_type, LinkType::Ipv4 | LinkType::Ipv6) {
        "L3"
    } else {
        "L2"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    use pnet::datalink::NetworkInterface;
    use pnet::packet::ip::IpNextHeaderProtocols;

    use crate::engine::spec::LoggingSpec;
    use crate::network::io::sender::{PlanningMode, TransmissionPolicy, TransmissionSummary};

    fn test_interface() -> NetworkInterface {
        NetworkInterface {
            name: "test0".to_string(),
            description: String::new(),
            index: 0,
            mac: None,
            ips: vec![],
            flags: 0,
        }
    }

    fn test_plan(
        destination: NetworkTarget,
        link_type: LinkType,
        transmit: TransmissionSpec,
        policy: TransmissionPolicy,
    ) -> TransmissionPlan {
        TransmissionPlan {
            frames: vec![vec![0; 64], vec![0; 128]],
            link_type,
            transmit,
            destination,
            interface: test_interface(),
            protocol: IpNextHeaderProtocols::Udp,
            summary: TransmissionSummary {
                payload_len: 8,
                largest_frame_len: 128,
                frame_count: 2,
                transport: "UDP",
            },
            logging: LoggingSpec::default(),
            mode: PlanningMode::Live,
            policy,
        }
    }

    #[test]
    fn preflight_view_reports_finite_ipv4_layer3_plan() {
        let transmit = TransmissionSpec {
            count: Some(3),
            force_layer3: true,
            ..Default::default()
        };
        let plan = test_plan(
            NetworkTarget::Ipv4(Ipv4Addr::new(192, 0, 2, 10)),
            LinkType::Ipv4,
            transmit,
            TransmissionPolicy::default(),
        );

        let view = PreflightView::try_from_plan(&plan).expect("preflight view");

        assert_eq!(view.destination, "192.0.2.10");
        assert_eq!(view.destination_family, "IPv4");
        assert_eq!(view.interface, "test0");
        assert_eq!(view.mode, "L3");
        assert_eq!(view.transport, "UDP");
        assert_eq!(view.count, Some(3));
        assert_eq!(view.send_mode, "finite");
        assert_eq!(view.frame_count, 2);
        assert_eq!(view.largest_frame_len, 128);
    }

    #[test]
    fn preflight_view_reports_unbounded_flood_when_policy_allows_it() {
        let transmit = TransmissionSpec {
            flood: true,
            ..Default::default()
        };
        let plan = test_plan(
            NetworkTarget::Ipv4(Ipv4Addr::new(198, 51, 100, 20)),
            LinkType::Ipv4,
            transmit,
            TransmissionPolicy::new(true, false),
        );

        let view = PreflightView::try_from_plan(&plan).expect("preflight view");

        assert_eq!(view.count, None);
        assert_eq!(view.send_mode, "unbounded");
    }

    #[test]
    fn preflight_view_reports_ethernet_as_layer2() {
        let plan = test_plan(
            NetworkTarget::Ipv4(Ipv4Addr::new(203, 0, 113, 30)),
            LinkType::Ethernet,
            TransmissionSpec::default(),
            TransmissionPolicy::default(),
        );

        let view = PreflightView::try_from_plan(&plan).expect("preflight view");

        assert_eq!(view.mode, "L2");
    }

    #[test]
    fn preflight_view_reports_ipv6_destination_family() {
        let plan = test_plan(
            NetworkTarget::Ipv6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            LinkType::Ipv6,
            TransmissionSpec::default(),
            TransmissionPolicy::default(),
        );

        let view = PreflightView::try_from_plan(&plan).expect("preflight view");

        assert_eq!(view.destination, "2001:db8::1");
        assert_eq!(view.destination_family, "IPv6");
        assert_eq!(view.mode, "L3");
    }
}
