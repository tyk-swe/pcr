// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

mod backends;
mod recorder;
mod transmission_loop;

use crate::network::sender::error::{ExecutorError, Result};

use backends::send_via_datalink;
use log::error;
use recorder::PacketRecorder;

use super::types::{LinkType, NetworkTransmissionPlan};
pub(crate) use backends::send_via_transport;

pub(crate) async fn execute_transmission(plan: NetworkTransmissionPlan) -> Result<()> {
    if plan.mode == crate::network::sender::types::PlanningMode::DryRun {
        return Err(ExecutorError::DryRunBlocked.into());
    }
    let result = tokio::task::spawn_blocking(move || run_transmission_task(plan)).await;

    match result {
        Ok(inner) => inner,
        Err(e) => {
            if e.is_cancelled() {
                error!("Transmission task cancelled");
                Err(ExecutorError::TaskCancelled.into())
            } else {
                error!("Transmission task panicked");
                Err(ExecutorError::TaskPanicked.into())
            }
        }
    }
}

fn run_transmission_task(plan: NetworkTransmissionPlan) -> Result<()> {
    let mut recorder = PacketRecorder::for_plan(&plan)?;

    let link_type = plan.link_type.clone();
    let result = {
        let mut record_packet = |frame: &[u8]| recorder.record(frame);
        match link_type {
            LinkType::Ethernet => send_via_datalink(plan, &mut record_packet),
            LinkType::Ipv4 | LinkType::Ipv6 => send_via_transport(plan, &mut record_packet),
        }
    };

    if result.is_ok() {
        recorder.flush()?;
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::policy::{TrafficBudget, TransmissionPolicy};
    use crate::domain::spec::{LoggingSpec, TransmissionSpec};
    use crate::network::sender::error::SenderError;
    use crate::network::sender::types::{
        DestinationSelectionReason, InterfaceSelectionReason, NetworkTarget, PlanningMode,
        SelectionMetadata, SourceSelectionReason, TransmissionSummary,
    };
    use pnet::datalink::{MacAddr, NetworkInterface};
    use pnet::packet::ip::IpNextHeaderProtocols;
    use std::net::{IpAddr, Ipv4Addr};

    fn dry_run_plan() -> NetworkTransmissionPlan {
        NetworkTransmissionPlan {
            frames: vec![vec![0x45, 0, 0, 20]],
            link_type: LinkType::Ipv4,
            transmit: TransmissionSpec::default(),
            destination: NetworkTarget::Ipv4(Ipv4Addr::new(192, 0, 2, 10)),
            interface: NetworkInterface {
                name: "eth-test".to_string(),
                description: String::new(),
                index: 1,
                mac: Some(MacAddr::new(0x02, 0, 0, 0, 0, 1)),
                ips: vec!["192.0.2.5/24".parse().unwrap()],
                flags: libc::IFF_UP as u32,
            },
            selection: SelectionMetadata {
                selected_interface: "eth-test".to_string(),
                interface_reason: InterfaceSelectionReason::ExplicitInterface,
                source_ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 5)),
                source_reason: SourceSelectionReason::ExplicitSourceIp,
                destination_ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
                destination_reason: DestinationSelectionReason::TargetLiteral,
            },
            protocol: IpNextHeaderProtocols::Udp,
            summary: TransmissionSummary {
                payload_len: 0,
                largest_frame_len: 4,
                frame_count: 1,
                transport: "udp",
            },
            logging: LoggingSpec::default(),
            mode: PlanningMode::DryRun,
            policy: TransmissionPolicy {
                budget: TrafficBudget {
                    max_rate_per_sec: 0,
                    ..Default::default()
                },
                ..Default::default()
            },
        }
    }

    #[tokio::test]
    async fn execute_transmission_rejects_dry_run_before_transmission() {
        let err = execute_transmission(dry_run_plan()).await.unwrap_err();

        assert!(matches!(
            err,
            SenderError::Executor(ExecutorError::DryRunBlocked)
        ));
    }
}
