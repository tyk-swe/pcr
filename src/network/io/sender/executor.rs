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
