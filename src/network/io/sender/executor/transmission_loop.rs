// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::thread::sleep;

use crate::network::sender::error::Result;
use crate::util::telemetry;

use super::super::control::{determine_send_mode, SendMode};
use super::super::types::TransmissionPlan;

pub(crate) fn run_transmission_loop<S, R, I, C>(
    plan: &TransmissionPlan,
    mut send_frame: S,
    mut record_packet: R,
    on_infinite_start: I,
    on_complete: C,
) -> Result<()>
where
    S: FnMut(&[u8]) -> Result<()>,
    R: FnMut(&[u8]) -> Result<()>,
    I: FnOnce(),
    C: FnOnce(u64),
{
    let mode = determine_send_mode(&plan.transmit, plan.policy)?;

    if matches!(mode, SendMode::Infinite) {
        on_infinite_start();
    }

    let (frames_counter, bytes_counter) =
        telemetry::get_frame_sent_counters(plan.link_type.as_str(), plan.summary.transport);

    let mut iterations: u64 = 0;
    let mut transmitted: u64 = 0;
    let interval = plan.transmit.interval;

    loop {
        for frame in &plan.frames {
            send_frame(frame)?;
            record_packet(frame)?;
            frames_counter.inc();
            bytes_counter.inc_by(frame.len() as u64);
            transmitted += 1;
        }
        iterations += 1;

        if let SendMode::Finite(limit) = mode {
            if iterations >= limit {
                on_complete(transmitted);
                break;
            }
        }

        if plan.transmit.flood {
            continue;
        }

        if let Some(delay) = interval {
            sleep(delay);
        }
    }
    Ok(())
}
