// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::{Duration, Instant};

use packetcraftr::{capture::Frame, client, net, output, packet};

use crate::errors::CliError;
use crate::filtering::FrameSelector;

#[derive(Debug)]
pub(super) struct CaptureOutcome {
    pub(super) diagnostics: Vec<packet::diagnostic::Diagnostic>,
    pub(super) stats: output::envelope::Stats,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct CaptureBudget {
    pub(super) max_frames: u64,
    pub(super) max_bytes: u64,
}

impl From<&client::policy::Policy> for CaptureBudget {
    fn from(policy: &client::policy::Policy) -> Self {
        Self {
            max_frames: policy.max_packets_per_operation,
            max_bytes: policy.max_bytes_per_operation,
        }
    }
}

pub(super) fn drive_capture<C, F>(
    mut capture: C,
    timeout: Duration,
    limits: net::capture::Limits,
    budget: CaptureBudget,
    selector: Option<&FrameSelector>,
    mut emit: F,
) -> Result<CaptureOutcome, CliError>
where
    C: net::capture::Session,
    F: FnMut(Frame, u64) -> Result<(), CliError>,
{
    let started = Instant::now();
    let deadline = started
        .checked_add(timeout)
        .expect("validated capture timeout must fit the monotonic clock");
    if !timeout.is_zero() {
        let readiness_timeout = deadline
            .checked_duration_since(Instant::now())
            .unwrap_or(Duration::ZERO);
        if let Err(source) = capture.wait_ready(readiness_timeout) {
            let error = CliError::classified(source).at_sequence(0);
            return Err(shutdown_after_error(&mut capture, error));
        }
    }
    // Two counters, because they answer different questions: `frames` counts
    // every frame the backend delivered, which is what the policy budgets
    // account for whether or not the display filter keeps the frame, while
    // `matched` numbers the records actually emitted so a filtered stream
    // stays contiguous. Without a display filter the two never diverge.
    let mut frames = 0_u64;
    let mut matched = 0_u64;
    let mut bytes = 0_u64;
    while frames < budget.max_frames {
        let now = Instant::now();
        let Some(remaining) = deadline.checked_duration_since(now) else {
            break;
        };
        if remaining.is_zero() {
            break;
        }
        let frame = match capture.next_captured_frame(remaining) {
            Ok(Some(captured)) => captured.frame,
            Ok(None) => break,
            Err(source) => {
                let error = CliError::classified(source).at_sequence(matched);
                return Err(shutdown_after_error(&mut capture, error));
            }
        };
        let frame_bytes = u64::try_from(frame.bytes().len()).map_err(|_| {
            shutdown_after_error(
                &mut capture,
                CliError::new(
                    70,
                    "captured frame length exceeds the byte-accounting domain",
                )
                .at_sequence(matched),
            )
        })?;
        let next_bytes = bytes.checked_add(frame_bytes).ok_or_else(|| {
            shutdown_after_error(
                &mut capture,
                CliError::new(70, "capture output byte accounting overflowed").at_sequence(matched),
            )
        })?;
        if next_bytes > budget.max_bytes {
            let error = CliError::classified(client::policy::Error::ByteLimit {
                actual: next_bytes,
                limit: budget.max_bytes,
            })
            .at_sequence(matched);
            return Err(shutdown_after_error(&mut capture, error));
        }
        bytes = next_bytes;
        let number = frames.checked_add(1).ok_or_else(|| {
            shutdown_after_error(
                &mut capture,
                CliError::classified(output::contract::Error::SequenceOverflow)
                    .at_sequence(matched),
            )
        })?;
        if let Some(selector) = selector {
            match selector.keep(number, &frame) {
                Ok(true) => {}
                Ok(false) => {
                    frames = number;
                    continue;
                }
                Err(error) => {
                    return Err(shutdown_after_error(
                        &mut capture,
                        error.at_sequence_if_absent(matched),
                    ));
                }
            }
        }
        if let Err(error) = emit(frame, matched) {
            return Err(shutdown_after_error(
                &mut capture,
                error.at_sequence_if_absent(matched),
            ));
        }
        matched = matched.checked_add(1).ok_or_else(|| {
            shutdown_after_error(
                &mut capture,
                CliError::classified(output::contract::Error::SequenceOverflow)
                    .at_sequence(matched),
            )
        })?;
        frames = number;
    }
    capture
        .shutdown()
        .map_err(CliError::classified)
        .map_err(|error| error.at_sequence(matched))?;
    let statistics = capture
        .statistics()
        .validate()
        .map_err(CliError::classified)
        .map_err(|error| error.at_sequence(matched))?;
    let mut diagnostics = Vec::new();
    if statistics.has_loss() {
        if limits.overflow_policy == net::capture::OverflowPolicy::Fail {
            return Err(CliError::classified(
                statistics
                    .evidence_loss_error()
                    .expect("lossy capture statistics must produce a typed error"),
            )
            .at_sequence(matched));
        }
        diagnostics.push(packet::diagnostic::Diagnostic::warning(
            "capture.evidence_incomplete",
            format!(
                "capture backend reported {} overflow event(s), {} receiver drop(s), {} total dropped frame(s), and {} dropped byte(s) under {:?}",
                statistics.overflow_events,
                statistics.receiver_dropped_frames,
                statistics.dropped_frames,
                statistics.dropped_bytes,
                limits.overflow_policy
            ),
        ));
    }
    Ok(CaptureOutcome {
        diagnostics,
        stats: output::envelope::Stats {
            packets_attempted: frames,
            packets_completed: matched,
            bytes,
            elapsed: started.elapsed(),
            capture: statistics.into(),
        },
    })
}

pub(super) fn shutdown_after_error<C: net::capture::Session>(
    capture: &mut C,
    error: CliError,
) -> CliError {
    match capture.shutdown() {
        Ok(()) => error,
        Err(cleanup) => error.with_cleanup(cleanup),
    }
}
