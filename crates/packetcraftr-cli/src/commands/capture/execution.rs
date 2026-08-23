// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::{Duration, Instant};

use packetcraftr::{core, core::frame::Frame, netio as net, output};

use super::super::increment_counter;
use crate::errors::CliError;
use crate::filtering::FrameSelector;

#[derive(Debug)]
pub(super) struct Outcome {
    pub(super) diagnostics: Vec<core::diagnostic::Diagnostic>,
    pub(super) stats: output::envelope::Stats,
}

struct Progress {
    started: Instant,
    deadline: Instant,
    frames_captured: u64,
    frames_matched: u64,
    captured_bytes: u64,
}

impl Progress {
    fn new(timeout: Duration) -> Self {
        let started = Instant::now();
        let deadline = started
            .checked_add(timeout)
            .expect("validated capture timeout must fit the monotonic clock");
        Self {
            started,
            deadline,
            frames_captured: 0,
            frames_matched: 0,
            captured_bytes: 0,
        }
    }
}

pub(super) fn run<C, F>(
    mut capture: C,
    timeout: Duration,
    limits: net::capture::Limits,
    policy: &packetcraftr::policy::Policy,
    selector: Option<&FrameSelector>,
    mut emit: F,
) -> Result<Outcome, CliError>
where
    C: net::capture::Session,
    F: FnMut(Frame, u64) -> Result<(), CliError>,
{
    let mut progress = Progress::new(timeout);
    if let Err(error) = wait_ready(&mut capture, timeout, progress.deadline) {
        return Err(shutdown_after_error(&mut capture, error));
    }
    if let Err(error) = capture_frames(&mut capture, &mut progress, policy, selector, &mut emit) {
        return Err(shutdown_after_error(&mut capture, error));
    }
    finish(capture, progress, limits)
}

fn wait_ready<C: net::capture::Session>(
    capture: &mut C,
    timeout: Duration,
    deadline: Instant,
) -> Result<(), CliError> {
    if timeout.is_zero() {
        return Ok(());
    }
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .unwrap_or(Duration::ZERO);
    capture.wait_ready(remaining).map_err(CliError::classified)
}

fn capture_frames<C, F>(
    capture: &mut C,
    progress: &mut Progress,
    policy: &packetcraftr::policy::Policy,
    selector: Option<&FrameSelector>,
    emit: &mut F,
) -> Result<(), CliError>
where
    C: net::capture::Session,
    F: FnMut(Frame, u64) -> Result<(), CliError>,
{
    while progress.frames_captured < policy.max_packets_per_operation {
        let Some(remaining) = progress.deadline.checked_duration_since(Instant::now()) else {
            break;
        };
        if remaining.is_zero() {
            break;
        }
        let Some(frame) = capture
            .next_captured_frame(remaining)
            .map_err(CliError::classified)?
            .map(|captured| captured.frame)
        else {
            break;
        };
        account_bytes(progress, &frame, policy)?;
        let source_frame = increment_counter(progress.frames_captured, "capture frame count")?;
        if let Some(selector) = selector {
            match selector.keep(source_frame, &frame) {
                Ok(true) => {}
                Ok(false) => {
                    progress.frames_captured = source_frame;
                    continue;
                }
                Err(error) => return Err(error),
            }
        }
        emit(frame, source_frame)?;
        progress.frames_matched =
            increment_counter(progress.frames_matched, "capture matched-frame count")?;
        progress.frames_captured = source_frame;
    }
    Ok(())
}

fn account_bytes(
    progress: &mut Progress,
    frame: &Frame,
    policy: &packetcraftr::policy::Policy,
) -> Result<(), CliError> {
    let frame_bytes = u64::try_from(frame.bytes().len()).map_err(|_| {
        CliError::new(
            70,
            "captured frame length exceeds the byte-accounting domain",
        )
    })?;
    let bytes = progress
        .captured_bytes
        .checked_add(frame_bytes)
        .ok_or_else(|| CliError::new(70, "capture output byte accounting overflowed"))?;
    policy
        .authorize_operation(progress.frames_captured, bytes)
        .map_err(CliError::classified)?;
    progress.captured_bytes = bytes;
    Ok(())
}

fn finish<C: net::capture::Session>(
    mut capture: C,
    progress: Progress,
    limits: net::capture::Limits,
) -> Result<Outcome, CliError> {
    capture.shutdown().map_err(CliError::classified)?;
    let statistics = capture
        .statistics()
        .validate()
        .map_err(CliError::classified)?;
    let diagnostics = loss_diagnostics(&statistics, limits)?;
    Ok(Outcome {
        diagnostics,
        stats: output::envelope::Stats {
            packets_attempted: progress.frames_captured,
            packets_completed: progress.frames_matched,
            bytes: progress.captured_bytes,
            elapsed: progress.started.elapsed(),
            capture: statistics.into(),
        },
    })
}

fn loss_diagnostics(
    statistics: &net::capture::Statistics,
    limits: net::capture::Limits,
) -> Result<Vec<core::diagnostic::Diagnostic>, CliError> {
    if !statistics.has_loss() {
        return Ok(Vec::new());
    }
    if limits.overflow_policy == net::capture::OverflowPolicy::Fail {
        return Err(CliError::classified(
            statistics
                .evidence_loss_error()
                .expect("lossy capture statistics must produce a typed error"),
        ));
    }
    Ok(vec![core::diagnostic::Diagnostic::warning(
        "capture.evidence_incomplete",
        format!(
            "capture backend reported {} overflow event(s), {} receiver drop(s), {} total dropped frame(s), and {} dropped byte(s) under {:?}",
            statistics.overflow_events,
            statistics.receiver_dropped_frames,
            statistics.dropped_frames,
            statistics.dropped_bytes,
            limits.overflow_policy
        ),
    )])
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
