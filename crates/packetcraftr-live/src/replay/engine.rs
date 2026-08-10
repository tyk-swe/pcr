// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

/// Streams, authorizes, schedules, and transmits without retaining more than one frame.
use std::io::Read;
use std::time::Duration;

use packetcraftr_analysis::pcap::{Format, Reader};
use packetcraftr_packet::budget::{Deadline, DeadlineExceeded};

use crate::clock::Clock as WorkflowClock;

use super::error::ReplayError;
use super::model::{
    ReplayAuthorizationContext, ReplayAuthorizer, ReplayFrameEvidence, ReplayOptions,
    ReplaySelector, ReplaySummary, ReplayTransmitter,
};
use super::wire::{replay_link_mode, validate_transmission_evidence};

pub fn replay_capture<R, A, T, C, F>(
    reader: &mut Reader<R>,
    options: &ReplayOptions,
    authorizer: &mut A,
    transmitter: &mut T,
    clock: &mut C,
    emit: F,
) -> Result<ReplaySummary, ReplayError>
where
    R: Read,
    A: ReplayAuthorizer,
    T: ReplayTransmitter,
    C: WorkflowClock,
    F: FnMut(ReplayFrameEvidence) -> Result<(), ReplayError>,
{
    replay_capture_with_selector(reader, options, None, authorizer, transmitter, clock, emit)
}

/// Replays only the capture frames the selector keeps.
///
/// # Panics
///
/// Panics only if the transmitter reports more completed frames than authorized.
pub fn replay_capture_with_selector<R, A, T, C, F>(
    reader: &mut Reader<R>,
    options: &ReplayOptions,
    mut selector: Option<&mut dyn ReplaySelector>,
    authorizer: &mut A,
    transmitter: &mut T,
    clock: &mut C,
    mut emit: F,
) -> Result<ReplaySummary, ReplayError>
where
    R: Read,
    A: ReplayAuthorizer,
    T: ReplayTransmitter,
    C: WorkflowClock,
    F: FnMut(ReplayFrameEvidence) -> Result<(), ReplayError>,
{
    let mut deadline = Deadline::new(options.limits.max_duration);
    let limits = options.limits.validate()?;
    let timing = options.timing.validate()?;
    enforce_deadline(&deadline, 0)?;
    let source_format = reader.format();
    let mut previous_timestamp = None;
    let mut has_previous = false;
    let mut frames_attempted = 0_u64;
    let mut frames_completed = 0_u64;
    let mut bytes_completed = 0_u64;
    let mut scheduled_duration = Duration::ZERO;
    let mut timestamp_adjustments = 0_u64;

    loop {
        let source_index = frames_attempted;
        enforce_deadline(&deadline, source_index)?;
        let frame = reader.next_frame();
        enforce_deadline(&deadline, source_index)?;
        let Some(frame) = frame.map_err(|source| ReplayError::Capture {
            source_index,
            source,
        })?
        else {
            break;
        };
        let capture_interface = frame
            .interface
            .and_then(|interface| reader.interfaces().get(interface as usize))
            .or_else(|| {
                (reader.format() == Format::Pcap)
                    .then(|| reader.interfaces().first())
                    .flatten()
            })
            .cloned()
            .ok_or_else(|| ReplayError::InvalidEvidence {
                source_index,
                message: "capture frame has no matching interface metadata".to_owned(),
            })?;

        let next_frames = frames_attempted
            .checked_add(1)
            .ok_or(ReplayError::FrameLimit {
                source_index,
                actual: u64::MAX,
                limit: limits.max_frames,
            })?;
        if next_frames > limits.max_frames {
            return Err(ReplayError::FrameLimit {
                source_index,
                actual: next_frames,
                limit: limits.max_frames,
            });
        }
        if frame.bytes().len() > limits.max_frame_bytes {
            return Err(ReplayError::FrameSizeLimit {
                source_index,
                actual: frame.bytes().len(),
                limit: limits.max_frame_bytes,
            });
        }
        frames_attempted = next_frames;

        // Selection consumes the read-side frame budget but precedes byte accounting,
        // authorization, timing, and transmission.
        if let Some(selector) = selector.as_deref_mut() {
            enforce_deadline(&deadline, source_index)?;
            let selected =
                selector
                    .select(next_frames, &frame)
                    .map_err(|source| ReplayError::Selection {
                        source_index,
                        source,
                    })?;
            enforce_deadline(&deadline, source_index)?;
            if !selected {
                continue;
            }
        }

        let next_bytes = bytes_completed
            .checked_add(u64::from(frame.captured_length()))
            .ok_or(ReplayError::ByteLimit {
                source_index,
                actual: u64::MAX,
                limit: limits.max_bytes,
            })?;
        if next_bytes > limits.max_bytes {
            return Err(ReplayError::ByteLimit {
                source_index,
                actual: next_bytes,
                limit: limits.max_bytes,
            });
        }

        let mode = replay_link_mode(source_index, frame.link_type, options.link_mode)?;
        let current_timestamp = if timing.requires_capture_timestamp() {
            Some(frame.timestamp.ok_or(ReplayError::TimestampUnavailable {
                source_index,
                mode: timing.mode_name(),
            })?)
        } else {
            frame.timestamp
        };
        let (delay, timestamp_adjustment) = if has_previous {
            match timing.delay_between(
                previous_timestamp,
                current_timestamp,
                source_index,
                options.nonmonotonic_timestamps,
            ) {
                Ok(result) => result,
                Err(ReplayError::InvalidTiming { mode, value }) => {
                    return Err(ReplayError::Timing {
                        source_index,
                        mode,
                        value,
                    });
                }
                Err(error) => return Err(error),
            }
        } else {
            (Duration::ZERO, None)
        };
        let next_duration =
            scheduled_duration
                .checked_add(delay)
                .ok_or(ReplayError::DurationLimit {
                    source_index,
                    actual: Duration::MAX,
                    limit: limits.max_duration,
                })?;
        if next_duration > limits.max_duration {
            return Err(ReplayError::DurationLimit {
                source_index,
                actual: next_duration,
                limit: limits.max_duration,
            });
        }
        deadline
            .check_additional(delay)
            .map_err(|error| duration_limit(source_index, error))?;
        // Policy budgets cover prospective wire frames only; skipped frames use the
        // read-side frame budget, never policy.
        let next_completed = frames_completed
            .checked_add(1)
            .expect("completed frames cannot exceed validated attempted frames");
        enforce_deadline(&deadline, source_index)?;
        let authorization = authorizer.authorize_operation(
            ReplayAuthorizationContext {
                packets: next_completed,
                wire_bytes: next_bytes,
            },
            &frame,
            mode,
        );
        enforce_deadline(&deadline, source_index)?;
        authorization.map_err(|source| ReplayError::Authorization {
            source_index,
            source,
        })?;

        enforce_deadline(&deadline, source_index)?;
        let concrete_interface = transmitter.validate_interface(&options.interface, mode, &frame);
        enforce_deadline(&deadline, source_index)?;
        let concrete_interface =
            concrete_interface.map_err(|source| ReplayError::Transmission {
                source_index,
                source,
            })?;

        deadline
            .start_accounting(delay)
            .map_err(|error| duration_limit(source_index, error))?;
        clock.sleep(delay).map_err(|source| ReplayError::Clock {
            source_index,
            message: source.to_string(),
        })?;
        deadline
            .account(delay)
            .map_err(|error| duration_limit(source_index, error))?;

        enforce_deadline(&deadline, source_index)?;
        let transmission = transmitter.transmit(&concrete_interface, mode, &frame);
        let transmission = transmission.map_err(|source| ReplayError::Transmission {
            source_index,
            source,
        })?;
        if transmission.interface != concrete_interface {
            return Err(ReplayError::InvalidEvidence {
                source_index,
                message: format!(
                    "backend reported transmission on {} (index {}) after validating {} (index {})",
                    transmission.interface.name,
                    transmission.interface.index,
                    concrete_interface.name,
                    concrete_interface.index
                ),
            });
        }
        validate_transmission_evidence(source_index, &frame, &transmission.report)?;

        frames_completed = next_completed;
        bytes_completed = next_bytes;
        scheduled_duration = next_duration;
        if timestamp_adjustment.is_some() {
            timestamp_adjustments = timestamp_adjustments
                .checked_add(1)
                .expect("timestamp adjustments cannot exceed completed frames");
        }
        if timestamp_adjustment.is_none() {
            previous_timestamp = current_timestamp;
        }
        has_previous = true;
        let emitted = emit(ReplayFrameEvidence {
            source_index,
            source_interface_id: frame.interface,
            capture_interface,
            link_mode: mode,
            scheduled_delay: delay,
            timestamp_adjustment,
            frame,
            transmission,
        });
        emitted?;
        enforce_deadline(&deadline, source_index)?;
    }

    enforce_deadline(&deadline, frames_attempted)?;
    Ok(ReplaySummary {
        source_format,
        timing,
        nonmonotonic_timestamps: options.nonmonotonic_timestamps,
        frames_attempted,
        frames_completed,
        bytes_completed,
        scheduled_duration,
        timestamp_adjustments,
    })
}

fn enforce_deadline(deadline: &Deadline, source_index: u64) -> Result<(), ReplayError> {
    deadline
        .check()
        .map_err(|error| duration_limit(source_index, error))
}

fn duration_limit(source_index: u64, error: DeadlineExceeded) -> ReplayError {
    ReplayError::DurationLimit {
        source_index,
        actual: error.actual,
        limit: error.limit,
    }
}
