// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

/// Streams, authorizes, schedules, and transmits without retaining more than one frame.
use std::io::Read;
use std::time::{Duration, SystemTime};

use packetcraftr_core::analysis::pcap::{Format, Interface, Reader};
use packetcraftr_core::budget::{Deadline, DeadlineExceeded};
use packetcraftr_core::frame::Frame;
use packetcraftr_netio::{interface::Id as InterfaceId, link::Mode as LinkMode};

use crate::clock::Clock;

use super::error::Error;
use super::model::{
    AuthorizationContext, Authorizer, FrameEvidence, Limits, Options, Selector, Summary, Timing,
    Transmission, Transmitter,
};
use super::wire::{replay_link_mode, validate_transmission_evidence};

#[derive(Default)]
struct Progress {
    frames_read: u64,
    frames_transmitted: u64,
    bytes_transmitted: u64,
    scheduled_duration: Duration,
    previous_timestamp: Option<SystemTime>,
    has_previous: bool,
}

struct ReadFrame {
    frame: Frame,
    capture_interface: Interface,
    number: u64,
}

struct FramePlan {
    mode: LinkMode,
    delay: Duration,
    next_completed: u64,
    next_bytes: u64,
    next_duration: Duration,
}

impl Progress {
    fn complete(&mut self, plan: &FramePlan, timestamp: Option<SystemTime>) {
        self.frames_transmitted = plan.next_completed;
        self.bytes_transmitted = plan.next_bytes;
        self.scheduled_duration = plan.next_duration;
        self.previous_timestamp = timestamp;
        self.has_previous = true;
    }
}

pub fn run<R, A, T, C, F>(
    reader: &mut Reader<R>,
    options: &Options,
    authorizer: &mut A,
    transmitter: &mut T,
    clock: &mut C,
    emit: F,
) -> Result<Summary, Error>
where
    R: Read,
    A: Authorizer,
    T: Transmitter,
    C: Clock,
    F: FnMut(FrameEvidence) -> Result<(), Error>,
{
    run_with_selector(reader, options, None, authorizer, transmitter, clock, emit)
}

/// Replays only the capture frames the selector keeps.
///
/// # Panics
///
/// Panics only if the transmitter reports more completed frames than authorized.
pub fn run_with_selector<R, A, T, C, F>(
    reader: &mut Reader<R>,
    options: &Options,
    mut selector: Option<&mut dyn Selector>,
    authorizer: &mut A,
    transmitter: &mut T,
    clock: &mut C,
    mut emit: F,
) -> Result<Summary, Error>
where
    R: Read,
    A: Authorizer,
    T: Transmitter,
    C: Clock,
    F: FnMut(FrameEvidence) -> Result<(), Error>,
{
    let mut deadline = Deadline::new(options.limits.max_duration);
    let limits = options.limits.validate()?;
    let timing = options.timing.validate()?;
    enforce_deadline(&deadline, 0)?;
    let source_format = reader.format();
    let mut progress = Progress::default();

    loop {
        let source_index = progress.frames_read;
        let Some(read) = read_frame(reader, &limits, &deadline, source_index)? else {
            break;
        };
        progress.frames_read = read.number;
        if !select_frame(
            &mut selector,
            &deadline,
            source_index,
            read.number,
            &read.frame,
        )? {
            continue;
        }

        let plan = plan_frame(
            options,
            &limits,
            timing,
            &progress,
            &read.frame,
            source_index,
            &deadline,
        )?;
        authorize_frame(
            authorizer,
            &deadline,
            source_index,
            AuthorizationContext {
                packets: plan.next_completed,
                wire_bytes: plan.next_bytes,
            },
            &read.frame,
            plan.mode,
        )?;
        let interface = validate_interface(
            transmitter,
            options,
            &deadline,
            source_index,
            plan.mode,
            &read.frame,
        )?;
        pace(clock, &mut deadline, source_index, plan.delay)?;
        let transmission = transmit_frame(
            transmitter,
            &deadline,
            source_index,
            &interface,
            plan.mode,
            &read.frame,
        )?;

        progress.complete(&plan, read.frame.timestamp);
        emit(FrameEvidence {
            source_index,
            source_interface_id: read.frame.interface,
            capture_interface: read.capture_interface,
            link_mode: plan.mode,
            scheduled_delay: plan.delay,
            frame: read.frame,
            transmission,
        })?;
        enforce_deadline(&deadline, source_index)?;
    }

    finish_summary(&deadline, progress, source_format, timing)
}

fn read_frame<R: Read>(
    reader: &mut Reader<R>,
    limits: &Limits,
    deadline: &Deadline,
    source_index: u64,
) -> Result<Option<ReadFrame>, Error> {
    enforce_deadline(deadline, source_index)?;
    let frame = reader.next_frame();
    enforce_deadline(deadline, source_index)?;
    let Some(frame) = frame.map_err(|source| Error::Capture {
        source_index,
        source,
    })?
    else {
        return Ok(None);
    };
    let capture_interface = capture_interface(reader, &frame, source_index)?;
    let number = source_index.checked_add(1).ok_or(Error::FrameLimit {
        source_index,
        actual: u64::MAX,
        limit: limits.max_frames,
    })?;
    if number > limits.max_frames {
        return Err(Error::FrameLimit {
            source_index,
            actual: number,
            limit: limits.max_frames,
        });
    }
    if frame.bytes().len() > limits.max_frame_bytes {
        return Err(Error::FrameSizeLimit {
            source_index,
            actual: frame.bytes().len(),
            limit: limits.max_frame_bytes,
        });
    }
    Ok(Some(ReadFrame {
        frame,
        capture_interface,
        number,
    }))
}

fn capture_interface<R: Read>(
    reader: &Reader<R>,
    frame: &Frame,
    source_index: u64,
) -> Result<Interface, Error> {
    frame
        .interface
        .and_then(|interface| {
            reader
                .interfaces()
                .get(usize::try_from(interface).unwrap_or(usize::MAX))
        })
        .or_else(|| {
            (reader.format() == Format::Pcap)
                .then(|| reader.interfaces().first())
                .flatten()
        })
        .cloned()
        .ok_or_else(|| Error::InvalidEvidence {
            source_index,
            message: "capture frame has no matching interface metadata".to_owned(),
        })
}

fn select_frame(
    selector: &mut Option<&mut dyn Selector>,
    deadline: &Deadline,
    source_index: u64,
    number: u64,
    frame: &Frame,
) -> Result<bool, Error> {
    let Some(selector) = selector.as_deref_mut() else {
        return Ok(true);
    };
    enforce_deadline(deadline, source_index)?;
    let selected = selector
        .select(number, frame)
        .map_err(|source| Error::Selection {
            source_index,
            source,
        })?;
    enforce_deadline(deadline, source_index)?;
    Ok(selected)
}

fn plan_frame(
    options: &Options,
    limits: &Limits,
    timing: Timing,
    progress: &Progress,
    frame: &Frame,
    source_index: u64,
    deadline: &Deadline,
) -> Result<FramePlan, Error> {
    let next_bytes = progress
        .bytes_transmitted
        .checked_add(u64::from(frame.captured_length()))
        .ok_or(Error::ByteLimit {
            source_index,
            actual: u64::MAX,
            limit: limits.max_bytes,
        })?;
    if next_bytes > limits.max_bytes {
        return Err(Error::ByteLimit {
            source_index,
            actual: next_bytes,
            limit: limits.max_bytes,
        });
    }
    let mode = replay_link_mode(source_index, frame.link_type, options.link_mode)?;
    let delay = scheduled_delay(timing, progress, frame, source_index)?;
    let next_duration =
        progress
            .scheduled_duration
            .checked_add(delay)
            .ok_or(Error::DurationLimit {
                source_index,
                actual: Duration::MAX,
                limit: limits.max_duration,
            })?;
    if next_duration > limits.max_duration {
        return Err(Error::DurationLimit {
            source_index,
            actual: next_duration,
            limit: limits.max_duration,
        });
    }
    deadline
        .check_additional(delay)
        .map_err(|error| duration_limit(source_index, error))?;
    let next_completed = progress
        .frames_transmitted
        .checked_add(1)
        .expect("completed frames cannot exceed validated attempted frames");
    Ok(FramePlan {
        mode,
        delay,
        next_completed,
        next_bytes,
        next_duration,
    })
}

fn scheduled_delay(
    timing: Timing,
    progress: &Progress,
    frame: &Frame,
    source_index: u64,
) -> Result<Duration, Error> {
    if !progress.has_previous {
        return Ok(Duration::ZERO);
    }
    match timing.delay_between(progress.previous_timestamp, frame.timestamp, source_index) {
        Ok(delay) => Ok(delay),
        Err(Error::InvalidTiming { mode, value }) => Err(Error::Timing {
            source_index,
            mode,
            value,
        }),
        Err(error) => Err(error),
    }
}

fn authorize_frame<A: Authorizer>(
    authorizer: &mut A,
    deadline: &Deadline,
    source_index: u64,
    context: AuthorizationContext,
    frame: &Frame,
    mode: LinkMode,
) -> Result<(), Error> {
    enforce_deadline(deadline, source_index)?;
    let authorization = authorizer.authorize_operation(context, frame, mode);
    enforce_deadline(deadline, source_index)?;
    authorization.map_err(|source| Error::Authorization {
        source_index,
        source,
    })
}

fn validate_interface<T: Transmitter>(
    transmitter: &mut T,
    options: &Options,
    deadline: &Deadline,
    source_index: u64,
    mode: LinkMode,
    frame: &Frame,
) -> Result<InterfaceId, Error> {
    enforce_deadline(deadline, source_index)?;
    let interface = transmitter.validate_interface(&options.interface, mode, frame);
    enforce_deadline(deadline, source_index)?;
    interface.map_err(|source| Error::Transmission {
        source_index,
        source,
    })
}

fn pace<C: Clock>(
    clock: &mut C,
    deadline: &mut Deadline,
    source_index: u64,
    delay: Duration,
) -> Result<(), Error> {
    deadline
        .start_accounting(delay)
        .map_err(|error| duration_limit(source_index, error))?;
    clock.sleep(delay).map_err(|source| Error::Clock {
        source_index,
        message: source.to_string(),
    })?;
    deadline
        .account(delay)
        .map_err(|error| duration_limit(source_index, error))
}

fn transmit_frame<T: Transmitter>(
    transmitter: &mut T,
    deadline: &Deadline,
    source_index: u64,
    interface: &InterfaceId,
    mode: LinkMode,
    frame: &Frame,
) -> Result<Transmission, Error> {
    enforce_deadline(deadline, source_index)?;
    let transmission = transmitter
        .transmit(interface, mode, frame)
        .map_err(|source| Error::Transmission {
            source_index,
            source,
        })?;
    if &transmission.interface != interface {
        return Err(Error::InvalidEvidence {
            source_index,
            message: format!(
                "backend reported transmission on {} (index {}) after validating {} (index {})",
                transmission.interface.name,
                transmission.interface.index,
                interface.name,
                interface.index
            ),
        });
    }
    validate_transmission_evidence(source_index, frame, &transmission.report)?;
    Ok(transmission)
}

fn finish_summary(
    deadline: &Deadline,
    progress: Progress,
    source_format: Format,
    timing: Timing,
) -> Result<Summary, Error> {
    enforce_deadline(deadline, progress.frames_read)?;
    Ok(Summary {
        source_format,
        timing,
        frames_read: progress.frames_read,
        frames_transmitted: progress.frames_transmitted,
        bytes_transmitted: progress.bytes_transmitted,
        scheduled_duration: progress.scheduled_duration,
    })
}

fn enforce_deadline(deadline: &Deadline, source_index: u64) -> Result<(), Error> {
    deadline
        .check()
        .map_err(|error| duration_limit(source_index, error))
}

fn duration_limit(source_index: u64, error: DeadlineExceeded) -> Error {
    Error::DurationLimit {
        source_index,
        actual: error.actual,
        limit: error.limit,
    }
}
