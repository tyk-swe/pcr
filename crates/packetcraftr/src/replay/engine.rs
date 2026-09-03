// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

/// Streams, authorizes, schedules, and transmits without retaining more than one frame.
use std::io::Read;
use std::time::{Duration, SystemTime};

use packetcraftr_core::analysis::pcap::{Format, Interface, Reader};
use packetcraftr_core::budget::{Deadline, DeadlineExceeded};
use packetcraftr_core::frame::Frame;
use packetcraftr_netio::{
    link::Mode as LinkMode, route::Materialized as MaterializedRoute, route::Plan as RoutePlan,
};

use crate::clock::Clock;

use super::error::Error;
use super::model::{
    FrameEvidence, Limits, Options, Selector, Summary, Timing, Transmission, Transmitter,
};
use super::wire::{replay_link_mode, validate_transmission_evidence};
use crate::authorization::{Authorizer, Operation, ReplayFrame, WireBudget};

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

/// Replays only the capture frames the selector keeps.
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
    options.limits.validate()?;
    options.timing.validate()?;
    let limits = options.limits;
    let timing = options.timing;
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
            plan.next_completed,
            plan.next_bytes,
            &read.frame,
            plan.mode,
        )?;
        let route = plan_frame_route(
            transmitter,
            options,
            &deadline,
            source_index,
            plan.mode,
            &read.frame,
        )?;
        authorize_final_wire(
            authorizer,
            &deadline,
            source_index,
            &read.frame,
            &route.plan,
        )?;
        pace(clock, &mut deadline, source_index, plan.delay)?;
        let transmission =
            transmit_frame(transmitter, &deadline, source_index, &route, &read.frame)?;

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
    let number = source_index.checked_add(1).ok_or(Error::SourceFrameLimit {
        source_index,
        actual: u64::MAX,
        limit: limits.max_source_frames,
    })?;
    if number > limits.max_source_frames {
        return Err(Error::SourceFrameLimit {
            source_index,
            actual: number,
            limit: limits.max_source_frames,
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
        .ok_or(Error::TransmittedByteLimit {
            source_index,
            actual: u64::MAX,
            limit: limits.max_transmitted_bytes,
        })?;
    if next_bytes > limits.max_transmitted_bytes {
        return Err(Error::TransmittedByteLimit {
            source_index,
            actual: next_bytes,
            limit: limits.max_transmitted_bytes,
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
    let next_completed =
        progress
            .frames_transmitted
            .checked_add(1)
            .ok_or(Error::SourceFrameLimit {
                source_index,
                actual: u64::MAX,
                limit: limits.max_source_frames,
            })?;
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
    packets: u64,
    wire_bytes: u64,
    frame: &Frame,
    mode: LinkMode,
) -> Result<(), Error> {
    enforce_deadline(deadline, source_index)?;
    let authorization = authorizer.authorize_operation(Operation::Replay(ReplayFrame::new(
        WireBudget::new(packets, wire_bytes),
        frame,
        mode,
    )));
    enforce_deadline(deadline, source_index)?;
    authorization.map_err(|source| Error::Authorization {
        source_index,
        source,
    })
}

fn plan_frame_route<T: Transmitter>(
    transmitter: &mut T,
    options: &Options,
    deadline: &Deadline,
    source_index: u64,
    mode: LinkMode,
    frame: &Frame,
) -> Result<MaterializedRoute, Error> {
    enforce_deadline(deadline, source_index)?;
    let route = transmitter.plan_frame(&options.interface, mode, frame);
    enforce_deadline(deadline, source_index)?;
    route.map_err(|source| Error::Transmission {
        source_index,
        source,
    })
}

fn authorize_final_wire<A: Authorizer>(
    authorizer: &mut A,
    deadline: &Deadline,
    source_index: u64,
    frame: &Frame,
    route: &RoutePlan,
) -> Result<(), Error> {
    enforce_deadline(deadline, source_index)?;
    let authorization = authorizer.authorize_final_wire(frame, route);
    enforce_deadline(deadline, source_index)?;
    authorization.map_err(|source| Error::Authorization {
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
        source: Box::new(source),
    })?;
    deadline
        .account(delay)
        .map_err(|error| duration_limit(source_index, error))
}

fn transmit_frame<T: Transmitter>(
    transmitter: &mut T,
    deadline: &Deadline,
    source_index: u64,
    route: &MaterializedRoute,
    frame: &Frame,
) -> Result<Transmission, Error> {
    enforce_deadline(deadline, source_index)?;
    let interface = &route.plan.decision.interface;
    let transmission =
        transmitter
            .transmit(route, frame)
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
