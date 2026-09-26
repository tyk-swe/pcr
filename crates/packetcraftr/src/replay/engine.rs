// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Streams, authorizes, schedules, and transmits without retaining more than one frame.

use std::io::{Read, Seek};
use std::time::{Duration, Instant, SystemTime};

use packetcraftr_core::budget::{Cancelled, Deadline, DeadlineExceeded, Interrupted};
use packetcraftr_core::capture_file::{Format, Interface, Reader};
use packetcraftr_core::frame::Frame;
use packetcraftr_netio::link::Mode as LinkMode;

use crate::clock::Clock;
use crate::execution;
use crate::route::{Materialized as MaterializedRoute, Plan as RoutePlan};

use super::error::Error;
use super::model::{
    FrameEvidence, Limits, Options, Selector, Summary, Timing, Transmission, Transmitter,
};
use super::wire::{replay_link_mode, requested_interface_matches, validate_transmission_evidence};
use crate::policy::{Authorizer, Operation, ReplayFrame, WireBudget};

#[derive(Default)]
struct Progress {
    frames_read: u64,
    frames_transmitted: u64,
    bytes_transmitted: u64,
    scheduled_duration: Duration,
    pause_duration: Duration,
    passes_completed: u32,
    interfaces_used: Vec<packetcraftr_netio::interface::Id>,
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

struct Session {
    deadline: Deadline,
    progress: Progress,
    anchor: Instant,
    pass: u32,
}
impl Session {
    fn new<C: Clock>(options: &Options, clock: &mut C) -> Result<Self, Error> {
        options.validate()?;
        let deadline =
            Deadline::new(options.limits.max_duration).with_cancellation(clock.cancellation());
        enforce_deadline(&deadline, 0)?;
        Ok(Self {
            deadline,
            progress: Progress::default(),
            anchor: clock.now(),
            pass: 1,
        })
    }
}
struct Run<'o, 's, 'a, 't, 'c, A, T, C, F> {
    options: &'o Options,
    selector: Option<&'s mut dyn Selector>,
    authorizer: &'a mut A,
    transmitter: &'t mut T,
    clock: &'c mut C,
    emit: F,
}

/// Replays one streaming input. Repetition uses the seekable entry point.
pub fn run_with_selector<R, A, T, C, F>(
    reader: &mut Reader<R>,
    options: &Options,
    selector: Option<&mut dyn Selector>,
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
    let mut session = Session::new(options, clock)?;
    if options.repeat != 1 {
        return Err(Error::InvalidLimit {
            field: "repeat",
            value: u64::from(options.repeat),
            reason: "repetition requires run_repeated_with_selector and a stable seekable capture",
        });
    }
    let source_format = reader.format();
    let end_index = Run {
        options,
        selector,
        authorizer,
        transmitter,
        clock,
        emit,
    }
    .pass(reader, &mut session)?;
    finish_summary(
        &session.deadline,
        end_index,
        session.progress,
        source_format,
        options.timing,
    )
}

/// Replays a stable seekable capture under one aggregate budget and schedule.
/// The caller owns source immutability; the CLI supplies an anonymous validated snapshot.
pub fn run_repeated_with_selector<R, A, T, C, F>(
    reader: &mut Reader<R>,
    options: &Options,
    selector: Option<&mut dyn Selector>,
    authorizer: &mut A,
    transmitter: &mut T,
    clock: &mut C,
    emit: F,
) -> Result<Summary, Error>
where
    R: Read + Seek,
    A: Authorizer,
    T: Transmitter,
    C: Clock,
    F: FnMut(FrameEvidence) -> Result<(), Error>,
{
    let mut session = Session::new(options, clock)?;
    reader.rewind().map_err(|source| Error::Capture {
        source_index: 0,
        source,
    })?;
    let source_format = reader.format();
    let mut run = Run {
        options,
        selector,
        authorizer,
        transmitter,
        clock,
        emit,
    };
    let mut end_index = 0;
    for pass in 1..=options.repeat {
        session.pass = pass;
        if pass > 1 {
            enforce_deadline(&session.deadline, 0)?;
            reader.rewind().map_err(|source| Error::Capture {
                source_index: 0,
                source,
            })?;
            if reader.format() != source_format {
                return Err(Error::InvalidEvidence {
                    source_index: 0,
                    message: "capture format changed between passes".to_owned(),
                });
            }
            pace(
                run.clock,
                &mut session.deadline,
                0,
                options.inter_pass_delay,
            )?;
            session.progress.scheduled_duration = session
                .progress
                .scheduled_duration
                .checked_add(options.inter_pass_delay)
                .ok_or(Error::InvalidDuration {
                    value: Duration::MAX,
                    maximum: options.limits.max_duration,
                })?;
            session.progress.pause_duration = session
                .progress
                .pause_duration
                .checked_add(options.inter_pass_delay)
                .ok_or(Error::InvalidDuration {
                    value: Duration::MAX,
                    maximum: options.limits.max_duration,
                })?;
            session.anchor = run
                .clock
                .now()
                .checked_sub(session.progress.scheduled_duration)
                .ok_or(Error::InvalidDuration {
                    value: Duration::MAX,
                    maximum: options.limits.max_duration,
                })?;
            if matches!(options.timing, Timing::Original | Timing::Scaled(_)) {
                session.progress.has_previous = false;
                session.progress.previous_timestamp = None;
            }
        }
        end_index = run.pass(reader, &mut session)?;
    }
    finish_summary(
        &session.deadline,
        end_index,
        session.progress,
        source_format,
        options.timing,
    )
}

impl<A: Authorizer, T: Transmitter, C: Clock, F: FnMut(FrameEvidence) -> Result<(), Error>>
    Run<'_, '_, '_, '_, '_, A, T, C, F>
{
    /// Replays one pass and returns the source index one past its last
    /// frame, the coordinate its end-of-capture deadline gate reports.
    fn pass<R: Read>(
        &mut self,
        reader: &mut Reader<R>,
        session: &mut Session,
    ) -> Result<u64, Error> {
        let limits = self.options.limits;
        let timing = self.options.timing;
        let mut source_index = 0u64;
        loop {
            let Some(read) = read_frame(
                reader,
                &limits,
                &session.deadline,
                source_index,
                session.progress.frames_read,
            )?
            else {
                break;
            };
            session.progress.frames_read += 1;
            source_index = read.number - 1;
            if !select_frame(
                &mut self.selector,
                &session.deadline,
                source_index,
                read.number,
                &read.frame,
            )? {
                source_index += 1;
                continue;
            }

            let plan = plan_frame(
                self.options,
                &limits,
                timing,
                &session.progress,
                &read.frame,
                source_index,
            )?;
            authorize_frame(
                self.authorizer,
                &session.deadline,
                source_index,
                plan.next_completed,
                plan.next_bytes,
                &read.frame,
                plan.mode,
            )?;
            let mapped = match self.selector.as_deref_mut() {
                Some(selector) => {
                    selector
                        .interface(read.number, &read.frame)
                        .map_err(|source| Error::Selection {
                            source_index,
                            source,
                        })?
                }
                None => None,
            };
            let interface =
                mapped
                    .as_ref()
                    .or(self.options.interface.as_ref())
                    .ok_or(Error::InvalidLimit {
                        field: "interface",
                        value: 0,
                        reason: "selected frame has no mapped or fallback interface",
                    })?;
            let route = plan_frame_route(
                self.transmitter,
                interface,
                &session.deadline,
                source_index,
                plan.mode,
                &read.frame,
            )?;
            authorize_final_wire(
                self.authorizer,
                &session.deadline,
                source_index,
                &read.frame,
                &route.plan,
            )?;
            // Overdue frames are sent immediately; later targets stay on the same anchor.
            let target = session
                .anchor
                .checked_add(plan.next_duration)
                .ok_or_else(|| {
                    duration_limit(
                        source_index,
                        DeadlineExceeded {
                            actual: Duration::MAX,
                            limit: limits.max_duration,
                        },
                    )
                })?;
            let remaining = target.saturating_duration_since(self.clock.now());
            pace(self.clock, &mut session.deadline, source_index, remaining)?;
            let transmission = transmit_frame(
                self.transmitter,
                &session.deadline,
                source_index,
                &route,
                &read.frame,
            )?;

            session.progress.complete(&plan, read.frame.timestamp);
            if !session
                .progress
                .interfaces_used
                .contains(&transmission.interface)
            {
                session
                    .progress
                    .interfaces_used
                    .push(transmission.interface.clone());
            }
            (self.emit)(FrameEvidence {
                pass: session.pass,
                source_index,
                source_interface_id: read.frame.interface,
                capture_interface: read.capture_interface,
                link_mode: plan.mode,
                scheduled_delay: plan.delay,
                frame: read.frame,
                transmission,
            })?;
            enforce_deadline(&session.deadline, source_index)?;
            source_index += 1;
        }

        session.progress.passes_completed += 1;
        Ok(source_index)
    }
}

fn read_frame<R: Read>(
    reader: &mut Reader<R>,
    limits: &Limits,
    deadline: &Deadline,
    source_index: u64,
    frames_read: u64,
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
    let total = frames_read.checked_add(1).ok_or(Error::SourceFrameLimit {
        source_index,
        actual: u64::MAX,
        limit: limits.max_source_frames,
    })?;
    if total > limits.max_source_frames {
        return Err(Error::SourceFrameLimit {
            source_index,
            actual: total,
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
    match timing.delay_between(
        progress.previous_timestamp,
        frame.timestamp,
        source_index,
        progress.bytes_transmitted,
        progress
            .scheduled_duration
            .saturating_sub(progress.pause_duration),
    ) {
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
    interface: &packetcraftr_netio::interface::Id,
    deadline: &Deadline,
    source_index: u64,
    mode: LinkMode,
    frame: &Frame,
) -> Result<MaterializedRoute, Error> {
    enforce_deadline(deadline, source_index)?;
    let route = transmitter.plan_frame(interface, mode, frame);
    enforce_deadline(deadline, source_index)?;
    let route = route.map_err(|source| Error::Transmission {
        source_index,
        source,
    })?;
    // The caller's selector may name only the interface's name or index; the
    // transmitter resolves it to the complete identity it will use.
    if !requested_interface_matches(&route.plan.decision.interface, interface) {
        return Err(Error::InvalidEvidence {
            source_index,
            message: "planned route changed the selected output interface".to_owned(),
        });
    }
    Ok(route)
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

/// Waits a source-timing delay in the shared pacing order. Replay keeps its
/// own schedule in [`Progress`] and no execution statistics.
fn pace<C: Clock>(
    clock: &mut C,
    deadline: &mut Deadline,
    source_index: u64,
    delay: Duration,
) -> Result<(), Error> {
    execution::pause(deadline, clock, &SourceFrames, source_index, delay)
}

/// Names pacing failures as replay errors at a source index.
struct SourceFrames;

impl execution::PacingErrors for SourceFrames {
    type Error = Error;
    type Step = u64;

    fn duration_limit(&self, source_index: u64, source: DeadlineExceeded) -> Error {
        duration_limit(source_index, source)
    }

    fn interrupted(&self, source_index: u64, source: Interrupted) -> Error {
        interrupted(source_index, source)
    }

    fn clock(&self, source_index: u64, source: Box<dyn std::error::Error + Send + Sync>) -> Error {
        Error::Clock {
            source_index,
            source,
        }
    }
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
    end_index: u64,
    progress: Progress,
    source_format: Format,
    timing: Timing,
) -> Result<Summary, Error> {
    enforce_deadline(deadline, end_index)?;
    Ok(Summary {
        passes_completed: progress.passes_completed,
        interfaces_used: progress.interfaces_used,
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
        .enforce()
        .map_err(|source| interrupted(source_index, source))
}

fn interrupted(source_index: u64, source: Interrupted) -> Error {
    match source {
        Interrupted::Cancelled(cancelled) => cancelled.into(),
        Interrupted::Exceeded(error) => duration_limit(source_index, error),
        _ => Error::Cancelled(Cancelled),
    }
}

fn duration_limit(source_index: u64, error: DeadlineExceeded) -> Error {
    Error::DurationLimit {
        source_index,
        actual: error.actual,
        limit: error.limit,
    }
}
