// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::io::Read;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use packetcraftr_core::budget::{Cancelled, Deadline, DeadlineExceeded, Interrupted};
use packetcraftr_core::capture_file::{Format, Interface, Reader};
use packetcraftr_core::frame::Frame;

use crate::clock::Clock;
use crate::engine::execution::{self, Paused};
use crate::policy::WireLimits;
use crate::providers::PacketProviders;
use crate::route::{self, Materialized as MaterializedRoute};
use crate::{Client, Sink};
use packetcraftr_core::error::BoundaryError;

use super::admission::FrameAdmission;
use super::error::Error;
use super::evidence::{FrameEvidence, Transmission, validate_transmission};
use super::executor::ProviderExecutor;
use super::plan::{FramePlan, Tally, plan_frame};
use super::report::{Event, Report};
use super::request::{Limits, Options, Parts, Request, Selector, Timing, validate};

impl<P: PacketProviders, K: Clock> Client<P, K> {
    /// Replays the request's capture: every selected frame is admitted by the
    /// client's policy, routed through the client's providers, authorized
    /// again against its final route, and transmitted exactly as captured.
    pub fn replay<R, E>(&self, request: Request<R>, sink: E) -> Result<Report, Error>
    where
        R: Read,
        E: Sink<Event, Ack = ()>,
    {
        request.validate()?;
        let deadline = self.deadline(request.options.limits.max_duration);
        enforce_deadline(&deadline, 0)?;
        let mut publish =
            execution::publisher(&self.runtime, sink, BoundaryError::from_error, |source| {
                source
            })
            .map_err(|source| publication_error(0, &deadline, source))?;
        let mut admission = FrameAdmission::new(
            &self.policy,
            Arc::clone(&self.registry),
            request.options.allow_permissive_live,
        );
        run(
            request.into_parts(),
            &mut admission,
            &mut ProviderExecutor::new(self.providers.as_ref()),
            &mut self.clock.clone(),
            deadline,
            |evidence, deadline| {
                let source_index = evidence.source_index;
                publish(Event::Frame(evidence), deadline)
                    .map_err(|source| publication_error(source_index, deadline, source))
            },
        )
    }
}

/// A failed publication at `source_index`. An interruption wins over the
/// output failure it caused: the sink's own interruption, or the replay's.
fn publication_error(source_index: u64, deadline: &Deadline, source: BoundaryError) -> Error {
    if let Some(interruption) = interruption(&source) {
        return interrupted(source_index, interruption);
    }
    if let Err(interruption) = deadline.enforce() {
        return interrupted(source_index, interruption);
    }
    Error::Output {
        source_index,
        source,
    }
}

fn interruption(error: &BoundaryError) -> Option<Interrupted> {
    let source = std::error::Error::source(error)?;
    source
        .downcast_ref::<Interrupted>()
        .copied()
        .or_else(|| {
            source
                .downcast_ref::<Cancelled>()
                .map(|cancelled| Interrupted::Cancelled(*cancelled))
        })
        .or_else(|| {
            source
                .downcast_ref::<DeadlineExceeded>()
                .map(|exceeded| Interrupted::Exceeded(*exceeded))
        })
}

struct ReadFrame {
    frame: Frame,
    capture_interface: Interface,
}

struct Session {
    deadline: Deadline,
    tally: Tally,
    started: Instant,
    anchor: Option<Instant>,
    pass: u32,
}

impl Session {
    fn anchor_at(&mut self, anchor: Instant) {
        self.anchor = Some(anchor);
        self.tally.setup_duration = anchor.saturating_duration_since(self.started);
    }
}

struct Run<'a, 'x, 'e, 'c, 'p, P, S, C, F> {
    options: &'a Options,
    selector: S,
    authorizer: &'a mut FrameAdmission<'p>,
    executor: &'x mut ProviderExecutor<'e, P>,
    clock: &'c mut C,
    emit: F,
}

pub(crate) fn run<R, S, P, C, F>(
    parts: Parts<R, S>,
    authorizer: &mut FrameAdmission<'_>,
    executor: &mut ProviderExecutor<'_, P>,
    clock: &mut C,
    deadline: Deadline,
    emit: F,
) -> Result<Report, Error>
where
    R: Read,
    S: Selector,
    P: PacketProviders,
    C: Clock,
    F: FnMut(FrameEvidence, &Deadline) -> Result<(), Error>,
{
    let Parts {
        source,
        selector,
        options,
    } = parts;
    validate(&source, &options)?;
    enforce_deadline(&deadline, 0)?;
    let mut reader = source.reader;
    let rewind = source.rewind;
    let mut session = Session {
        deadline,
        tally: Tally::default(),
        started: clock.now(),
        anchor: None,
        pass: 1,
    };
    let rewound = |reader: &mut Reader<R>| match rewind {
        Some(rewind) => rewind(reader).map_err(|source| Error::Capture {
            source_index: 0,
            source,
        }),
        None => Ok(()),
    };
    rewound(&mut reader)?;
    let source_format = reader.format();
    let mut run = Run {
        options: &options,
        selector,
        authorizer,
        executor,
        clock,
        emit,
    };
    let mut end_index = 0;
    for pass in 1..=options.repeat {
        session.pass = pass;
        if pass > 1 {
            enforce_deadline(&session.deadline, 0)?;
            rewound(&mut reader)?;
            if reader.format() != source_format {
                return Err(Error::InvalidEvidence {
                    source_index: 0,
                    message: "capture format changed between passes".to_owned(),
                });
            }
            run.pause_between_passes(&mut session)?;
        }
        end_index = run.pass(&mut reader, &mut session)?;
    }
    enforce_deadline(&session.deadline, end_index)?;
    let tally = session.tally;
    Ok(Report {
        passes_completed: tally.passes_completed,
        interfaces_used: tally.interfaces_used,
        source_format,
        timing: options.timing,
        frames_read: tally.frames_read,
        frames_transmitted: tally.frames_transmitted,
        bytes_transmitted: tally.bytes_transmitted,
        scheduled_duration: tally.scheduled_duration,
    })
}

impl<P, S, C, F> Run<'_, '_, '_, '_, '_, P, S, C, F>
where
    P: PacketProviders,
    S: Selector,
    C: Clock,
    F: FnMut(FrameEvidence, &Deadline) -> Result<(), Error>,
{
    fn pause_between_passes(&mut self, session: &mut Session) -> Result<(), Error> {
        let options = self.options;
        let overflow = || Error::InvalidDuration {
            value: Duration::MAX,
            maximum: options.limits.max_duration,
        };
        pace(
            self.clock,
            &mut session.deadline,
            0,
            options.inter_pass_delay,
        )?;
        let tally = &mut session.tally;
        tally.scheduled_duration = tally
            .scheduled_duration
            .checked_add(options.inter_pass_delay)
            .ok_or_else(overflow)?;
        tally.pause_duration = tally
            .pause_duration
            .checked_add(options.inter_pass_delay)
            .ok_or_else(overflow)?;
        let scheduled = tally.scheduled_duration;
        if matches!(options.timing, Timing::Original | Timing::Scaled(_)) {
            tally.has_previous = false;
            tally.previous_timestamp = None;
        }
        let anchor = self
            .clock
            .now()
            .checked_sub(scheduled)
            .ok_or_else(overflow)?;
        session.anchor_at(anchor);
        Ok(())
    }

    fn pass<R: Read>(
        &mut self,
        reader: &mut Reader<R>,
        session: &mut Session,
    ) -> Result<u64, Error> {
        let limits = self.options.limits;
        let mut source_index = 0u64;
        loop {
            let Some(read) = read_frame(
                reader,
                &limits,
                &session.deadline,
                source_index,
                session.tally.frames_read,
            )?
            else {
                break;
            };
            session.tally.frames_read += 1;
            let selected = guarded(&session.deadline, source_index, || {
                self.selector.select(source_index, &read.frame)
            })?;
            if !selected {
                source_index += 1;
                continue;
            }

            let plan = plan_frame(self.options, &session.tally, &read.frame, source_index)?;
            let packet_source = guarded(&session.deadline, source_index, || {
                self.authorizer
                    .admit_frame(
                        WireLimits::new(plan.next_completed, plan.next_bytes),
                        &read.frame,
                        plan.mode,
                    )
                    .map_err(|source| Error::Authorization {
                        source_index,
                        source,
                    })
            })?;
            let interface = self.selector.interface(source_index, &read.frame)?;
            let route = plan_frame_route(
                self.executor,
                &interface,
                &session.deadline,
                source_index,
                &plan,
                &read.frame,
                packet_source,
            )?;
            guarded(&session.deadline, source_index, || {
                self.authorizer
                    .authorize_final_wire(&read.frame, &route.plan)
                    .map_err(|source| Error::Authorization {
                        source_index,
                        source,
                    })
            })?;
            let overflow = || {
                duration_limit(
                    source_index,
                    DeadlineExceeded {
                        actual: Duration::MAX,
                        limit: limits.max_duration,
                    },
                )
            };
            // The first frame of a schedule starts it, so its one-time setup
            // cost does not shorten the gaps that follow.
            let anchor = match session.anchor {
                Some(anchor) if session.tally.has_previous => anchor,
                _ => {
                    let anchor = self
                        .clock
                        .now()
                        .checked_sub(plan.next_duration)
                        .ok_or_else(overflow)?;
                    session.anchor_at(anchor);
                    anchor
                }
            };
            // Overdue frames are sent immediately; later targets stay on the same anchor.
            let target = anchor
                .checked_add(plan.next_duration)
                .ok_or_else(overflow)?;
            let remaining = target.saturating_duration_since(self.clock.now());
            pace(self.clock, &mut session.deadline, source_index, remaining)?;
            let transmission = transmit_frame(
                self.executor,
                &session.deadline,
                source_index,
                &route,
                &read.frame,
            )?;

            session.tally.complete(&plan, read.frame.timestamp);
            session.tally.used(&transmission.interface);
            (self.emit)(
                FrameEvidence {
                    pass: session.pass,
                    source_index,
                    capture_interface: read.capture_interface,
                    link_mode: plan.mode,
                    scheduled_delay: plan.delay,
                    frame: read.frame,
                    transmission,
                },
                &session.deadline,
            )?;
            enforce_deadline(&session.deadline, source_index)?;
            source_index += 1;
        }

        session.tally.passes_completed += 1;
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
    let frame = guarded(deadline, source_index, || {
        reader.next_frame().map_err(|source| Error::Capture {
            source_index,
            source,
        })
    })?;
    let Some(frame) = frame else {
        return Ok(None);
    };
    let capture_interface = capture_interface(reader, &frame, source_index)?;
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

fn plan_frame_route<P: PacketProviders>(
    executor: &mut ProviderExecutor<'_, P>,
    interface: &route::Interface,
    deadline: &Deadline,
    source_index: u64,
    plan: &FramePlan,
    frame: &Frame,
    packet_source: Option<IpAddr>,
) -> Result<MaterializedRoute, Error> {
    let route = guarded(deadline, source_index, || {
        executor
            .plan_frame(interface, plan.mode, frame, packet_source, deadline)
            .map_err(|source| Error::Transmission {
                source_index,
                source,
            })
    })?;
    // The routed interface may name only the interface's name or index; the
    // executor resolves it to the complete identity it will use.
    if !interface.matches(&route.plan.decision.interface) {
        return Err(Error::InvalidEvidence {
            source_index,
            message: "planned route changed the selected output interface".to_owned(),
        });
    }
    Ok(route)
}

fn pace<C: Clock>(
    clock: &mut C,
    deadline: &mut Deadline,
    source_index: u64,
    delay: Duration,
) -> Result<(), Error> {
    execution::pause(deadline, clock, delay).map_err(|paused| match paused {
        Paused::DurationLimit(source) => duration_limit(source_index, source),
        Paused::Interrupted(source) => interrupted(source_index, source),
        Paused::Clock(source) => Error::Clock {
            source_index,
            source,
        },
    })
}

fn transmit_frame<P: PacketProviders>(
    executor: &mut ProviderExecutor<'_, P>,
    deadline: &Deadline,
    source_index: u64,
    route: &MaterializedRoute,
    frame: &Frame,
) -> Result<Transmission, Error> {
    enforce_deadline(deadline, source_index)?;
    let report = executor
        .transmit(route, frame)
        .map_err(|source| Error::Transmission {
            source_index,
            source,
        })?;
    validate_transmission(source_index, frame, &report)?;
    Ok(Transmission {
        interface: route.plan.decision.interface.clone(),
        report,
    })
}

fn guarded<T>(
    deadline: &Deadline,
    source_index: u64,
    step: impl FnOnce() -> Result<T, Error>,
) -> Result<T, Error> {
    enforce_deadline(deadline, source_index)?;
    let result = step();
    enforce_deadline(deadline, source_index)?;
    result
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

#[cfg(test)]
mod tests;
