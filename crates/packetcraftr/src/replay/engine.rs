// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Streams, authorizes, schedules, and transmits without retaining more than one frame.

use std::io::Read;
use std::sync::Arc;
use std::time::{Duration, Instant};

use packetcraftr_core::budget::{Cancelled, Deadline, DeadlineExceeded, Interrupted};
use packetcraftr_core::capture_file::{Format, Interface, Reader};
use packetcraftr_core::frame::Frame;

use crate::clock::Clock;
use crate::execution::{self, Paused};
use crate::policy::{Authorizer, Operation, ReplayFrame, WireLimits};
use crate::providers::Providers;
use crate::route::{Materialized as MaterializedRoute, Plan as RoutePlan};
use crate::{BoundaryError, Client, Sink};

use super::admission::{FinalWire, FrameAdmission};
use super::error::Error;
use super::evidence::{FrameEvidence, Transmission, validate_transmission};
use super::executor::{Executor, ProviderExecutor, requested_interface_matches};
use super::plan::{FramePlan, Tally, plan_frame};
use super::report::{Event, Report};
use super::request::{Limits, Options, Request, Selector, Timing};

impl<P: Providers, K: Clock> Client<P, K> {
    /// Replays the request's capture: every selected frame is admitted by the
    /// client's policy, routed through the client's providers, authorized
    /// again against its final route, and transmitted exactly as captured.
    ///
    /// Each frame is admitted before any provider is consulted for it, and the
    /// replay keeps no more than one frame. Each confirmed frame is published
    /// to `sink` on a worker admitted by the client's runtime, and the replay
    /// waits for the sink's answer before it reads the next frame, so
    /// evidence published before a failure is preserved. The request's
    /// timing runs on the client's clock, within one deadline of
    /// `limits.max_duration`.
    ///
    /// A sink that fails because the run was interrupted (its error's source
    /// is a [`Cancelled`], [`DeadlineExceeded`], or [`Interrupted`]) stops the
    /// replay as interrupted rather than as an output failure, and so does any
    /// sink failure once the replay's own deadline is spent or cancelled.
    ///
    /// # Errors
    ///
    /// Returns the invalid request, the capture, policy, provider, or clock
    /// failure, the sink's failure, or the interruption, each at the source
    /// frame it stopped at.
    pub fn replay<R, S, E>(&self, request: Request<R, S>, sink: E) -> Result<Report, Error>
    where
        R: Read,
        S: Selector,
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
            self.admission(),
            Arc::clone(&self.registry),
            request.options.allow_permissive_live,
        );
        run(
            request,
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

/// The interruption a sink failure reports as its source, if any.
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
    number: u64,
}

/// One replay in progress: its deadline, totals, and schedule anchor.
struct Session {
    deadline: Deadline,
    tally: Tally,
    anchor: Instant,
    pass: u32,
}

struct Run<'a, 'x, 'c, S, A, X, C, F> {
    options: &'a Options,
    selector: S,
    authorizer: &'a mut A,
    executor: &'x mut X,
    clock: &'c mut C,
    emit: F,
}

/// Replays `request` under `deadline`, authorizing through `authorizer`,
/// sending through `executor`, and handing each confirmed frame to `emit`.
/// A seekable source is rewound before every pass under one aggregate budget
/// and schedule.
pub(crate) fn run<R, S, A, X, C, F>(
    request: Request<R, S>,
    authorizer: &mut A,
    executor: &mut X,
    clock: &mut C,
    deadline: Deadline,
    emit: F,
) -> Result<Report, Error>
where
    R: Read,
    S: Selector,
    A: Authorizer + FinalWire,
    X: Executor,
    C: Clock,
    F: FnMut(FrameEvidence, &Deadline) -> Result<(), Error>,
{
    request.validate()?;
    enforce_deadline(&deadline, 0)?;
    let Request {
        source,
        selector,
        options,
    } = request;
    let mut reader = source.reader;
    let rewind = source.rewind;
    let mut session = Session {
        deadline,
        tally: Tally::default(),
        anchor: clock.now(),
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

impl<S, A, X, C, F> Run<'_, '_, '_, S, A, X, C, F>
where
    S: Selector,
    A: Authorizer + FinalWire,
    X: Executor,
    C: Clock,
    F: FnMut(FrameEvidence, &Deadline) -> Result<(), Error>,
{
    /// Waits the inter-pass delay and restarts the schedule's anchor after it.
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
        session.anchor = self
            .clock
            .now()
            .checked_sub(tally.scheduled_duration)
            .ok_or_else(overflow)?;
        if matches!(options.timing, Timing::Original | Timing::Scaled(_)) {
            tally.has_previous = false;
            tally.previous_timestamp = None;
        }
        Ok(())
    }

    /// Replays one pass and returns the source index one past its last
    /// frame, the coordinate its end-of-capture deadline gate reports.
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
            source_index = read.number - 1;
            if !self.select(&session.deadline, source_index, &read)? {
                source_index += 1;
                continue;
            }

            let plan = plan_frame(self.options, &session.tally, &read.frame, source_index)?;
            authorize_frame(
                self.authorizer,
                &session.deadline,
                source_index,
                &plan,
                &read.frame,
            )?;
            let interface = self.interface(source_index, &read)?;
            let route = plan_frame_route(
                self.executor,
                &interface,
                &session.deadline,
                source_index,
                &plan,
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
                    source_interface_id: read.frame.interface,
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

    fn select(
        &mut self,
        deadline: &Deadline,
        source_index: u64,
        read: &ReadFrame,
    ) -> Result<bool, Error> {
        enforce_deadline(deadline, source_index)?;
        let selected = self
            .selector
            .select(read.number, &read.frame)
            .map_err(|source| Error::Selection {
                source_index,
                source,
            })?;
        enforce_deadline(deadline, source_index)?;
        Ok(selected)
    }

    /// The selector's interface for the frame, or the request's fallback.
    fn interface(
        &mut self,
        source_index: u64,
        read: &ReadFrame,
    ) -> Result<packetcraftr_netio::interface::Id, Error> {
        let mapped = self
            .selector
            .interface(read.number, &read.frame)
            .map_err(|source| Error::Selection {
                source_index,
                source,
            })?;
        mapped
            .or_else(|| self.options.interface.clone())
            .ok_or(Error::InvalidLimit {
                field: "interface",
                value: 0,
                reason: "selected frame has no mapped or fallback interface",
            })
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

fn authorize_frame<A: Authorizer>(
    authorizer: &mut A,
    deadline: &Deadline,
    source_index: u64,
    plan: &FramePlan,
    frame: &Frame,
) -> Result<(), Error> {
    enforce_deadline(deadline, source_index)?;
    let authorization = authorizer.authorize_operation(Operation::Replay(ReplayFrame::new(
        WireLimits::new(plan.next_completed, plan.next_bytes),
        frame,
        plan.mode,
    )));
    enforce_deadline(deadline, source_index)?;
    authorization.map_err(|source| Error::Authorization {
        source_index,
        source,
    })
}

fn plan_frame_route<X: Executor>(
    executor: &mut X,
    interface: &packetcraftr_netio::interface::Id,
    deadline: &Deadline,
    source_index: u64,
    plan: &FramePlan,
    frame: &Frame,
) -> Result<MaterializedRoute, Error> {
    enforce_deadline(deadline, source_index)?;
    let route = executor.plan_frame(interface, plan.mode, frame, deadline);
    enforce_deadline(deadline, source_index)?;
    let route = route.map_err(|source| Error::Transmission {
        source_index,
        source,
    })?;
    // The caller's selector may name only the interface's name or index; the
    // executor resolves it to the complete identity it will use.
    if !requested_interface_matches(&route.plan.decision.interface, interface) {
        return Err(Error::InvalidEvidence {
            source_index,
            message: "planned route changed the selected output interface".to_owned(),
        });
    }
    Ok(route)
}

fn authorize_final_wire<A: FinalWire>(
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
/// own schedule in its [`Tally`] and no execution statistics.
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

fn transmit_frame<X: Executor>(
    executor: &mut X,
    deadline: &Deadline,
    source_index: u64,
    route: &MaterializedRoute,
    frame: &Frame,
) -> Result<Transmission, Error> {
    enforce_deadline(deadline, source_index)?;
    let interface = &route.plan.decision.interface;
    let transmission = executor
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
    validate_transmission(source_index, frame, &transmission.report)?;
    Ok(transmission)
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
