// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::{Duration, Instant};

use packetcraftr_core::budget::Deadline;
use packetcraftr_core::diagnostic::Diagnostic;
use packetcraftr_netio::capture::{self as native, Group, GroupRequest, Session as _};

use crate::clock::Clock;
use crate::deadline::DeadlineExt as _;
use crate::policy::CaptureBudget;
use crate::providers::Providers;
use crate::{BoundaryError, Client, Sink, Stats};

use super::{Cause, Control, Error, Event, Report, Request, Source, StopReason};

/// The longest single read, so cancellation, the budget, and the window are
/// checked at least this often while no frame arrives.
const READ_SLICE: Duration = Duration::from_millis(50);

impl<P: Providers, K: Clock> Client<P, K> {
    /// Captures from every interface the request names, as one capture group
    /// under one frame and byte budget from the client's policy.
    ///
    /// Every source is armed and ready before [`Event::Started`] is
    /// published. Each delivered frame is then charged to the budget, offered
    /// to the request's selector, and, when kept, published as an
    /// [`Event::Frame`] whose `interface` is its source index. Events reach
    /// `sink` on a worker admitted by the client's runtime, and the capture
    /// waits for each [`Control`] before it reads the next frame. The capture
    /// stops when the window closes on the client's clock, the frame budget
    /// is spent, or the sink asks it to, and the client's cancellation stops
    /// it with a failure. Every exit shuts every armed source down before
    /// the report is returned.
    ///
    /// # Errors
    ///
    /// Returns the invalid request, the provider, budget, selector, or sink
    /// failure, the cancellation, or evidence lost under
    /// [`OverflowPolicy::Fail`](native::OverflowPolicy::Fail). The error keeps
    /// the report of everything done before it, after every source was shut
    /// down.
    pub fn capture<S>(&self, request: Request, sink: S) -> Result<Report, Error>
    where
        S: Sink<Event>,
        S::Ack: Into<Control>,
    {
        let Request {
            group: group_request,
            window,
            mut select,
        } = request;
        let started = self.now();
        let deadline = self.deadline(window);
        let report = self.admit(&group_request, window, started, &deadline)?;
        let mut publisher = match crate::execution::publisher(
            &self.runtime,
            sink,
            |deadline| Cause::Consumer(BoundaryError::from_error(deadline)),
            Cause::Consumer,
        ) {
            Ok(publisher) => publisher,
            Err(cause) => return Err(failure(cause, report, None)),
        };
        // Each event gets the longest wait a capture has.
        let mut publish = |event: Event| -> Result<Control, Cause> {
            publisher(event, &self.deadline(native::MAX_TIMEOUT))
                .map(Into::into)
                .map_err(|cause| interrupted_or(&deadline, cause))
        };
        let Armed {
            mut group,
            mut report,
            mut primary,
        } = self.arm(&group_request, window, &deadline, report)?;
        let mut source_frame = None;
        replace_sources(&mut report, &group.snapshot());
        if primary.is_none() {
            match publish(Event::Started {
                sources: report.sources.clone(),
            }) {
                Ok(Control::Continue) => {}
                Ok(Control::StopBefore | Control::StopAfter) => report.stop = StopReason::Sink,
                Err(cause) => primary = Some(cause),
            }
        }
        while primary.is_none() && report.stop != StopReason::Sink {
            if let Err(cancelled) = deadline.check_cancelled() {
                primary = Some(Cause::Cancelled(cancelled));
                break;
            }
            if report.budget.is_exhausted() {
                report.stop = StopReason::FrameBudget;
                break;
            }
            // Reads wait on the capture in real time, never past the window.
            let Ok(slice) = deadline.for_wait(READ_SLICE) else {
                report.stop = StopReason::Window;
                break;
            };
            let record = match group.next_captured_frame(&slice) {
                Ok(Some(record)) => record,
                Ok(None) => continue,
                Err(error) => {
                    source_frame = report.frames_delivered.checked_add(1);
                    primary = Some(interrupted_or(&deadline, Cause::Native(error)));
                    break;
                }
            };
            let Some(number) = report.frames_delivered.checked_add(1) else {
                primary = Some(Cause::Statistics);
                break;
            };
            report.frames_delivered = number;
            source_frame = Some(number);
            if deadline.check().is_err() {
                report.sources[record.source].late_frames += 1;
                report.stop = StopReason::Window;
                source_frame = None;
                break;
            }
            let mut frame = record.frame;
            frame.interface = Some(record.source as u32);
            if let Err(error) = report.budget.account(u64::from(frame.captured_length())) {
                primary = Some(Cause::Budget(error));
                break;
            }
            report.sources[record.source].admitted_frames += 1;
            match select
                .as_mut()
                .map_or(Ok(true), |select| select(number, &frame))
            {
                Ok(true) => {}
                Ok(false) => {
                    source_frame = None;
                    continue;
                }
                Err(error) => {
                    primary = Some(Cause::Consumer(error));
                    break;
                }
            }
            report.sources[record.source].matched_frames += 1;
            match publish(Event::Frame {
                source_frame: number,
                source: record.source,
                elapsed: self.now().saturating_duration_since(started),
                frame,
            }) {
                Ok(control) => {
                    if control != Control::StopBefore {
                        report.sources[record.source].emitted_frames += 1;
                    }
                    if control != Control::Continue {
                        report.stop = StopReason::Sink;
                    }
                    source_frame = None;
                }
                Err(cause) => {
                    primary = Some(cause);
                    break;
                }
            }
        }
        // A group failure already shut every source down; this reports that
        // cleanup, or performs it after any other exit.
        let mut cleanup = Vec::new();
        if let Err(error) = group.shutdown() {
            if primary.is_none() {
                primary = Some(Cause::Native(error));
                source_frame = None;
            } else {
                cleanup.push(error);
            }
        }
        replace_sources(&mut report, &group.snapshot());
        let elapsed = self.now().saturating_duration_since(started);
        if !finish_stats(&mut report, elapsed) && primary.is_none() {
            primary = Some(Cause::Statistics);
        }
        if primary.is_none() {
            primary = evidence_loss(&mut report);
        }
        if let Some(cause) = primary {
            report.stop = StopReason::Failure;
            Err(Error {
                cause: Box::new(cause),
                report: Box::new(report),
                cleanup,
                source_frame,
            })
        } else {
            Ok(report)
        }
    }

    /// Validates the request before any provider is consulted, and returns
    /// the report skeleton every later failure carries.
    fn admit(
        &self,
        request: &GroupRequest,
        window: Duration,
        started: Instant,
        deadline: &Deadline,
    ) -> Result<Report, Error> {
        let validated = request.validate();
        let report = Report {
            requested_interfaces: if validated.is_ok() {
                request.interfaces.clone()
            } else {
                Vec::new()
            },
            sources: Vec::new(),
            frames_delivered: 0,
            stats: Stats::default(),
            budget: CaptureBudget::new(&self.policy),
            stop: StopReason::Failure,
            capture_statistics_complete: false,
            diagnostics: Vec::new(),
        };
        if let Err(error) = validated {
            return Err(failure(Cause::Native(error), report, None));
        }
        if window > native::MAX_TIMEOUT || started.checked_add(window).is_none() {
            return Err(failure(
                Cause::Invalid("capture window exceeds the supported range"),
                report,
                None,
            ));
        }
        if let Err(cancelled) = deadline.check_cancelled() {
            return Err(failure(Cause::Cancelled(cancelled), report, None));
        }
        Ok(report)
    }

    /// Arms the capture group and waits for it to become ready within the
    /// window. A failure before the group exists carries the report skeleton
    /// inside its error; a later one becomes the primary failure of the
    /// returned group.
    fn arm(
        &self,
        request: &GroupRequest,
        window: Duration,
        deadline: &Deadline,
        report: Report,
    ) -> Result<Armed<<P::Capture as native::Provider>::Capture>, Error> {
        // The window bounds arming and readiness. A zero window still arms its
        // sources, bounded only by the longest wait a provider accepts, and
        // then stops without waiting.
        let unbounded;
        let arming = if window.is_zero() {
            unbounded = self.deadline(native::MAX_TIMEOUT);
            &unbounded
        } else {
            deadline
        };
        let mut group = match Group::new(request) {
            Ok(group) => group,
            Err(error) => return Err(failure(Cause::Native(error), report, None)),
        };
        let mut primary = group
            .arm(self.providers.capture(), arming)
            .err()
            .map(Cause::Native);
        if primary.is_none() && !window.is_zero() {
            if deadline
                .remaining()
                .map_or(true, |remaining| remaining.is_zero())
            {
                primary = Some(Cause::Invalid("capture window expired during activation"));
            } else if let Err(error) = group.wait_ready(deadline) {
                primary = Some(Cause::Native(error));
            }
        }
        Ok(Armed {
            group,
            report,
            primary,
        })
    }
}

/// The capture after activation: the group, the report skeleton, and the
/// first activation failure if arming, `wait_ready`, or the window produced
/// one.
struct Armed<C: native::Session> {
    group: Group<C>,
    report: Report,
    primary: Option<Cause>,
}

/// A failure while the capture is cancelled reports the cancellation.
fn interrupted_or(deadline: &Deadline, cause: Cause) -> Cause {
    match deadline.check_cancelled() {
        Err(cancelled) => Cause::Cancelled(cancelled),
        Ok(()) => cause,
    }
}

fn failure(cause: Cause, report: Report, source_frame: Option<u64>) -> Error {
    Error {
        cause: Box::new(cause),
        report: Box::new(report),
        cleanup: Vec::new(),
        source_frame,
    }
}

fn replace_sources(report: &mut Report, sources: &[native::Source]) {
    for source in sources {
        if let Some(existing) = report.sources.get_mut(source.index) {
            existing.update(source);
        } else {
            report.sources.push(Source::armed(source));
        }
    }
}

/// Fills the run's statistics from the budget and every source. Returns
/// whether every requested source reported complete statistics.
fn finish_stats(report: &mut Report, elapsed: Duration) -> bool {
    report.stats.packets_attempted = report.budget.frames();
    report.stats.bytes = report.budget.bytes();
    report.stats.packets_completed = report
        .sources
        .iter()
        .map(|source| source.emitted_frames)
        .sum();
    report.stats.elapsed = elapsed;
    let mut capture = native::Stats::default();
    let mut complete = report.sources.len() == report.requested_interfaces.len();
    for source in &report.sources {
        complete &= source.metadata_valid && source.shutdown_confirmed && source.statistics_valid;
        if let Some(sum) = capture.checked_add(source.statistics) {
            capture = sum;
        } else {
            report.capture_statistics_complete = false;
            return false;
        }
    }
    report.stats.capture = capture;
    report.capture_statistics_complete = complete;
    complete
}

/// Fails on the first source that lost evidence under
/// [`OverflowPolicy::Fail`](native::OverflowPolicy::Fail), and warns about
/// every other source that lost evidence.
fn evidence_loss(report: &mut Report) -> Option<Cause> {
    for source in &report.sources {
        if let Some(error) = source.statistics.evidence_loss_error() {
            if source.limits.overflow_policy == native::OverflowPolicy::Fail {
                return Some(Cause::Loss {
                    source_index: source.index,
                    error,
                });
            }
            report.diagnostics.push(Diagnostic::warning(
                "capture.evidence_incomplete",
                format!(
                    "source {} ({}): {error}",
                    source.index, source.metadata.interface.name
                ),
            ));
        }
    }
    None
}
