// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

use packetcraftr_netio::capture::{self as native, Session as _};

use crate::clock::Clock;
use crate::deadline::DeadlineExt as _;
use crate::providers::Providers;
use crate::{Client, Sink};
use packetcraftr_core::error::BoundaryError;

use super::error::{failure, interrupted_or};
use super::evidence::{evidence_loss, finish_stats, replace_sources};
use super::executor::Armed;
use super::{Cause, Control, Error, Event, Report, Request, StopReason};

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
        let report = self.plan_capture(&group_request, window, started, &deadline)?;
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
        } = self.arm_capture_group(&group_request, window, &deadline, report)?;
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
}
