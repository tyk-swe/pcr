// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::{Duration, Instant};

use packetcraftr_core::budget::Deadline;
use packetcraftr_netio::capture::{self as native, Group, Session as _};

use crate::clock::Clock;
use crate::providers::CaptureProviders;
use crate::{Client, Sink};
use packetcraftr_core::error::BoundaryError;

use super::error::{failure, failure_after_cleanup, interrupted_or};
use super::evidence::{evidence_loss, finish_stats, replace_sources};
use super::executor::Armed;
use super::request::SelectFrame;
use super::{Cause, Control, Error, Event, Report, Request, StopReason};

const READ_SLICE: Duration = Duration::from_millis(50);

impl<P: CaptureProviders, K: Clock> Client<P, K> {
    /// Captures from every interface the request names, as one capture group.
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
        let mut publish = |event: Event| -> Result<Control, Cause> {
            publisher(
                event,
                &self.deadline(packetcraftr_netio::deadline::MAX_WAIT),
            )
            .map(Into::into)
            .map_err(|cause| interrupted_or(&deadline, cause))
        };
        let Armed {
            mut group,
            mut report,
            primary,
        } = self.arm_capture_group(&group_request, window, &deadline, report)?;
        replace_sources(&mut report, &group.snapshot());
        let failed = match primary {
            Some(cause) => Some((cause, None)),
            None => self
                .pump_frames(
                    &mut group,
                    &mut report,
                    &deadline,
                    &mut select,
                    &mut publish,
                    started,
                )
                .err(),
        };
        self.close(group, report, failed, started)
    }

    /// A failure carries the one-based position of the frame that caused it, if any.
    fn pump_frames<C: native::Session>(
        &self,
        group: &mut Group<C>,
        report: &mut Report,
        deadline: &Deadline,
        select: &mut Option<SelectFrame>,
        publish: &mut impl FnMut(Event) -> Result<Control, Cause>,
        started: Instant,
    ) -> Result<(), (Cause, Option<u64>)> {
        match publish(Event::Started {
            sources: report.sources.clone(),
        }) {
            Ok(Control::Continue) => {}
            Ok(Control::StopBefore | Control::StopAfter) => report.stop = StopReason::Sink,
            Err(cause) => return Err((cause, None)),
        }
        while report.stop != StopReason::Sink {
            if let Err(cancelled) = deadline.check_cancelled() {
                return Err((Cause::Cancelled(cancelled), None));
            }
            if report.budget.is_exhausted() {
                report.stop = StopReason::FrameBudget;
                break;
            }
            let Ok(slice) = deadline.for_wait(READ_SLICE) else {
                report.stop = StopReason::Window;
                break;
            };
            let record = match group.next_captured_frame(&slice) {
                Ok(Some(record)) => record,
                Ok(None) => continue,
                Err(error) => {
                    return Err((
                        interrupted_or(deadline, Cause::Native(error)),
                        report.frames_delivered.checked_add(1),
                    ));
                }
            };
            let Some(number) = report.frames_delivered.checked_add(1) else {
                return Err((Cause::Statistics, None));
            };
            report.frames_delivered = number;
            if deadline.check().is_err() {
                report.sources[record.source].late_frames += 1;
                report.stop = StopReason::Window;
                break;
            }
            let mut frame = record.frame;
            frame.interface = Some(record.source as u32);
            if let Err(error) = report.budget.account(u64::from(frame.captured_length())) {
                return Err((Cause::Budget(error), Some(number)));
            }
            report.sources[record.source].admitted_frames += 1;
            match select
                .as_mut()
                .map_or(Ok(true), |select| select(number, &frame))
            {
                Ok(true) => {}
                Ok(false) => continue,
                Err(error) => return Err((Cause::Consumer(error), Some(number))),
            }
            report.sources[record.source].matched_frames += 1;
            let control = publish(Event::Frame {
                source_frame: number,
                source: record.source,
                elapsed: self.now().saturating_duration_since(started),
                frame,
            })
            .map_err(|cause| (cause, Some(number)))?;
            if control != Control::StopBefore {
                report.sources[record.source].emitted_frames += 1;
            }
            if control != Control::Continue {
                report.stop = StopReason::Sink;
            }
        }
        Ok(())
    }

    fn close<C: native::Session>(
        &self,
        mut group: Group<C>,
        mut report: Report,
        mut failed: Option<(Cause, Option<u64>)>,
        started: Instant,
    ) -> Result<Report, Error> {
        let mut cleanup = Vec::new();
        if let Err(error) = group.shutdown() {
            if failed.is_none() {
                failed = Some((Cause::Native(error), None));
            } else {
                cleanup.push(error);
            }
        }
        replace_sources(&mut report, &group.snapshot());
        let elapsed = self.now().saturating_duration_since(started);
        if !finish_stats(&mut report, elapsed) && failed.is_none() {
            failed = Some((Cause::Statistics, None));
        }
        if failed.is_none() {
            failed = evidence_loss(&mut report).map(|cause| (cause, None));
        }
        match failed {
            Some((cause, source_frame)) => {
                report.stop = StopReason::Failure;
                Err(failure_after_cleanup(cause, report, source_frame, cleanup))
            }
            None => Ok(report),
        }
    }
}
