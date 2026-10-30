// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr_core::diagnostic::Severity;
use packetcraftr_netio::{Error as LiveIoError, capture::Session};

use super::executor::OperationError;
use super::executor::Transaction;
use super::{ProcessContext, ProcessOutcome, WorkflowResponseMatcher, WorkflowStopPredicate};

#[derive(Clone, Copy)]
pub(super) enum DrainPolicy {
    /// Requests remain to be sent, so the window closing aborts the operation.
    Enforced,
    /// Every request is sent; the window closing just ends correlation.
    BestEffort,
}

impl DrainPolicy {
    const fn is_enforced(self) -> bool {
        matches!(self, Self::Enforced)
    }
}

impl<C: Session> Transaction<C> {
    pub(super) fn collect_remaining<F>(
        &mut self,
        workflow_matcher: &mut Option<&mut WorkflowResponseMatcher<'_>>,
        stop_predicate: &mut Option<&mut WorkflowStopPredicate<'_>>,
        emit: &mut F,
    ) -> Result<(), OperationError>
    where
        F: FnMut(super::Event) -> Result<(), packetcraftr_core::error::BoundaryError>,
    {
        if !self.correlation_stopped {
            while !self.window.expired() {
                let Some(frame) = self
                    .capture
                    .inner
                    .next_captured_frame(self.window.deadline())?
                else {
                    break;
                };
                match self.process_frame(frame, workflow_matcher, stop_predicate, emit)? {
                    ProcessOutcome::StopCapture => return Ok(()),
                    ProcessOutcome::CorrelationDeadlineExpired => break,
                    ProcessOutcome::Continue => {}
                }
            }
        }
        let _ = self.drain(
            DrainPolicy::BestEffort,
            workflow_matcher,
            stop_predicate,
            emit,
        )?;
        Ok(())
    }

    pub(super) fn drain<F>(
        &mut self,
        policy: DrainPolicy,
        workflow_matcher: &mut Option<&mut WorkflowResponseMatcher<'_>>,
        stop_predicate: &mut Option<&mut WorkflowStopPredicate<'_>>,
        emit: &mut F,
    ) -> Result<ProcessOutcome, OperationError>
    where
        F: FnMut(super::Event) -> Result<(), packetcraftr_core::error::BoundaryError>,
    {
        let queued = packetcraftr_core::budget::Deadline::immediate(self.cancellation.clone());
        for _ in 0..self.collection.capture.max_frames {
            if policy.is_enforced() && self.window.expired() {
                return Err(drain_deadline_error().into());
            }
            let Some(frame) = self.capture.inner.next_captured_frame(&queued)? else {
                return Ok(ProcessOutcome::Continue);
            };
            let outcome = self.process_frame(frame, workflow_matcher, stop_predicate, emit)?;
            if outcome == ProcessOutcome::StopCapture {
                return Ok(outcome);
            }
            if outcome == ProcessOutcome::CorrelationDeadlineExpired {
                if policy.is_enforced() {
                    return Err(drain_deadline_error().into());
                }
                return Ok(outcome);
            }
        }
        self.captured
            .diagnostics
            .push_once(packetcraftr_core::diagnostic::Diagnostic::new(
                Severity::Warning,
                "exchange.drain_limit",
                format!(
                    "zero-time capture drain stopped after the bounded {} frame(s)",
                    self.collection.capture.max_frames
                ),
            ));
        self.publish_diagnostics(emit)?;
        Ok(ProcessOutcome::Continue)
    }

    fn process_frame<F>(
        &mut self,
        frame: packetcraftr_netio::capture::Captured,
        workflow_matcher: &mut Option<&mut WorkflowResponseMatcher<'_>>,
        stop_predicate: &mut Option<&mut WorkflowStopPredicate<'_>>,
        emit: &mut F,
    ) -> Result<ProcessOutcome, OperationError>
    where
        F: FnMut(super::Event) -> Result<(), packetcraftr_core::error::BoundaryError>,
    {
        let context = ProcessContext {
            registry: &self.registry,
            dissector: &self.dissector,
            request_count: self.request_count,
            sent: &self.sent,
            window: &self.window,
            collection: &self.collection,
        };
        // A duplicated ingress record aborts, so nothing downstream runs for its frame.
        let processed = self
            .captured
            .process(frame, context, workflow_matcher.as_deref_mut())
            .map_err(|duplicate| OperationError::from(duplicate.into_error()))?;
        let promoted = match workflow_matcher.as_deref_mut() {
            Some(matches_request) => self
                .captured
                .promote_workflow_unsolicited(context, matches_request),
            None => {
                self.captured.finalize_unsolicited();
                ProcessOutcome::Continue
            }
        };
        let stop_requested = self.workflow_stop_requested(stop_predicate);
        self.publish_diagnostics(emit)?;
        for event in self.captured.drain_events() {
            emit(event).map_err(OperationError::output)?;
        }
        if stop_requested {
            return Ok(ProcessOutcome::StopCapture);
        }
        if processed == ProcessOutcome::CorrelationDeadlineExpired
            || promoted == ProcessOutcome::CorrelationDeadlineExpired
        {
            return Ok(ProcessOutcome::CorrelationDeadlineExpired);
        }
        Ok(ProcessOutcome::Continue)
    }

    fn workflow_stop_requested(
        &self,
        stop_predicate: &mut Option<&mut WorkflowStopPredicate<'_>>,
    ) -> bool {
        let Some(stop_predicate) = stop_predicate.as_deref_mut() else {
            return false;
        };
        // By waiting for the event, a stop can never discard its own evidence.
        self.captured.pending_events.iter().any(|event| {
            let super::Event::Response(response) = event else {
                return false;
            };
            let request = &self.sent[response.request_index].built().packet;
            stop_predicate(response.request_index, request, &response.response)
        })
    }

    pub(super) fn publish_diagnostics<F>(&mut self, emit: &mut F) -> Result<(), OperationError>
    where
        F: FnMut(super::Event) -> Result<(), packetcraftr_core::error::BoundaryError>,
    {
        self.captured.diagnostics.publish_new(|diagnostic| {
            emit(super::Event::Diagnostic(diagnostic)).map_err(OperationError::output)
        })
    }
}

fn drain_deadline_error() -> LiveIoError {
    LiveIoError::DeadlineExceeded {
        operation: "draining capture before all requests were sent",
    }
}
