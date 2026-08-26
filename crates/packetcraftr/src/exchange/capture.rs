// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Capture readiness, bounded draining, and post-send collection.

use std::time::{Duration, Instant};

use packetcraftr_netio::{Error as LiveIoError, capture::Session};

use super::transaction::OperationError;
use super::transaction::Transaction;
use super::{ProcessContext, ProcessOutcome, WorkflowPromotionContext, WorkflowResponseMatcher};

impl<C: Session> Transaction<C> {
    pub(super) fn collect_remaining<F>(
        &mut self,
        workflow_matcher: &mut Option<&mut WorkflowResponseMatcher<'_>>,
        emit: &mut F,
    ) -> Result<(), OperationError>
    where
        F: FnMut(super::Event) -> Result<(), crate::BoundaryError>,
    {
        if !self.correlation_stopped {
            while let Some(remaining) = self.deadline.checked_duration_since(Instant::now()) {
                let Some(frame) = self.capture.inner.next_captured_frame(remaining)? else {
                    break;
                };
                match self.process_frame(frame, workflow_matcher, emit)? {
                    ProcessOutcome::CorrelationDeadlineExpired => break,
                    ProcessOutcome::DuplicateRecordIdentity => {
                        return Err(LiveIoError::Capture {
                            message:
                                "capture provider returned the same ingress record more than once"
                                    .to_owned(),
                        }
                        .into());
                    }
                    ProcessOutcome::Continue => {}
                }
            }
        }
        let _ = self.drain(None, workflow_matcher, emit)?;
        Ok(())
    }

    pub(super) fn drain<F>(
        &mut self,
        enforced_deadline: Option<Instant>,
        workflow_matcher: &mut Option<&mut WorkflowResponseMatcher<'_>>,
        emit: &mut F,
    ) -> Result<ProcessOutcome, OperationError>
    where
        F: FnMut(super::Event) -> Result<(), crate::BoundaryError>,
    {
        for _ in 0..self.capture_limits.max_frames {
            Self::ensure_drain_deadline(enforced_deadline)?;
            let Some(frame) = self.capture.inner.next_captured_frame(Duration::ZERO)? else {
                return Ok(ProcessOutcome::Continue);
            };
            let outcome = self.process_frame(frame, workflow_matcher, emit)?;
            if outcome == ProcessOutcome::CorrelationDeadlineExpired {
                if enforced_deadline.is_some() {
                    return Err(drain_deadline_error().into());
                }
                return Ok(outcome);
            }
            if outcome == ProcessOutcome::DuplicateRecordIdentity {
                return Err(LiveIoError::Capture {
                    message: "capture provider returned the same ingress record more than once"
                        .to_owned(),
                }
                .into());
            }
        }
        packetcraftr_core::diagnostic::push_once(
            &mut self.captured.diagnostics,
            packetcraftr_core::diagnostic::Diagnostic::warning(
                "exchange.drain_limit",
                format!(
                    "zero-time capture drain stopped after the bounded {} frame(s)",
                    self.capture_limits.max_frames
                ),
            ),
        );
        self.publish_diagnostics(emit)?;
        Ok(ProcessOutcome::Continue)
    }

    fn process_frame<F>(
        &mut self,
        frame: packetcraftr_netio::capture::Captured,
        workflow_matcher: &mut Option<&mut WorkflowResponseMatcher<'_>>,
        emit: &mut F,
    ) -> Result<ProcessOutcome, OperationError>
    where
        F: FnMut(super::Event) -> Result<(), crate::BoundaryError>,
    {
        let context = ProcessContext {
            registry: &self.registry,
            dissector: &self.dissector,
            prepared: &self.prepared,
            sent: &self.sent,
            deadline: self.deadline,
            options: &self.options,
        };
        let processed = self.captured.process(frame, context);
        let promoted = self.promote_workflow(workflow_matcher);
        self.publish_diagnostics(emit)?;
        for event in self.captured.drain_events() {
            emit(event).map_err(OperationError::output)?;
        }
        if processed == ProcessOutcome::DuplicateRecordIdentity {
            return Ok(processed);
        }
        if processed == ProcessOutcome::CorrelationDeadlineExpired
            || promoted == ProcessOutcome::CorrelationDeadlineExpired
        {
            return Ok(ProcessOutcome::CorrelationDeadlineExpired);
        }
        Ok(ProcessOutcome::Continue)
    }

    pub(super) fn promote_workflow(
        &mut self,
        workflow_matcher: &mut Option<&mut WorkflowResponseMatcher<'_>>,
    ) -> ProcessOutcome {
        let Some(matches_request) = workflow_matcher.as_deref_mut() else {
            self.captured.finalize_unsolicited();
            return ProcessOutcome::Continue;
        };
        let context = WorkflowPromotionContext {
            prepared: &self.prepared,
            sent: &self.sent,
            deadline: self.deadline,
            max_responses: self.options.max_responses,
        };
        self.captured
            .promote_workflow_unsolicited(context, matches_request)
    }

    fn ensure_drain_deadline(enforced_deadline: Option<Instant>) -> Result<(), OperationError> {
        if enforced_deadline
            .is_some_and(|deadline| deadline.checked_duration_since(Instant::now()).is_none())
        {
            return Err(drain_deadline_error().into());
        }
        Ok(())
    }

    pub(super) fn publish_diagnostics<F>(&mut self, emit: &mut F) -> Result<(), OperationError>
    where
        F: FnMut(super::Event) -> Result<(), crate::BoundaryError>,
    {
        #[expect(
            clippy::indexing_slicing,
            reason = "`published_diagnostics` only ever counts diagnostics already emitted \
                      from this append-only vector, so it stays within `diagnostics.len()`"
        )]
        let diagnostics = self.captured.diagnostics[self.published_diagnostics..].to_vec();
        for diagnostic in diagnostics {
            emit(super::Event::Diagnostic(diagnostic)).map_err(OperationError::output)?;
            #[expect(
                clippy::arithmetic_side_effects,
                reason = "one increment per diagnostic in the vector, so the count cannot exceed \
                          `diagnostics.len()`"
            )]
            {
                self.published_diagnostics += 1;
            }
        }
        Ok(())
    }
}

fn drain_deadline_error() -> LiveIoError {
    LiveIoError::DeadlineExceeded {
        operation: "draining capture before all requests were sent",
    }
}
