// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Capture readiness, bounded draining, and post-send collection.

use std::time::{Duration, Instant};

use packetcraftr_netio::{Error as LiveIoError, capture::Session};

use super::shutdown::CaptureGuard;
use super::transaction::Transaction;
use super::{
    Accumulator, ProcessContext, ProcessOutcome, WorkflowPromotionContext, WorkflowResponseMatcher,
};

fn drain_available<C: Session>(
    capture: &mut CaptureGuard<C>,
    enforced_deadline: Option<Instant>,
    frame_limit: usize,
    captured: &mut Accumulator,
    context: ProcessContext<'_>,
) -> Result<(), LiveIoError> {
    for _ in 0..frame_limit {
        if enforced_deadline
            .is_some_and(|deadline| deadline.checked_duration_since(Instant::now()).is_none())
        {
            return Err(LiveIoError::DeadlineExceeded {
                operation: "draining capture before all requests were sent",
            });
        }
        let Some(frame) = capture.inner.next_captured_frame(Duration::ZERO)? else {
            return Ok(());
        };
        match captured.process(frame, context) {
            ProcessOutcome::CorrelationDeadlineExpired => {
                if enforced_deadline.is_some() {
                    return Err(LiveIoError::DeadlineExceeded {
                        operation: "draining capture before all requests were sent",
                    });
                }
                return Ok(());
            }
            ProcessOutcome::DuplicateRecordIdentity => {
                return Err(LiveIoError::Capture {
                    message: "capture provider returned the same ingress record more than once"
                        .to_owned(),
                });
            }
            ProcessOutcome::Continue => {}
        }
    }
    packetcraftr_core::diagnostic::push_once(
        &mut captured.diagnostics,
        packetcraftr_core::diagnostic::Diagnostic::warning(
            "exchange.drain_limit",
            format!("zero-time capture drain stopped after the bounded {frame_limit} frame(s)"),
        ),
    );
    Ok(())
}

impl<C: Session> Transaction<C> {
    pub(super) fn collect_remaining(
        &mut self,
        workflow_matcher: &mut Option<&mut WorkflowResponseMatcher<'_>>,
    ) -> Result<(), LiveIoError> {
        if !self.correlation_stopped {
            while let Some(remaining) = self.deadline.checked_duration_since(Instant::now()) {
                let Some(frame) = self.capture.inner.next_captured_frame(remaining)? else {
                    break;
                };
                let context = ProcessContext {
                    registry: &self.registry,
                    dissector: &self.dissector,
                    prepared: &self.prepared,
                    sent: &self.sent,
                    deadline: self.deadline,
                    options: &self.options,
                };
                match self.captured.process(frame, context) {
                    ProcessOutcome::CorrelationDeadlineExpired => break,
                    ProcessOutcome::DuplicateRecordIdentity => {
                        return Err(LiveIoError::Capture {
                            message:
                                "capture provider returned the same ingress record more than once"
                                    .to_owned(),
                        });
                    }
                    ProcessOutcome::Continue => {}
                }
                if self.promote_workflow(workflow_matcher)
                    == ProcessOutcome::CorrelationDeadlineExpired
                {
                    break;
                }
            }
        }
        self.drain(None)?;
        let _ = self.promote_workflow(workflow_matcher);
        Ok(())
    }

    pub(super) fn drain(&mut self, enforced_deadline: Option<Instant>) -> Result<(), LiveIoError> {
        let context = ProcessContext {
            registry: &self.registry,
            dissector: &self.dissector,
            prepared: &self.prepared,
            sent: &self.sent,
            deadline: self.deadline,
            options: &self.options,
        };
        drain_available(
            &mut self.capture,
            enforced_deadline,
            self.capture_limits.max_frames,
            &mut self.captured,
            context,
        )
    }

    pub(super) fn promote_workflow(
        &mut self,
        workflow_matcher: &mut Option<&mut WorkflowResponseMatcher<'_>>,
    ) -> ProcessOutcome {
        let Some(matches_request) = workflow_matcher.as_deref_mut() else {
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
}
