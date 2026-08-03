// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Capture readiness, bounded draining, and post-send collection.

use std::time::{Duration, Instant};

use packetcraftr_net::{Error as LiveIoError, capture::CaptureSession};
use packetcraftr_packet::diagnostic::push_diagnostic_once;

use super::shutdown::CaptureGuard;
use super::transaction::ExchangeTransaction;
use super::{
    ExchangeAccumulator, ExchangeProcessContext, ExchangeProcessOutcome, WorkflowPromotionContext,
    WorkflowResponseMatcher,
};

fn drain_available<C: CaptureSession>(
    capture: &mut CaptureGuard<C>,
    enforced_deadline: Option<Instant>,
    frame_limit: usize,
    captured: &mut ExchangeAccumulator,
    context: ExchangeProcessContext<'_>,
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
        if captured.process(frame, context) == ExchangeProcessOutcome::CorrelationDeadlineExpired {
            if enforced_deadline.is_some() {
                return Err(LiveIoError::DeadlineExceeded {
                    operation: "draining capture before all requests were sent",
                });
            }
            return Ok(());
        }
    }
    push_diagnostic_once(
        &mut captured.diagnostics,
        packetcraftr_packet::diagnostic::Diagnostic::warning(
            "exchange.drain_limit",
            format!("zero-time capture drain stopped after the bounded {frame_limit} frame(s)"),
        ),
    );
    Ok(())
}

impl<C: CaptureSession> ExchangeTransaction<C> {
    pub(super) fn collect_remaining(
        &mut self,
        workflow_matcher: &mut Option<&mut WorkflowResponseMatcher<'_>>,
    ) -> Result<(), LiveIoError> {
        if !self.correlation_stopped {
            while let Some(remaining) = self.deadline.checked_duration_since(Instant::now()) {
                let Some(frame) = self.capture.inner.next_captured_frame(remaining)? else {
                    break;
                };
                let context = ExchangeProcessContext {
                    registry: &self.registry,
                    dissector: &self.dissector,
                    prepared: &self.prepared,
                    sent_at: &self.sent_at,
                    deadline: self.deadline,
                    options: &self.options,
                };
                if self.captured.process(frame, context)
                    == ExchangeProcessOutcome::CorrelationDeadlineExpired
                {
                    break;
                }
                if self.promote_workflow(workflow_matcher)
                    == ExchangeProcessOutcome::CorrelationDeadlineExpired
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
        let context = ExchangeProcessContext {
            registry: &self.registry,
            dissector: &self.dissector,
            prepared: &self.prepared,
            sent_at: &self.sent_at,
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
    ) -> ExchangeProcessOutcome {
        let Some(matches_request) = workflow_matcher.as_deref_mut() else {
            return ExchangeProcessOutcome::Continue;
        };
        let context = WorkflowPromotionContext {
            prepared: &self.prepared,
            sent_at: &self.sent_at,
            deadline: self.deadline,
            max_responses: self.options.max_responses,
        };
        self.captured
            .promote_workflow_unsolicited(context, matches_request)
    }
}
