// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Armed exchange transaction and capture lifecycle phases.

use std::sync::Arc;
use std::time::{Instant, SystemTime};

use crate::capture::{Frame, LinkType};
use crate::net::{
    Error as LiveIoError,
    capture::{CaptureOverflowPolicy, CaptureQueueLimits, CaptureSession, CaptureStatistics},
    link::LinkMode,
    transmit::{PacketIo, TransmissionFrame},
};
use crate::packet::{decode::Dissector, registry::ProtocolRegistry};

use super::super::Stats;
use super::super::helpers::{push_diagnostic_once, validate_send_report};
use super::super::send::ClientError;
use super::{
    CaptureGuard, ExchangeAccumulator, ExchangeOptions, ExchangeProcessContext,
    ExchangeProcessOutcome, ExchangeResult, PreparedExchangePacket, WorkflowPromotionContext,
    WorkflowResponseMatcher, drain_available,
};

pub(crate) struct PreparedExchange {
    pub(crate) started: Instant,
    pub(crate) deadline: Instant,
    pub(crate) capture_limits: CaptureQueueLimits,
    pub(crate) options: ExchangeOptions,
    pub(crate) packets: Vec<PreparedExchangePacket>,
    pub(crate) packet_count: u64,
    pub(crate) total_bytes: u64,
}

/// State that exists only after capture has been armed. Owning the guard here
/// makes every post-arm exit pass through one shutdown-composition boundary;
/// `CaptureGuard::drop` remains the panic fallback.
pub(crate) struct ExchangeTransaction<C: CaptureSession> {
    registry: Arc<ProtocolRegistry>,
    capture: CaptureGuard<C>,
    started: Instant,
    deadline: Instant,
    capture_limits: CaptureQueueLimits,
    options: ExchangeOptions,
    prepared: Vec<PreparedExchangePacket>,
    packet_count: u64,
    total_bytes: u64,
    sent_at: Vec<Instant>,
    sent_evidence: Vec<Frame>,
    completed_sends: u64,
    dissector: Dissector,
    captured: ExchangeAccumulator,
    correlation_stopped: bool,
}

impl<C: CaptureSession> ExchangeTransaction<C> {
    pub(crate) fn new(
        registry: Arc<ProtocolRegistry>,
        capture: C,
        prepared: PreparedExchange,
    ) -> Self {
        let request_count = prepared.packets.len();
        Self {
            dissector: Dissector::new(Arc::clone(&registry)),
            registry,
            capture: CaptureGuard::new(capture),
            started: prepared.started,
            deadline: prepared.deadline,
            capture_limits: prepared.capture_limits,
            options: prepared.options,
            prepared: prepared.packets,
            packet_count: prepared.packet_count,
            total_bytes: prepared.total_bytes,
            sent_at: Vec::with_capacity(request_count),
            sent_evidence: Vec::with_capacity(request_count),
            completed_sends: 0,
            captured: ExchangeAccumulator::new(request_count),
            correlation_stopped: false,
        }
    }

    pub(crate) fn execute<I: PacketIo>(
        mut self,
        io: &I,
        mut workflow_matcher: Option<&mut WorkflowResponseMatcher<'_>>,
    ) -> Result<ExchangeResult, ClientError> {
        let operation = self.run(io, &mut workflow_matcher);
        if let Err(operation) = operation {
            return Err(self.fail_after_shutdown(operation));
        }

        self.capture.shutdown()?;
        self.finalize_exchange()
    }

    fn run<I: PacketIo>(
        &mut self,
        io: &I,
        workflow_matcher: &mut Option<&mut WorkflowResponseMatcher<'_>>,
    ) -> Result<(), LiveIoError> {
        self.await_capture_readiness()?;
        self.send_and_correlate(io, workflow_matcher)?;
        self.collect_remaining(workflow_matcher)
    }

    fn await_capture_readiness(&mut self) -> Result<(), LiveIoError> {
        if !self.capture.supports_monotonic_ingress_time() {
            return Err(LiveIoError::MissingMonotonicCaptureTimestamp);
        }
        let readiness_timeout = self.deadline.checked_duration_since(Instant::now()).ok_or(
            LiveIoError::DeadlineExceeded {
                operation: "waiting for capture readiness",
            },
        )?;
        self.capture.wait_ready(readiness_timeout)
    }

    fn send_and_correlate<I: PacketIo>(
        &mut self,
        io: &I,
        workflow_matcher: &mut Option<&mut WorkflowResponseMatcher<'_>>,
    ) -> Result<(), LiveIoError> {
        for send_index in 0..self.prepared.len() {
            self.drain(Some(self.deadline))?;
            if self.promote_workflow(workflow_matcher)
                == ExchangeProcessOutcome::CorrelationDeadlineExpired
            {
                return Err(LiveIoError::DeadlineExceeded {
                    operation: "correlating workflow responses before all requests were sent",
                });
            }
            self.ensure_send_deadline()?;
            self.send_one(io, send_index)?;
            self.ensure_send_deadline()?;

            let more_requests = send_index + 1 < self.prepared.len();
            self.drain(more_requests.then_some(self.deadline))?;
            if self.promote_workflow(workflow_matcher)
                == ExchangeProcessOutcome::CorrelationDeadlineExpired
            {
                if more_requests {
                    return Err(LiveIoError::DeadlineExceeded {
                        operation: "correlating workflow responses before all requests were sent",
                    });
                }
                self.correlation_stopped = true;
            }
        }
        Ok(())
    }

    fn send_one<I: PacketIo>(&mut self, io: &I, send_index: usize) -> Result<(), LiveIoError> {
        let prepared = &self.prepared[send_index];
        let built = &prepared.built;
        let route = &prepared.route;
        let send_started = Instant::now();
        let send_wall_time = SystemTime::now();
        let frame = TransmissionFrame::try_new(&built.bytes, route)?;
        let report = io.send(frame)?;
        validate_send_report(&built.bytes, &report)?;
        let link_type = match route.plan.mode {
            LinkMode::Layer2 => route.plan.route.link_type,
            LinkMode::Layer3 => LinkType::RAW,
            LinkMode::Auto => return Err(LiveIoError::UnresolvedLinkMode),
        };
        let evidence =
            Frame::new(send_wall_time, link_type, built.bytes.clone()).map_err(|source| {
                LiveIoError::InvalidSendEvidence {
                    message: source.to_string(),
                }
            })?;
        self.sent_at.push(send_started);
        self.sent_evidence.push(evidence);
        self.completed_sends =
            self.completed_sends
                .checked_add(1)
                .ok_or(LiveIoError::InvalidSendReport {
                    bytes_sent: usize::MAX,
                    wire_bytes: usize::MAX,
                })?;
        Ok(())
    }

    fn collect_remaining(
        &mut self,
        workflow_matcher: &mut Option<&mut WorkflowResponseMatcher<'_>>,
    ) -> Result<(), LiveIoError> {
        if !self.correlation_stopped {
            while let Some(remaining) = self.deadline.checked_duration_since(Instant::now()) {
                let Some(frame) = self.capture.next_captured_frame(remaining)? else {
                    break;
                };
                let context = Self::process_context(
                    &self.registry,
                    &self.dissector,
                    &self.prepared,
                    &self.sent_at,
                    self.deadline,
                    &self.options,
                );
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

    fn drain(&mut self, enforced_deadline: Option<Instant>) -> Result<(), LiveIoError> {
        let context = Self::process_context(
            &self.registry,
            &self.dissector,
            &self.prepared,
            &self.sent_at,
            self.deadline,
            &self.options,
        );
        drain_available(
            &mut self.capture,
            enforced_deadline,
            self.capture_limits.max_frames,
            &mut self.captured,
            context,
        )
    }

    fn promote_workflow(
        &mut self,
        workflow_matcher: &mut Option<&mut WorkflowResponseMatcher<'_>>,
    ) -> ExchangeProcessOutcome {
        let Some(matches_request) = workflow_matcher.as_deref_mut() else {
            return ExchangeProcessOutcome::Continue;
        };
        let context = Self::promotion_context(
            &self.prepared,
            &self.sent_at,
            self.deadline,
            self.options.max_responses,
        );
        self.captured
            .promote_workflow_unsolicited(context, matches_request)
    }

    fn process_context<'a>(
        registry: &'a ProtocolRegistry,
        dissector: &'a Dissector,
        prepared: &'a [PreparedExchangePacket],
        sent_at: &'a [Instant],
        deadline: Instant,
        options: &'a ExchangeOptions,
    ) -> ExchangeProcessContext<'a> {
        ExchangeProcessContext {
            registry,
            dissector,
            prepared,
            sent_at,
            deadline,
            options,
        }
    }

    fn promotion_context<'a>(
        prepared: &'a [PreparedExchangePacket],
        sent_at: &'a [Instant],
        deadline: Instant,
        max_responses: usize,
    ) -> WorkflowPromotionContext<'a> {
        WorkflowPromotionContext {
            prepared,
            sent_at,
            deadline,
            max_responses,
        }
    }

    fn ensure_send_deadline(&self) -> Result<(), LiveIoError> {
        if self
            .deadline
            .checked_duration_since(Instant::now())
            .is_none()
        {
            return Err(LiveIoError::DeadlineExceeded {
                operation: "sending exchange requests",
            });
        }
        Ok(())
    }

    fn fail_after_shutdown(&mut self, operation: LiveIoError) -> ClientError {
        match self.capture.shutdown() {
            Ok(()) => ClientError::Io(operation),
            Err(shutdown) => ClientError::OperationAndCaptureShutdown {
                operation,
                shutdown,
            },
        }
    }

    fn finalize_exchange(mut self) -> Result<ExchangeResult, ClientError> {
        let capture_statistics = self.capture.statistics().validate()?;
        self.apply_capture_loss_policy(capture_statistics)?;
        let unanswered = self
            .captured
            .response_counts
            .iter()
            .enumerate()
            .filter_map(|(index, count)| (*count == 0).then_some(index))
            .collect();
        let sent = self
            .prepared
            .into_iter()
            .map(|prepared| prepared.built)
            .collect();
        Ok(self.captured.finish(
            sent,
            self.sent_evidence,
            unanswered,
            Stats {
                packets_attempted: self.packet_count,
                packets_completed: self.completed_sends,
                bytes: self.total_bytes,
                elapsed: self.started.elapsed(),
                capture: capture_statistics,
            },
        ))
    }

    fn apply_capture_loss_policy(
        &mut self,
        statistics: CaptureStatistics,
    ) -> Result<(), ClientError> {
        if !statistics.has_loss() {
            return Ok(());
        }
        if self.capture_limits.overflow_policy == CaptureOverflowPolicy::Fail {
            return Err(statistics
                .evidence_loss_error()
                .expect("lossy capture statistics must produce a typed error")
                .into());
        }
        push_diagnostic_once(
            &mut self.captured.diagnostics,
            crate::packet::diagnostic::Diagnostic::warning(
                "capture.evidence_incomplete",
                format!(
                    "capture backend reported {} overflow event(s), {} receiver drop(s), {} total dropped frame(s), and {} dropped byte(s) under {:?}",
                    statistics.overflow_events,
                    statistics.receiver_dropped_frames,
                    statistics.dropped_frames,
                    statistics.dropped_bytes,
                    self.capture_limits.overflow_policy,
                ),
            ),
        );
        Ok(())
    }
}
