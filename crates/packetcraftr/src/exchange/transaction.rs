// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! The single owner of state after an exchange capture has been armed.

use std::sync::Arc;
use std::time::Instant;

use packetcraftr_core::{decode::Dissector, registry::Registry};
use packetcraftr_netio::{
    Error as LiveIoError,
    capture::{OverflowPolicy, Session, Statistics},
    transmit::{Frame as TransmissionFrame, Sender as PacketIo},
};

use super::CaptureGuard;
use super::capture::DrainPolicy;
use super::{Accumulator, Event, ProcessOutcome, WorkflowResponseMatcher, WorkflowStopPredicate};

use crate::materialize::PreparedPacket;
use crate::planning::expired;
use crate::{Error, Stats};

pub(super) enum OperationError {
    Io(LiveIoError),
    Output(crate::BoundaryError),
}

impl From<LiveIoError> for OperationError {
    fn from(error: LiveIoError) -> Self {
        Self::Io(error)
    }
}

impl OperationError {
    pub(super) fn output(error: crate::BoundaryError) -> Self {
        Self::Output(error)
    }

    pub(super) fn into_error(self) -> Error {
        match self {
            Self::Io(error) => Error::Io(error),
            Self::Output(source) => Error::ExchangeOutput {
                source: Box::new(source),
            },
        }
    }
}

/// Mutable live-operation state, created after capture is armed.
pub(crate) struct Transaction<C: Session> {
    pub(super) registry: Arc<Registry>,
    pub(super) capture: CaptureGuard<C>,
    pub(super) started: Instant,
    pub(super) deadline: Instant,
    pub(super) options: super::Options,
    pub(super) prepared: Vec<PreparedPacket>,
    pub(super) packet_count: u64,
    pub(super) total_bytes: u64,
    pub(super) sent: Vec<Arc<crate::SentPacket>>,
    pub(super) completed_sends: u64,
    pub(super) dissector: Dissector,
    pub(super) captured: Accumulator,
    pub(super) correlation_stopped: bool,
}

impl<C: Session> Transaction<C> {
    pub(crate) fn new(registry: Arc<Registry>, capture: C, prepared: super::Prepared) -> Self {
        let request_count = prepared.packets.len();
        Self {
            dissector: Dissector::new(Arc::clone(&registry)),
            registry,
            capture: CaptureGuard::new(capture),
            started: prepared.started,
            deadline: prepared.deadline,
            options: prepared.options,
            prepared: prepared.packets,
            packet_count: prepared.packet_count,
            total_bytes: prepared.total_bytes,
            sent: Vec::with_capacity(request_count),
            completed_sends: 0,
            captured: Accumulator::new(request_count),
            correlation_stopped: false,
        }
    }

    pub(crate) fn execute<I, F>(
        mut self,
        io: &I,
        mut workflow_matcher: Option<&mut WorkflowResponseMatcher<'_>>,
        mut stop_predicate: Option<&mut WorkflowStopPredicate<'_>>,
        emit: &mut F,
    ) -> Result<super::Summary, Error>
    where
        I: PacketIo,
        F: FnMut(super::Event) -> Result<(), crate::BoundaryError>,
    {
        let operation = self.run(io, &mut workflow_matcher, &mut stop_predicate, emit);
        if let Err(operation) = operation {
            return Err(self.fail_after_shutdown(operation));
        }

        self.capture.shutdown()?;
        self.finalize_exchange(emit)
    }

    fn run<I, F>(
        &mut self,
        io: &I,
        workflow_matcher: &mut Option<&mut WorkflowResponseMatcher<'_>>,
        stop_predicate: &mut Option<&mut WorkflowStopPredicate<'_>>,
        emit: &mut F,
    ) -> Result<(), OperationError>
    where
        I: PacketIo,
        F: FnMut(super::Event) -> Result<(), crate::BoundaryError>,
    {
        self.await_capture_readiness()?;
        if self.send_requests(io, workflow_matcher, stop_predicate, emit)?
            == ProcessOutcome::StopCapture
        {
            return Ok(());
        }
        self.collect_remaining(workflow_matcher, stop_predicate, emit)
    }

    fn await_capture_readiness(&mut self) -> Result<(), LiveIoError> {
        let readiness_timeout = self.deadline.checked_duration_since(Instant::now()).ok_or(
            LiveIoError::DeadlineExceeded {
                operation: "waiting for capture readiness",
            },
        )?;
        self.capture.inner.wait_ready(readiness_timeout)
    }
}

impl<C: Session> Transaction<C> {
    pub(super) fn send_requests<I, F>(
        &mut self,
        io: &I,
        workflow_matcher: &mut Option<&mut WorkflowResponseMatcher<'_>>,
        stop_predicate: &mut Option<&mut WorkflowStopPredicate<'_>>,
        emit: &mut F,
    ) -> Result<ProcessOutcome, OperationError>
    where
        I: PacketIo,
        F: FnMut(Event) -> Result<(), crate::BoundaryError>,
    {
        for send_index in 0..self.prepared.len() {
            if self.drain(
                DrainPolicy::Enforced(self.deadline),
                workflow_matcher,
                stop_predicate,
                emit,
            )? == ProcessOutcome::StopCapture
            {
                return Ok(ProcessOutcome::StopCapture);
            }
            self.ensure_send_deadline()?;
            self.send_one(io, send_index, emit)?;
            self.ensure_send_deadline()?;

            let policy = if send_index.saturating_add(1) < self.prepared.len() {
                DrainPolicy::Enforced(self.deadline)
            } else {
                DrainPolicy::BestEffort
            };
            let outcome = self.drain(policy, workflow_matcher, stop_predicate, emit)?;
            if outcome == ProcessOutcome::StopCapture {
                return Ok(outcome);
            }
            if outcome == ProcessOutcome::CorrelationDeadlineExpired {
                self.correlation_stopped = true;
            }
        }
        Ok(ProcessOutcome::Continue)
    }

    fn send_one<I, F>(
        &mut self,
        io: &I,
        send_index: usize,
        emit: &mut F,
    ) -> Result<(), OperationError>
    where
        I: PacketIo,
        F: FnMut(Event) -> Result<(), crate::BoundaryError>,
    {
        #[expect(
            clippy::indexing_slicing,
            reason = "`send_index` is produced by `0..self.prepared.len()` in `send_requests`, the \
                      only caller"
        )]
        let prepared = &self.prepared[send_index];
        let built = &prepared.built;
        let route = &prepared.route;
        let frame = TransmissionFrame::try_new(&built.bytes, route)?;
        let report = io.send(frame)?;
        let sent = Arc::new(crate::SentPacket::try_new(
            built.clone(),
            route.clone(),
            report,
        )?);
        self.completed_sends =
            self.completed_sends
                .checked_add(1)
                .ok_or(LiveIoError::InvalidSendReport {
                    bytes_sent: usize::MAX,
                    wire_bytes: usize::MAX,
                })?;
        self.sent.push(Arc::clone(&sent));
        emit(Event::Sent {
            request_index: send_index,
            sent,
        })
        .map_err(OperationError::output)?;
        Ok(())
    }

    fn ensure_send_deadline(&self) -> Result<(), LiveIoError> {
        if expired(self.deadline) {
            return Err(LiveIoError::DeadlineExceeded {
                operation: "sending exchange requests",
            });
        }
        Ok(())
    }
}

impl<C: Session> Transaction<C> {
    pub(super) fn fail_after_shutdown(&mut self, operation: OperationError) -> Error {
        match self.capture.shutdown() {
            Ok(()) => operation.into_error(),
            Err(shutdown) => match operation {
                OperationError::Io(operation) => Error::OperationAndCaptureShutdown {
                    operation: Box::new(operation),
                    shutdown: Box::new(shutdown),
                },
                OperationError::Output(output) => Error::ExchangeOutputAndCaptureShutdown {
                    output: Box::new(output),
                    shutdown,
                },
            },
        }
    }

    pub(super) fn finalize_exchange<F>(mut self, emit: &mut F) -> Result<super::Summary, Error>
    where
        F: FnMut(super::Event) -> Result<(), crate::BoundaryError>,
    {
        let capture_statistics = self.capture.inner.statistics();
        capture_statistics.validate()?;
        self.apply_capture_loss_policy(capture_statistics)?;
        self.publish_diagnostics(emit)
            .map_err(OperationError::into_error)?;
        let unanswered = self
            .captured
            .response_counts
            .iter()
            .take(self.sent.len())
            .enumerate()
            .filter_map(|(index, count)| (*count == 0).then_some(index))
            .collect::<Vec<_>>();
        for request_index in &unanswered {
            emit(super::Event::Unanswered {
                request_index: *request_index,
            })
            .map_err(|source| Error::ExchangeOutput {
                source: Box::new(source),
            })?;
        }
        let stopped_before_all_sends = self.sent.len() < self.prepared.len();
        let (packets_attempted, bytes) = if stopped_before_all_sends {
            (self.completed_sends, sent_bytes(&self.sent))
        } else {
            (self.packet_count, self.total_bytes)
        };
        Ok(super::Summary {
            unanswered,
            diagnostics: Vec::new(),
            stats: Stats {
                packets_attempted,
                packets_completed: self.completed_sends,
                bytes,
                elapsed: self.started.elapsed(),
                capture: capture_statistics,
            },
        })
    }

    fn apply_capture_loss_policy(&mut self, statistics: Statistics) -> Result<(), Error> {
        let Some(loss) = statistics.evidence_loss_error() else {
            return Ok(());
        };
        if self.options.capture.overflow_policy == OverflowPolicy::Fail {
            return Err(loss.into());
        }
        self.captured.diagnostics.push_once(
            packetcraftr_core::diagnostic::Diagnostic::warning(
                "capture.evidence_incomplete",
                format!(
                    "capture backend reported {} overflow event(s), {} receiver drop(s), {} total dropped frame(s), and {} dropped byte(s) under {}",
                    statistics.overflow_events,
                    statistics.receiver_dropped_frames,
                    statistics.dropped_frames,
                    statistics.dropped_bytes,
                    self.options.capture.overflow_policy,
                ),
            ),
        );
        Ok(())
    }
}

/// A live operation never aborts while accounting for traffic it has already
/// emitted: an overflowing total is reported saturated, and the evidence
/// validator that recomputes the same fold rejects it as an overflow there.
fn sent_bytes(sent: &[std::sync::Arc<crate::SentPacket>]) -> u64 {
    crate::evidence::total_bytes_sent(sent.iter().map(std::sync::Arc::as_ref)).unwrap_or(u64::MAX)
}
