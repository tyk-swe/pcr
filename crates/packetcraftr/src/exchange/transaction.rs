// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! The single owner of state after an exchange capture has been armed.

use std::sync::Arc;

use packetcraftr_core::{decode::Dissector, registry::Registry};
use packetcraftr_netio::{
    Error as LiveIoError,
    capture::{self, OverflowPolicy, Session},
    transmit,
};

use super::CaptureGuard;
use super::capture::DrainPolicy;
use super::{
    Accumulator, Collection, Error, Event, ProcessOutcome, Report, Window, WorkflowResponseMatcher,
    WorkflowStopPredicate,
};

use crate::Stats;
use crate::preparation::PreparedPacket;

pub(super) enum OperationError {
    Io(LiveIoError),
    Output(packetcraftr_core::error::BoundaryError),
}

impl From<LiveIoError> for OperationError {
    fn from(error: LiveIoError) -> Self {
        Self::Io(error)
    }
}

impl OperationError {
    pub(super) fn output(error: packetcraftr_core::error::BoundaryError) -> Self {
        Self::Output(error)
    }

    pub(super) fn into_error(self) -> Error {
        match self {
            Self::Io(error) => error.into(),
            Self::Output(source) => Error::Output {
                source: Box::new(source),
            },
        }
    }
}

pub(crate) struct Transaction<C: Session> {
    pub(super) registry: Arc<Registry>,
    pub(super) capture: CaptureGuard<C>,
    pub(super) cancellation: Option<packetcraftr_core::budget::Cancellation>,
    pub(super) window: Window,
    pub(super) collection: Collection,
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
            cancellation: prepared.cancellation,
            window: prepared.window,
            collection: prepared.collection,
            prepared: prepared.packets,
            packet_count: prepared.packet_count,
            total_bytes: prepared.total_bytes,
            sent: Vec::with_capacity(request_count),
            completed_sends: 0,
            captured: Accumulator::new(request_count),
            correlation_stopped: false,
        }
    }

    pub(crate) fn execute<T, F>(
        mut self,
        transmit: &T,
        mut workflow_matcher: Option<&mut WorkflowResponseMatcher<'_>>,
        mut stop_predicate: Option<&mut WorkflowStopPredicate<'_>>,
        emit: &mut F,
    ) -> Result<Report, Error>
    where
        T: transmit::Provider + ?Sized,
        F: FnMut(super::Event) -> Result<(), packetcraftr_core::error::BoundaryError>,
    {
        let operation = self.run(transmit, &mut workflow_matcher, &mut stop_predicate, emit);
        if let Err(operation) = operation {
            return Err(self.fail_after_shutdown(operation));
        }

        self.capture.shutdown()?;
        self.finalize_exchange(emit)
    }

    fn run<T, F>(
        &mut self,
        transmit: &T,
        workflow_matcher: &mut Option<&mut WorkflowResponseMatcher<'_>>,
        stop_predicate: &mut Option<&mut WorkflowStopPredicate<'_>>,
        emit: &mut F,
    ) -> Result<(), OperationError>
    where
        T: transmit::Provider + ?Sized,
        F: FnMut(super::Event) -> Result<(), packetcraftr_core::error::BoundaryError>,
    {
        self.await_capture_readiness()?;
        if self.send_requests(transmit, workflow_matcher, stop_predicate, emit)?
            == ProcessOutcome::StopCapture
        {
            return Ok(());
        }
        self.collect_remaining(workflow_matcher, stop_predicate, emit)
    }

    fn await_capture_readiness(&mut self) -> Result<(), LiveIoError> {
        if self.window.expired() {
            return Err(LiveIoError::DeadlineExceeded {
                operation: "waiting for capture readiness",
            });
        }
        self.capture.inner.wait_ready(self.window.deadline())
    }
}

impl<C: Session> Transaction<C> {
    pub(super) fn send_requests<T, F>(
        &mut self,
        transmit: &T,
        workflow_matcher: &mut Option<&mut WorkflowResponseMatcher<'_>>,
        stop_predicate: &mut Option<&mut WorkflowStopPredicate<'_>>,
        emit: &mut F,
    ) -> Result<ProcessOutcome, OperationError>
    where
        T: transmit::Provider + ?Sized,
        F: FnMut(Event) -> Result<(), packetcraftr_core::error::BoundaryError>,
    {
        for send_index in 0..self.prepared.len() {
            if self.drain(
                DrainPolicy::Enforced,
                workflow_matcher,
                stop_predicate,
                emit,
            )? == ProcessOutcome::StopCapture
            {
                return Ok(ProcessOutcome::StopCapture);
            }
            self.ensure_send_deadline()?;
            self.send_one(transmit, send_index, emit)?;
            self.ensure_send_deadline()?;

            let policy = if send_index.saturating_add(1) < self.prepared.len() {
                DrainPolicy::Enforced
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

    fn send_one<T, F>(
        &mut self,
        transmit: &T,
        send_index: usize,
        emit: &mut F,
    ) -> Result<(), OperationError>
    where
        T: transmit::Provider + ?Sized,
        F: FnMut(Event) -> Result<(), packetcraftr_core::error::BoundaryError>,
    {
        // `send_index` is produced by `0..self.prepared.len()` in `send_requests`, the only caller
        let sent = Arc::new(self.prepared[send_index].clone().transmit(transmit, || {
            if let Some(signal) = &self.cancellation {
                signal.check().map_err(LiveIoError::from)?;
            }
            Ok::<(), OperationError>(())
        })?);
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
        if self.window.expired() {
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
                OperationError::Output(output) => Error::OutputAndCaptureShutdown {
                    output: Box::new(output),
                    shutdown: Box::new(shutdown),
                },
            },
        }
    }

    pub(super) fn finalize_exchange<F>(mut self, emit: &mut F) -> Result<Report, Error>
    where
        F: FnMut(super::Event) -> Result<(), packetcraftr_core::error::BoundaryError>,
    {
        let capture_statistics = self.capture.inner.stats();
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
            .map_err(|source| Error::Output {
                source: Box::new(source),
            })?;
        }
        let stopped_before_all_sends = self.sent.len() < self.prepared.len();
        let (packets_attempted, bytes) = if stopped_before_all_sends {
            (self.completed_sends, sent_bytes(&self.sent))
        } else {
            (self.packet_count, self.total_bytes)
        };
        Ok(Report {
            unanswered,
            diagnostics: Vec::new(),
            stats: Stats {
                packets_attempted,
                packets_completed: self.completed_sends,
                bytes,
                elapsed: self.window.elapsed(),
                capture: capture_statistics,
            },
        })
    }

    fn apply_capture_loss_policy(&mut self, statistics: capture::Stats) -> Result<(), Error> {
        let Some(loss) = statistics.evidence_loss_error() else {
            return Ok(());
        };
        if self.collection.capture.overflow_policy == OverflowPolicy::Fail {
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
                    self.collection.capture.overflow_policy,
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
