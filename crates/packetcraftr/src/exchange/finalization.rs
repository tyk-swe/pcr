// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Capture shutdown composition and fail-closed result/statistics validation.

use packetcraftr_netio::capture::{OverflowPolicy, Session, Statistics};

use super::transaction::OperationError;
use super::transaction::Transaction;
use crate::Error;
use crate::Stats;

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
