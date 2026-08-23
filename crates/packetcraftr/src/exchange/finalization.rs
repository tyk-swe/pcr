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
                    operation,
                    shutdown,
                },
                OperationError::Output(output) => Error::OutputAndCaptureShutdown {
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
        let capture_statistics = self.capture.inner.statistics().validate()?;
        self.apply_capture_loss_policy(capture_statistics)?;
        self.publish_diagnostics(emit)
            .map_err(OperationError::into_error)?;
        let unanswered = self
            .captured
            .response_counts
            .iter()
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
        Ok(super::Summary {
            unanswered,
            diagnostics: Vec::new(),
            stats: Stats {
                packets_attempted: self.packet_count,
                packets_completed: self.completed_sends,
                bytes: self.total_bytes,
                elapsed: self.started.elapsed(),
                capture: capture_statistics,
            },
        })
    }

    fn apply_capture_loss_policy(&mut self, statistics: Statistics) -> Result<(), Error> {
        if !statistics.has_loss() {
            return Ok(());
        }
        if self.capture_limits.overflow_policy == OverflowPolicy::Fail {
            return Err(statistics
                .evidence_loss_error()
                .expect("lossy capture statistics must produce a typed error")
                .into());
        }
        packetcraftr_core::diagnostic::push_once(
            &mut self.captured.diagnostics,
            packetcraftr_core::diagnostic::Diagnostic::warning(
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
