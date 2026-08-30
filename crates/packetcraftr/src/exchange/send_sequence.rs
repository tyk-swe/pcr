// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Ordered packet transmission and inter-send correlation drains.

use std::sync::Arc;
use std::time::Instant;

use packetcraftr_netio::{
    Error as LiveIoError,
    capture::Session,
    transmit::{Frame as TransmissionFrame, Sender as PacketIo},
};

use super::transaction::OperationError;
use super::transaction::Transaction;
use super::{Event, ProcessOutcome, WorkflowResponseMatcher, WorkflowStopPredicate};

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
            if self.drain(Some(self.deadline), workflow_matcher, stop_predicate, emit)?
                == ProcessOutcome::StopCapture
            {
                return Ok(ProcessOutcome::StopCapture);
            }
            self.ensure_send_deadline()?;
            self.send_one(io, send_index, emit)?;
            self.ensure_send_deadline()?;

            let more_requests = send_index.saturating_add(1) < self.prepared.len();
            let outcome = self.drain(
                more_requests.then_some(self.deadline),
                workflow_matcher,
                stop_predicate,
                emit,
            )?;
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
}
