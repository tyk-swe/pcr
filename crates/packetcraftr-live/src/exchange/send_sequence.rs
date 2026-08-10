// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Ordered packet transmission and inter-send correlation drains.

use std::time::Instant;

use packetcraftr_network::{
    Error as LiveIoError,
    capture::Session,
    transmit::{Frame as TransmissionFrame, Sender as PacketIo},
};

use super::transaction::ExchangeTransaction;
use super::{ExchangeProcessOutcome, WorkflowResponseMatcher};

impl<C: Session> ExchangeTransaction<C> {
    pub(super) fn send_requests<I: PacketIo>(
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
        let frame = TransmissionFrame::try_new(&built.bytes, route)?;
        let report = io.send(frame)?;
        self.sent.push(crate::SentPacket::try_new(
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
