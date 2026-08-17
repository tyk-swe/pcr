// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! The single owner of state after an exchange capture has been armed.

use std::sync::Arc;
use std::time::Instant;

use packetcraftr_core::{decode::Dissector, registry::Registry};
use packetcraftr_netio::{
    Error as LiveIoError,
    capture::{Limits as CaptureQueueLimits, Session},
    transmit::Sender as PacketIo,
};

use super::CaptureGuard;
use super::{Accumulator, PreparedPacket, WorkflowResponseMatcher};

use crate::Error;

/// Mutable live-operation state, created after capture is armed.
pub(crate) struct Transaction<C: Session> {
    pub(super) registry: Arc<Registry>,
    pub(super) capture: CaptureGuard<C>,
    pub(super) started: Instant,
    pub(super) deadline: Instant,
    pub(super) capture_limits: CaptureQueueLimits,
    pub(super) options: super::Options,
    pub(super) prepared: Vec<PreparedPacket>,
    pub(super) packet_count: u64,
    pub(super) total_bytes: u64,
    pub(super) sent: Vec<crate::SentPacket>,
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
            capture_limits: prepared.capture_limits,
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

    pub(crate) fn execute<I: PacketIo>(
        mut self,
        io: &I,
        mut workflow_matcher: Option<&mut WorkflowResponseMatcher<'_>>,
    ) -> Result<super::Result, Error> {
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
    ) -> Result<(), packetcraftr_netio::Error> {
        self.await_capture_readiness()?;
        self.send_requests(io, workflow_matcher)?;
        self.collect_remaining(workflow_matcher)
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
