// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! The single owner of state after an exchange capture has been armed.

use std::sync::Arc;
use std::time::Instant;

use packetcraftr_network::{
    Error as LiveIoError,
    capture::{Limits as CaptureQueueLimits, Session},
    transmit::Sender as PacketIo,
};
use packetcraftr_packet::{decode::Decoder as Dissector, registry::Registry};

use super::CaptureGuard;
use super::{
    ExchangeAccumulator, ExchangeOptions, ExchangeResult, PreparedExchangePacket,
    WorkflowResponseMatcher,
};
use crate::send::ClientError;

/// Mutable live-operation state, created after capture is armed.
pub(crate) struct ExchangeTransaction<C: Session> {
    pub(super) registry: Arc<Registry>,
    pub(super) capture: CaptureGuard<C>,
    pub(super) started: Instant,
    pub(super) deadline: Instant,
    pub(super) capture_limits: CaptureQueueLimits,
    pub(super) options: ExchangeOptions,
    pub(super) prepared: Vec<PreparedExchangePacket>,
    pub(super) packet_count: u64,
    pub(super) total_bytes: u64,
    pub(super) sent_at: Vec<Instant>,
    pub(super) sent_evidence: Vec<packetcraftr_packet::frame::Frame>,
    pub(super) completed_sends: u64,
    pub(super) dissector: Dissector,
    pub(super) captured: ExchangeAccumulator,
    pub(super) correlation_stopped: bool,
}

impl<C: Session> ExchangeTransaction<C> {
    pub(crate) fn new(
        registry: Arc<Registry>,
        capture: C,
        prepared: super::PreparedExchange,
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
    ) -> Result<(), packetcraftr_network::Error> {
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
