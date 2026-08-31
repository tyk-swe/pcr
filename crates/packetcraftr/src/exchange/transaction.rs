// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! The single owner of state after an exchange capture has been armed.

use std::sync::Arc;
use std::time::Instant;

use packetcraftr_core::{decode::Dissector, registry::Registry};
use packetcraftr_netio::{Error as LiveIoError, capture::Session, transmit::Sender as PacketIo};

use super::CaptureGuard;
use super::{
    Accumulator, PreparedPacket, ProcessOutcome, WorkflowResponseMatcher, WorkflowStopPredicate,
};

use crate::Error;

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
