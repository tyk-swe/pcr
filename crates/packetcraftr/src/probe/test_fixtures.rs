// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
// Test code indexes fixtures and counts by hand; the fail-closed lints are
// for library paths.
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

//! Unit-test scaffolding shared by the probe workflows. Integration tests use
//! `tests/support/` instead.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use packetcraftr_core::error::{Classification, Kind};
use packetcraftr_core::frame::{Frame, LinkType};
use packetcraftr_core::layout::PacketLayout;
use packetcraftr_core::{Packet, decode::DecodedPacket, diagnostic::Diagnostic};

use super::executor::{Executor, Request};
use crate::BoundaryError;

/// The finite authorization budgets every probe workflow unit test reuses: a
/// private target with room for small deterministic batches.
pub(crate) fn private_policy() -> crate::policy::Policy {
    crate::policy::Policy {
        max_packets_per_operation: 1_000,
        max_bytes_per_operation: 1_000_000,
        ..crate::policy::Policy::default()
    }
}

/// Builds decoded evidence for `packet` with an explicit timestamp, wire bytes,
/// and diagnostics. Scan, traceroute, and evidence-selection tests share this
/// constructor; each keeps only a thin adapter when it needs fixed bytes.
pub(crate) fn decoded_packet(
    packet: Packet,
    timestamp: SystemTime,
    bytes: &[u8],
    diagnostics: Vec<Diagnostic>,
) -> DecodedPacket {
    let frame = evidence_frame(timestamp, bytes);
    DecodedPacket {
        packet,
        original: frame.bytes().clone(),
        frame,
        layout: PacketLayout::default(),
        diagnostics,
    }
}

/// Builds one exact evidence frame for test fixtures.
pub(crate) fn evidence_frame(timestamp: SystemTime, bytes: &[u8]) -> Frame {
    Frame::new(timestamp, LinkType::RAW, Bytes::copy_from_slice(bytes))
        .expect("probe test fixture frame carries bytes")
}

/// Builds the `[0x45]` RAW fixture frame at `UNIX_EPOCH + seconds`, the shape
/// traceroute's retained-evidence tests already use.
pub(crate) fn raw_frame(seconds: u64) -> Frame {
    evidence_frame(
        SystemTime::UNIX_EPOCH + Duration::from_secs(seconds),
        &[0x45],
    )
}

/// Counts executions and shutdowns while optionally failing the `fail_at`-th
/// call, so progressive-output tests share one failure-injection executor
/// across request types. `failure_message` and `failure_code` keep the induced
/// failure workflow-specific.
pub(crate) struct ProgressiveExecutor<I> {
    pub(crate) inner: I,
    pub(crate) calls: Arc<AtomicUsize>,
    pub(crate) shutdowns: Arc<AtomicUsize>,
    pub(crate) fail_at: Option<usize>,
    pub(crate) failure_message: &'static str,
    pub(crate) failure_code: &'static str,
}

impl<R, I> Executor<R> for ProgressiveExecutor<I>
where
    R: Request,
    I: Executor<R>,
{
    fn execute(&mut self, request: &R) -> Result<R::Execution, BoundaryError> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
        if self.fail_at == Some(call) {
            return Err(BoundaryError::new(
                self.failure_message,
                Classification::new(self.failure_code, Kind::Io, None),
                Vec::new(),
            ));
        }
        let execution = self.inner.execute(request);
        self.shutdowns.fetch_add(1, Ordering::SeqCst);
        execution
    }
}

/// Retains `frames` plus `diagnostic` on every batch the inner executor
/// produces, so evidence-limits tests share one fixture across workflows.
pub(crate) struct RetainedEvidenceExecutor<I> {
    pub(crate) inner: I,
    pub(crate) frames: Vec<Frame>,
    pub(crate) diagnostic: Diagnostic,
}

impl<R, I> Executor<R> for RetainedEvidenceExecutor<I>
where
    R: Request<Execution = super::runner::Execution>,
    I: Executor<R>,
{
    fn execute(&mut self, request: &R) -> Result<R::Execution, BoundaryError> {
        let mut execution = self.inner.execute(request)?;
        execution.undecoded.extend(self.frames.iter().cloned());
        execution.diagnostics.push(self.diagnostic.clone());
        Ok(execution)
    }
}
