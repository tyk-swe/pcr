// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Cross-frame protocol health findings computed over the analysis pipeline.

use std::collections::{BTreeMap, HashMap};

use crate::diagnostic::Severity;
use crate::protocol::transport::Tcp;

use crate::analysis::pipeline::{FrameRecord, Summary as RunSummary};
use crate::analysis::reassembly::tcp::{Event as TcpEvent, ScopedFlowKey};
use crate::analysis::session::{self, Needs};
use crate::analysis::{StreamRef, StreamTransport};
use crate::error::BoundaryError;

use tcp::DirectionState;

mod finding;
mod generation;
mod observation;
mod tcp;

const fn tcp_stream_ref(index: u64) -> StreamRef {
    StreamRef {
        transport: StreamTransport::Tcp,
        index,
    }
}

const fn udp_stream_ref(index: u64) -> StreamRef {
    StreamRef {
        transport: StreamTransport::Udp,
        index,
    }
}

/// Cross-frame finding attributed to the revealing frame. Layer-scoped decode
/// diagnostics are also included with their own codes and severities.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Finding {
    pub severity: Severity,
    /// Stable machine-readable code, such as `tcp.retransmission`; always a
    /// literal from the published set.
    pub code: &'static str,
    /// 1-based capture frame number that revealed the condition.
    pub number: u64,
    pub stream: Option<StreamRef>,
    pub message: String,
}

/// Per-severity and per-code totals for a completed pass.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Summary {
    pub clock: crate::analysis::ClockReport,
    pub findings: u64,
    pub errors: u64,
    pub warnings: u64,
    pub notes: u64,
    /// Total findings per code, in code order.
    pub codes: BTreeMap<&'static str, u64>,
}

impl Summary {
    // u64 finding counters cannot reach u64::MAX from a bounded frame count
    fn count(&mut self, finding: &Finding) {
        self.findings += 1;
        match finding.severity {
            Severity::Error => self.errors += 1,
            Severity::Warning => self.warnings += 1,
            Severity::Info => self.notes += 1,
        }
        *self.codes.entry(finding.code).or_default() += 1;
    }
}

/// Detects TCP conditions from headers. Reassembly events supply retransmission
/// and gap evidence; acknowledgment and window fields supply duplicate ACK,
/// zero window, window-full, keep-alive, and reset findings.
#[derive(Debug, Default)]
pub struct Collector {
    flows: HashMap<ScopedFlowKey, DirectionState>,
    streams: HashMap<ScopedFlowKey, u64>,
    summary: Summary,
}

impl Collector {
    pub fn new() -> Self {
        Self::default()
    }

    /// Folds one matched frame, returning the findings it revealed.
    pub fn observe(&mut self, record: &FrameRecord<'_>) -> Vec<Finding> {
        let mut findings = finding::from_capture_evidence(record);
        findings.extend(finding::from_diagnostics(record));
        self.reconcile_tcp_evictions(record.tcp_events);
        if let Some(tcp) = record.tcp
            && let Some(conversation) = tcp.conversation
        {
            self.observe_tcp(record, conversation, tcp, &mut findings);
        }

        for finding in &findings {
            self.summary.count(finding);
        }
        findings
    }

    /// Finishes the pass, folding in the run's trailing reassembly events: a
    /// flow flushed with bytes still buffered never healed its holes, which
    /// is evidence the per-frame view cannot carry. Returned findings are
    /// attributed to the run's last frame read.
    pub fn finish(mut self, summary: &RunSummary) -> (Vec<Finding>, Summary) {
        self.summary.clock = summary.clock.clone();
        let findings = tcp::finish(
            &self.streams,
            &summary.trailing_tcp_events,
            summary.frames_read,
        );
        for finding in &findings {
            self.summary.count(finding);
        }
        (findings, self.summary)
    }
}

impl session::Collector for Collector {
    type Event = Finding;
    type Summary = Summary;

    /// Findings read transport indexes, the reassembler's byte-exact
    /// retransmission evidence, and reconstructed-datagram diagnostics.
    fn needs(&self) -> Needs {
        Needs {
            tcp_stream: true,
            udp_stream: true,
            ip_reassembly: true,
            tcp_events: true,
            ..Needs::default()
        }
    }

    fn observe(&mut self, record: &FrameRecord<'_>) -> Result<Vec<Finding>, BoundaryError> {
        Ok(Self::observe(self, record))
    }

    fn finish(self, run: &RunSummary) -> Result<(Vec<Finding>, Summary), BoundaryError> {
        Ok(Self::finish(self, run))
    }
}
