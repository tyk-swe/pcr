// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Cross-frame protocol health findings computed over the analysis pipeline.

use std::collections::{BTreeMap, HashMap};

use crate::diagnostic::Severity as DiagnosticSeverity;
use crate::protocol::transport::Tcp;

use crate::analysis::adapter::{transport_payload, transports};
use crate::analysis::pipeline::FrameRecord;
use crate::analysis::reassembly::tcp::{Event as TcpEvent, FlowKey};

use tcp::DirectionState;

mod finding;
mod generation;
mod observation;
mod tcp;

/// The transport namespace a conversation index belongs to.
///
/// TCP and UDP indices are allocated independently, so a bare number cannot
/// name a conversation in a capture that holds both.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamTransport {
    Tcp,
    Udp,
}

/// One conversation: its transport namespace plus per-transport index,
/// matching the `tcp.stream` and `udp.stream` filter vocabularies.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StreamRef {
    pub transport: StreamTransport,
    pub index: u64,
}

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

/// One expert finding, attributed to the frame that revealed it.
///
/// Findings are cross-frame observations — a retransmission only exists
/// relative to an earlier segment — so they carry their own model rather
/// than the per-frame, layer-scoped decode diagnostics; decode diagnostics
/// are folded in as findings of their own code and severity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Finding {
    pub severity: DiagnosticSeverity,
    /// Stable machine-readable code, such as `tcp.retransmission`.
    pub code: String,
    /// 1-based capture frame number that revealed the condition.
    pub number: u64,
    /// The conversation concerned, when there is one.
    pub stream: Option<StreamRef>,
    pub message: String,
}

/// Per-severity and per-code totals for a completed pass.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExpertSummary {
    pub findings: u64,
    pub errors: u64,
    pub warnings: u64,
    pub notes: u64,
    /// Total findings per code, in code order.
    pub codes: BTreeMap<String, u64>,
}

impl ExpertSummary {
    fn count(&mut self, finding: &Finding) {
        self.findings += 1;
        match finding.severity {
            DiagnosticSeverity::Error => self.errors += 1,
            DiagnosticSeverity::Warning => self.warnings += 1,
            DiagnosticSeverity::Info => self.notes += 1,
        }
        *self.codes.entry(finding.code.clone()).or_default() += 1;
    }
}

/// Detects cross-frame TCP conditions from dissected headers.
///
/// Retransmission and gap evidence comes from the reassembly engine's
/// sequence tracking, delivered through the pipeline's TCP events; the
/// header-derived conditions here — duplicate acknowledgment, zero window,
/// window full, keep-alive, reset — need acknowledgment and window fields
/// reassembly deliberately does not carry.
#[derive(Debug, Default)]
pub struct ExpertCollector {
    flows: HashMap<FlowKey, DirectionState>,
    streams: HashMap<FlowKey, u64>,
    summary: ExpertSummary,
}

impl ExpertCollector {
    pub fn new() -> Self {
        Self::default()
    }

    /// Folds one matched frame, returning the findings it revealed.
    pub fn observe(&mut self, record: &FrameRecord<'_>) -> Vec<Finding> {
        let frame_transports = transports(&record.decoded.packet);
        let mut findings = finding::from_diagnostics(record, &frame_transports);
        self.reconcile_tcp_evictions(record.tcp_events);
        if let Some((index, flow, tcp)) = frame_transports.tcp {
            let payload_len = transport_payload(record.decoded, index).len();
            self.observe_tcp(record, &flow, tcp, payload_len, &mut findings);
        }

        for finding in &findings {
            self.summary.count(finding);
        }
        findings
    }

    /// Finishes the pass, folding in the pipeline's trailing reassembly
    /// events: a flow flushed with bytes still buffered never healed its
    /// holes, which is evidence the per-frame view cannot carry. Returned
    /// findings are attributed to `end_number`, the last frame read.
    pub fn finish(
        mut self,
        trailing: &[TcpEvent],
        end_number: u64,
    ) -> (Vec<Finding>, ExpertSummary) {
        let findings = tcp::finish(&self.streams, trailing, end_number);
        for finding in &findings {
            self.summary.count(finding);
        }
        (findings, self.summary)
    }
}
