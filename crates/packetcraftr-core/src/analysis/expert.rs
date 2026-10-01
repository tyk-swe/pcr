// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Cross-frame protocol health findings computed over the analysis pipeline.

use std::collections::{BTreeMap, HashMap};

use crate::diagnostic::Severity;
use crate::protocol::transport::Tcp;

use crate::analysis::pipeline::{FrameRecord, Summary as RunSummary};
use crate::analysis::reassembly::tcp::{Event as TcpEvent, ScopedFlowKey};
use crate::analysis::session::{self, CollectorNeeds};
use crate::analysis::{StreamRef, StreamTransport};
use crate::error::BoundaryError;

use tcp::DirectionState;

mod finding;
mod generation;
mod observation;
mod selector;
mod tcp;

pub use selector::Selector;

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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Finding {
    pub severity: Severity,
    pub code: &'static str,
    /// 1-based capture frame number that revealed the condition.
    pub number: u64,
    pub stream: Option<StreamRef>,
    pub message: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Summary {
    pub clock: crate::analysis::ClockReport,
    pub findings: u64,
    pub errors: u64,
    pub warnings: u64,
    pub notes: u64,
    pub codes: BTreeMap<&'static str, u64>,
}

impl Summary {
    /// Tallies one finding into the totals, per-severity counters and per-code counts.
    // u64 finding counters cannot reach u64::MAX from a bounded frame count
    pub fn record(&mut self, finding: &Finding) {
        self.findings += 1;
        match finding.severity {
            Severity::Error => self.errors += 1,
            Severity::Warning => self.warnings += 1,
            Severity::Info => self.notes += 1,
        }
        *self.codes.entry(finding.code).or_default() += 1;
    }
}

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

    pub fn observe(&mut self, record: &FrameRecord<'_>) -> Vec<Finding> {
        let mut findings = finding::from_capture_evidence(record);
        findings.extend(finding::from_diagnostics(record));
        let tcp = record
            .tcp
            .and_then(|tcp| tcp.conversation.map(|conversation| (conversation, tcp)));
        // Handshake verdicts read the flow as it stood before this frame's own evictions.
        let prior =
            tcp.map(|(conversation, _)| tcp::Prior::capture(&self.flows, conversation.flow));
        self.reconcile_tcp_evictions(record.tcp_events);
        if let (Some((conversation, tcp)), Some(prior)) = (tcp, prior) {
            self.observe_tcp(record, conversation, tcp, prior, &mut findings);
        }

        for finding in &findings {
            self.summary.record(finding);
        }
        findings
    }

    pub fn finish(mut self, summary: &RunSummary) -> (Vec<Finding>, Summary) {
        self.summary.clock = summary.clock.clone();
        let findings = tcp::finish(
            &self.flows,
            &self.streams,
            &summary.trailing_tcp_events,
            summary.frames_read,
        );
        for finding in &findings {
            self.summary.record(finding);
        }
        (findings, self.summary)
    }
}

impl session::Collector for Collector {
    type Event = Finding;
    type Summary = Summary;

    fn needs(&self) -> CollectorNeeds {
        CollectorNeeds {
            tcp_stream: true,
            udp_stream: true,
            ip_reassembly: true,
            tcp_events: true,
            ..CollectorNeeds::default()
        }
    }

    fn observe(&mut self, record: &FrameRecord<'_>) -> Result<Vec<Finding>, BoundaryError> {
        Ok(Self::observe(self, record))
    }

    fn finish(self, run: &RunSummary) -> Result<(Vec<Finding>, Summary), BoundaryError> {
        Ok(Self::finish(self, run))
    }
}
