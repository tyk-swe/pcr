// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use serde::Serialize;

use packetcraftr_core::analysis::{self as library, expert};

use super::analysis::{Clock, StreamTransport};
use super::diagnostic::Severity;

/// A finding attributed to one capture frame. `transport` and `stream` jointly
/// identify its conversation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Finding {
    pub severity: Severity,
    pub code: &'static str,
    pub frame: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transport: Option<StreamTransport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stream: Option<u64>,
    pub message: String,
}

impl From<expert::Finding> for Finding {
    fn from(value: expert::Finding) -> Self {
        Self {
            severity: value.severity.into(),
            code: value.code,
            frame: value.number,
            transport: value.stream.map(|stream| stream.transport.into()),
            stream: value.stream.map(|stream| stream.index),
            message: value.message,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CodeCount {
    pub code: &'static str,
    pub findings: u64,
}

published_enum! {
    /// The verdict a completed gate evaluation publishes.
    pub enum Verdict from expert::gate::Verdict {
        /// Triggering findings stayed within the allowance and coverage sufficed.
        Pass => "pass",
        /// Triggering findings exceeded the configured allowance.
        Fail => "fail",
        /// Coverage was too thin to establish the requested predicate.
        Inconclusive => "inconclusive",
    }
}

published_enum! {
    /// Why a gate produced its verdict.
    pub enum Reason from expert::gate::Reason {
        /// Triggering findings and matched coverage satisfied the gate.
        WithinAllowance => "within_allowance",
        /// Triggering findings exceeded the configured allowance.
        FindingAllowanceExceeded => "finding_allowance_exceeded",
        /// Matched frames fell below the required minimum coverage.
        InsufficientFrames => "insufficient_frames",
    }
}

/// A completed CI gate evaluation: the configured criteria and the complete
/// observed and triggering counts it evaluated, independent of report
/// selectors.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct GateReport {
    pub verdict: Verdict,
    pub reason: Reason,
    pub min_severity: Severity,
    pub allow_findings: u64,
    pub minimum_frames: u64,
    pub frames_matched: u64,
    pub findings_observed: u64,
    pub triggering_findings: u64,
}

impl From<expert::gate::Report> for GateReport {
    fn from(value: expert::gate::Report) -> Self {
        Self {
            verdict: value.verdict.into(),
            reason: value.reason.into(),
            min_severity: value.min_severity.into(),
            allow_findings: value.allow_findings,
            minimum_frames: value.minimum_frames,
            frames_matched: value.frames_matched,
            findings_observed: value.findings_observed,
            triggering_findings: value.triggering_findings,
        }
    }
}

/// Aggregate result or terminal NDJSON record; the latter omits already-streamed
/// findings.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Report {
    pub clock: Clock,
    pub frames_read: u64,
    pub frames_matched: u64,
    pub errors: u64,
    pub warnings: u64,
    pub notes: u64,
    pub codes: Vec<CodeCount>,
    pub findings: Vec<Finding>,
    pub ip_reassembly: super::reassembly::Report,
    /// The evaluated gate; null when the run enabled no gate.
    pub gate: Option<GateReport>,
}

/// The totals of the findings a run published, the frames it read and
/// matched, the findings retained for the document, the capture's IP
/// reassembly, and the gate the run evaluated when one was enabled.
impl
    From<(
        expert::Summary,
        u64,
        u64,
        Vec<Finding>,
        &library::IpReassemblyReport,
        Option<GateReport>,
    )> for Report
{
    fn from(
        (summary, frames_read, frames_matched, findings, ip_reassembly, gate): (
            expert::Summary,
            u64,
            u64,
            Vec<Finding>,
            &library::IpReassemblyReport,
            Option<GateReport>,
        ),
    ) -> Self {
        Self {
            clock: summary.clock.into(),
            frames_read,
            frames_matched,
            errors: summary.errors,
            warnings: summary.warnings,
            notes: summary.notes,
            codes: summary
                .codes
                .into_iter()
                .map(|(code, findings)| CodeCount { code, findings })
                .collect(),
            findings,
            ip_reassembly: ip_reassembly.into(),
            gate,
        }
    }
}

impl crate::output::stream::StreamRecord for Finding {
    fn event_name(&self) -> &'static str {
        "finding"
    }
}
