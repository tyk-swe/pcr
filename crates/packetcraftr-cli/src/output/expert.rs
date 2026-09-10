// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Structured expert-analysis output.

use packetcraftr_core::analysis::StreamTransport;

use serde::Serialize;

use packetcraftr_core::analysis::expert::Finding as AnalysisFinding;

use packetcraftr_core::diagnostic::Severity;

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

impl From<AnalysisFinding> for Finding {
    fn from(value: AnalysisFinding) -> Self {
        Self {
            severity: value.severity,
            code: value.code,
            frame: value.number,
            transport: value.stream.map(|stream| stream.transport),
            stream: value.stream.map(|stream| stream.index),
            message: value.message,
        }
    }
}

/// Total findings under one code.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CodeCount {
    pub code: &'static str,
    pub findings: u64,
}

/// Aggregate result or terminal NDJSON record; the latter omits already-streamed
/// findings.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Report {
    pub clock: packetcraftr_core::analysis::ClockReport,
    pub frames_read: u64,
    pub frames_matched: u64,
    pub errors: u64,
    pub warnings: u64,
    pub notes: u64,
    pub codes: Vec<CodeCount>,
    pub findings: Vec<Finding>,
    pub ip_reassembly: super::reassembly::Report,
}

impl Report {
    pub fn from_summary(
        summary: packetcraftr_core::analysis::expert::Summary,
        frames_read: u64,
        frames_matched: u64,
        findings: Vec<Finding>,
        ip_reassembly: &packetcraftr_core::analysis::IpReassemblyReport,
    ) -> Self {
        Self {
            clock: summary.clock,
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
            ip_reassembly: super::reassembly::Report::from_analysis(ip_reassembly),
        }
    }
}

impl crate::output::stream::StreamRecord for Finding {
    fn event_name(&self) -> &'static str {
        "finding"
    }
}
