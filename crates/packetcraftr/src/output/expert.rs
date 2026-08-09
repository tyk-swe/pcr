// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Structured expert-analysis output.

use serde::Serialize;

use packetcraftr_analysis::expert::{
    ExpertSummary, Finding as AnalysisFinding, StreamTransport as AnalysisStreamTransport,
};
use packetcraftr_packet::diagnostic::Severity as DiagnosticSeverity;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Warning,
    Error,
}

impl From<DiagnosticSeverity> for Severity {
    fn from(value: DiagnosticSeverity) -> Self {
        match value {
            DiagnosticSeverity::Info => Self::Info,
            DiagnosticSeverity::Warning => Self::Warning,
            DiagnosticSeverity::Error => Self::Error,
        }
    }
}

/// Transport namespace for a stream index; TCP and UDP indices are independent.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StreamTransport {
    Tcp,
    Udp,
}

impl StreamTransport {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

impl From<AnalysisStreamTransport> for StreamTransport {
    fn from(value: AnalysisStreamTransport) -> Self {
        match value {
            AnalysisStreamTransport::Tcp => Self::Tcp,
            AnalysisStreamTransport::Udp => Self::Udp,
        }
    }
}

/// A finding attributed to one capture frame. `transport` and `stream` jointly
/// identify its conversation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Finding {
    pub severity: Severity,
    pub code: String,
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
            severity: value.severity.into(),
            code: value.code,
            frame: value.number,
            transport: value.stream.map(|stream| stream.transport.into()),
            stream: value.stream.map(|stream| stream.index),
            message: value.message,
        }
    }
}

/// Total findings under one code.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CodeCount {
    pub code: String,
    pub findings: u64,
}

/// Aggregate result or terminal NDJSON record; the latter omits already-streamed
/// findings.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Result {
    pub frames_read: u64,
    pub frames_matched: u64,
    pub errors: u64,
    pub warnings: u64,
    pub notes: u64,
    pub codes: Vec<CodeCount>,
    pub findings: Vec<Finding>,
}

impl Result {
    pub fn from_summary(
        summary: ExpertSummary,
        frames_read: u64,
        frames_matched: u64,
        findings: Vec<Finding>,
    ) -> Self {
        Self {
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
        }
    }
}
