// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use serde::Serialize;

use packetcraftr_analysis::expert::{ExpertSummary, Finding, StreamTransport};
use packetcraftr_packet::diagnostic::DiagnosticSeverity;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExpertSeverity {
    Info,
    Warning,
    Error,
}

impl From<DiagnosticSeverity> for ExpertSeverity {
    fn from(value: DiagnosticSeverity) -> Self {
        match value {
            DiagnosticSeverity::Info => Self::Info,
            DiagnosticSeverity::Warning => Self::Warning,
            DiagnosticSeverity::Error => Self::Error,
        }
    }
}

/// The transport whose conversation numbering a stream index belongs to.
///
/// TCP and UDP indices are allocated independently, so the index alone
/// cannot name a conversation in a capture holding both.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExpertStreamTransport {
    Tcp,
    Udp,
}

impl ExpertStreamTransport {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

impl From<StreamTransport> for ExpertStreamTransport {
    fn from(value: StreamTransport) -> Self {
        match value {
            StreamTransport::Tcp => Self::Tcp,
            StreamTransport::Udp => Self::Udp,
        }
    }
}

/// One finding, attributed to the capture frame that revealed it.
///
/// `transport` and `stream` are present together: the pair names the
/// conversation in the same vocabulary the `tcp.stream` and `udp.stream`
/// display filters use.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ExpertFindingOutput {
    pub severity: ExpertSeverity,
    pub code: String,
    pub frame: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transport: Option<ExpertStreamTransport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stream: Option<u64>,
    pub message: String,
}

impl From<Finding> for ExpertFindingOutput {
    fn from(value: Finding) -> Self {
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
pub struct ExpertCodeCount {
    pub code: String,
    pub findings: u64,
}

/// Aggregate or terminal result of `expert`.
///
/// The aggregate carries every finding; the NDJSON terminal record carries
/// the totals with an empty list, since each finding was already streamed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ExpertCommandResult {
    pub frames_read: u64,
    pub frames_matched: u64,
    pub errors: u64,
    pub warnings: u64,
    pub notes: u64,
    pub codes: Vec<ExpertCodeCount>,
    pub findings: Vec<ExpertFindingOutput>,
}

impl ExpertCommandResult {
    pub fn from_summary(
        summary: ExpertSummary,
        frames_read: u64,
        frames_matched: u64,
        findings: Vec<ExpertFindingOutput>,
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
                .map(|(code, findings)| ExpertCodeCount { code, findings })
                .collect(),
            findings,
        }
    }
}
