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
}

/// The totals of the findings a run published, the frames it read and
/// matched, the findings retained for the document, and the capture's IP
/// reassembly.
impl
    From<(
        expert::Summary,
        u64,
        u64,
        Vec<Finding>,
        &library::IpReassemblyReport,
    )> for Report
{
    fn from(
        (summary, frames_read, frames_matched, findings, ip_reassembly): (
            expert::Summary,
            u64,
            u64,
            Vec<Finding>,
            &library::IpReassemblyReport,
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
        }
    }
}

impl crate::output::stream::StreamRecord for Finding {
    fn event_name(&self) -> &'static str {
        "finding"
    }
}
