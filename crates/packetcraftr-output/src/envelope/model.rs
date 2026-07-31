// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::fmt;
use std::time::Duration;

use serde::Serialize;

use packetcraftr_error::{Classification, Classified, Kind};
use packetcraftr_packet::diagnostic::Diagnostic;

use super::super::contract::{CommandName, OUTPUT_SCHEMA_V1, OutputMode};

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct OutputError {
    pub code: String,
    pub kind: Kind,
    pub message: String,
    pub causes: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
}

impl OutputError {
    pub fn new(
        classification: Classification,
        message: impl Into<String>,
        causes: Vec<String>,
    ) -> Self {
        Self {
            code: classification.code.to_owned(),
            kind: classification.kind,
            message: message.into(),
            causes,
            remediation: classification.remediation.map(str::to_owned),
        }
    }

    pub fn classified(error: &(impl Classified + fmt::Display)) -> Self {
        Self::new(error.classification(), error.to_string(), error.causes())
    }
}

/// Output-v1 live-capture counters.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct CaptureStats {
    pub received_frames: u64,
    pub received_bytes: u64,
    pub dropped_frames: u64,
    pub dropped_bytes: u64,
    pub overflow_events: u64,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub receiver_dropped_frames: u64,
}

const fn is_zero(value: &u64) -> bool {
    *value == 0
}

impl From<packetcraftr_net::capture::Statistics> for CaptureStats {
    fn from(value: packetcraftr_net::capture::Statistics) -> Self {
        Self {
            received_frames: value.received_frames,
            received_bytes: value.received_bytes,
            dropped_frames: value.dropped_frames,
            dropped_bytes: value.dropped_bytes,
            overflow_events: value.overflow_events,
            receiver_dropped_frames: value.receiver_dropped_frames,
        }
    }
}

/// Output-v1 operation statistics carried by structured envelopes.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct OperationStats {
    pub packets_attempted: u64,
    pub packets_completed: u64,
    pub bytes: u64,
    pub elapsed: Duration,
    pub capture: CaptureStats,
}

impl From<packetcraftr_client::Stats> for OperationStats {
    fn from(value: packetcraftr_client::Stats) -> Self {
        Self {
            packets_attempted: value.packets_attempted,
            packets_completed: value.packets_completed,
            bytes: value.bytes,
            elapsed: value.elapsed,
            capture: value.capture.into(),
        }
    }
}

impl From<&packetcraftr_workflow::fuzz::Stats> for OperationStats {
    fn from(value: &packetcraftr_workflow::fuzz::Stats) -> Self {
        Self {
            packets_attempted: value.packets_attempted,
            packets_completed: value.packets_completed,
            bytes: value.bytes,
            elapsed: value.elapsed,
            capture: value.capture.into(),
        }
    }
}

/// Output-v1 diagnostic severity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticSeverityOutput {
    Info,
    Warning,
    Error,
}

impl From<packetcraftr_packet::diagnostic::DiagnosticSeverity> for DiagnosticSeverityOutput {
    fn from(value: packetcraftr_packet::diagnostic::DiagnosticSeverity) -> Self {
        match value {
            packetcraftr_packet::diagnostic::DiagnosticSeverity::Info => Self::Info,
            packetcraftr_packet::diagnostic::DiagnosticSeverity::Warning => Self::Warning,
            packetcraftr_packet::diagnostic::DiagnosticSeverity::Error => Self::Error,
        }
    }
}

/// Output-v1 byte range used by diagnostics.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct DiagnosticRangeOutput {
    pub start: usize,
    pub end: usize,
}

impl From<packetcraftr_packet::layout::ByteRange> for DiagnosticRangeOutput {
    fn from(value: packetcraftr_packet::layout::ByteRange) -> Self {
        Self {
            start: value.start,
            end: value.end,
        }
    }
}

/// Output-v1 diagnostic record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DiagnosticOutput {
    pub code: String,
    pub severity: DiagnosticSeverityOutput,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub layer: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub range: Option<DiagnosticRangeOutput>,
}

impl From<Diagnostic> for DiagnosticOutput {
    fn from(value: Diagnostic) -> Self {
        Self {
            code: value.code,
            severity: value.severity.into(),
            message: value.message,
            layer: value.layer,
            field: value.field,
            range: value.range.map(Into::into),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum OutputPayload<T> {
    Success { result: T },
    Error { error: OutputError },
}

/// One aggregate JSON success or error. Its type cannot carry a stream sequence.
#[derive(Clone, Debug, Serialize)]
pub struct AggregateOutput<T> {
    schema: &'static str,
    command: Option<CommandName>,
    mode: OutputMode,
    #[serde(flatten)]
    payload: OutputPayload<T>,
    diagnostics: Vec<DiagnosticOutput>,
    #[serde(skip_serializing_if = "Option::is_none")]
    stats: Option<OperationStats>,
}

impl<T> AggregateOutput<T> {
    pub fn success(command: CommandName, result: T, diagnostics: Vec<Diagnostic>) -> Self {
        Self {
            schema: OUTPUT_SCHEMA_V1,
            command: Some(command),
            mode: OutputMode::Aggregate,
            payload: OutputPayload::Success { result },
            diagnostics: diagnostics.into_iter().map(Into::into).collect(),
            stats: None,
        }
    }

    pub fn error(command: Option<CommandName>, error: OutputError) -> Self {
        Self {
            schema: OUTPUT_SCHEMA_V1,
            command,
            mode: OutputMode::Aggregate,
            payload: OutputPayload::Error { error },
            diagnostics: Vec::new(),
            stats: None,
        }
    }

    #[must_use]
    pub fn with_stats(mut self, stats: OperationStats) -> Self {
        self.stats = Some(stats);
        self
    }
}

/// Aggregate error envelope with no unused success-result type parameter.
pub type AggregateErrorOutput = AggregateOutput<()>;

/// One independently valid NDJSON success or terminal-error record.
#[derive(Clone, Debug, Serialize)]
pub struct StreamRecord<T> {
    schema: &'static str,
    command: Option<CommandName>,
    mode: OutputMode,
    sequence: u64,
    #[serde(flatten)]
    payload: OutputPayload<T>,
    diagnostics: Vec<DiagnosticOutput>,
    #[serde(skip_serializing_if = "Option::is_none")]
    stats: Option<OperationStats>,
}

impl<T> StreamRecord<T> {
    pub fn success(
        command: CommandName,
        sequence: u64,
        result: T,
        diagnostics: Vec<Diagnostic>,
    ) -> Self {
        Self {
            schema: OUTPUT_SCHEMA_V1,
            command: Some(command),
            mode: OutputMode::Stream,
            sequence,
            payload: OutputPayload::Success { result },
            diagnostics: diagnostics.into_iter().map(Into::into).collect(),
            stats: None,
        }
    }

    pub fn error(command: Option<CommandName>, sequence: u64, error: OutputError) -> Self {
        Self {
            schema: OUTPUT_SCHEMA_V1,
            command,
            mode: OutputMode::Stream,
            sequence,
            payload: OutputPayload::Error { error },
            diagnostics: Vec::new(),
            stats: None,
        }
    }

    #[must_use]
    pub fn with_stats(mut self, stats: OperationStats) -> Self {
        self.stats = Some(stats);
        self
    }
}

/// Terminal NDJSON error record with no unused success-result type parameter.
pub type StreamErrorRecord = StreamRecord<()>;
