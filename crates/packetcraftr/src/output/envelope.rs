// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Aggregate JSON and streaming NDJSON envelopes.

use std::fmt;
use std::time::Duration;

use serde::Serialize;

use packetcraftr_core::diagnostic::Diagnostic as PacketDiagnostic;
use packetcraftr_core::error::{Classification, Classified, Kind};

use super::contract::{Command, Mode, SCHEMA_V1};

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Error {
    pub code: String,
    pub kind: Kind,
    pub message: String,
    pub causes: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
}

impl Error {
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

impl From<packetcraftr_netio::capture::Statistics> for CaptureStats {
    fn from(value: packetcraftr_netio::capture::Statistics) -> Self {
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
pub struct Stats {
    pub packets_attempted: u64,
    pub packets_completed: u64,
    pub bytes: u64,
    pub elapsed: Duration,
    pub capture: CaptureStats,
}

impl From<crate::Stats> for Stats {
    fn from(value: crate::Stats) -> Self {
        Self {
            packets_attempted: value.packets_attempted,
            packets_completed: value.packets_completed,
            bytes: value.bytes,
            elapsed: value.elapsed,
            capture: value.capture.into(),
        }
    }
}

impl From<&crate::fuzz::Stats> for Stats {
    fn from(value: &crate::fuzz::Stats) -> Self {
        Self {
            packets_attempted: value.packets_attempted,
            packets_completed: value.packets_completed,
            bytes: value.bytes,
            elapsed: value.elapsed,
            capture: value.capture.into(),
        }
    }
}

impl From<&packetcraftr_core::fuzz::Stats> for Stats {
    fn from(value: &packetcraftr_core::fuzz::Stats) -> Self {
        Self {
            packets_attempted: value.packets_attempted,
            packets_completed: value.packets_completed,
            bytes: value.bytes,
            elapsed: value.elapsed,
            capture: CaptureStats::default(),
        }
    }
}

/// Output-v1 diagnostic severity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticSeverity {
    Info,
    Warning,
    Error,
}

impl From<packetcraftr_core::diagnostic::Severity> for DiagnosticSeverity {
    fn from(value: packetcraftr_core::diagnostic::Severity) -> Self {
        match value {
            packetcraftr_core::diagnostic::Severity::Info => Self::Info,
            packetcraftr_core::diagnostic::Severity::Warning => Self::Warning,
            packetcraftr_core::diagnostic::Severity::Error => Self::Error,
        }
    }
}

/// Output-v1 byte range used by diagnostics.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct DiagnosticRange {
    pub start: usize,
    pub end: usize,
}

impl From<packetcraftr_core::layout::ByteRange> for DiagnosticRange {
    fn from(value: packetcraftr_core::layout::ByteRange) -> Self {
        Self {
            start: value.start,
            end: value.end,
        }
    }
}

/// Output-v1 diagnostic record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Diagnostic {
    pub code: String,
    pub severity: DiagnosticSeverity,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub layer: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub range: Option<DiagnosticRange>,
}

impl From<PacketDiagnostic> for Diagnostic {
    fn from(value: PacketDiagnostic) -> Self {
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
    Error { error: Error },
}

/// One aggregate JSON success or error. Its type cannot carry a stream sequence.
#[derive(Clone, Debug, Serialize)]
pub struct Aggregate<T> {
    schema: &'static str,
    command: Option<Command>,
    mode: Mode,
    #[serde(flatten)]
    payload: OutputPayload<T>,
    diagnostics: Vec<Diagnostic>,
    #[serde(skip_serializing_if = "Option::is_none")]
    stats: Option<Stats>,
}

impl<T> Aggregate<T> {
    pub fn success(command: Command, result: T, diagnostics: Vec<PacketDiagnostic>) -> Self {
        Self {
            schema: SCHEMA_V1,
            command: Some(command),
            mode: Mode::Aggregate,
            payload: OutputPayload::Success { result },
            diagnostics: diagnostics.into_iter().map(Into::into).collect(),
            stats: None,
        }
    }

    pub fn error(command: Option<Command>, error: Error) -> Self {
        Self {
            schema: SCHEMA_V1,
            command,
            mode: Mode::Aggregate,
            payload: OutputPayload::Error { error },
            diagnostics: Vec::new(),
            stats: None,
        }
    }

    #[must_use]
    pub fn with_stats(mut self, stats: Stats) -> Self {
        self.stats = Some(stats);
        self
    }
}

/// Aggregate error envelope with no unused success-result type parameter.
pub type AggregateError = Aggregate<()>;

/// The next zero-based ordinal in one NDJSON command invocation.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct StreamPosition(u64);

impl StreamPosition {
    /// Starts an empty stream at record zero.
    pub const fn initial() -> Self {
        Self(0)
    }

    /// Returns the ordinal that the next record will carry.
    pub const fn ordinal(&self) -> u64 {
        self.0
    }

    /// Produces the following position without allowing the ordinal to wrap.
    pub fn checked_next(&self) -> Result<Self, super::contract::Error> {
        self.0
            .checked_add(1)
            .map(Self)
            .ok_or(super::contract::Error::SequenceOverflow)
    }
}

/// One independently valid NDJSON success or terminal-error record.
#[derive(Clone, Debug, Serialize)]
pub struct Stream<T> {
    schema: &'static str,
    command: Option<Command>,
    mode: Mode,
    sequence: u64,
    #[serde(flatten)]
    payload: OutputPayload<T>,
    diagnostics: Vec<Diagnostic>,
    #[serde(skip_serializing_if = "Option::is_none")]
    stats: Option<Stats>,
}

impl<T> Stream<T> {
    pub fn success(
        command: Command,
        position: &StreamPosition,
        result: T,
        diagnostics: Vec<PacketDiagnostic>,
    ) -> Self {
        Self {
            schema: SCHEMA_V1,
            command: Some(command),
            mode: Mode::Stream,
            sequence: position.ordinal(),
            payload: OutputPayload::Success { result },
            diagnostics: diagnostics.into_iter().map(Into::into).collect(),
            stats: None,
        }
    }

    pub fn error(command: Option<Command>, position: &StreamPosition, error: Error) -> Self {
        Self {
            schema: SCHEMA_V1,
            command,
            mode: Mode::Stream,
            sequence: position.ordinal(),
            payload: OutputPayload::Error { error },
            diagnostics: Vec::new(),
            stats: None,
        }
    }

    #[must_use]
    pub fn with_stats(mut self, stats: Stats) -> Self {
        self.stats = Some(stats);
        self
    }
}

/// Terminal NDJSON error record with no unused success-result type parameter.
pub type StreamError = Stream<()>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stream_position_starts_at_zero_and_cannot_wrap() {
        let initial = StreamPosition::initial();
        assert_eq!(initial.ordinal(), 0);
        assert_eq!(initial.checked_next().expect("zero advances").ordinal(), 1);

        let maximum = StreamPosition(u64::MAX);
        assert_eq!(
            maximum.checked_next(),
            Err(super::super::contract::Error::SequenceOverflow)
        );
        assert_eq!(maximum.ordinal(), u64::MAX);
    }
}
