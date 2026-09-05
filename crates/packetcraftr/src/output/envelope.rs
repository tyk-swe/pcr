// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Aggregate JSON and streaming NDJSON envelopes.

use std::fmt;
use std::time::Duration;

use serde::Serialize;

use packetcraftr_core::error::{Classification, Classified, Coordinate, Kind};

use super::contract::{Command, Mode, SCHEMA_V1};

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Error {
    pub code: String,
    pub kind: Kind,
    pub message: String,
    pub causes: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<Coordinate>,
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
            context: None,
            remediation: classification.remediation.map(str::to_owned),
        }
    }

    pub fn classified(error: &(impl Classified + fmt::Display)) -> Self {
        Self::new(error.classification(), error.to_string(), error.causes())
            .with_context(error.context())
    }

    #[must_use]
    pub const fn with_context(mut self, context: Option<Coordinate>) -> Self {
        self.context = context;
        self
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
    #[serde(skip_serializing_if = "is_zero")]
    pub receiver_dropped_frames: u64,
}

/// The one `skip_serializing_if` predicate for counters the contract omits
/// when they are zero.
pub(super) const fn is_zero(value: &u64) -> bool {
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

pub use packetcraftr_core::diagnostic::{Diagnostic, Severity as DiagnosticSeverity};

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum OutputPayload<T> {
    Success { result: T },
    Error { error: Error },
}

/// One structured record: an aggregate JSON result, or the same shape plus the
/// `sequence` that makes it one NDJSON stream record.
#[derive(Clone, Debug, Serialize)]
pub struct Envelope<T> {
    schema: &'static str,
    command: Option<Command>,
    mode: Mode,
    #[serde(skip_serializing_if = "Option::is_none")]
    sequence: Option<u64>,
    #[serde(flatten)]
    payload: OutputPayload<T>,
    diagnostics: Vec<Diagnostic>,
    #[serde(skip_serializing_if = "Option::is_none")]
    stats: Option<Stats>,
}

impl<T> Envelope<T> {
    /// One aggregate JSON success.
    pub fn success(command: Command, result: T, diagnostics: Vec<Diagnostic>) -> Self {
        Self {
            schema: SCHEMA_V1,
            command: Some(command),
            mode: Mode::Aggregate,
            sequence: None,
            payload: OutputPayload::Success { result },
            diagnostics,
            stats: None,
        }
    }

    /// One NDJSON success record at `sequence`.
    pub(super) fn record(
        command: Command,
        sequence: u64,
        result: T,
        diagnostics: Vec<Diagnostic>,
    ) -> Self {
        Self {
            schema: SCHEMA_V1,
            command: Some(command),
            mode: Mode::Stream,
            sequence: Some(sequence),
            payload: OutputPayload::Success { result },
            diagnostics,
            stats: None,
        }
    }

    #[must_use]
    pub fn with_stats(mut self, stats: Stats) -> Self {
        self.stats = Some(stats);
        self
    }
}

impl Envelope<()> {
    /// One aggregate JSON error. `command` is absent when the failure happened
    /// before command selection.
    pub fn error(command: Option<Command>, error: Error) -> Self {
        Self {
            schema: SCHEMA_V1,
            command,
            mode: Mode::Aggregate,
            sequence: None,
            payload: OutputPayload::Error { error },
            diagnostics: Vec::new(),
            stats: None,
        }
    }

    /// One terminal NDJSON error record at `sequence`.
    pub(super) fn error_record(command: Option<Command>, sequence: u64, error: Error) -> Self {
        Self {
            schema: SCHEMA_V1,
            command,
            mode: Mode::Stream,
            sequence: Some(sequence),
            payload: OutputPayload::Error { error },
            diagnostics: Vec::new(),
            stats: None,
        }
    }
}
