// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Aggregate JSON and streaming NDJSON envelopes.

use packetcraftr::Stats;

use std::fmt;

use serde::Serialize;

use packetcraftr_core::diagnostic::Diagnostic;
use packetcraftr_core::error::{Classification, Classified, Coordinate, Kind};

use super::contract::{Command, Mode, SCHEMA_V6};

/// The failure class an `error` object publishes.
///
/// The CLI's name for each neutral [`Kind`]: a usage failure is published as
/// `"cli"`, the frozen v6 vocabulary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorKind {
    Cli,
    Packet,
    Capability,
    Io,
    Policy,
    Internal,
}

impl ErrorKind {
    /// The published name, as it appears in `error.kind`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Cli => "cli",
            Self::Packet => "packet",
            Self::Capability => "capability",
            Self::Io => "io",
            Self::Policy => "policy",
            Self::Internal => "internal",
        }
    }
}

impl From<Kind> for ErrorKind {
    fn from(kind: Kind) -> Self {
        match kind {
            Kind::Cli => Self::Cli,
            Kind::Packet => Self::Packet,
            Kind::Capability => Self::Capability,
            Kind::Io => Self::Io,
            Kind::Policy => Self::Policy,
            Kind::Internal => Self::Internal,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Error {
    pub code: String,
    pub kind: ErrorKind,
    pub message: String,
    pub causes: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<Coordinate>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capture: Option<Box<super::capture::Snapshot>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scan: Option<Box<super::scan::Failure>>,
}

impl Error {
    pub fn new(
        classification: Classification,
        message: impl Into<String>,
        causes: Vec<String>,
    ) -> Self {
        Self {
            code: classification.code.to_owned(),
            kind: classification.kind.into(),
            message: message.into(),
            causes,
            context: None,
            capture: None,
            scan: None,
            remediation: classification.remediation.map(str::to_owned),
        }
    }

    pub fn classified(error: &(impl Classified + fmt::Display)) -> Self {
        Self::new(error.classification(), error.to_string(), error.causes())
            .with_context(error.context())
    }

    #[must_use]
    pub fn with_capture(mut self, capture: Option<Box<super::capture::Snapshot>>) -> Self {
        self.capture = capture;
        self
    }

    #[must_use]
    pub fn with_scan(mut self, scan: Option<Box<super::scan::Failure>>) -> Self {
        self.scan = scan;
        self
    }

    #[must_use]
    pub const fn with_context(mut self, context: Option<Coordinate>) -> Self {
        self.context = context;
        self
    }
}

pub(super) const fn is_zero(value: &u64) -> bool {
    *value == 0
}

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
    #[serde(skip_serializing_if = "Option::is_none")]
    event: Option<&'static str>,
    #[serde(flatten)]
    payload: OutputPayload<T>,
    diagnostics: Vec<Diagnostic>,
    #[serde(skip_serializing_if = "Option::is_none")]
    stats: Option<Stats>,
    #[serde(skip_serializing_if = "Option::is_none")]
    resources: Option<super::resources::Report>,
}

impl<T> Envelope<T> {
    pub fn success(command: Command, result: T, diagnostics: Vec<Diagnostic>) -> Self {
        Self {
            schema: SCHEMA_V6,
            command: Some(command),
            mode: Mode::Aggregate,
            sequence: None,
            event: None,
            payload: OutputPayload::Success { result },
            diagnostics,
            stats: None,
            resources: None,
        }
    }

    pub(super) fn record(
        command: Command,
        sequence: u64,
        event: &'static str,
        result: T,
        diagnostics: Vec<Diagnostic>,
    ) -> Self {
        Self {
            schema: SCHEMA_V6,
            command: Some(command),
            mode: Mode::Stream,
            sequence: Some(sequence),
            event: Some(event),
            payload: OutputPayload::Success { result },
            diagnostics,
            stats: None,
            resources: None,
        }
    }

    /// Adds explicitly requested resource metadata without changing default records.
    #[must_use]
    pub fn with_resources(mut self, resources: super::resources::Report) -> Self {
        self.resources = Some(resources);
        self
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
            schema: SCHEMA_V6,
            command,
            mode: Mode::Aggregate,
            sequence: None,
            event: None,
            payload: OutputPayload::Error { error },
            diagnostics: Vec::new(),
            stats: None,
            resources: None,
        }
    }

    pub(super) fn error_record(command: Option<Command>, sequence: u64, error: Error) -> Self {
        Self {
            schema: SCHEMA_V6,
            command,
            mode: Mode::Stream,
            sequence: Some(sequence),
            event: Some("error"),
            payload: OutputPayload::Error { error },
            diagnostics: Vec::new(),
            stats: None,
            resources: None,
        }
    }
}
