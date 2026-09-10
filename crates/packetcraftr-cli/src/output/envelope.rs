// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Aggregate JSON and streaming NDJSON envelopes.

use packetcraftr::Stats;

use std::fmt;

use serde::Serialize;

use packetcraftr_core::error::{Classification, Classified, Coordinate, Kind};

use super::contract::{Command, Mode, SCHEMA_V4};

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

/// The one `skip_serializing_if` predicate for counters the contract omits
/// when they are zero.
pub(super) const fn is_zero(value: &u64) -> bool {
    *value == 0
}

use packetcraftr_core::diagnostic::Diagnostic;

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
    /// One aggregate JSON success.
    pub fn success(command: Command, result: T, diagnostics: Vec<Diagnostic>) -> Self {
        Self {
            schema: SCHEMA_V4,
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

    /// One NDJSON success record at `sequence`.
    pub(super) fn record(
        command: Command,
        sequence: u64,
        event: &'static str,
        result: T,
        diagnostics: Vec<Diagnostic>,
    ) -> Self {
        Self {
            schema: SCHEMA_V4,
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
            schema: SCHEMA_V4,
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

    /// One terminal NDJSON error record at `sequence`.
    pub(super) fn error_record(command: Option<Command>, sequence: u64, error: Error) -> Self {
        Self {
            schema: SCHEMA_V4,
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
