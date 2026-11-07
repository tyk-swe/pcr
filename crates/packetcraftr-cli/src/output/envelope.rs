// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::fmt;

use serde::Serialize;

use packetcraftr_core::diagnostic::Diagnostic as RuntimeDiagnostic;
use packetcraftr_core::error::{Classification, Classified, Coordinate};

use super::contract::{Command, Mode, SCHEMA};

published_enum! {
    pub enum Kind from packetcraftr_core::error::Kind {
        Usage => "usage",
        Packet => "packet",
        Capability => "capability",
        Io => "io",
        Policy => "policy",
        Internal => "internal",
    }
}

published_enum! {
    pub enum Severity from packetcraftr_core::diagnostic::Severity {
        Info => "info",
        Warning => "warning",
        Error => "error",
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Diagnostic {
    pub code: &'static str,
    pub severity: Severity,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub layer: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field: Option<&'static str>,
}
impl From<packetcraftr_core::diagnostic::Diagnostic> for Diagnostic {
    fn from(value: packetcraftr_core::diagnostic::Diagnostic) -> Self {
        Self {
            code: value.code,
            severity: value.severity.into(),
            message: value.message,
            layer: value.layer,
            field: value.field,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Stats {
    pub packets_attempted: u64,
    pub packets_completed: u64,
    pub bytes: u64,
    pub elapsed: std::time::Duration,
    pub capture: super::capture::Stats,
}

impl From<packetcraftr::Stats> for Stats {
    fn from(value: packetcraftr::Stats) -> Self {
        Self {
            packets_attempted: value.packets_attempted,
            packets_completed: value.packets_completed,
            bytes: value.bytes,
            elapsed: value.elapsed,
            capture: value.capture.into(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum ErrorContext {
    #[serde(rename = "source_frame")]
    SourceFrame(u64),
    #[serde(rename = "probe_sequence")]
    ProbeSequence(u64),
    #[serde(rename = "attempt")]
    Attempt(u32),
    #[serde(rename = "case_index")]
    CaseIndex(u64),
}

impl TryFrom<Coordinate> for ErrorContext {
    type Error = Coordinate;

    fn try_from(coordinate: Coordinate) -> Result<Self, Coordinate> {
        match coordinate {
            Coordinate::SourceFrame(frame) => Ok(Self::SourceFrame(frame)),
            Coordinate::ProbeSequence(sequence) => Ok(Self::ProbeSequence(sequence)),
            Coordinate::Attempt(attempt) => Ok(Self::Attempt(attempt)),
            Coordinate::CaseIndex(index) => Ok(Self::CaseIndex(index)),
            unpublished => Err(unpublished),
        }
    }
}

/// The causes an [`Error`] records for `source`: its own message, then
/// every source beneath it.
pub(crate) fn source_causes(source: &(impl std::error::Error + ?Sized)) -> Vec<String> {
    std::iter::once(source.to_string())
        .chain(packetcraftr_core::error::source_chain(source))
        .collect()
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Error {
    pub code: String,
    pub kind: Kind,
    pub message: String,
    pub causes: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<ErrorContext>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capture: Option<Box<super::capture::Snapshot>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scan: Option<Box<super::scan_failure::Failure>>,
}

impl Error {
    pub fn new(
        classification: Classification,
        message: impl Into<String>,
        causes: Vec<String>,
    ) -> Self {
        Self {
            code: classification.code.as_str().to_owned(),
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
    pub fn with_scan(mut self, scan: Option<Box<super::scan_failure::Failure>>) -> Self {
        self.scan = scan;
        self
    }

    #[must_use]
    pub fn with_context(mut self, context: Option<Coordinate>) -> Self {
        self.context = context.and_then(|coordinate| ErrorContext::try_from(coordinate).ok());
        self
    }
}

#[derive(Clone, Debug)]
pub struct Published<T> {
    pub result: T,
    pub diagnostics: Vec<RuntimeDiagnostic>,
    pub stats: Option<packetcraftr::Stats>,
}

impl<T> Published<T> {
    pub(crate) fn new(result: T, diagnostics: Vec<RuntimeDiagnostic>) -> Self {
        Self {
            result,
            diagnostics,
            stats: None,
        }
    }

    #[must_use]
    pub(crate) fn with_stats(mut self, stats: packetcraftr::Stats) -> Self {
        self.stats = Some(stats);
        self
    }
}

pub(crate) const fn is_zero(value: &u64) -> bool {
    *value == 0
}

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum OutputPayload<T> {
    Success { result: T },
    Error { error: Error },
}

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
    pub fn published(command: Command, published: Published<T>) -> Self {
        let Published {
            result,
            diagnostics,
            stats,
        } = published;
        Self {
            schema: SCHEMA,
            command: Some(command),
            mode: Mode::Aggregate,
            sequence: None,
            event: None,
            payload: OutputPayload::Success { result },
            diagnostics: diagnostics.into_iter().map(Into::into).collect(),
            stats: stats.map(Into::into),
            resources: None,
        }
    }

    pub(super) fn record(
        command: Command,
        sequence: u64,
        event: &'static str,
        result: T,
        diagnostics: Vec<RuntimeDiagnostic>,
    ) -> Self {
        Self {
            schema: SCHEMA,
            command: Some(command),
            mode: Mode::Stream,
            sequence: Some(sequence),
            event: Some(event),
            payload: OutputPayload::Success { result },
            diagnostics: diagnostics.into_iter().map(Into::into).collect(),
            stats: None,
            resources: None,
        }
    }

    #[must_use]
    pub fn with_resources(mut self, resources: super::resources::Report) -> Self {
        self.resources = Some(resources);
        self
    }

    #[must_use]
    pub fn with_stats(mut self, stats: packetcraftr::Stats) -> Self {
        self.stats = Some(stats.into());
        self
    }
}

impl Envelope<()> {
    pub fn error(command: Option<Command>, error: Error) -> Self {
        Self {
            schema: SCHEMA,
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
            schema: SCHEMA,
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

#[cfg(test)]
mod tests {
    use super::*;
    use packetcraftr_core::{diagnostic, error::Code};
    use serde_json::json;

    #[test]
    fn envelope_maps_runtime_diagnostics_statistics_and_error_kind() {
        let diagnostic = RuntimeDiagnostic {
            code: "output.test",
            severity: diagnostic::Severity::Warning,
            message: "bounded output".into(),
            layer: Some(2),
            field: None,
        };
        let published = Published::new(json!({ "ready": true }), vec![diagnostic]).with_stats(
            packetcraftr::Stats {
                packets_attempted: 3,
                packets_completed: 2,
                bytes: 27,
                elapsed: std::time::Duration::new(1, 2),
                ..packetcraftr::Stats::default()
            },
        );
        let value = serde_json::to_value(Envelope::published(Command::Send, published)).unwrap();
        assert_eq!(
            value["diagnostics"],
            json!([{ "code": "output.test", "severity": "warning", "message": "bounded output", "layer": 2 }])
        );
        assert_eq!(value["stats"]["packets_attempted"], 3);
        assert_eq!(value["stats"]["packets_completed"], 2);
        assert_eq!(value["stats"]["bytes"], 27);
        assert_eq!(value["stats"]["elapsed"], json!({ "secs": 1, "nanos": 2 }));
        let classification = Classification::new(
            Code::CliSendLimit,
            packetcraftr_core::error::Kind::Usage,
            None,
        );
        let error = serde_json::to_value(Error::new(classification, "invalid options", Vec::new()))
            .unwrap();
        assert_eq!(error["kind"], "usage");
        assert_eq!(error["code"], Code::CliSendLimit.as_str());
    }
}
