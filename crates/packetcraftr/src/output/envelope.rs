// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Aggregate JSON and streaming NDJSON envelopes.

use std::fmt;
use std::io::{self, Write};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::Serialize;

use packetcraftr_core::diagnostic::Diagnostic as PacketDiagnostic;
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

impl From<&packetcraftr_core::fuzz::Stats> for Stats {
    /// An offline campaign transmits nothing, so each generated case is the
    /// packet operation it attempted and each built case the one it completed.
    fn from(value: &packetcraftr_core::fuzz::Stats) -> Self {
        Self {
            packets_attempted: value.cases_generated,
            packets_completed: value.cases_built,
            bytes: value.bytes,
            elapsed: value.elapsed,
            capture: CaptureStats::default(),
        }
    }
}

pub use packetcraftr_core::diagnostic::Severity as DiagnosticSeverity;

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
}

impl From<PacketDiagnostic> for Diagnostic {
    fn from(value: PacketDiagnostic) -> Self {
        Self {
            code: value.code,
            severity: value.severity,
            message: value.message,
            layer: value.layer,
            field: value.field,
        }
    }
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
    #[serde(flatten)]
    payload: OutputPayload<T>,
    diagnostics: Vec<Diagnostic>,
    #[serde(skip_serializing_if = "Option::is_none")]
    stats: Option<Stats>,
}

impl<T> Envelope<T> {
    /// One aggregate JSON success.
    pub fn success(command: Command, result: T, diagnostics: Vec<PacketDiagnostic>) -> Self {
        Self {
            schema: SCHEMA_V1,
            command: Some(command),
            mode: Mode::Aggregate,
            sequence: None,
            payload: OutputPayload::Success { result },
            diagnostics: diagnostics.into_iter().map(Into::into).collect(),
            stats: None,
        }
    }

    /// One NDJSON success record at `sequence`.
    fn record(
        command: Command,
        sequence: u64,
        result: T,
        diagnostics: Vec<PacketDiagnostic>,
    ) -> Self {
        Self {
            schema: SCHEMA_V1,
            command: Some(command),
            mode: Mode::Stream,
            sequence: Some(sequence),
            payload: OutputPayload::Success { result },
            diagnostics: diagnostics.into_iter().map(Into::into).collect(),
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
    fn error_record(command: Option<Command>, sequence: u64, error: Error) -> Self {
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

/// The aggregate JSON envelope, named for the mode its constructors produce.
pub type Aggregate<T> = Envelope<T>;

/// Aggregate error envelope with no unused success-result type parameter.
pub type AggregateError = Envelope<()>;

/// Writes the single NDJSON error record a failure before command selection can
/// publish. Such a failure has no stream to join, so this record is the whole
/// document — which is why it, alone, may carry a null `command`.
pub fn write_unattributed_error(
    mut writer: impl Write,
    command: Option<Command>,
    error: Error,
) -> Result<(), EncodeError> {
    let line = serialize_line(&Envelope::error_record(command, 0, error), 0)?;
    writer
        .write_all(&line)
        .and_then(|()| writer.flush())
        .map_err(|source| EncodeError::Write {
            sequence: 0,
            source,
        })
}

/// Whether the stream may still be written to, and why not when it may not.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EncoderState {
    Open,
    Terminal,
    Failed,
}

/// The whole encoder state, held under one mutex so a record is written, the
/// sequence advanced, and the state settled as one indivisible step.
struct EncoderOutput {
    state: EncoderState,
    sequence: u64,
    writer: Box<dyn Write + Send>,
}

impl EncoderOutput {
    const fn require_open(&self) -> Result<(), EncodeError> {
        match self.state {
            EncoderState::Open => Ok(()),
            EncoderState::Terminal => Err(EncodeError::Terminal),
            EncoderState::Failed => Err(EncodeError::Failed),
        }
    }
}

/// The single owning encoder for one contiguous NDJSON invocation.
#[derive(Clone)]
pub struct StreamEncoder {
    command: Command,
    output: Arc<Mutex<EncoderOutput>>,
}

impl StreamEncoder {
    pub fn new(command: Command, writer: impl Write + Send + 'static) -> Self {
        Self {
            command,
            output: Arc::new(Mutex::new(EncoderOutput {
                state: EncoderState::Open,
                sequence: 0,
                writer: Box::new(writer),
            })),
        }
    }

    pub fn emit_data<T: Serialize>(
        &self,
        result: T,
        diagnostics: Vec<PacketDiagnostic>,
    ) -> Result<(), EncodeError> {
        self.write_success(result, diagnostics, None, false)
    }

    pub fn complete<T: Serialize>(
        &self,
        result: T,
        diagnostics: Vec<PacketDiagnostic>,
    ) -> Result<(), EncodeError> {
        self.write_success(result, diagnostics, None, true)
    }

    pub fn complete_with_stats<T: Serialize>(
        &self,
        result: T,
        diagnostics: Vec<PacketDiagnostic>,
        stats: Stats,
    ) -> Result<(), EncodeError> {
        self.write_success(result, diagnostics, Some(stats), true)
    }

    pub fn emit_error(&self, error: Error) -> Result<(), EncodeError> {
        let mut output = self.lock_output()?;
        output.require_open()?;
        let sequence = output.sequence;
        let record = Envelope::error_record(Some(self.command), sequence, error);
        let line = serialize_line(&record, sequence)?;
        write_line(&mut output, &line, sequence, true)
    }

    #[must_use]
    pub fn is_open(&self) -> bool {
        self.state() == Some(EncoderState::Open)
    }

    #[must_use]
    pub fn is_terminal(&self) -> bool {
        self.state() == Some(EncoderState::Terminal)
    }

    fn write_success<T: Serialize>(
        &self,
        result: T,
        diagnostics: Vec<PacketDiagnostic>,
        stats: Option<Stats>,
        terminal: bool,
    ) -> Result<(), EncodeError> {
        let mut output = self.lock_output()?;
        output.require_open()?;
        let sequence = output.sequence;
        let next = if terminal {
            None
        } else {
            Some(
                sequence
                    .checked_add(1)
                    .ok_or(EncodeError::SequenceOverflow)?,
            )
        };
        let mut record = Envelope::record(self.command, sequence, result, diagnostics);
        if let Some(stats) = stats {
            record = record.with_stats(stats);
        }
        let line = serialize_line(&record, sequence)?;
        write_line(&mut output, &line, sequence, terminal)?;
        if let Some(next) = next {
            output.sequence = next;
        }
        Ok(())
    }

    fn lock_output(&self) -> Result<std::sync::MutexGuard<'_, EncoderOutput>, EncodeError> {
        self.output.lock().map_err(|_| EncodeError::Poisoned)
    }

    /// `None` once the lock is poisoned: a stream whose state cannot be read is
    /// neither open nor cleanly terminated.
    fn state(&self) -> Option<EncoderState> {
        self.output.lock().ok().map(|output| output.state)
    }
}

fn write_line(
    output: &mut EncoderOutput,
    line: &[u8],
    sequence: u64,
    terminal: bool,
) -> Result<(), EncodeError> {
    if let Err(source) = output
        .writer
        .write_all(line)
        .and_then(|()| output.writer.flush())
    {
        output.state = EncoderState::Failed;
        return Err(EncodeError::Write { sequence, source });
    }
    output.state = if terminal {
        EncoderState::Terminal
    } else {
        EncoderState::Open
    };
    Ok(())
}

fn serialize_line(record: &impl Serialize, sequence: u64) -> Result<Vec<u8>, EncodeError> {
    let mut line =
        serde_json::to_vec(record).map_err(|source| EncodeError::Serialize { sequence, source })?;
    line.push(b'\n');
    Ok(line)
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum EncodeError {
    #[error("NDJSON stream is already terminated")]
    Terminal,
    #[error("NDJSON stream output has already failed")]
    Failed,
    #[error("NDJSON stream state lock was poisoned")]
    Poisoned,
    #[error("NDJSON sequence overflowed")]
    SequenceOverflow,
    #[error("NDJSON record at sequence {sequence} failed to serialize: {source}")]
    Serialize {
        sequence: u64,
        #[source]
        source: serde_json::Error,
    },
    #[error("NDJSON record at sequence {sequence} failed to write: {source}")]
    Write {
        sequence: u64,
        #[source]
        source: io::Error,
    },
}

impl Classified for EncodeError {
    fn classification(&self) -> Classification {
        match self {
            Self::Write { .. } => Classification::new(
                "io.stdout",
                Kind::Io,
                Some("inspect the output sink and account for records already written"),
            ),
            _ => Classification::new(
                "internal.ndjson_stream",
                Kind::Internal,
                Some("treat the structured stream as incomplete"),
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classified_error_includes_typed_context() {
        let source = packetcraftr_core::error::BoundaryError::new(
            "failed",
            Classification::new("fixture", Kind::Packet, None),
            Vec::new(),
        )
        .with_context(Some(Coordinate::Attempt(7)));
        let error = Error::classified(&source);
        assert_eq!(error.context, Some(Coordinate::Attempt(7)));
        // The externally tagged coordinate publishes exactly the one key the
        // output contract declares.
        let value = serde_json::to_value(&error).expect("error serializes");
        assert_eq!(
            value.get("context"),
            Some(&serde_json::json!({"attempt": 7}))
        );
    }
}
