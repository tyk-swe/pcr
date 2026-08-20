// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Aggregate JSON and streaming NDJSON envelopes.

use std::fmt;
use std::io::{self, Write};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::Serialize;

use packetcraftr_core::diagnostic::Diagnostic as PacketDiagnostic;
use packetcraftr_core::error::{Classification, Classified, Context, Kind};

use super::contract::{Command, Mode, SCHEMA_V1};

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Error {
    pub code: String,
    pub kind: Kind,
    pub message: String,
    pub causes: Vec<String>,
    #[serde(skip_serializing_if = "Context::is_empty")]
    pub context: Context,
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
            context: Context::default(),
            remediation: classification.remediation.map(str::to_owned),
        }
    }

    pub fn classified(error: &(impl Classified + fmt::Display)) -> Self {
        Self::new(error.classification(), error.to_string(), error.causes())
            .with_context(error.context())
    }

    #[must_use]
    pub const fn with_context(mut self, context: Context) -> Self {
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

    #[must_use]
    pub fn with_stats(mut self, stats: Stats) -> Self {
        self.stats = Some(stats);
        self
    }
}

impl Aggregate<()> {
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
}

/// Aggregate error envelope with no unused success-result type parameter.
pub type AggregateError = Aggregate<()>;

/// One independently valid NDJSON success or terminal-error record.
#[derive(Clone, Debug, Serialize)]
struct Stream<T> {
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
    fn success(
        command: Command,
        sequence: u64,
        result: T,
        diagnostics: Vec<PacketDiagnostic>,
    ) -> Self {
        Self {
            schema: SCHEMA_V1,
            command: Some(command),
            mode: Mode::Stream,
            sequence,
            payload: OutputPayload::Success { result },
            diagnostics: diagnostics.into_iter().map(Into::into).collect(),
            stats: None,
        }
    }

    fn error(command: Option<Command>, sequence: u64, error: Error) -> Self {
        Self {
            schema: SCHEMA_V1,
            command,
            mode: Mode::Stream,
            sequence,
            payload: OutputPayload::Error { error },
            diagnostics: Vec::new(),
            stats: None,
        }
    }

    #[must_use]
    fn with_stats(mut self, stats: Stats) -> Self {
        self.stats = Some(stats);
        self
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
enum EncoderState {
    Open,
    Writing,
    Terminal,
    Failed,
}

impl EncoderState {
    fn from_u8(value: u8) -> Self {
        match value {
            0 => Self::Open,
            1 => Self::Writing,
            2 => Self::Terminal,
            _ => Self::Failed,
        }
    }
}

struct EncoderOutput {
    sequence: u64,
    writer: Box<dyn Write + Send>,
}

struct EncoderShared {
    command: Option<Command>,
    state: AtomicU8,
    output: Mutex<EncoderOutput>,
}

/// The single owning encoder for one contiguous NDJSON invocation.
#[derive(Clone)]
pub struct StreamEncoder {
    shared: Arc<EncoderShared>,
}

impl StreamEncoder {
    pub fn new(command: Option<Command>, writer: impl Write + Send + 'static) -> Self {
        Self {
            shared: Arc::new(EncoderShared {
                command,
                state: AtomicU8::new(EncoderState::Open as u8),
                output: Mutex::new(EncoderOutput {
                    sequence: 0,
                    writer: Box::new(writer),
                }),
            }),
        }
    }

    pub fn emit_data<T: Serialize>(
        &self,
        result: T,
        diagnostics: Vec<PacketDiagnostic>,
    ) -> Result<(), EncodeError> {
        let command = self.shared.command.ok_or(EncodeError::MissingCommand)?;
        self.write_success(command, result, diagnostics, None, false)
    }

    pub fn complete<T: Serialize>(
        &self,
        result: T,
        diagnostics: Vec<PacketDiagnostic>,
    ) -> Result<(), EncodeError> {
        let command = self.shared.command.ok_or(EncodeError::MissingCommand)?;
        self.write_success(command, result, diagnostics, None, true)
    }

    pub fn complete_with_stats<T: Serialize>(
        &self,
        result: T,
        diagnostics: Vec<PacketDiagnostic>,
        stats: Stats,
    ) -> Result<(), EncodeError> {
        let command = self.shared.command.ok_or(EncodeError::MissingCommand)?;
        self.write_success(command, result, diagnostics, Some(stats), true)
    }

    pub fn emit_error(&self, error: Error) -> Result<(), EncodeError> {
        let mut output = self.lock_output()?;
        self.require_open()?;
        let sequence = output.sequence;
        let record: Stream<()> = Stream::error(self.shared.command, sequence, error);
        let line = serialize_line(&record, sequence)?;
        self.write_line(&mut output, &line, sequence, true)
    }

    #[must_use]
    pub fn is_open(&self) -> bool {
        self.state() == EncoderState::Open
    }

    #[must_use]
    pub fn is_terminal(&self) -> bool {
        self.state() == EncoderState::Terminal
    }

    #[must_use]
    pub fn is_failed(&self) -> bool {
        matches!(self.state(), EncoderState::Writing | EncoderState::Failed)
    }

    #[must_use]
    pub fn next_sequence(&self) -> Option<u64> {
        if !self.is_open() {
            return None;
        }
        self.shared.output.lock().ok().map(|output| output.sequence)
    }

    fn write_success<T: Serialize>(
        &self,
        command: Command,
        result: T,
        diagnostics: Vec<PacketDiagnostic>,
        stats: Option<Stats>,
        terminal: bool,
    ) -> Result<(), EncodeError> {
        let mut output = self.lock_output()?;
        self.require_open()?;
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
        let mut record = Stream::success(command, sequence, result, diagnostics);
        if let Some(stats) = stats {
            record = record.with_stats(stats);
        }
        let line = serialize_line(&record, sequence)?;
        self.write_line(&mut output, &line, sequence, terminal)?;
        if let Some(next) = next {
            output.sequence = next;
        }
        Ok(())
    }

    fn write_line(
        &self,
        output: &mut EncoderOutput,
        line: &[u8],
        sequence: u64,
        terminal: bool,
    ) -> Result<(), EncodeError> {
        self.set_state(EncoderState::Writing);
        if let Err(source) = output
            .writer
            .write_all(line)
            .and_then(|()| output.writer.flush())
        {
            self.set_state(EncoderState::Failed);
            return Err(EncodeError::Write { sequence, source });
        }
        self.set_state(if terminal {
            EncoderState::Terminal
        } else {
            EncoderState::Open
        });
        Ok(())
    }

    fn lock_output(&self) -> Result<std::sync::MutexGuard<'_, EncoderOutput>, EncodeError> {
        self.shared.output.lock().map_err(|_| EncodeError::Poisoned)
    }

    fn require_open(&self) -> Result<(), EncodeError> {
        match self.state() {
            EncoderState::Open => Ok(()),
            EncoderState::Writing => Err(EncodeError::Writing),
            EncoderState::Terminal => Err(EncodeError::Terminal),
            EncoderState::Failed => Err(EncodeError::Failed),
        }
    }

    fn state(&self) -> EncoderState {
        EncoderState::from_u8(self.shared.state.load(Ordering::Acquire))
    }

    fn set_state(&self, state: EncoderState) {
        self.shared.state.store(state as u8, Ordering::Release);
    }
}

fn serialize_line(record: &impl Serialize, sequence: u64) -> Result<Vec<u8>, EncodeError> {
    let mut line =
        serde_json::to_vec(record).map_err(|source| EncodeError::Serialize { sequence, source })?;
    line.push(b'\n');
    Ok(line)
}

#[derive(Debug, thiserror::Error)]
pub enum EncodeError {
    #[error("NDJSON success record has no command")]
    MissingCommand,
    #[error("NDJSON stream is writing a record")]
    Writing,
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

    fn causes(&self) -> Vec<String> {
        match self {
            Self::Serialize { source, .. } => vec![source.to_string()],
            Self::Write { source, .. } => vec![source.to_string()],
            _ => Vec::new(),
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
        .with_context(Context::attempt(7));
        assert_eq!(Error::classified(&source).context.attempt, Some(7));
    }
}
