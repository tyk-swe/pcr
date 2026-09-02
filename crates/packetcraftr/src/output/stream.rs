// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Streaming NDJSON encoder and the unattributed error record.

use std::io::{self, Write};
use std::sync::{Arc, Mutex};

use serde::Serialize;

use packetcraftr_core::diagnostic::Diagnostic as PacketDiagnostic;
use packetcraftr_core::error::{Classification, Classified, Kind};

use super::contract::Command;
use super::envelope::{Envelope, Error, Stats};

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
    use packetcraftr_core::error::Coordinate;

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
