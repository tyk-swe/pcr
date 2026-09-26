// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::io::{self, Write};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use packetcraftr_core::budget::{Cancelled, Deadline, Interrupted};
use packetcraftr_core::error::BoundaryError;

use packetcraftr::progress::{Runtime, Sink};

use serde::Serialize;

use packetcraftr_core::diagnostic::Diagnostic as PacketDiagnostic;
use packetcraftr_core::error::{Classification, Classified, Kind};

use super::contract::Command;
use super::envelope::Envelope;
use super::envelope::Error;
use packetcraftr::Stats;

/// A data record declares its discriminator independently of its serialized
/// payload. The encoder supplies `complete` and `error` terminal records.
pub trait StreamRecord: Serialize {
    fn event_name(&self) -> &'static str;
}

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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EncoderState {
    Open,
    Complete,
    Error,
    Failed,
}

/// The whole encoder state, held under one mutex so a record is written, the
/// sequence advanced, and the state settled as one indivisible step.
struct EncoderOutput {
    state: EncoderState,
    sequence: u64,
    writer: EncoderWriter,
}

/// Bounded output retains its worker permit until the underlying write returns.
enum EncoderWriter {
    Direct(Box<dyn Write + Send>),
    Bounded {
        sink: Sink<Vec<u8>>,
        timeout: Duration,
    },
}

impl EncoderOutput {
    const fn require_open(&self) -> Result<(), EncodeError> {
        match self.state {
            EncoderState::Open => Ok(()),
            EncoderState::Complete | EncoderState::Error => Err(EncodeError::Terminal),
            EncoderState::Failed => Err(EncodeError::Failed),
        }
    }
}

/// The single owning encoder for one contiguous NDJSON invocation.
#[derive(Clone)]
pub struct StreamEncoder {
    deadline: Option<Arc<Deadline>>,
    command: Command,
    output: Arc<Mutex<EncoderOutput>>,
    resources: Option<Arc<dyn Fn() -> super::resources::Report + Send + Sync>>,
    terminal_error_timeout: Option<Duration>,
}

impl StreamEncoder {
    /// Applies an operation deadline to this publisher and its clones. Retain
    /// the original handle to report a terminal error after the deadline.
    /// Lock waiting and bounded writer waiting consume the remaining budget;
    /// synchronous serialization is checked on return and cannot be preempted.
    #[must_use]
    pub fn with_deadline(mut self, deadline: Arc<Deadline>) -> Self {
        self.deadline = Some(deadline);
        self
    }

    /// Samples resource metadata on the first and terminal records. The
    /// observer must return promptly; like serialization it is cooperative.
    #[must_use]
    pub fn with_resource_diagnostics(
        mut self,
        observe: impl Fn() -> super::resources::Report + Send + Sync + 'static,
    ) -> Self {
        self.resources = Some(Arc::new(observe));
        self
    }

    /// Selects a separate finite wait for terminal error cleanup. The default
    /// remains the timeout supplied to `new_bounded`.
    #[must_use]
    pub fn with_terminal_error_timeout(mut self, timeout: Duration) -> Self {
        self.terminal_error_timeout = Some(timeout);
        self
    }

    pub fn new(command: Command, writer: impl Write + Send + 'static) -> Self {
        Self {
            deadline: None,
            resources: None,
            terminal_error_timeout: None,
            command,
            output: Arc::new(Mutex::new(EncoderOutput {
                state: EncoderState::Open,
                sequence: 0,
                writer: EncoderWriter::Direct(Box::new(writer)),
            })),
        }
    }

    /// Opens a stream whose individual writes and flushes wait at most `timeout`.
    ///
    /// The writer occupies one callback worker in `runtime`, independently of
    /// any workflow event callback. On timeout the stream fails closed; the
    /// write may finish later and retains its worker permit until it returns.
    /// Serialization remains synchronous, as it is for [`Self::new`].
    pub fn new_bounded(
        command: Command,
        mut writer: impl Write + Send + 'static,
        runtime: &Runtime,
        timeout: Duration,
    ) -> Result<Self, BoundaryError> {
        let sink = Sink::new_in(runtime, move |line: Vec<u8>| {
            writer
                .write_all(&line)
                .and_then(|()| writer.flush())
                .map_err(|source| {
                    BoundaryError::with_source(
                        format!("write NDJSON output failed: {source}"),
                        Classification::new("io.stdout", Kind::Io, None),
                        Vec::new(),
                        source,
                    )
                })
        })?;
        Ok(Self {
            deadline: None,
            resources: None,
            terminal_error_timeout: None,
            command,
            output: Arc::new(Mutex::new(EncoderOutput {
                state: EncoderState::Open,
                sequence: 0,
                writer: EncoderWriter::Bounded { sink, timeout },
            })),
        })
    }

    pub fn emit_data<T: StreamRecord>(
        &self,
        result: T,
        diagnostics: Vec<PacketDiagnostic>,
    ) -> Result<(), EncodeError> {
        let event = result.event_name();
        if event.is_empty() || matches!(event, "complete" | "error") {
            return Err(EncodeError::ReservedEvent);
        }
        self.write_success(event, result, diagnostics, None, false)
    }

    pub fn complete<T: Serialize>(
        &self,
        result: T,
        diagnostics: Vec<PacketDiagnostic>,
    ) -> Result<(), EncodeError> {
        self.write_success("complete", result, diagnostics, None, true)
    }

    pub fn complete_with_stats<T: Serialize>(
        &self,
        result: T,
        diagnostics: Vec<PacketDiagnostic>,
        stats: Stats,
    ) -> Result<(), EncodeError> {
        self.write_success("complete", result, diagnostics, Some(stats), true)
    }

    pub fn emit_error(&self, error: Error) -> Result<(), EncodeError> {
        let mut output = self.lock_output()?;
        output.require_open()?;
        let sequence = output.sequence;
        let mut record = Envelope::error_record(Some(self.command), sequence, error);
        if let Some(observe) = &self.resources {
            record = record.with_resources(observe());
        }
        let line = serialize_line(&record, sequence)?;
        check_publication_budget(self.deadline.as_deref(), "serialization")?;
        write_line(
            &mut output,
            line,
            sequence,
            EncoderState::Error,
            self.deadline.as_deref(),
            self.terminal_error_timeout,
        )
    }

    /// Returns false while a record is being written or the state is poisoned.
    #[must_use]
    pub fn is_open(&self) -> bool {
        self.state() == Some(EncoderState::Open)
    }

    /// Returns true only after a terminal write and flush have finished.
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        matches!(
            self.state(),
            Some(EncoderState::Complete | EncoderState::Error)
        )
    }

    /// A completion acknowledgment is distinct from an emitted terminal error.
    pub fn is_complete(&self) -> bool {
        self.state() == Some(EncoderState::Complete)
    }

    fn write_success<T: Serialize>(
        &self,
        event: &'static str,
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
        let mut record = Envelope::record(self.command, sequence, event, result, diagnostics);
        if (sequence == 0 || terminal)
            && let Some(observe) = &self.resources
        {
            record = record.with_resources(observe());
        }
        if let Some(stats) = stats {
            record = record.with_stats(stats);
        }
        let line = serialize_line(&record, sequence)?;
        check_publication_budget(self.deadline.as_deref(), "serialization")?;
        write_line(
            &mut output,
            line,
            sequence,
            if terminal {
                EncoderState::Complete
            } else {
                EncoderState::Open
            },
            self.deadline.as_deref(),
            None,
        )?;
        if let Some(next) = next {
            output.sequence = next;
        }
        Ok(())
    }

    fn lock_output(&self) -> Result<std::sync::MutexGuard<'_, EncoderOutput>, EncodeError> {
        let output = if self.deadline.is_some() {
            loop {
                check_publication_budget(self.deadline.as_deref(), "lock")?;
                match self.output.try_lock() {
                    Ok(output) => break output,
                    Err(std::sync::TryLockError::Poisoned(_)) => return Err(EncodeError::Poisoned),
                    Err(std::sync::TryLockError::WouldBlock) => {
                        std::thread::sleep(Duration::from_millis(1));
                    }
                }
            }
        } else {
            self.output.lock().map_err(|_| EncodeError::Poisoned)?
        };
        Ok(output)
    }

    /// A busy or poisoned stream cannot safely accept a cleanup record.
    fn state(&self) -> Option<EncoderState> {
        self.output.try_lock().ok().map(|output| output.state)
    }
}

fn write_line(
    output: &mut EncoderOutput,
    line: Vec<u8>,
    sequence: u64,
    next_state: EncoderState,
    deadline: Option<&Deadline>,
    timeout_override: Option<Duration>,
) -> Result<(), EncodeError> {
    check_publication_budget(deadline, "publication")?;
    let written = match &mut output.writer {
        EncoderWriter::Direct(writer) => writer.write_all(&line).and_then(|()| writer.flush()),
        EncoderWriter::Bounded { sink, timeout } => {
            let timeout = timeout_override.unwrap_or(*timeout);
            let wait = match deadline {
                Some(deadline) => {
                    deadline
                        .for_wait(timeout)
                        .map_err(|source| EncodeError::Deadline {
                            phase: "publication",
                            source,
                        })?
                }
                None => Deadline::new(timeout),
            };
            sink.emit(line, &wait).map_err(io::Error::other)
        }
    };
    if let Err(source) = written {
        output.state = EncoderState::Failed;
        return Err(EncodeError::Write { sequence, source });
    }
    output.state = next_state;
    Ok(())
}

fn check_publication_budget(
    deadline: Option<&Deadline>,
    phase: &'static str,
) -> Result<(), EncodeError> {
    if let Some(deadline) = deadline {
        deadline
            .enforce()
            .map_err(|interrupted| match interrupted {
                Interrupted::Cancelled(cancelled) => EncodeError::Cancelled(cancelled),
                Interrupted::Exceeded(source) => EncodeError::Deadline { phase, source },
                _ => EncodeError::Cancelled(Cancelled),
            })?;
    }
    Ok(())
}

/// Maximum encoded NDJSON record bytes, including its newline. This bounds
/// serialization storage independently of frame limits and string/hex expansion.
pub const MAX_RECORD_BYTES: usize = 16 * 1024 * 1024;

fn serialize_line(record: &impl Serialize, sequence: u64) -> Result<Vec<u8>, EncodeError> {
    serialize_line_with_limit(record, sequence, MAX_RECORD_BYTES)
}

fn serialize_line_with_limit(
    record: &impl Serialize,
    sequence: u64,
    limit: usize,
) -> Result<Vec<u8>, EncodeError> {
    struct BoundedLine {
        bytes: Vec<u8>,
        limit: usize,
        exceeded: bool,
    }
    impl Write for BoundedLine {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if bytes.len() > self.limit.saturating_sub(self.bytes.len()) {
                self.exceeded = true;
                return Err(io::Error::other("NDJSON record byte ceiling exceeded"));
            }
            let required = self.bytes.len() + bytes.len();
            if required > self.bytes.capacity() {
                let capacity = required
                    .max(self.bytes.capacity().saturating_mul(2))
                    .min(self.limit);
                self.bytes
                    .try_reserve_exact(capacity - self.bytes.len())
                    .map_err(io::Error::other)?;
            }
            self.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut line = BoundedLine {
        bytes: Vec::new(),
        limit,
        exceeded: false,
    };
    let result = serde_json::to_writer(&mut line, record);
    if line.exceeded || limit == 0 {
        return Err(EncodeError::RecordLimit { sequence, limit });
    }
    result.map_err(|source| EncodeError::Serialize { sequence, source })?;
    if let Err(source) = line.write_all(b"\n") {
        if line.exceeded {
            return Err(EncodeError::RecordLimit { sequence, limit });
        }
        return Err(EncodeError::Serialize {
            sequence,
            source: serde_json::Error::io(source),
        });
    }
    Ok(line.bytes)
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum EncodeError {
    #[error("NDJSON {phase} exceeded the operation publication deadline: {source}")]
    Deadline {
        phase: &'static str,
        #[source]
        source: packetcraftr_core::budget::DeadlineExceeded,
    },
    #[error(transparent)]
    Cancelled(#[from] packetcraftr_core::budget::Cancelled),
    #[error(
        "NDJSON record at sequence {sequence} exceeds {limit} encoded bytes; operation is incomplete"
    )]
    RecordLimit { sequence: u64, limit: usize },
    #[error("data records must declare a nonterminal event kind")]
    ReservedEvent,
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
    #[error("NDJSON stream is incomplete: record at sequence {sequence} failed to write: {source}")]
    Write {
        sequence: u64,
        #[source]
        source: io::Error,
    },
}

impl Classified for EncodeError {
    fn classification(&self) -> Classification {
        match self {
            Self::Deadline { .. } => Classification::new(
                "io.output_deadline",
                Kind::Io,
                Some(
                    "treat the operation as incomplete; serialization and publication share the remaining duration budget",
                ),
            ),
            Self::Cancelled(source) => source.classification(),
            Self::RecordLimit { .. } => Classification::new(
                "io.output_record_limit",
                Kind::Io,
                Some(
                    "reduce record contents or select a smaller input; account for earlier records",
                ),
            ),
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
mod test_support;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod failure_boundaries;

#[cfg(test)]
mod trace_properties;

#[cfg(test)]
mod publication_budget_tests;

#[cfg(test)]
mod configurable_timeout_tests;
