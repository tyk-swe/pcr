// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::io::{self, Write};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use packetcraftr_core::budget::{Cancelled, Deadline, Interrupted};
use packetcraftr_core::error::BoundaryError;

use packetcraftr::runtime::{Runtime, Worker};

use serde::Serialize;

use packetcraftr_core::diagnostic::Diagnostic as PacketDiagnostic;
use packetcraftr_core::error::{Classification, Kind};

use super::contract::Command;
use super::envelope::{Envelope, Error, Published, source_causes};

mod error;
mod record;

pub use error::EncodeError;
pub use record::MAX_RECORD_BYTES;
pub(crate) use record::MeteredError;
use record::{Counted, ResultMeter, serialize_line};

pub trait StreamRecord: Serialize {
    fn event_name(&self) -> &'static str;
}

pub fn write_unattributed_error(
    mut writer: impl Write,
    command: Option<Command>,
    error: Error,
) -> Result<(), EncodeError> {
    let line = serialize_line(
        &Envelope::error_record(command, 0, error),
        0,
        crate::output::stream::MAX_RECORD_BYTES,
        None,
    )?;
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

struct EncoderOutput {
    state: EncoderState,
    sequence: u64,
    writer: EncoderWriter,
}

enum EncoderWriter {
    Direct(Box<dyn Write + Send>),
    Bounded {
        sink: Worker<Vec<u8>>,
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

#[derive(Clone)]
pub struct StreamEncoder {
    deadline: Option<Arc<Deadline>>,
    command: Command,
    output: Arc<Mutex<EncoderOutput>>,
    resources: Option<Arc<dyn Fn() -> super::resources::Report + Send + Sync>>,
    terminal_error_timeout: Option<Duration>,
}

impl StreamEncoder {
    /// Terminal error cleanup keeps the writer timeout but releases the execution ceiling.
    pub(crate) fn terminal(mut self) -> Self {
        self.deadline = None;
        self
    }

    #[must_use]
    pub fn with_deadline(mut self, deadline: Arc<Deadline>) -> Self {
        self.deadline = Some(deadline);
        self
    }

    pub(crate) fn with_control(mut self, control: Arc<Deadline>) -> Self {
        self.deadline = Some(Arc::new(
            Deadline::new(Duration::MAX)
                .with_parent(self.deadline.clone())
                .with_parent(Some(control)),
        ));
        self
    }

    #[must_use]
    pub fn with_resource_diagnostics(
        mut self,
        observe: impl Fn() -> super::resources::Report + Send + Sync + 'static,
    ) -> Self {
        self.resources = Some(Arc::new(observe));
        self
    }

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

    pub fn new_bounded(
        command: Command,
        mut writer: impl Write + Send + 'static,
        runtime: &Runtime,
        timeout: Duration,
    ) -> Result<Self, BoundaryError> {
        let sink = Worker::new_in(runtime, move |line: Vec<u8>| {
            writer
                .write_all(&line)
                .and_then(|()| writer.flush())
                .map_err(|source| {
                    BoundaryError::with_source(
                        "write NDJSON output failed",
                        Classification::new("io.stdout", Kind::Io, None),
                        source_causes(&source),
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

    /// Trusted CLI emitters may run cooperatively only when writes are already
    /// isolated behind this encoder's bounded writer.
    pub(crate) fn isolates_writes(&self) -> bool {
        self.output
            .try_lock()
            .is_ok_and(|output| matches!(output.writer, EncoderWriter::Bounded { .. }))
    }

    pub(crate) fn emit_data_counted<T: StreamRecord>(
        &self,
        result: T,
        diagnostics: Vec<PacketDiagnostic>,
        remaining: &mut usize,
    ) -> Result<(), MeteredError> {
        let event = result.event_name();
        if event.is_empty() || matches!(event, "complete" | "error") {
            return Err(MeteredError::Encode(EncodeError::ReservedEvent));
        }
        let meter = ResultMeter::new(*remaining);
        let outcome = self.write_success(
            event,
            Published::new(result, diagnostics),
            false,
            Some((&meter, remaining)),
        );
        if meter.exceeded.get() {
            Err(MeteredError::Limit)
        } else {
            outcome.map_err(|error| match error {
                EncodeError::Serialize { source, .. }
                    if meter.value_failed.get() && !source.is_io() =>
                {
                    MeteredError::Serialize(source)
                }
                error => MeteredError::Encode(error),
            })
        }
    }

    pub fn emit_published<T: StreamRecord>(
        &self,
        published: Published<T>,
    ) -> Result<(), EncodeError> {
        let event = published.result.event_name();
        if event.is_empty() || matches!(event, "complete" | "error") {
            return Err(EncodeError::ReservedEvent);
        }
        self.write_success(event, published, false, None)
    }

    pub fn complete_published<T: Serialize>(
        &self,
        published: Published<T>,
    ) -> Result<(), EncodeError> {
        self.write_success("complete", published, true, None)
    }

    pub fn emit_error(&self, error: Error) -> Result<(), EncodeError> {
        let mut output = self.lock_output()?;
        output.require_open()?;
        let sequence = output.sequence;
        let mut record = Envelope::error_record(Some(self.command), sequence, error);
        if let Some(observe) = &self.resources {
            record = record.with_resources(observe());
        }
        let line = serialize_line(
            &record,
            sequence,
            crate::output::stream::MAX_RECORD_BYTES,
            None,
        )?;
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

    #[must_use]
    pub fn is_open(&self) -> bool {
        self.state() == Some(EncoderState::Open)
    }

    #[must_use]
    pub fn is_terminal(&self) -> bool {
        matches!(
            self.state(),
            Some(EncoderState::Complete | EncoderState::Error)
        )
    }

    pub fn is_complete(&self) -> bool {
        self.state() == Some(EncoderState::Complete)
    }

    fn write_success<T: Serialize>(
        &self,
        event: &'static str,
        published: Published<T>,
        terminal: bool,
        budget: Option<(&ResultMeter, &mut usize)>,
    ) -> Result<(), EncodeError> {
        let Published {
            result,
            diagnostics,
            stats,
        } = published;
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
        let meter = budget.as_ref().map(|(meter, _)| *meter);
        let result = Counted {
            value: result,
            meter,
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
        let line = serialize_line(&record, sequence, MAX_RECORD_BYTES, meter)?;
        if let Some((meter, remaining)) = budget {
            *remaining -= meter.bytes.get();
        }
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

#[cfg(test)]
mod tests;
