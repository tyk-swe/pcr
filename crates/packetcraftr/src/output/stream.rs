// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Streaming NDJSON encoder and the unattributed error record.

use std::io::{self, Write};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use packetcraftr_core::budget::Deadline;
use packetcraftr_core::error::BoundaryError;

use crate::progress::{Runtime, Sink};

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
            command,
            output: Arc::new(Mutex::new(EncoderOutput {
                state: EncoderState::Open,
                sequence: 0,
                writer: EncoderWriter::Bounded { sink, timeout },
            })),
        })
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
        write_line(&mut output, line, sequence, true)
    }

    /// Returns false while a record is being written or the state is poisoned.
    #[must_use]
    pub fn is_open(&self) -> bool {
        self.state() == Some(EncoderState::Open)
    }

    /// Returns true only after a terminal write and flush have finished.
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
        write_line(&mut output, line, sequence, terminal)?;
        if let Some(next) = next {
            output.sequence = next;
        }
        Ok(())
    }

    fn lock_output(&self) -> Result<std::sync::MutexGuard<'_, EncoderOutput>, EncodeError> {
        self.output.lock().map_err(|_| EncodeError::Poisoned)
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
    terminal: bool,
) -> Result<(), EncodeError> {
    let written = match &mut output.writer {
        EncoderWriter::Direct(writer) => writer.write_all(&line).and_then(|()| writer.flush()),
        EncoderWriter::Bounded { sink, timeout } => sink
            .emit(line, &Deadline::new(*timeout))
            .map_err(|source| io::Error::other(format!("NDJSON stream is incomplete: {source}"))),
    };
    if let Err(source) = written {
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
    #![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        mpsc,
    };
    use std::time::Instant;

    use super::*;
    use packetcraftr_core::error::Coordinate;

    struct BlockedWriter {
        entered: mpsc::Sender<()>,
        release: mpsc::Receiver<()>,
        dropped: mpsc::Sender<()>,
        writes: Arc<AtomicUsize>,
    }

    impl Write for BlockedWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.writes.fetch_add(1, Ordering::SeqCst);
            self.entered.send(()).map_err(io::Error::other)?;
            self.release
                .recv_timeout(Duration::from_secs(3))
                .map_err(io::Error::other)?;
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl Drop for BlockedWriter {
        fn drop(&mut self) {
            let _ = self.dropped.send(());
        }
    }

    #[test]
    fn bounded_terminal_writes_fail_incomplete_without_retrying_or_releasing_the_worker() {
        for terminal_error in [false, true] {
            let (entered, writer_entered) = mpsc::channel();
            let (release, wait) = mpsc::channel();
            let (dropped, writer_dropped) = mpsc::channel();
            let writes = Arc::new(AtomicUsize::new(0));
            let runtime = Runtime::new(1);
            let stream = StreamEncoder::new_bounded(
                Command::Read,
                BlockedWriter {
                    entered,
                    release: wait,
                    dropped,
                    writes: Arc::clone(&writes),
                },
                &runtime,
                Duration::from_millis(50),
            )
            .unwrap();
            let started = Instant::now();
            let error = if terminal_error {
                stream.emit_error(Error::new(
                    Classification::new("io.fixture", Kind::Io, None),
                    "fixture failure".to_owned(),
                    Vec::new(),
                ))
            } else {
                stream.complete(serde_json::json!({"event": "complete"}), Vec::new())
            }
            .expect_err("terminal output is blocked");
            assert!(started.elapsed() < Duration::from_secs(1));
            assert!(error.to_string().contains("incomplete"));
            assert!(!stream.is_open());
            assert!(!stream.is_terminal());
            assert!(stream.complete((), Vec::new()).is_err());
            assert!(stream.emit_data((), Vec::new()).is_err());
            writer_entered.recv_timeout(Duration::from_secs(1)).unwrap();
            assert_eq!(writes.load(Ordering::SeqCst), 1);
            drop(stream);
            assert!(Sink::new_in(&runtime, |(): ()| Ok(())).is_err());
            release.send(()).unwrap();
            writer_dropped.recv_timeout(Duration::from_secs(1)).unwrap();
            let reclaimed = Instant::now();
            loop {
                if Sink::new_in(&runtime, |(): ()| Ok(())).is_ok() {
                    break;
                }
                assert!(reclaimed.elapsed() < Duration::from_secs(1));
                std::thread::yield_now();
            }
        }
    }

    #[test]
    fn bounded_output_keeps_sequences_contiguous_and_writes_one_terminal() {
        #[derive(Clone, Default)]
        struct Buffer(Arc<Mutex<Vec<u8>>>);
        impl Write for Buffer {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let output = Buffer::default();
        let stream = StreamEncoder::new_bounded(
            Command::Read,
            output.clone(),
            &Runtime::new(1),
            Duration::from_secs(1),
        )
        .unwrap();
        for frame in 0..3 {
            stream
                .emit_data(serde_json::json!({"frame": frame}), Vec::new())
                .unwrap();
        }
        stream
            .complete_with_stats(
                serde_json::json!({"event": "complete"}),
                Vec::new(),
                Stats::default(),
            )
            .unwrap();
        assert!(stream.is_terminal());
        assert!(stream.complete((), Vec::new()).is_err());
        let records: Vec<serde_json::Value> =
            serde_json::Deserializer::from_slice(&output.0.lock().unwrap())
                .into_iter()
                .collect::<Result<_, _>>()
                .unwrap();
        assert_eq!(records.len(), 4);
        for (sequence, record) in records.iter().enumerate() {
            assert_eq!(record["sequence"], sequence);
        }
        assert_eq!(
            records
                .iter()
                .filter(|record| record["result"]["event"] == "complete")
                .count(),
            1
        );
    }

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
