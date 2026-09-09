// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Streaming NDJSON encoder and the unattributed error record.

use std::io::{self, Write};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use packetcraftr_core::budget::{Deadline, Interrupted};
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

/// Whether the stream may still be written to, and why not when it may not.
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
                        std::thread::sleep(Duration::from_millis(1))
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
mod fixtures {
    use std::io::{self, Write};
    use std::sync::{Arc, Mutex};

    use serde::Serialize;

    use super::StreamRecord;

    /// Shared in-memory sink for encoder tests.
    #[derive(Clone, Default)]
    pub(super) struct Buffer(pub(super) Arc<Mutex<Vec<u8>>>);
    impl Write for Buffer {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// Minimal nonterminal record.
    #[derive(Serialize)]
    pub(super) struct Data;
    impl StreamRecord for Data {
        fn event_name(&self) -> &'static str {
            "frame"
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fixtures::Buffer;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        mpsc,
    };
    use std::time::Instant;

    use super::*;
    #[derive(Serialize)]
    #[serde(transparent)]
    struct TestRecord<T>(T);
    impl<T: Serialize> StreamRecord for TestRecord<T> {
        fn event_name(&self) -> &'static str {
            "frame"
        }
    }

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
            assert!(stream.emit_data(TestRecord(()), Vec::new()).is_err());
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
                .emit_data(TestRecord(serde_json::json!({"frame": frame})), Vec::new())
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
                .filter(|record| record["event"] == "complete")
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

#[cfg(test)]
mod failure_boundaries {
    use super::fixtures::Data;
    use super::*;

    #[test]
    fn serialized_limit_counts_escaping_and_newline_at_exact_boundaries() {
        let value = "\n\"";
        let expected = serde_json::to_vec(&value).unwrap().len() + 1;
        for limit in [expected - 1, expected, expected + 1] {
            let result = serialize_line_with_limit(&value, 7, limit);
            if limit < expected {
                assert!(matches!(
                    result,
                    Err(EncodeError::RecordLimit { sequence: 7, .. })
                ));
            } else {
                assert_eq!(result.unwrap().len(), expected);
            }
        }
    }

    struct FailAfter {
        remaining: usize,
        fail_flush: bool,
    }
    impl Write for FailAfter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.remaining == 0 {
                return Err(io::Error::other("injected byte failure"));
            }
            let count = self.remaining.min(bytes.len());
            self.remaining -= count;
            Ok(count)
        }
        fn flush(&mut self) -> io::Result<()> {
            if self.fail_flush {
                Err(io::Error::other("injected flush failure"))
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn every_partial_data_or_terminal_write_and_flush_failure_is_final() {
        for terminal in [false, true] {
            let envelope = Envelope::record(
                Command::Read,
                0,
                if terminal { "complete" } else { "frame" },
                (),
                Vec::new(),
            );
            let length = serialize_line(&envelope, 0).unwrap().len();
            for remaining in 0..=length {
                let stream = StreamEncoder::new(
                    Command::Read,
                    FailAfter {
                        remaining,
                        fail_flush: remaining == length,
                    },
                );
                let result = if terminal {
                    stream.complete((), Vec::new())
                } else {
                    stream.emit_data(Data, Vec::new())
                };
                assert!(matches!(
                    result,
                    Err(EncodeError::Write { sequence: 0, .. })
                ));
                assert!(!stream.is_open());
                assert!(!stream.is_complete());
                assert!(!stream.is_terminal());
                assert!(matches!(
                    stream.complete((), Vec::new()),
                    Err(EncodeError::Failed)
                ));
                assert!(matches!(
                    stream.emit_data(Data, Vec::new()),
                    Err(EncodeError::Failed)
                ));
            }
        }
    }
}

#[cfg(test)]
mod trace_properties {
    use super::fixtures::Buffer;
    use super::*;
    use proptest::prelude::*;

    #[derive(Serialize)]
    struct Data {
        value: u8,
    }
    impl StreamRecord for Data {
        fn event_name(&self) -> &'static str {
            "frame"
        }
    }

    proptest! {
        #[test]
        fn complete_invocation_traces_have_one_terminal_and_no_post_terminal_data(
            actions in proptest::collection::vec(0u8..4, 0..128),
            command in 0..Command::ALL.len(),
        ) {
            let command = Command::ALL[command];
            let buffer = Buffer::default();
            let stream = StreamEncoder::new(command, buffer.clone());
            let mut terminal = false;
            let mut count = 0;
            for action in actions {
                let result = match action {
                    0 | 1 => stream.emit_data(Data { value: action }, Vec::new()),
                    2 => stream.complete((), Vec::new()),
                    _ => stream.emit_error(Error::new(Classification::new("io.fixture", Kind::Io, None), "fixture".to_owned(), Vec::new())),
                };
                if terminal { prop_assert!(matches!(result, Err(EncodeError::Terminal))); }
                else {
                    prop_assert!(result.is_ok());
                    count += 1;
                    terminal = action >= 2;
                }
            }
            if !terminal { stream.complete((), Vec::new()).unwrap(); count += 1; }
            let bytes = buffer.0.lock().unwrap();
            prop_assert_eq!(bytes.last(), Some(&b'\n'));
            let records: Vec<serde_json::Value> = serde_json::Deserializer::from_slice(&bytes).into_iter().collect::<Result<_, _>>().unwrap();
            prop_assert_eq!(records.len(), count);
            for (sequence, record) in records.iter().enumerate() {
                prop_assert_eq!(record["sequence"].as_u64(), Some(sequence as u64));
                prop_assert_eq!(&record["schema"], "packetcraftr.output/v3");
                prop_assert_eq!(&record["command"], command.as_str());
                let terminal = matches!(record["event"].as_str(), Some("complete" | "error"));
                prop_assert_eq!(terminal, sequence + 1 == records.len());
            }
        }
    }
}

#[cfg(test)]
mod publication_budget_tests {
    use super::fixtures::{Buffer, Data};
    use super::*;
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        mpsc,
    };
    use std::time::Instant;

    struct SpendDuringSerialization(Arc<AtomicBool>);
    impl Serialize for SpendDuringSerialization {
        fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            self.0.store(true, Ordering::Release);
            serializer.serialize_unit()
        }
    }
    impl StreamRecord for SpendDuringSerialization {
        fn event_name(&self) -> &'static str {
            "frame"
        }
    }

    #[test]
    fn serialization_that_spends_the_budget_is_not_published_and_can_report_an_error() {
        let spent = Arc::new(AtomicBool::new(false));
        let observed = spent.clone();
        let now = Instant::now();
        let deadline = Deadline::with_time_source(Duration::from_secs(1), move || {
            if observed.load(Ordering::Acquire) {
                now + Duration::from_secs(2)
            } else {
                now
            }
        });
        let buffer = Buffer::default();
        let owner = StreamEncoder::new(Command::Read, buffer.clone());
        let publisher = owner.clone().with_deadline(Arc::new(deadline));
        let error = publisher
            .emit_data(SpendDuringSerialization(spent), Vec::new())
            .unwrap_err();
        assert!(matches!(
            error,
            EncodeError::Deadline {
                phase: "serialization",
                ..
            }
        ));
        assert!(buffer.0.lock().unwrap().is_empty());
        owner
            .emit_error(Error::new(
                error.classification(),
                error.to_string(),
                Vec::new(),
            ))
            .unwrap();
        let record: serde_json::Value = serde_json::from_slice(&buffer.0.lock().unwrap()).unwrap();
        assert_eq!(record["sequence"], 0);
        assert_eq!(record["event"], "error");
        assert!(!owner.is_complete());
    }

    #[test]
    fn an_operation_deadline_bounds_waiting_for_the_encoder_lock() {
        let owner = StreamEncoder::new(Command::Read, io::sink());
        let publisher = owner
            .clone()
            .with_deadline(Arc::new(Deadline::new(Duration::from_millis(25))));
        let guard = owner.output.lock().unwrap();
        let (send, receive) = mpsc::channel();
        let worker =
            std::thread::spawn(move || send.send(publisher.emit_data(Data, Vec::new())).unwrap());
        let result = receive.recv_timeout(Duration::from_secs(2));
        drop(guard);
        worker.join().unwrap();
        assert!(matches!(
            result.unwrap(),
            Err(EncodeError::Deadline { phase: "lock", .. })
        ));
        assert!(owner.is_open());
    }

    struct Blocked {
        entered: mpsc::Sender<()>,
        release: mpsc::Receiver<()>,
    }
    impl Write for Blocked {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.entered.send(()).unwrap();
            self.release.recv().unwrap();
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    #[test]
    fn writer_wait_uses_remaining_operation_budget_and_retains_cleanup_capacity() {
        let runtime = Runtime::new(1);
        let (entered, waiting) = mpsc::channel();
        let (release, released) = mpsc::channel();
        let owner = StreamEncoder::new_bounded(
            Command::Read,
            Blocked {
                entered,
                release: released,
            },
            &runtime,
            Duration::from_secs(30),
        )
        .unwrap();
        let now = Instant::now();
        let publisher = owner
            .clone()
            .with_deadline(Arc::new(Deadline::with_time_source(
                Duration::from_millis(25),
                move || now,
            )));
        let (send, receive) = mpsc::channel();
        let worker =
            std::thread::spawn(move || send.send(publisher.emit_data(Data, Vec::new())).unwrap());
        let entered = waiting.recv_timeout(Duration::from_secs(2));
        let result = receive.recv_timeout(Duration::from_secs(2));
        let retained = runtime.snapshot().active;
        release.send(()).unwrap();
        worker.join().unwrap();
        entered.unwrap();
        assert!(matches!(result.unwrap(), Err(EncodeError::Write { .. })));
        assert_eq!(
            retained, 1,
            "a deadline never releases a still-blocked writer"
        );
        assert!(!owner.is_open());
        assert!(!owner.is_complete());
    }
}

#[cfg(test)]
mod configurable_timeout_tests {
    use super::fixtures::Data;
    use super::*;
    use std::sync::mpsc;

    struct WaitingWriter(mpsc::Sender<()>, mpsc::Receiver<()>);
    impl Write for WaitingWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.send(()).unwrap();
            self.1
                .recv_timeout(Duration::from_secs(3))
                .map_err(io::Error::other)?;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    #[test]
    fn extended_wait_accepts_a_slow_writer_and_cleanup_uses_its_own_ceiling() {
        let runtime = Runtime::new(1);
        let (entered, waiting) = mpsc::channel();
        let (release, released) = mpsc::channel();
        let stream = StreamEncoder::new_bounded(
            Command::Read,
            WaitingWriter(entered, released),
            &runtime,
            Duration::from_secs(2),
        )
        .unwrap()
        .with_terminal_error_timeout(Duration::from_millis(10));
        let publisher = stream.clone();
        let worker = std::thread::spawn(move || publisher.emit_data(Data, Vec::new()));
        waiting.recv_timeout(Duration::from_secs(2)).unwrap();
        // Coordinate release rather than asserting wall-time performance.
        release.send(()).unwrap();
        worker.join().unwrap().unwrap();
        let result = stream.emit_error(Error::new(
            Classification::new("io.fixture", Kind::Io, None),
            "stop",
            Vec::new(),
        ));
        assert!(matches!(
            result,
            Err(EncodeError::Write { sequence: 1, .. })
        ));
        assert_eq!(runtime.snapshot().timed_out_retaining_capacity, 1);
        release.send(()).unwrap();
        assert!(!stream.is_complete());
    }
}
