// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    mpsc,
};
use std::time::Instant;

use packetcraftr_core::error::Coordinate;
use proptest::{prop_assert, prop_assert_eq, proptest};

use super::*;
use crate::test_support::{SharedBuffer, TestRecord};

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
        assert!(Worker::<()>::new_in(&runtime, |(): ()| Ok(())).is_err());
        release.send(()).unwrap();
        writer_dropped.recv_timeout(Duration::from_secs(1)).unwrap();
        let reclaimed = Instant::now();
        loop {
            if Worker::<()>::new_in(&runtime, |(): ()| Ok(())).is_ok() {
                break;
            }
            assert!(reclaimed.elapsed() < Duration::from_secs(1));
            std::thread::yield_now();
        }
    }
}

#[test]
fn bounded_output_keeps_sequences_contiguous_and_writes_one_terminal() {
    let output = SharedBuffer::default();
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
    let bytes = output.bytes();
    assert_eq!(bytes.last(), Some(&b'\n'));
    let records: Vec<serde_json::Value> = std::str::from_utf8(&bytes)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
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
    assert_eq!(
        error.context,
        Some(crate::output::envelope::ErrorContext::Attempt(7))
    );
    // The externally tagged coordinate publishes exactly the one key the
    // output contract declares.
    let value = serde_json::to_value(&error).expect("error serializes");
    assert_eq!(
        value.get("context"),
        Some(&serde_json::json!({"attempt": 7}))
    );
}

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
                stream.emit_data(TestRecord(()), Vec::new())
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
                stream.emit_data(TestRecord(()), Vec::new()),
                Err(EncodeError::Failed)
            ));
        }
    }
}

#[derive(Serialize)]
struct Valued {
    value: u8,
}
impl StreamRecord for Valued {
    fn event_name(&self) -> &'static str {
        "frame"
    }
}

fn fixture_error() -> Error {
    Error::new(
        Classification::new("io.fixture", Kind::Io, None),
        "fixture".to_owned(),
        Vec::new(),
    )
}

proptest! {
    #[test]
    fn complete_invocation_traces_have_one_terminal_and_no_post_terminal_data(
        actions in proptest::collection::vec(0u8..4, 0..128),
        command in 0..Command::ALL.len(),
    ) {
        let command = Command::ALL[command];
        let buffer = SharedBuffer::default();
        let stream = StreamEncoder::new(command, buffer.clone());
        let mut terminal = false;
        let mut count = 0;
        for action in actions {
            let result = match action {
                0 | 1 => stream.emit_data(Valued { value: action }, Vec::new()),
                2 => stream.complete((), Vec::new()),
                _ => stream.emit_error(fixture_error()),
            };
            if terminal {
                prop_assert!(matches!(result, Err(EncodeError::Terminal)));
            } else {
                prop_assert!(result.is_ok());
                count += 1;
                terminal = action >= 2;
            }
        }
        if !terminal {
            stream.complete((), Vec::new()).unwrap();
            count += 1;
        }
        let bytes = buffer.bytes();
        prop_assert_eq!(bytes.last(), Some(&b'\n'));
        // Physical NDJSON framing: one complete JSON value per line. A
        // streaming deserializer would also accept concatenated values or a
        // record spread across lines, so parse line-wise instead.
        let text = std::str::from_utf8(&bytes).unwrap();
        let records: Vec<serde_json::Value> = text
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        prop_assert_eq!(records.len(), count);
        for (sequence, record) in records.iter().enumerate() {
            prop_assert_eq!(record["sequence"].as_u64(), Some(sequence as u64));
            prop_assert_eq!(&record["schema"], "packetcraftr.output/v6");
            prop_assert_eq!(&record["command"], command.as_str());
            let terminal = matches!(record["event"].as_str(), Some("complete" | "error"));
            prop_assert_eq!(terminal, sequence + 1 == records.len());
        }
    }
}

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
    let buffer = SharedBuffer::default();
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
    assert!(buffer.bytes().is_empty());
    owner
        .emit_error(Error::new(
            error.classification(),
            error.to_string(),
            Vec::new(),
        ))
        .unwrap();
    let record: serde_json::Value = serde_json::from_slice(&buffer.bytes()).unwrap();
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
    let worker = std::thread::spawn(move || {
        send.send(publisher.emit_data(TestRecord(()), Vec::new()))
            .unwrap();
    });
    let result = receive.recv_timeout(Duration::from_secs(2));
    drop(guard);
    worker.join().unwrap();
    assert!(matches!(
        result.unwrap(),
        Err(EncodeError::Deadline { phase: "lock", .. })
    ));
    assert!(owner.is_open());
}

/// Generous bound on the fixture's release wait so a broken test fails
/// instead of blocking the writer worker forever; far above the millisecond
/// production deadline under test.
const RELEASE_WATCHDOG: Duration = Duration::from_secs(30);

struct Blocked {
    entered: mpsc::Sender<()>,
    release: mpsc::Receiver<()>,
    expired: Arc<AtomicBool>,
}
impl Write for Blocked {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.entered.send(()).unwrap();
        if self.release.recv_timeout(RELEASE_WATCHDOG).is_err() {
            self.expired.store(true, Ordering::Release);
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "Blocked fixture release watchdog expired",
            ));
        }
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
    let expired = Arc::new(AtomicBool::new(false));
    let owner = StreamEncoder::new_bounded(
        Command::Read,
        Blocked {
            entered,
            release: released,
            expired: expired.clone(),
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
    let worker = std::thread::spawn(move || {
        send.send(publisher.emit_data(TestRecord(()), Vec::new()))
            .unwrap();
    });
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
    assert!(
        !expired.load(Ordering::Acquire),
        "the release watchdog fired; the test never released the writer"
    );
    assert!(!owner.is_open());
    assert!(!owner.is_complete());
}

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
    let worker = std::thread::spawn(move || publisher.emit_data(TestRecord(()), Vec::new()));
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
