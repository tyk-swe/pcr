// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::test_support::Buffer;
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
    let bytes = output.0.lock().unwrap();
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
    assert_eq!(error.context, Some(Coordinate::Attempt(7)));
    // The externally tagged coordinate publishes exactly the one key the
    // output contract declares.
    let value = serde_json::to_value(&error).expect("error serializes");
    assert_eq!(
        value.get("context"),
        Some(&serde_json::json!({"attempt": 7}))
    );
}
