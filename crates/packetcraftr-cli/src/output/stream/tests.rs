// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
#![allow(dead_code)]

use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    mpsc,
};
use std::time::Instant;

use super::*;
use crate::test_support::TestRecord;

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
        let runtime = Runtime::new(1).unwrap();
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
