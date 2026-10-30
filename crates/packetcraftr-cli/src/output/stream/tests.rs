// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::record::serialize_line;
use super::*;
use crate::output::envelope::Published;
use std::{
    sync::{
        Condvar,
        atomic::{AtomicUsize, Ordering},
        mpsc,
    },
    time::Instant,
};

#[derive(Serialize)]
struct Data {
    value: usize,
}
impl StreamRecord for Data {
    fn event_name(&self) -> &'static str {
        "message"
    }
}

#[test]
fn complete_record_limit_includes_newline_and_serialization_failure_never_writes() {
    let value = serde_json::json!({"value": "abc"});
    let bytes = serde_json::to_vec(&value).unwrap();
    let exact = serialize_line(&value, 0, bytes.len() + 1, None).unwrap();
    assert_eq!(&exact[..bytes.len()], bytes);
    assert_eq!(exact.last(), Some(&b'\n'));
    assert!(matches!(
        serialize_line(&value, 0, bytes.len(), None),
        Err(EncodeError::RecordLimit { sequence: 0, .. })
    ));
    assert!(matches!(
        serialize_line(&value, 0, 0, None),
        Err(EncodeError::RecordLimit { .. })
    ));
}

struct PartialWriter {
    calls: Arc<AtomicUsize>,
    flushes: Arc<AtomicUsize>,
    prefix: Arc<Mutex<Vec<u8>>>,
}
impl Write for PartialWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.calls.fetch_add(1, Ordering::Relaxed) != 0 {
            return Err(io::Error::other("injected partial failure"));
        }
        let count = bytes.len().min(3);
        self.prefix
            .lock()
            .unwrap()
            .extend_from_slice(&bytes[..count]);
        Ok(count)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.flushes.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}

#[test]
fn failed_partial_write_is_terminally_failed_without_a_false_complete_or_later_flush() {
    let runtime = Runtime::new(1).unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let flushes = Arc::new(AtomicUsize::new(0));
    let prefix = Arc::new(Mutex::new(Vec::new()));
    let stream = StreamEncoder::new_bounded(
        Command::Http,
        PartialWriter {
            calls: Arc::clone(&calls),
            flushes: Arc::clone(&flushes),
            prefix: Arc::clone(&prefix),
        },
        &runtime,
        Duration::from_secs(5),
    )
    .unwrap();
    assert!(
        stream
            .emit_published(Published::new(Data { value: 1 }, Vec::new()))
            .is_err()
    );
    assert_eq!(prefix.lock().unwrap().len(), 3);
    assert_eq!(calls.load(Ordering::Relaxed), 2);
    assert_eq!(flushes.load(Ordering::Relaxed), 0);
    assert!(!stream.is_open());
    assert!(!stream.is_complete());
    assert!(matches!(
        stream.complete_published(Published::new((), Vec::new())),
        Err(EncodeError::Failed)
    ));
    assert_eq!(calls.load(Ordering::Relaxed), 2);
}

struct BlockedWriter {
    entered: mpsc::Sender<()>,
    release: Arc<(Mutex<bool>, Condvar)>,
    writes: Arc<AtomicUsize>,
    flushes: Arc<AtomicUsize>,
    published: Arc<Mutex<Vec<u8>>>,
}
impl Write for BlockedWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.writes.fetch_add(1, Ordering::Relaxed);
        self.entered.send(()).unwrap();
        let (released, changed) = self.release.as_ref();
        let mut released = released.lock().unwrap();
        while !*released {
            released = changed.wait(released).unwrap();
        }
        self.published.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        self.flushes.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}

#[test]
fn cancelled_bounded_writer_keeps_actual_work_charged_and_never_returns_complete() {
    let runtime = Runtime::new(1).unwrap();
    let (entered, writing) = mpsc::channel();
    let release = Arc::new((Mutex::new(false), Condvar::new()));
    let writes = Arc::new(AtomicUsize::new(0));
    let flushes = Arc::new(AtomicUsize::new(0));
    let cancellation = packetcraftr_core::budget::Cancellation::default();
    let parent =
        Deadline::new(Duration::from_secs(30)).with_cancellation(Some(cancellation.clone()));
    let control = Deadline::new(Duration::from_secs(30)).with_parent(Some(Arc::new(parent)));
    let stream = StreamEncoder::new_bounded(
        Command::Http,
        BlockedWriter {
            entered,
            release: Arc::clone(&release),
            writes: Arc::clone(&writes),
            flushes: Arc::clone(&flushes),
            published: Arc::default(),
        },
        &runtime,
        Duration::from_secs(30),
    )
    .unwrap()
    .with_deadline(Arc::new(control));
    let publishing = stream.clone();
    let (returned, result) = mpsc::channel();
    let caller = std::thread::spawn(move || {
        returned
            .send(
                publishing
                    .emit_published(Published::new(Data { value: 1 }, Vec::new()))
                    .is_err(),
            )
            .unwrap();
    });
    writing.recv_timeout(Duration::from_secs(5)).unwrap();
    cancellation.cancel();
    assert!(result.recv_timeout(Duration::from_secs(5)).unwrap());
    caller.join().unwrap();
    assert!(!stream.is_complete());
    assert!(!stream.is_open());
    assert!(
        stream
            .complete_published(Published::new((), Vec::new()))
            .is_err()
    );
    drop(stream);
    assert_eq!(runtime.snapshot().active, 1);
    assert_eq!(runtime.snapshot().timed_out_retaining_capacity, 1);
    *release.0.lock().unwrap() = true;
    release.1.notify_all();
    let guard = Instant::now() + Duration::from_secs(5);
    while runtime.snapshot().active != 0 {
        assert!(Instant::now() < guard);
        std::thread::yield_now();
    }
    assert_eq!(writes.load(Ordering::Relaxed), 1);
    assert_eq!(flushes.load(Ordering::Relaxed), 1);
}

#[test]
fn a_started_complete_write_can_finish_after_cancellation_without_acknowledging_success() {
    let runtime = Runtime::new(1).unwrap();
    let (entered, writing) = mpsc::channel();
    let release = Arc::new((Mutex::new(false), Condvar::new()));
    let writes = Arc::new(AtomicUsize::new(0));
    let flushes = Arc::new(AtomicUsize::new(0));
    let published = Arc::new(Mutex::new(Vec::new()));
    let cancellation = packetcraftr_core::budget::Cancellation::default();
    let stream = StreamEncoder::new_bounded(
        Command::Http,
        BlockedWriter {
            entered,
            release: Arc::clone(&release),
            writes: Arc::clone(&writes),
            flushes: Arc::clone(&flushes),
            published: Arc::clone(&published),
        },
        &runtime,
        Duration::from_secs(30),
    )
    .unwrap()
    .with_deadline(Arc::new(
        Deadline::new(Duration::from_secs(30)).with_cancellation(Some(cancellation.clone())),
    ));
    let publishing = stream.clone();
    let (returned, result) = mpsc::channel();
    let caller = std::thread::spawn(move || {
        returned
            .send(publishing.complete_published(Published::new((), Vec::new())))
            .unwrap();
    });
    writing.recv_timeout(Duration::from_secs(5)).unwrap();
    cancellation.cancel();
    assert!(
        result
            .recv_timeout(Duration::from_secs(5))
            .unwrap()
            .is_err()
    );
    caller.join().unwrap();
    assert!(!stream.is_complete());
    assert!(!stream.is_open());
    assert!(published.lock().unwrap().is_empty());
    drop(stream);
    assert_eq!(runtime.snapshot().active, 1);
    assert_eq!(runtime.snapshot().timed_out_retaining_capacity, 1);
    *release.0.lock().unwrap() = true;
    release.1.notify_all();
    let guard = Instant::now() + Duration::from_secs(5);
    while runtime.snapshot().active != 0 {
        assert!(Instant::now() < guard);
        std::thread::yield_now();
    }
    let bytes = published.lock().unwrap();
    let record: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(record["event"], "complete");
    assert_eq!(writes.load(Ordering::Relaxed), 1);
    assert_eq!(flushes.load(Ordering::Relaxed), 1);
}
