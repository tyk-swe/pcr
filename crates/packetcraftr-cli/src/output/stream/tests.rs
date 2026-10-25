// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::record::serialize_line_with_limit;
use super::*;
use std::{
    sync::{Condvar, mpsc},
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
fn complete_record_limit_includes_newline_and_zero_budget_is_refused() {
    let value = serde_json::json!({"value": "abc"});
    let bytes = serde_json::to_vec(&value).unwrap();
    let exact = serialize_line_with_limit(&value, 0, bytes.len() + 1).unwrap();
    assert_eq!(&exact[..bytes.len()], bytes);
    assert_eq!(exact.last(), Some(&b'\n'));
    assert!(matches!(
        serialize_line_with_limit(&value, 0, bytes.len()),
        Err(EncodeError::RecordLimit { sequence: 0, .. })
    ));
    assert!(matches!(
        serialize_line_with_limit(&value, 0, 0),
        Err(EncodeError::RecordLimit { .. })
    ));
}

struct PartialWriter {
    remaining: usize,
    refused: bool,
    prefix: Arc<Mutex<Vec<u8>>>,
    visible: Arc<Mutex<Vec<u8>>>,
}
impl Write for PartialWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.remaining == 0 && !self.refused {
            self.refused = true;
            return Err(io::Error::other("injected partial failure"));
        }
        let count = if self.refused {
            bytes.len()
        } else {
            bytes.len().min(self.remaining)
        };
        self.remaining = self.remaining.saturating_sub(count);
        self.prefix
            .lock()
            .unwrap()
            .extend_from_slice(&bytes[..count]);
        Ok(count)
    }
    fn flush(&mut self) -> io::Result<()> {
        *self.visible.lock().unwrap() = self.prefix.lock().unwrap().clone();
        Ok(())
    }
}

#[test]
fn failed_partial_write_is_terminally_failed_without_a_false_complete_or_later_flush() {
    let runtime = Runtime::new(1).unwrap();
    let prefix = Arc::new(Mutex::new(Vec::new()));
    let visible = Arc::new(Mutex::new(Vec::new()));
    let stream = StreamEncoder::new_bounded(
        Command::Http,
        PartialWriter {
            remaining: 3,
            refused: false,
            prefix: Arc::clone(&prefix),
            visible: Arc::clone(&visible),
        },
        &runtime,
        Duration::from_secs(5),
    )
    .unwrap();
    assert!(stream.emit_data(Data { value: 1 }, Vec::new()).is_err());
    let expected = serde_json::to_vec(&crate::output::envelope::Envelope::record(
        Command::Http,
        0,
        "message",
        Data { value: 1 },
        Vec::new(),
    ))
    .unwrap();
    assert_eq!(prefix.lock().unwrap().as_slice(), &expected[..3]);
    assert!(visible.lock().unwrap().is_empty());
    assert!(!stream.is_open());
    assert!(!stream.is_complete());
    assert!(matches!(
        stream.complete((), Vec::new()),
        Err(EncodeError::Failed)
    ));
    drop(stream);
    let worker = wait_for_worker(&runtime);
    assert_eq!(
        worker
            .emit(7, &Deadline::new(Duration::from_secs(5)))
            .unwrap(),
        7
    );
    assert_eq!(prefix.lock().unwrap().as_slice(), &expected[..3]);
    assert!(visible.lock().unwrap().is_empty());
}

struct BlockedWriter {
    entered: mpsc::Sender<()>,
    release: Arc<(Mutex<bool>, Condvar)>,
    published: Arc<Mutex<Vec<u8>>>,
    visible: Arc<Mutex<Vec<u8>>>,
}
impl Write for BlockedWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
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
        *self.visible.lock().unwrap() = self.published.lock().unwrap().clone();
        Ok(())
    }
}

fn wait_for_worker(runtime: &Runtime) -> Worker<usize, usize> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match Worker::new_in(runtime, Ok) {
            Ok(worker) => return worker,
            Err(_) => {
                assert!(
                    Instant::now() < deadline,
                    "writer admission did not recover"
                );
                std::thread::yield_now();
            }
        }
    }
}

#[test]
fn cancelled_bounded_writer_keeps_actual_work_charged_and_never_returns_complete() {
    let runtime = Runtime::new(1).unwrap();
    let (entered, writing) = mpsc::channel();
    let release = Arc::new((Mutex::new(false), Condvar::new()));
    let visible = Arc::new(Mutex::new(Vec::new()));
    let cancellation = packetcraftr_core::budget::Cancellation::default();
    let parent =
        Deadline::new(Duration::from_secs(30)).with_cancellation(Some(cancellation.clone()));
    let control = Deadline::new(Duration::from_secs(30)).with_parent(Some(Arc::new(parent)));
    let stream = StreamEncoder::new_bounded(
        Command::Http,
        BlockedWriter {
            entered,
            release: Arc::clone(&release),
            published: Arc::default(),
            visible: Arc::clone(&visible),
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
            .send(publishing.emit_data(Data { value: 1 }, Vec::new()).is_err())
            .unwrap();
    });
    writing.recv_timeout(Duration::from_secs(5)).unwrap();
    cancellation.cancel();
    assert!(result.recv_timeout(Duration::from_secs(5)).unwrap());
    caller.join().unwrap();
    assert!(!stream.is_complete());
    assert!(!stream.is_open());
    assert!(stream.complete((), Vec::new()).is_err());
    drop(stream);
    assert!(Worker::new_in(&runtime, |_: ()| Ok(())).is_err());
    *release.0.lock().unwrap() = true;
    release.1.notify_all();
    let worker = wait_for_worker(&runtime);
    assert_eq!(
        worker
            .emit(7, &Deadline::new(Duration::from_secs(5)))
            .unwrap(),
        7
    );
    let record: serde_json::Value = serde_json::from_slice(&visible.lock().unwrap()).unwrap();
    assert_eq!(record["event"], "message");
    assert_eq!(record["result"]["value"], 1);
}

#[test]
fn a_started_complete_write_can_finish_after_cancellation_without_acknowledging_success() {
    let runtime = Runtime::new(1).unwrap();
    let (entered, writing) = mpsc::channel();
    let release = Arc::new((Mutex::new(false), Condvar::new()));
    let published = Arc::new(Mutex::new(Vec::new()));
    let visible = Arc::new(Mutex::new(Vec::new()));
    let cancellation = packetcraftr_core::budget::Cancellation::default();
    let stream = StreamEncoder::new_bounded(
        Command::Http,
        BlockedWriter {
            entered,
            release: Arc::clone(&release),
            published: Arc::clone(&published),
            visible: Arc::clone(&visible),
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
        returned.send(publishing.complete((), Vec::new())).unwrap();
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
    assert!(Worker::new_in(&runtime, |_: ()| Ok(())).is_err());
    *release.0.lock().unwrap() = true;
    release.1.notify_all();
    let worker = wait_for_worker(&runtime);
    assert_eq!(
        worker
            .emit(9, &Deadline::new(Duration::from_secs(5)))
            .unwrap(),
        9
    );
    let bytes = visible.lock().unwrap();
    let record: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(record["event"], "complete");
}
