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

#[derive(Clone)]
struct RecordingWriter(Arc<Mutex<Vec<u8>>>);

impl Write for RecordingWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[derive(Serialize)]
struct NamedData(&'static str);

impl StreamRecord for NamedData {
    fn event_name(&self) -> &'static str {
        self.0
    }
}

#[test]
fn unattributed_encoder_refuses_records_but_reports_errors() {
    let writer = RecordingWriter(Arc::default());
    let stream = StreamEncoder::unattributed(writer.clone());
    let refused = stream.emit_published(Published::new(NamedData("sample"), Vec::new()));
    assert!(matches!(refused, Err(EncodeError::Unattributed)));
    assert!(writer.0.lock().unwrap().is_empty());
    assert!(stream.is_open());
    stream
        .emit_error(Error::new(
            Classification::new(packetcraftr_core::error::Code::IoStdout, Kind::Io, None),
            "startup failed",
            Vec::new(),
        ))
        .unwrap();
    let written = writer.0.lock().unwrap().clone();
    let record: serde_json::Value = serde_json::from_slice(&written).unwrap();
    assert_eq!(record["event"], "error");
    assert!(
        record.get("command").is_none_or(serde_json::Value::is_null),
        "unattributed error must not borrow a command identity: {record}"
    );
}

#[test]
fn reserved_events_preserve_budget_and_sequence() {
    for counted in [false, true] {
        let writer = RecordingWriter(Arc::default());
        let stream = StreamEncoder::new(Command::Http, writer.clone());
        let budget = 1024;
        let mut remaining = budget;
        for event in ["", "complete", "error"] {
            let result = if counted {
                stream.emit_data_counted(NamedData(event), Vec::new(), &mut remaining)
            } else {
                stream
                    .emit_published(Published::new(NamedData(event), Vec::new()))
                    .map_err(MeteredError::Encode)
            };
            assert!(matches!(
                result,
                Err(MeteredError::Encode(EncodeError::ReservedEvent))
            ));
            assert_eq!(remaining, budget);
            assert!(writer.0.lock().unwrap().is_empty());
            assert!(stream.is_open());
        }
        if counted {
            stream
                .emit_data_counted(NamedData("message"), Vec::new(), &mut remaining)
                .unwrap();
            assert_eq!(
                budget - remaining,
                serde_json::to_vec(&NamedData("message")).unwrap().len()
            );
        } else {
            stream
                .emit_published(Published::new(NamedData("message"), Vec::new()))
                .unwrap();
        }
        stream
            .complete_published(Published::new((), Vec::new()))
            .unwrap();
        assert!(stream.is_complete());
        let bytes = writer.0.lock().unwrap().clone();
        let records: Vec<serde_json::Value> = serde_json::Deserializer::from_slice(&bytes)
            .into_iter()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0]["sequence"], 0);
        assert_eq!(records[0]["event"], "message");
        assert_eq!(records[1]["sequence"], 1);
        assert_eq!(records[1]["event"], "complete");
        assert!(matches!(
            stream.emit_published(Published::new(NamedData("complete"), Vec::new())),
            Err(EncodeError::ReservedEvent)
        ));
        assert!(matches!(
            stream.emit_data_counted(NamedData("error"), Vec::new(), &mut remaining),
            Err(MeteredError::Encode(EncodeError::ReservedEvent))
        ));
        assert_eq!(*writer.0.lock().unwrap(), bytes);
    }
}

#[test]
fn record_limit_includes_newline() {
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
fn partial_write_failure_is_terminal() {
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
fn cancelled_writer_charges_work_without_completion() {
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
fn cancelled_write_cannot_acknowledge_success() {
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

#[derive(Clone, Default)]
struct CountingWriter {
    published: Arc<Mutex<Vec<u8>>>,
    writes: Arc<AtomicUsize>,
}

impl Write for CountingWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.writes.fetch_add(1, Ordering::Relaxed);
        self.published.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn bounded_stream(runtime: &Runtime, writer: CountingWriter) -> StreamEncoder {
    StreamEncoder::new_bounded(Command::Http, writer, runtime, Duration::from_secs(5)).unwrap()
}

fn emit_records(stream: &StreamEncoder, count: usize) {
    for value in 0..count {
        stream
            .emit_published(Published::new(Data { value }, Vec::new()))
            .unwrap();
    }
}

#[test]
fn regular_file_records_match_the_unbatched_stream_through_either_terminal() {
    let terminals: [fn(&StreamEncoder); 2] = [
        |stream| {
            stream
                .complete_published(Published::new((), Vec::new()))
                .unwrap();
        },
        |stream| {
            stream
                .emit_error(Error::new(
                    Classification::new(packetcraftr_core::error::Code::IoStdout, Kind::Io, None),
                    "stopped",
                    Vec::new(),
                ))
                .unwrap();
        },
    ];
    for terminal in terminals {
        for count in [0, 3, 2000] {
            let runtime = Runtime::new(2).unwrap();
            let unbatched = CountingWriter::default();
            let stream = bounded_stream(&runtime, unbatched.clone());
            emit_records(&stream, count);
            terminal(&stream);
            drop(stream);

            let batched = CountingWriter::default();
            let stream = bounded_stream(&runtime, batched.clone());
            stream.observe_input(true);
            emit_records(&stream, count);
            terminal(&stream);
            drop(stream);

            assert_eq!(
                *batched.published.lock().unwrap(),
                *unbatched.published.lock().unwrap()
            );
        }
    }
}

#[test]
fn expired_batch_admission_preserves_accepted_records_for_terminal_error() {
    for complete in [false, true] {
        let runtime = Runtime::new(1).unwrap();
        let writer = CountingWriter::default();
        let stream = bounded_stream(&runtime, writer.clone());
        stream.observe_input(true);
        emit_records(&stream, 3);
        assert!(writer.published.lock().unwrap().is_empty());

        let now = Instant::now();
        let stream = stream.with_deadline(Arc::new(Deadline::with_time_source(
            Duration::ZERO,
            move || now,
        )));
        let result = if complete {
            stream.complete_published(Published::new((), Vec::new()))
        } else {
            stream.observe_input(false);
            stream.emit_published(Published::new(Data { value: 3 }, Vec::new()))
        };
        assert!(matches!(
            result,
            Err(EncodeError::Deadline {
                phase: "publication",
                ..
            })
        ));
        assert!(stream.is_open());
        stream
            .terminal()
            .emit_error(Error::new(
                Classification::new(
                    packetcraftr_core::error::Code::IoOutputDeadline,
                    Kind::Io,
                    None,
                ),
                "stopped",
                Vec::new(),
            ))
            .unwrap();

        let bytes = writer.published.lock().unwrap();
        let records: Vec<serde_json::Value> = serde_json::Deserializer::from_slice(&bytes)
            .into_iter()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(records.len(), 4);
        for (sequence, record) in records.iter().enumerate() {
            assert_eq!(record["sequence"], sequence);
            if sequence < 3 {
                assert_eq!(record["event"], "message");
                assert_eq!(record["result"]["value"], sequence);
            } else {
                assert_eq!(record["event"], "error");
            }
        }
    }
}

#[test]
fn regular_file_records_coalesce_their_writes() {
    let runtime = Runtime::new(1).unwrap();
    let writer = CountingWriter::default();
    let stream = bounded_stream(&runtime, writer.clone());
    stream.observe_input(true);
    emit_records(&stream, 2000);
    stream
        .complete_published(Published::new((), Vec::new()))
        .unwrap();
    assert!(writer.writes.load(Ordering::Relaxed) < 100);
}

#[test]
fn any_stalling_input_publishes_each_record_at_once() {
    for inputs in [&[false][..], &[true, false], &[false, true]] {
        let runtime = Runtime::new(1).unwrap();
        let writer = CountingWriter::default();
        let stream = bounded_stream(&runtime, writer.clone());
        for regular_file in inputs {
            stream.observe_input(*regular_file);
        }
        emit_records(&stream, 1);
        assert!(!writer.published.lock().unwrap().is_empty());
        drop(stream);
    }
}

#[test]
fn stalled_consumer_still_fails_within_the_write_timeout_when_batching() {
    let runtime = Runtime::new(1).unwrap();
    let (entered, _writing) = mpsc::channel();
    let release = Arc::new((Mutex::new(false), Condvar::new()));
    let stream = StreamEncoder::new_bounded(
        Command::Http,
        BlockedWriter {
            entered,
            release: Arc::clone(&release),
            writes: Arc::default(),
            flushes: Arc::default(),
            published: Arc::default(),
        },
        &runtime,
        Duration::from_millis(50),
    )
    .unwrap();
    stream.observe_input(true);
    let failed = (0..BATCH_BYTES).any(|value| {
        stream
            .emit_published(Published::new(Data { value }, Vec::new()))
            .is_err()
    });
    assert!(failed);
    assert!(!stream.is_open());
    *release.0.lock().unwrap() = true;
    release.1.notify_all();
}
