// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use crate::{
    invocation::Invocation,
    output::{contract::Command, stream::StreamEncoder},
};
use packetcraftr_core::budget::{Cancellation, Deadline};
use serde::{Serialize, Serializer};
use std::{
    io::{self, Write},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

#[derive(Clone, Default)]
struct Tape {
    bytes: Arc<Mutex<Vec<u8>>>,
    writes: Arc<AtomicUsize>,
    flushes: Arc<AtomicUsize>,
}
impl Write for Tape {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.writes.fetch_add(1, Ordering::Relaxed);
        self.bytes.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        self.flushes.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}

struct Record {
    count: Arc<AtomicUsize>,
    value: serde_json::Value,
    fail: bool,
}
impl Serialize for Record {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.count.fetch_add(1, Ordering::Relaxed);
        if self.fail {
            return Err(serde::ser::Error::custom(
                "injected value serialization failure",
            ));
        }
        self.value.serialize(serializer)
    }
}
impl StreamRecord for Record {
    fn event_name(&self) -> &'static str {
        "message"
    }
}

fn invocation(encoder: StreamEncoder) -> Invocation {
    Invocation::new(
        Format::Ndjson,
        encoder.into(),
        None,
        Cancellation::default(),
        None,
    )
}
fn record(count: &Arc<AtomicUsize>, value: &serde_json::Value) -> Record {
    Record {
        count: Arc::clone(count),
        value: value.clone(),
        fail: false,
    }
}

#[test]
fn ndjson_application_serializes_once_and_charges_exact_result_bytes_with_line_visibility() {
    let tape = Tape::default();
    let invocation = invocation(StreamEncoder::new(Command::Http, tape.clone()));
    let count = Arc::new(AtomicUsize::new(0));
    let value = serde_json::json!({"body": "quote\" newline\n slash\\ unicode🦀", "nested": [0, true, null]});
    let bytes = serde_json::to_vec(&value).unwrap().len();
    let mut output = EventOutput::new(&invocation, bytes * 64);
    let mut retained = Vec::new();
    for index in 0..64 {
        output
            .emit(record(&count, &value), &mut retained, |_, _| {
                panic!("NDJSON called text renderer")
            })
            .unwrap();
        assert_eq!(count.load(Ordering::Relaxed), index + 1);
        assert_eq!(output.remaining, bytes * (63 - index));
        assert_eq!(tape.writes.load(Ordering::Relaxed), index + 1);
        assert_eq!(tape.flushes.load(Ordering::Relaxed), index + 1);
    }
    assert!(retained.is_empty());
    let snapshot = tape.bytes.lock().unwrap().clone();
    let lines: Vec<serde_json::Value> = snapshot
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice(line).unwrap())
        .collect();
    assert_eq!(lines.len(), 64);
    for (sequence, line) in lines.iter().enumerate() {
        assert_eq!(line["sequence"], sequence);
        assert_eq!(line["result"], value);
        assert!(serde_json::to_vec(line).unwrap().len() > bytes);
    }
    let failed = output
        .emit(record(&count, &value), &mut retained, |_, _| Ok(()))
        .unwrap_err();
    assert_eq!(failed.classification.kind, Kind::Policy);
    assert_eq!(*tape.bytes.lock().unwrap(), snapshot);
    assert_eq!(output.remaining, 0);
    invocation
        .output
        .complete(serde_json::json!({"messages": 64}), Vec::new())
        .unwrap();
    assert_eq!(tape.writes.load(Ordering::Relaxed), 65);
    assert_eq!(tape.flushes.load(Ordering::Relaxed), 65);
    assert!(invocation.output.is_complete());
}

#[test]
fn budget_and_serialization_failures_write_no_prefix_and_allow_one_error_terminal() {
    for serialize_failure in [false, true] {
        let tape = Tape::default();
        let invocation = invocation(StreamEncoder::new(Command::Http, tape.clone()));
        let count = Arc::new(AtomicUsize::new(0));
        let value = serde_json::json!({"body": "bounded"});
        let bytes = serde_json::to_vec(&value).unwrap().len();
        let mut output = EventOutput::new(&invocation, bytes - 1);
        let mut input = record(&count, &value);
        input.fail = serialize_failure;
        let failure = output
            .emit(input, &mut Vec::new(), |_, _| Ok(()))
            .unwrap_err();
        assert_eq!(
            failure.classification.kind,
            if serialize_failure {
                Kind::Internal
            } else {
                Kind::Policy
            }
        );
        assert_eq!(count.load(Ordering::Relaxed), 1);
        assert_eq!(output.remaining, bytes - 1);
        assert_eq!(tape.writes.load(Ordering::Relaxed), 0);
        assert_eq!(tape.flushes.load(Ordering::Relaxed), 0);
        assert!(invocation.output.is_open());
        invocation
            .output
            .emit_error(failure.output_error())
            .unwrap();
        assert!(invocation.output.is_terminal());
        assert!(!invocation.output.is_complete());
        assert_eq!(tape.writes.load(Ordering::Relaxed), 1);
    }
}

struct FailedWriter;
impl Write for FailedWriter {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        Err(io::Error::other("injected writer refusal"))
    }
    fn flush(&mut self) -> io::Result<()> {
        panic!("refused record must not flush")
    }
}

#[test]
fn writer_failure_keeps_exact_charge_and_prevents_false_success_or_repair_terminal() {
    let invocation = invocation(StreamEncoder::new(Command::Http, FailedWriter));
    let count = Arc::new(AtomicUsize::new(0));
    let value = serde_json::json!({"body": "hello"});
    let bytes = serde_json::to_vec(&value).unwrap().len();
    let mut output = EventOutput::new(&invocation, bytes);
    let failure = output
        .emit(record(&count, &value), &mut Vec::new(), |_, _| Ok(()))
        .unwrap_err();
    assert_eq!(count.load(Ordering::Relaxed), 1);
    assert_eq!(output.remaining, 0);
    assert_eq!(failure.classification.code, "io.stdout");
    assert!(!invocation.output.is_open());
    assert!(!invocation.output.is_complete());
    assert!(invocation.output.complete((), Vec::new()).is_err());
    assert!(
        invocation
            .output
            .emit_error(failure.output_error())
            .is_err()
    );
}

#[test]
fn cancellation_during_serialization_refuses_write_and_terminal_cleanup_remains_usable() {
    struct CancelValue {
        cancellation: Cancellation,
    }
    impl Serialize for CancelValue {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            self.cancellation.cancel();
            serializer.serialize_u8(7)
        }
    }
    impl StreamRecord for CancelValue {
        fn event_name(&self) -> &'static str {
            "message"
        }
    }
    let tape = Tape::default();
    let cancellation = Cancellation::default();
    let encoder = StreamEncoder::new(Command::Http, tape.clone()).with_deadline(Arc::new(
        Deadline::new(Duration::from_secs(5)).with_cancellation(Some(cancellation.clone())),
    ));
    let invocation = invocation(encoder);
    let mut output = EventOutput::new(&invocation, 1);
    let error = output
        .emit(CancelValue { cancellation }, &mut Vec::new(), |_, _| Ok(()))
        .unwrap_err();
    assert_eq!(error.classification.code, "io.cancelled");
    assert_eq!(tape.writes.load(Ordering::Relaxed), 0);
    invocation
        .terminal()
        .output
        .emit_error(error.output_error())
        .unwrap();
    assert_eq!(tape.writes.load(Ordering::Relaxed), 1);
    assert!(!invocation.output.is_complete());
}
