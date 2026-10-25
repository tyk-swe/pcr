// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use crate::{
    invocation::Invocation,
    output::{
        contract::Command,
        resources::{Setting, Value},
        stream::StreamEncoder,
    },
    resources::{Diagnostics, Enabled},
};
use packetcraftr_core::budget::{Cancellation, Deadline};
use serde::{Serialize, Serializer};
use std::{
    io::{self, Write},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

#[derive(Clone, Default)]
struct Tape {
    bytes: Arc<Mutex<Vec<u8>>>,
    visible: Arc<Mutex<Vec<u8>>>,
}
impl Write for Tape {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.bytes.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        *self.visible.lock().unwrap() = self.bytes.lock().unwrap().clone();
        Ok(())
    }
}

struct Record {
    value: serde_json::Value,
    fail: bool,
}
impl Serialize for Record {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
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
fn record(value: &serde_json::Value) -> Record {
    Record {
        value: value.clone(),
        fail: false,
    }
}

#[test]
fn ndjson_application_enforces_result_budget_and_flushes_complete_records() {
    let tape = Tape::default();
    let invocation = invocation(StreamEncoder::new(Command::Http, tape.clone()));
    let value = serde_json::json!({"body": "quote\" newline\n slash\\ unicode🦀", "nested": [0, true, null]});
    let bytes = serde_json::to_vec(&value).unwrap().len();
    let mut output = EventOutput::new(&invocation, bytes * 64);
    let mut retained = Vec::new();
    for index in 0..64 {
        output
            .emit(record(&value), &mut retained, |_, _| {
                panic!("NDJSON called text renderer")
            })
            .unwrap();
        let visible = tape.visible.lock().unwrap();
        let lines: Vec<_> = visible.split_inclusive(|byte| *byte == b'\n').collect();
        assert_eq!(lines.len(), index + 1);
        for line in lines {
            assert_eq!(line.last(), Some(&b'\n'));
            let parsed: serde_json::Value = serde_json::from_slice(line).unwrap();
            assert_eq!(parsed["result"], value);
        }
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
        .emit(record(&value), &mut retained, |_, _| Ok(()))
        .unwrap_err();
    assert_eq!(failed.classification.kind, Kind::Policy);
    assert_eq!(*tape.bytes.lock().unwrap(), snapshot);
    invocation
        .output
        .complete(serde_json::json!({"messages": 64}), Vec::new())
        .unwrap();
    let visible = tape.visible.lock().unwrap();
    let terminal: serde_json::Value = serde_json::from_slice(
        visible
            .split(|byte| *byte == b'\n')
            .rfind(|line| !line.is_empty())
            .unwrap(),
    )
    .unwrap();
    assert_eq!(terminal["event"], "complete");
    assert_eq!(terminal["sequence"], 64);
    assert_eq!(terminal["result"], serde_json::json!({"messages": 64}));
    assert!(invocation.output.is_complete());
}

#[test]
fn budget_and_serialization_failures_write_no_prefix_and_allow_one_error_terminal() {
    for serialize_failure in [false, true] {
        let tape = Tape::default();
        let invocation = invocation(StreamEncoder::new(Command::Http, tape.clone()));
        let value = serde_json::json!({"body": "bounded"});
        let bytes = serde_json::to_vec(&value).unwrap().len();
        let mut output = EventOutput::new(&invocation, bytes - 1);
        let mut input = record(&value);
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
        assert!(tape.bytes.lock().unwrap().is_empty());
        assert!(tape.visible.lock().unwrap().is_empty());
        assert!(invocation.output.is_open());
        invocation
            .output
            .emit_error(failure.output_error())
            .unwrap();
        assert!(invocation.output.is_terminal());
        assert!(!invocation.output.is_complete());
        let terminal: serde_json::Value =
            serde_json::from_slice(&tape.visible.lock().unwrap()).unwrap();
        assert_eq!(terminal["event"], "error");
        assert!(
            invocation
                .output
                .emit_error(failure.output_error())
                .is_err()
        );
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
fn writer_failure_prevents_false_success_or_repair_terminal() {
    let invocation = invocation(StreamEncoder::new(Command::Http, FailedWriter));
    let value = serde_json::json!({"body": "hello"});
    let bytes = serde_json::to_vec(&value).unwrap().len();
    let mut output = EventOutput::new(&invocation, bytes);
    let failure = output
        .emit(record(&value), &mut Vec::new(), |_, _| Ok(()))
        .unwrap_err();
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
    assert!(tape.bytes.lock().unwrap().is_empty());
    invocation
        .terminal()
        .output
        .emit_error(error.output_error())
        .unwrap();
    let terminal: serde_json::Value =
        serde_json::from_slice(&tape.visible.lock().unwrap()).unwrap();
    assert_eq!(terminal["event"], "error");
    assert!(!invocation.output.is_complete());
}

fn stream_index_diagnostics() -> Arc<Diagnostics> {
    Arc::new(Diagnostics::new(vec![(
        Setting {
            name: "stream_index".to_owned(),
            value: Value::Number(1),
            unit: "count".to_owned(),
            stage: "operation".to_owned(),
            scope: "Test stream index setting".to_owned(),
            source: "default".to_owned(),
            enabled: true,
        },
        Enabled::StreamIndex,
    )]))
}

#[test]
fn diagnostics_observe_live_settings_on_initial_and_replacement_outputs() {
    for replace in [false, true] {
        for diagnostics in [Some(stream_index_diagnostics()), None] {
            let tape = Tape::default();
            let encoder = StreamEncoder::new(Command::Http, tape.clone());
            let invocation = if replace {
                Invocation::new(
                    Format::Ndjson,
                    StreamEncoder::new(Command::Http, io::sink()).into(),
                    None,
                    Cancellation::default(),
                    diagnostics.clone(),
                )
                .with_output(encoder.into())
            } else {
                Invocation::new(
                    Format::Ndjson,
                    encoder.into(),
                    None,
                    Cancellation::default(),
                    diagnostics.clone(),
                )
            };
            if diagnostics.is_some() {
                invocation
                    .output
                    .emit_data(record(&serde_json::json!({"index": 0})), Vec::new())
                    .unwrap();
                invocation.stream_index_needed(false);
            }
            invocation
                .output
                .complete(serde_json::json!({"done": true}), Vec::new())
                .unwrap();
            let lines: Vec<serde_json::Value> = tape
                .bytes
                .lock()
                .unwrap()
                .split(|byte| *byte == b'\n')
                .filter(|line| !line.is_empty())
                .map(|line| serde_json::from_slice(line).unwrap())
                .collect();
            match &diagnostics {
                Some(_) => {
                    assert_eq!(lines.len(), 2);
                    assert_eq!(
                        lines[0]["resources"]["settings"][0]["enabled"],
                        serde_json::json!(true)
                    );
                    assert_eq!(
                        lines[1]["resources"]["settings"][0]["enabled"],
                        serde_json::json!(false)
                    );
                }
                None => {
                    assert_eq!(lines.len(), 1);
                    assert!(lines[0].get("resources").is_none());
                }
            }
        }
    }
}

#[test]
fn preexisting_encoder_deadline_survives_initial_and_replacement_configuration() {
    for replace in [false, true] {
        let tape = Tape::default();
        let base = Instant::now();
        let elapsed = Arc::new(AtomicU64::new(0));
        let source = elapsed.clone();
        let encoder = StreamEncoder::new(Command::Http, tape.clone()).with_deadline(Arc::new(
            Deadline::with_time_source(Duration::from_secs(1), move || {
                base + Duration::from_secs(source.load(Ordering::Relaxed))
            }),
        ));
        let invocation = if replace {
            Invocation::new(
                Format::Ndjson,
                StreamEncoder::new(Command::Http, io::sink()).into(),
                Some(Duration::from_secs(3600)),
                Cancellation::default(),
                None,
            )
            .with_output(encoder.into())
        } else {
            Invocation::new(
                Format::Ndjson,
                encoder.into(),
                Some(Duration::from_secs(3600)),
                Cancellation::default(),
                None,
            )
        };
        elapsed.store(2, Ordering::Relaxed);
        assert!(
            invocation
                .output
                .complete(serde_json::json!({"done": true}), Vec::new())
                .is_err()
        );
        assert!(!invocation.output.is_complete());
        assert!(tape.bytes.lock().unwrap().is_empty());
    }
}
