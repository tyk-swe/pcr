// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::cell::RefCell;
use std::io;
use std::rc::Rc;

use packetcraftr::output;
use serde_json::{Value, json};

use crate::errors::CliError;
use crate::rendering::NdjsonStream;
use crate::rendering::ndjson_test_support::{assert_contiguous, stream};

struct Fixture {
    command: output::contract::Command,
    event: Value,
    complete: Value,
}

fn result(document: &str) -> Value {
    serde_json::from_str::<Value>(document).expect("published example must parse")["result"].clone()
}

fn fixtures() -> Vec<Fixture> {
    vec![
        Fixture {
            command: output::contract::Command::Read,
            event: result(include_str!(
                "../../../examples/documents/output-read-event.json"
            )),
            complete: result(include_str!(
                "../../../examples/documents/output-read-complete.json"
            )),
        },
        Fixture {
            command: output::contract::Command::Capture,
            event: result(include_str!(
                "../../../examples/documents/output-capture-event.json"
            )),
            complete: result(include_str!(
                "../../../examples/documents/output-capture-complete.json"
            )),
        },
        Fixture {
            command: output::contract::Command::Replay,
            event: result(include_str!(
                "../../../examples/documents/output-replay-event.json"
            )),
            complete: result(include_str!(
                "../../../examples/documents/output-replay-success.json"
            )),
        },
        Fixture {
            command: output::contract::Command::Follow,
            event: result(include_str!(
                "../../../examples/documents/output-follow-event.json"
            )),
            complete: result(include_str!(
                "../../../examples/documents/output-follow-complete.json"
            )),
        },
        Fixture {
            command: output::contract::Command::Expert,
            event: result(include_str!(
                "../../../examples/documents/output-expert-event.json"
            )),
            complete: result(include_str!(
                "../../../examples/documents/output-expert-success.json"
            )),
        },
        Fixture {
            command: output::contract::Command::Scan,
            event: result(include_str!(
                "../../../examples/documents/output-scan-event.json"
            )),
            complete: result(include_str!(
                "../../../examples/documents/output-scan-complete.json"
            )),
        },
        Fixture {
            command: output::contract::Command::Traceroute,
            event: result(include_str!(
                "../../../examples/documents/output-traceroute-event.json"
            )),
            complete: result(include_str!(
                "../../../examples/documents/output-traceroute-complete.json"
            )),
        },
        Fixture {
            command: output::contract::Command::Dns,
            event: result(include_str!(
                "../../../examples/documents/output-dns-event.json"
            )),
            complete: result(include_str!(
                "../../../examples/documents/output-dns-complete.json"
            )),
        },
        Fixture {
            command: output::contract::Command::Fuzz,
            event: result(include_str!(
                "../../../examples/documents/output-fuzz-event.json"
            )),
            complete: result(include_str!(
                "../../../examples/documents/output-fuzz-complete.json"
            )),
        },
        Fixture {
            command: output::contract::Command::Exchange,
            event: result(include_str!(
                "../../../examples/documents/output-exchange-sent-event.json"
            )),
            complete: result(include_str!(
                "../../../examples/documents/output-exchange-complete.json"
            )),
        },
    ]
}

fn validator() -> jsonschema::Validator {
    let schema: Value = serde_json::from_str(include_str!(
        "../../../schemas/packetcraftr.output.v1.schema.json"
    ))
    .expect("published output schema must parse");
    jsonschema::validator_for(&schema).expect("published output schema must compile")
}

fn validate_records(validator: &jsonschema::Validator, records: &[Value]) {
    assert_contiguous(records);
    for record in records {
        validator
            .validate(record)
            .unwrap_or_else(|error| panic!("stream record must match the schema: {error}"));
    }
}

fn complete(
    sink: &mut NdjsonStream,
    command: output::contract::Command,
    result: Value,
) -> Result<(), CliError> {
    if matches!(
        command,
        output::contract::Command::Fuzz | output::contract::Command::Exchange
    ) {
        sink.complete_with_stats(result, Vec::new(), output::envelope::Stats::default())
    } else {
        sink.complete(result, Vec::new())
    }
}

#[test]
fn every_command_stream_is_schema_valid_contiguous_and_terminal() {
    let validator = validator();
    for fixture in fixtures() {
        let (mut sink, output) = stream(fixture.command);
        sink.emit_data(fixture.event, Vec::new()).unwrap();
        complete(&mut sink, fixture.command, fixture.complete).unwrap();
        let terminal_bytes = output.bytes();
        let records = output.records();

        validate_records(&validator, &records);
        assert_eq!(records.len(), 2);
        assert_eq!(records[0]["status"], "success");
        assert_eq!(records[1]["status"], "success");
        assert!(sink.emit_data(json!({"late": true}), Vec::new()).is_err());
        assert!(
            sink.emit_error(CliError::new(5, "late").output_error())
                .is_err()
        );
        assert_eq!(output.bytes(), terminal_bytes);
    }
}

#[test]
fn every_command_empty_success_completes_at_zero() {
    let validator = validator();
    for fixture in fixtures() {
        let (mut sink, output) = stream(fixture.command);
        complete(&mut sink, fixture.command, fixture.complete).unwrap();
        let records = output.records();

        validate_records(&validator, &records);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["sequence"], 0);
        assert_eq!(records[0]["status"], "success");
    }
}

#[test]
fn every_command_early_and_late_failure_is_the_only_terminal_record() {
    let validator = validator();
    for fixture in fixtures() {
        let (mut empty, output) = stream(fixture.command);
        empty
            .emit_error(CliError::new(5, "early failure").output_error())
            .unwrap();
        let records = output.records();
        validate_records(&validator, &records);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["sequence"], 0);
        assert_eq!(records[0]["status"], "error");

        let (mut partial, output) = stream(fixture.command);
        partial.emit_data(fixture.event, Vec::new()).unwrap();
        partial
            .emit_error(CliError::new(5, "late failure").output_error())
            .unwrap();
        let terminal_bytes = output.bytes();
        let records = output.records();
        validate_records(&validator, &records);
        assert_eq!(records.len(), 2);
        assert_eq!(records[1]["sequence"], 1);
        assert_eq!(records[1]["status"], "error");
        assert!(partial.emit_data(fixture.complete, Vec::new()).is_err());
        assert_eq!(output.bytes(), terminal_bytes);
    }
}

#[test]
fn sparse_domain_identifiers_never_select_envelope_sequence() {
    let validator = validator();
    for mut fixture in fixtures() {
        set_sparse_domain_identifier(fixture.command, &mut fixture.event);
        let (mut sink, output) = stream(fixture.command);
        sink.emit_data(fixture.event, Vec::new()).unwrap();
        complete(&mut sink, fixture.command, fixture.complete).unwrap();
        let records = output.records();

        validate_records(&validator, &records);
        assert_eq!(records[0]["sequence"], 0);
        assert_eq!(records[1]["sequence"], 1);
    }
}

fn set_sparse_domain_identifier(command: output::contract::Command, event: &mut Value) {
    let sparse = json!(9_000_000_007_u64);
    match command {
        output::contract::Command::Read | output::contract::Command::Capture => {
            event["source_frame"] = sparse;
        }
        output::contract::Command::Replay => event["source_sequence"] = sparse,
        output::contract::Command::Follow | output::contract::Command::Expert => {
            event["frame"] = sparse;
        }
        output::contract::Command::Scan => event["probe_sequence"] = sparse,
        output::contract::Command::Traceroute => event["probe"]["sequence"] = sparse,
        output::contract::Command::Dns => event["evidence"]["attempt"] = json!(31),
        output::contract::Command::Fuzz => {
            event["case"]["index"] = sparse.clone();
            event["case"]["reproduction"]["case_index"] = sparse;
        }
        output::contract::Command::Exchange => event["request_index"] = sparse,
        _ => unreachable!("fixtures contain only NDJSON-producing commands"),
    }
}

#[derive(Clone, Default)]
struct SharedBytes(Rc<RefCell<Vec<u8>>>);

impl io::Write for SharedBytes {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.borrow_mut().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Err(io::Error::other("induced flush failure"))
    }
}

#[test]
fn sink_failure_never_appends_a_second_stdout_document() {
    let validator = validator();
    for fixture in fixtures() {
        let output = SharedBytes::default();
        let mut sink = NdjsonStream::new(Some(fixture.command), output.clone());
        let error = sink
            .emit_data(fixture.event, Vec::new())
            .expect_err("the record flush must fail");
        assert!(error.message.contains("sequence 0"));
        let bytes_after_failure = output.0.borrow().clone();
        let records = std::str::from_utf8(&bytes_after_failure)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .collect::<Vec<_>>();
        validate_records(&validator, &records);
        assert_eq!(records.len(), 1);

        assert!(
            sink.emit_error(CliError::new(5, "secondary error").output_error())
                .is_err()
        );
        assert_eq!(*output.0.borrow(), bytes_after_failure);
    }
}

#[test]
fn cleanup_failure_augments_the_primary_error_at_the_next_position() {
    let (mut sink, output) = stream(output::contract::Command::Exchange);
    sink.emit_data(
        json!({
            "event": "sent",
            "request_index": 77,
            "frame": { "bytes_hex": "00", "length": 1 }
        }),
        Vec::new(),
    )
    .unwrap();
    let primary = CliError::from_classification(
        packetcraftr::core::error::Classification::new(
            "io.primary",
            packetcraftr::core::error::Kind::Io,
            None,
        ),
        "primary capture failure",
        vec!["primary cause".to_owned()],
    )
    .with_cleanup(packetcraftr::netio::Error::Capture {
        message: "cleanup failure".to_owned(),
    });
    sink.emit_error(primary.output_error()).unwrap();

    let records = output.records();
    validate_records(&validator(), &records);
    assert_eq!(records[1]["sequence"], 1);
    assert_eq!(records[1]["error"]["code"], "io.primary");
    assert_eq!(records[1]["error"]["causes"][0], "primary cause");
    assert!(
        records[1]["error"]["causes"][1]
            .as_str()
            .unwrap()
            .contains("cleanup failure")
    );
}
