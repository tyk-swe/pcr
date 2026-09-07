// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr_core::protocol;

use packetcraftr_cli::output::{
    contract::{Command, Format, SCHEMA_V2},
    envelope::Envelope,
    stream::StreamEncoder,
};
use serde_json::{Value, json};
use std::fs;
use std::path::PathBuf;

mod support;
use support::TestRecord;

use support::{SharedBuffer, output_schema, schema_validator};

#[test]
fn facade_reexports_domains_and_command_formats_are_complete() {
    let registry = protocol::builtin::registry();
    assert!(registry.codec("ipv4").is_some());
    for command in Command::ALL {
        assert!(!command.formats().is_empty());
        assert!(command.require_format(command.formats()[0]).is_ok());
    }
    assert!(Command::Protocols.require_format(Format::Ndjson).is_err());
}

#[test]
fn aggregate_and_stream_envelopes_keep_version_and_discriminators() {
    let aggregate = serde_json::to_value(Envelope::success(
        Command::Protocols,
        json!({"count": 1}),
        Vec::new(),
    ))
    .expect("aggregate must serialize");
    assert_eq!(aggregate["schema"], SCHEMA_V2);
    assert_eq!(aggregate["command"], "protocols");
    assert_eq!(aggregate["mode"], "aggregate");
    assert_eq!(aggregate["status"], "success");
    assert!(aggregate.get("sequence").is_none());

    let output = SharedBuffer::default();
    let encoder = StreamEncoder::new(Command::Read, output.clone());
    for frame in 0..8 {
        encoder
            .emit_data(TestRecord(json!({"frame": frame})), Vec::new())
            .expect("stream must serialize");
    }
    let stream = output.records().pop().expect("eighth record");
    assert_eq!(stream["schema"], SCHEMA_V2);
    assert_eq!(stream["mode"], "stream");
    assert_eq!(stream["sequence"], 7);
}

#[test]
fn schema_retains_output_version_and_broadcast_selection() {
    let schema = output_schema();
    assert_eq!(
        schema["$defs"]["baseEnvelope"]["properties"]["schema"]["const"],
        SCHEMA_V2
    );
    assert!(
        schema["$defs"]["routeDecision"]["properties"]["selection_reason"]["enum"]
            .as_array()
            .expect("route selection reasons are an enum")
            .contains(&Value::String("broadcast".to_owned()))
    );
}

#[test]
fn schema_accepts_one_based_source_frames_and_rejects_zero() {
    let validator = schema_validator();
    let mut document: Value = serde_json::from_str(include_str!(
        "../../../examples/documents/output-read-dissect-event.json"
    ))
    .expect("published read example must be JSON");
    document["result"]["source_frame"] = json!(1);
    validator
        .validate(&document)
        .unwrap_or_else(|error| panic!("source frame 1 is valid: {error}"));
    document["result"]["source_frame"] = json!(0);
    assert!(
        validator.validate(&document).is_err(),
        "source frame 0 is invalid"
    );
}

#[test]
fn every_published_output_example_validates_against_the_schema() {
    let validator = schema_validator();
    let directory = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/documents");
    let mut examples = fs::read_dir(directory)
        .expect("published examples directory must exist")
        .map(|entry| {
            entry
                .expect("published example entry must be readable")
                .path()
        })
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("output-") && name.ends_with(".json"))
        })
        .collect::<Vec<_>>();
    examples.sort();
    assert!(!examples.is_empty(), "published output examples must exist");

    for path in examples {
        let document: Value = serde_json::from_str(
            &fs::read_to_string(&path).expect("published example must be readable"),
        )
        .unwrap_or_else(|error| panic!("{} must be valid JSON: {error}", path.display()));
        validator.validate(&document).unwrap_or_else(|error| {
            panic!(
                "{} must validate against the output schema: {error}",
                path.display()
            )
        });
    }
}
