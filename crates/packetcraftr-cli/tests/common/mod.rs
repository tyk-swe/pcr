// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::path::Path;
use std::process::{Command, Output};
use std::sync::OnceLock;

use serde_json::Value;

pub(crate) fn schema_validator() -> &'static jsonschema::Validator {
    static VALIDATOR: OnceLock<jsonschema::Validator> = OnceLock::new();
    VALIDATOR.get_or_init(|| {
        jsonschema::validator_for(output_schema()).expect("published output schema must compile")
    })
}

pub(crate) fn frozen_v14_schema_validator() -> &'static jsonschema::Validator {
    static VALIDATOR: OnceLock<jsonschema::Validator> = OnceLock::new();
    VALIDATOR.get_or_init(|| {
        let schema: Value = serde_json::from_str(include_str!(
            "../../../../schemas/packetcraftr.output.v14.schema.json"
        ))
        .expect("frozen output/v14 schema must be JSON");
        jsonschema::validator_for(&schema).expect("frozen output/v14 schema must compile")
    })
}

pub(crate) fn frozen_v15_schema_validator() -> &'static jsonschema::Validator {
    static VALIDATOR: OnceLock<jsonschema::Validator> = OnceLock::new();
    VALIDATOR.get_or_init(|| {
        let schema: Value = serde_json::from_str(include_str!(
            "../../../../schemas/packetcraftr.output.v15.schema.json"
        ))
        .expect("frozen output/v15 schema must be JSON");
        jsonschema::validator_for(&schema).expect("frozen output/v15 schema must compile")
    })
}

pub(crate) fn frozen_v16_schema_validator() -> &'static jsonschema::Validator {
    static VALIDATOR: OnceLock<jsonschema::Validator> = OnceLock::new();
    VALIDATOR.get_or_init(|| {
        let schema: Value = serde_json::from_str(include_str!(
            "../../../../schemas/packetcraftr.output.v16.schema.json"
        ))
        .expect("frozen output/v16 schema must be JSON");
        jsonschema::validator_for(&schema).expect("frozen output/v16 schema must compile")
    })
}

pub(crate) fn frozen_v17_schema_validator() -> &'static jsonschema::Validator {
    static VALIDATOR: OnceLock<jsonschema::Validator> = OnceLock::new();
    VALIDATOR.get_or_init(|| {
        let schema: Value = serde_json::from_str(include_str!(
            "../../../../schemas/packetcraftr.output.v17.schema.json"
        ))
        .expect("frozen output/v17 schema must be JSON");
        jsonschema::validator_for(&schema).expect("frozen output/v17 schema must compile")
    })
}

pub(crate) fn path_text(path: &Path) -> &str {
    path.to_str().expect("temporary path must be UTF-8")
}

pub(crate) fn run(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_packetcraftr"))
        .args(arguments)
        .output()
        .expect("CLI process must start")
}

pub(crate) fn run_success(arguments: &[&str]) -> Output {
    let output = run(arguments);
    assert!(
        output.status.success(),
        "command {arguments:?} failed: stdout={:?}, stderr={:?}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    output
}

pub(crate) fn parse_json(output: &Output) -> Value {
    assert!(
        output.stdout.ends_with(b"\n"),
        "JSON output must end with a newline"
    );
    let value = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "command output must be JSON ({error}): stdout={:?}, stderr={:?}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        )
    });
    schema_validator()
        .validate(&value)
        .unwrap_or_else(|error| panic!("JSON output must match the published schema: {error}"));
    value
}

pub(crate) fn parse_ndjson(output: &Output) -> Vec<Value> {
    let records = parse_ndjson_bytes(&output.stdout);
    for record in &records {
        schema_validator().validate(record).unwrap_or_else(|error| {
            panic!("NDJSON record must match the published schema: {error}")
        });
    }
    records
}

fn parse_ndjson_bytes(bytes: &[u8]) -> Vec<Value> {
    let text = std::str::from_utf8(bytes).expect("NDJSON output must be UTF-8");
    assert!(
        text.is_empty() || text.ends_with('\n'),
        "nonempty NDJSON output ends every record with a newline"
    );
    text.lines()
        .map(|line| {
            serde_json::from_str(line)
                .expect("each NDJSON line holds exactly one complete JSON value")
        })
        .collect()
}

pub(crate) fn assert_contiguous(records: &[Value]) {
    for (expected, record) in records.iter().enumerate() {
        assert_eq!(
            record["sequence"].as_u64(),
            u64::try_from(expected).ok(),
            "record {expected} has the wrong stream sequence"
        );
    }
}

pub(crate) fn output_schema() -> &'static Value {
    static SCHEMA: OnceLock<Value> = OnceLock::new();
    SCHEMA.get_or_init(|| {
        serde_json::from_str(include_str!(
            "../../../../schemas/packetcraftr.output.v18.schema.json"
        ))
        .expect("published output schema must be JSON")
    })
}
