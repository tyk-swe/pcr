// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::process::{Command, Output};

use serde_json::Value;

#[path = "../../src/test_support.rs"]
mod shared;

pub(crate) use shared::{assert_contiguous, schema_validator};

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
        .expect("JSON output must match the published schema");
    value
}

pub(crate) fn parse_ndjson(output: &Output) -> Vec<Value> {
    let records = shared::parse_ndjson(&output.stdout);
    for record in &records {
        schema_validator()
            .validate(record)
            .expect("NDJSON record must match the published schema");
    }
    records
}
