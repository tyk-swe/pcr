// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
// Shared by several test binaries; each one uses a different subset.
#![allow(dead_code)]

use std::path::Path;
use std::process::{Command, Output};

use packetcraftr_cli::output;
use serde_json::Value;

#[path = "../../src/test_support.rs"]
mod shared;

// Re-exported for the binaries that need them; an unused re-export warns
// even though the definitions behind it are allowed to be dead.
#[allow(unused_imports)]
pub(crate) use shared::{
    SharedBuffer, TestRecord, assert_contiguous, output_schema, schema_validator,
};

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
    let records = shared::parse_ndjson(&output.stdout);
    for record in &records {
        schema_validator().validate(record).unwrap_or_else(|error| {
            panic!("NDJSON record must match the published schema: {error}")
        });
    }
    records
}

/// An NDJSON encoder writing into a buffer the caller can read back.
pub(crate) fn stream(
    command: output::contract::Command,
) -> (output::stream::StreamEncoder, SharedBuffer) {
    let buffer = SharedBuffer::default();
    (
        output::stream::StreamEncoder::new(command, buffer.clone()),
        buffer,
    )
}
