// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
// Shared by several test binaries; each one uses a different subset.
#![allow(dead_code)]
// Test code indexes fixtures and counts by hand; the fail-closed lints are
// for library paths.
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::path::Path;
use std::process::{Command, Output};

use packetcraftr::output;
use serde_json::Value;

#[path = "../../src/test_support.rs"]
mod shared;

pub(crate) use shared::{SharedBuffer, assert_contiguous, schema_validator};

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

/// An NDJSON encoder writing into a buffer the caller can read back.
pub(crate) fn stream(
    command: output::contract::Command,
) -> (output::envelope::StreamEncoder, SharedBuffer) {
    let buffer = SharedBuffer::default();
    (
        output::envelope::StreamEncoder::new(Some(command), buffer.clone()),
        buffer,
    )
}
