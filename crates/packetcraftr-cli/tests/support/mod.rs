// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::process::{Command, Output};

use serde_json::Value;

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
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "command output must be JSON ({error}): stdout={:?}, stderr={:?}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        )
    })
}

pub(crate) fn parse_ndjson(output: &Output) -> Vec<Value> {
    std::str::from_utf8(&output.stdout)
        .expect("NDJSON output must be UTF-8")
        .lines()
        .map(|line| serde_json::from_str(line).expect("each NDJSON line must be valid JSON"))
        .collect()
}

pub(crate) fn assert_contiguous_stream(records: &[Value]) {
    for (expected, record) in records.iter().enumerate() {
        assert_eq!(
            record["sequence"].as_u64(),
            u64::try_from(expected).ok(),
            "record {expected} has the wrong stream sequence"
        );
    }
}
