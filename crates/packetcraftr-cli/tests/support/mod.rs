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

// Facility prerequisites for the compile-time capability gates the package
// build script declares. Each assertion fails the scenario explicitly; a
// missing prerequisite is a failed test, never a silent pass.

/// Process cancellation contracts inspect `/proc` and deliver signals through
/// a `kill` utility.
#[cfg(packetcraftr_test_procfs)]
pub(crate) fn require_procfs() {
    assert!(
        std::fs::metadata("/proc/self/status").is_ok(),
        "process cancellation contracts require a readable procfs at /proc"
    );
    assert!(
        Command::new("kill")
            .arg("-l")
            .output()
            .is_ok_and(|output| output.status.success()),
        "process cancellation contracts require a `kill` signal utility"
    );
}

/// Terminal-stdin contracts allocate a pty with the util-linux `script` flags
/// `--quiet --return --command`; other `script` implementations do not accept
/// them.
#[cfg(packetcraftr_test_util_linux)]
pub(crate) fn require_util_linux_script() {
    let output = Command::new("script")
        .arg("--version")
        .output()
        .expect("terminal process contracts require the util-linux `script` allocator");
    assert!(
        output.status.success() && String::from_utf8_lossy(&output.stdout).contains("util-linux"),
        "terminal process contracts require util-linux `script`, got: {output:?}"
    );
}

/// Write-failure contracts sink stdout into `/dev/full`.
#[cfg(packetcraftr_test_dev_full)]
pub(crate) fn require_dev_full() {
    assert!(
        std::fs::metadata("/dev/full").is_ok(),
        "write-failure contracts require the /dev/full sink"
    );
}
