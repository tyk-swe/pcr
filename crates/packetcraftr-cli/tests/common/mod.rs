// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
#![allow(dead_code)]

pub(crate) mod application_output;

use std::path::Path;
use std::process::{Command, Output};
use std::sync::OnceLock;

use serde_json::Value;

use packetcraftr_cli::test_support;

// Re-exported for the binaries that need them; an unused re-export warns
// even though the definitions behind it are allowed to be dead.
#[allow(unused_imports)]
pub(crate) use packetcraftr_cli::test_support::{
    SharedBuffer, assert_contiguous, output_schema, stream,
};

pub(crate) fn schema_validator() -> &'static jsonschema::Validator {
    static VALIDATOR: OnceLock<jsonschema::Validator> = OnceLock::new();
    VALIDATOR.get_or_init(|| {
        jsonschema::validator_for(output_schema()).expect("published output schema must compile")
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
    let records = test_support::parse_ndjson(&output.stdout);
    for record in &records {
        schema_validator().validate(record).unwrap_or_else(|error| {
            panic!("NDJSON record must match the published schema: {error}")
        });
    }
    records
}

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

#[cfg(packetcraftr_test_dev_full)]
pub(crate) fn require_dev_full() {
    assert!(
        std::fs::metadata("/dev/full").is_ok(),
        "write-failure contracts require the /dev/full sink"
    );
}
