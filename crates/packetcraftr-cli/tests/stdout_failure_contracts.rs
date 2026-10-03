// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#![cfg(packetcraftr_test_dev_full)]

use std::process::Command;

mod common;

const REMEDIATION: &str = "restore the stdout consumer or choose a writable output destination";
const NDJSON_REMEDIATION: &str = "inspect the output sink and account for records already written";
const FULL_DEVICE: &str = "No space left on device";

#[test]
fn generated_command_errors_report_stderr_write_failures() {
    common::require_dev_full();
    let arguments = ["topics", "no-such-topic"];
    let normal = common::run(&arguments);
    assert_eq!(normal.status.code(), Some(2), "{normal:?}");
    assert!(normal.stdout.is_empty(), "{normal:?}");
    assert!(!normal.stderr.is_empty(), "{normal:?}");

    let failure = Command::new(env!("CARGO_BIN_EXE_packetcraftr"))
        .args(arguments)
        .stderr(
            std::fs::OpenOptions::new()
                .write(true)
                .open("/dev/full")
                .expect("/dev/full must be writable for the write-failure contract"),
        )
        .output()
        .expect("CLI process must start");
    assert_eq!(failure.status.code(), Some(5), "{failure:?}");
    assert!(failure.stdout.is_empty(), "{failure:?}");
}

fn stderr_of_failed_stdout_write(arguments: &[&str]) -> String {
    common::require_dev_full();
    let failure = Command::new(env!("CARGO_BIN_EXE_packetcraftr"))
        .args(arguments)
        .stdout(
            std::fs::OpenOptions::new()
                .write(true)
                .open("/dev/full")
                .expect("/dev/full must be writable for the write-failure contract"),
        )
        .output()
        .expect("CLI process must start");
    assert_eq!(failure.status.code(), Some(5), "{failure:?}");
    String::from_utf8(failure.stderr).expect("stderr is UTF-8")
}

fn assert_stdout_failure_is_classified(arguments: &[&str]) {
    let stderr = stderr_of_failed_stdout_write(arguments);
    assert!(
        stderr.starts_with("error[io.stdout]: write stdout failed\ncaused by: "),
        "{stderr}"
    );
    assert_eq!(stderr.matches("caused by: ").count(), 1, "{stderr}");
    assert_eq!(stderr.matches(FULL_DEVICE).count(), 1, "{stderr}");
    assert!(
        stderr.ends_with(&format!("\nhelp: {REMEDIATION}\n")),
        "{stderr}"
    );
}

#[test]
fn text_stdout_failure_reports_the_stdout_classification() {
    assert_stdout_failure_is_classified(&["--output", "text", "build", "--packet", "raw(text=a)"]);
}

#[test]
fn hex_stdout_failure_reports_the_stdout_classification() {
    assert_stdout_failure_is_classified(&["--output", "hex", "build", "--packet", "raw(text=a)"]);
}

#[test]
fn raw_stdout_failure_reports_the_stdout_classification() {
    assert_stdout_failure_is_classified(&["--output", "raw", "build", "--packet", "raw(text=a)"]);
}

#[test]
fn json_stdout_failure_reports_the_stdout_classification() {
    assert_stdout_failure_is_classified(&["--output", "json", "build", "--packet", "raw(text=a)"]);
}

#[test]
fn ndjson_stdout_failure_states_the_write_failure_once_as_its_cause() {
    let stderr = stderr_of_failed_stdout_write(&[
        "--output",
        "ndjson",
        "dissect",
        "--hex",
        "45000014000000004001f6e7c0000201c6336402",
    ]);
    assert!(
        stderr.starts_with(
            "error[io.stdout]: NDJSON stream is incomplete: record at sequence 0 failed to write\n\
             caused by: write NDJSON output failed\ncaused by: "
        ),
        "{stderr}"
    );
    assert_eq!(stderr.matches(FULL_DEVICE).count(), 1, "{stderr}");
    assert!(
        stderr.ends_with(&format!("\nhelp: {NDJSON_REMEDIATION}\n")),
        "{stderr}"
    );
}
