// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::io::Write;
use std::process::{Command, Output};

use serde_json::Value;

fn run(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_packetcraftr"))
        .args(arguments)
        .output()
        .expect("CLI process must start")
}

fn assert_no_terminal_style(bytes: &[u8]) {
    assert!(
        !bytes.windows(2).any(|window| window == b"\x1b["),
        "machine output contained an ANSI control sequence"
    );
}

#[test]
fn help_and_version_are_available_without_network_access() {
    let help = run(&["--help"]);
    assert!(help.status.success());
    assert!(String::from_utf8_lossy(&help.stdout).contains("Usage: packetcraftr"));

    let version = run(&["--version"]);
    assert!(version.status.success());
    assert_eq!(
        String::from_utf8_lossy(&version.stdout).trim(),
        concat!("packetcraftr ", env!("CARGO_PKG_VERSION"))
    );
}

#[test]
fn offline_build_supports_json_hex_and_raw_without_terminal_style() {
    let json_output = run(&[
        "--output",
        "json",
        "--color",
        "always",
        "build",
        "--packet",
        "raw(text=hello)",
    ]);
    assert!(json_output.status.success(), "{:?}", json_output.stderr);
    assert_no_terminal_style(&json_output.stdout);
    let value: Value = serde_json::from_slice(&json_output.stdout).expect("JSON must parse");
    assert_eq!(value["schema"], "packetcraftr.output/v1");
    assert_eq!(value["result"]["bytes_hex"], "68656c6c6f");

    let hex = run(&["--output", "hex", "build", "--packet", "raw(text=hello)"]);
    assert!(hex.status.success());
    assert_eq!(String::from_utf8_lossy(&hex.stdout).trim(), "68656c6c6f");

    let raw = run(&["--output", "raw", "build", "--packet", "raw(text=hello)"]);
    assert!(raw.status.success());
    assert_eq!(raw.stdout, b"hello");
}

#[test]
fn protocols_dissect_and_ndjson_read_are_offline_and_structured() {
    let protocols = run(&["--output", "json", "protocols", "IP4"]);
    assert!(protocols.status.success());
    let value: Value = serde_json::from_slice(&protocols.stdout).expect("JSON must parse");
    assert_eq!(value["command"], "protocols");
    assert_eq!(value["status"], "success");

    let dissect = run(&[
        "--output",
        "json",
        "dissect",
        "--link-type",
        "228",
        "--hex",
        "45000014000000004001f6e7c0000201c6336402",
    ]);
    assert!(dissect.status.success(), "{:?}", dissect.stderr);
    assert_no_terminal_style(&dissect.stdout);

    let mut capture = tempfile::NamedTempFile::new().expect("temporary capture must open");
    capture
        .write_all(&[
            0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 101, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0,
        ])
        .expect("temporary capture must write");
    let path = capture
        .path()
        .to_str()
        .expect("temporary path must be UTF-8");
    let read = run(&["--output", "ndjson", "read", path, "--max-frames", "1"]);
    assert!(read.status.success(), "{:?}", read.stderr);
    assert_no_terminal_style(&read.stdout);
    let records = String::from_utf8(read.stdout).expect("NDJSON must be UTF-8");
    assert_eq!(records.lines().count(), 1);
    let record: Value = serde_json::from_str(records.trim()).expect("record must parse");
    assert_eq!(record["mode"], "stream");
    assert_eq!(record["sequence"], 0);
}

#[test]
fn invalid_input_and_live_policy_gates_have_structured_exit_codes() {
    let invalid = run(&[
        "--output", "json", "--color", "always", "dissect", "--hex", "zz",
    ]);
    assert_eq!(invalid.status.code(), Some(2));
    assert_no_terminal_style(&invalid.stdout);
    let value: Value = serde_json::from_slice(&invalid.stdout).expect("error JSON must parse");
    assert_eq!(value["status"], "error");
    assert_eq!(value["error"]["kind"], "cli");

    let denied = run(&[
        "--output",
        "json",
        "dns",
        "8.8.8.8",
        "example.com",
        "--transaction-id",
        "1",
        "--source-port",
        "49152",
    ]);
    assert_eq!(denied.status.code(), Some(6));
    let value: Value = serde_json::from_slice(&denied.stdout).expect("error JSON must parse");
    assert_eq!(value["error"]["code"], "policy.public_destination");
}
