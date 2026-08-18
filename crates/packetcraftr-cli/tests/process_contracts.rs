// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::io::Write;

use serde_json::Value;

mod support;

use support::{parse_json, run, run_success};

fn assert_no_terminal_style(bytes: &[u8]) {
    assert!(
        !bytes.windows(2).any(|window| window == b"\x1b["),
        "machine output contained an ANSI control sequence"
    );
}

#[test]
fn help_and_version_are_available_without_network_access() {
    let help = run_success(&["--help"]);
    assert!(String::from_utf8_lossy(&help.stdout).contains("Usage: packetcraftr"));

    let version = run_success(&["--version"]);
    assert_eq!(
        String::from_utf8_lossy(&version.stdout).trim(),
        concat!("packetcraftr ", env!("CARGO_PKG_VERSION"))
    );
}

#[test]
fn offline_build_supports_json_hex_and_raw_without_terminal_style() {
    let json_output = run_success(&[
        "--output",
        "json",
        "--color",
        "always",
        "build",
        "--packet",
        "raw(text=hello)",
    ]);
    assert_no_terminal_style(&json_output.stdout);
    let value = parse_json(&json_output);
    assert_eq!(value["schema"], "packetcraftr.output/v1");
    assert_eq!(value["result"]["bytes_hex"], "68656c6c6f");

    let hex = run_success(&["--output", "hex", "build", "--packet", "raw(text=hello)"]);
    assert_eq!(String::from_utf8_lossy(&hex.stdout).trim(), "68656c6c6f");

    let raw = run_success(&["--output", "raw", "build", "--packet", "raw(text=hello)"]);
    assert_eq!(raw.stdout, b"hello");
}

#[test]
fn protocols_dissect_and_ndjson_read_are_offline_and_structured() {
    let protocols = run_success(&["--output", "json", "protocols", "IP4"]);
    let value = parse_json(&protocols);
    assert_eq!(value["command"], "protocols");
    assert_eq!(value["status"], "success");

    let dissect = run_success(&[
        "--output",
        "json",
        "dissect",
        "--link-type",
        "228",
        "--hex",
        "45000014000000004001f6e7c0000201c6336402",
    ]);
    assert_no_terminal_style(&dissect.stdout);
    let dissect_value = parse_json(&dissect);
    assert_eq!(dissect_value["result"]["matched"], true);
    assert!(dissect_value["result"]["dissection"].is_object());

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
    let read = run_success(&["--output", "ndjson", "read", path, "--max-frames", "1"]);
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
    let value = parse_json(&invalid);
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
    let value = parse_json(&denied);
    assert_eq!(value["error"]["code"], "policy.public_destination");
}

#[test]
fn human_runtime_errors_include_actionable_classification_and_help() {
    let expected = concat!(
        "error[cli.protocol]: unknown built-in protocol 'tcpc'\n",
        "help: run `packetcraftr protocols` to list built-in protocols\n",
    );

    for arguments in [
        &["protocols", "tcpc"][..],
        &["--color", "never", "protocols", "tcpc"][..],
    ] {
        let failure = run(arguments);
        assert_eq!(failure.status.code(), Some(2), "{arguments:?}");
        assert!(failure.stdout.is_empty(), "{arguments:?}");
        assert_eq!(
            String::from_utf8_lossy(&failure.stderr),
            expected,
            "{arguments:?}"
        );
        assert_no_terminal_style(&failure.stderr);
    }
}

#[test]
fn clap_failures_preserve_unambiguous_invocation_context() {
    for (arguments, expected_command) in [
        (
            &["--output", "json", "--color", "build", "protocols"][..],
            Some("protocols"),
        ),
        (&["--output", "json", "not-a-command", "build"][..], None),
    ] {
        let failure = run(arguments);
        assert_eq!(failure.status.code(), Some(2), "{arguments:?}");
        let value = parse_json(&failure);
        assert_eq!(value["command"].as_str(), expected_command, "{arguments:?}");
        assert_eq!(value["error"]["kind"], "cli", "{arguments:?}");
    }

    let failure = run(&["protocols", "--output", "ndjson", "--color", "invalid"]);
    assert_eq!(failure.status.code(), Some(2));
    assert_no_terminal_style(&failure.stdout);
    let text = String::from_utf8(failure.stdout).expect("NDJSON is UTF-8");
    assert_eq!(text.lines().count(), 1);
    let value: Value = serde_json::from_str(&text).expect("error NDJSON must parse");
    assert_eq!(value["command"], "protocols");
    assert_eq!(value["sequence"], 0);
    assert_eq!(value["error"]["kind"], "cli");
}
