// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::io::Write;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use serde_json::Value;

mod support;

use support::{parse_json, run, run_success};

const IPV4_FRAME_HEX: &str = "45000014000000004001f6e7c0000201c6336402";

fn run_with_stdin(arguments: &[&str], input: &[u8]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_packetcraftr"))
        .args(arguments)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("CLI process must start");
    child
        .stdin
        .take()
        .expect("stdin must be piped")
        .write_all(input)
        .expect("stdin must accept input");
    child.wait_with_output().expect("CLI process must finish")
}

fn run_with_open_stdin(arguments: &[&str]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_packetcraftr"))
        .args(arguments)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("CLI process must start");
    let stdin_writer = child.stdin.take().expect("stdin must be piped");
    let deadline = Instant::now() + Duration::from_secs(3);

    loop {
        match child.try_wait() {
            Ok(Some(_)) => {
                drop(stdin_writer);
                return child
                    .wait_with_output()
                    .expect("CLI process output must be readable");
            }
            Ok(None) if Instant::now() < deadline => std::thread::yield_now(),
            Ok(None) => {
                drop(stdin_writer);
                let _ = child.kill();
                let output = child
                    .wait_with_output()
                    .expect("timed-out CLI process must be reaped");
                panic!(
                    "command {arguments:?} waited for stdin: status={:?}, stdout={:?}, stderr={:?}",
                    output.status,
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr),
                );
            }
            Err(error) => {
                drop(stdin_writer);
                let _ = child.kill();
                let _ = child.wait();
                panic!("could not poll command {arguments:?}: {error}");
            }
        }
    }
}

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
fn explicit_packet_does_not_wait_for_an_open_stdin_pipe() {
    let output = run_with_open_stdin(&["--output", "hex", "build", "--packet", "raw(text=hello)"]);
    assert!(output.status.success(), "{:?}", output.stderr);
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "68656c6c6f");
}

#[test]
fn explicit_hex_does_not_wait_for_an_open_stdin_pipe() {
    let output = run_with_open_stdin(&[
        "--output",
        "json",
        "dissect",
        "--link-type",
        "228",
        "--hex",
        IPV4_FRAME_HEX,
    ]);
    assert!(output.status.success(), "{:?}", output.stderr);
    assert_eq!(parse_json(&output)["result"]["bytes_hex"], IPV4_FRAME_HEX);
}

#[test]
fn redirected_nonempty_stdin_is_accepted_without_an_explicit_source() {
    let recipe = run_with_stdin(&["--output", "hex", "build"], b"raw(text=hello)");
    assert!(recipe.status.success(), "{:?}", recipe.stderr);
    assert_eq!(String::from_utf8_lossy(&recipe.stdout).trim(), "68656c6c6f");

    let frame = run_with_stdin(
        &["--output", "json", "dissect", "--link-type", "228"],
        &decode_hex(IPV4_FRAME_HEX),
    );
    assert!(frame.status.success(), "{:?}", frame.stderr);
    assert_eq!(parse_json(&frame)["result"]["bytes_hex"], IPV4_FRAME_HEX);
}

#[test]
fn redirected_empty_stdin_reports_command_specific_input_options() {
    let recipe = run_with_stdin(&["--output", "json", "build"], &[]);
    assert_eq!(recipe.status.code(), Some(2));
    let recipe_error = parse_json(&recipe)["error"].clone();
    assert_eq!(recipe_error["code"], "cli.input_source");
    assert!(
        recipe_error["message"]
            .as_str()
            .unwrap()
            .contains("--packet")
    );
    assert!(
        recipe_error["message"]
            .as_str()
            .unwrap()
            .contains("--packet-file")
    );
    assert!(!recipe_error["message"].as_str().unwrap().contains("--hex"));

    let frame = run_with_stdin(&["--output", "json", "dissect"], &[]);
    assert_eq!(frame.status.code(), Some(2));
    let frame_error = parse_json(&frame)["error"].clone();
    assert_eq!(frame_error["code"], "cli.input_source");
    assert!(frame_error["message"].as_str().unwrap().contains("--hex"));
    assert!(frame_error["message"].as_str().unwrap().contains("--file"));
    assert!(
        !frame_error["message"]
            .as_str()
            .unwrap()
            .contains("--packet")
    );
    assert!(
        !frame_error["message"]
            .as_str()
            .unwrap()
            .contains("--packet-file")
    );
}

#[test]
fn explicit_files_ignore_an_unrelated_open_stdin_pipe() {
    let mut packet_file = tempfile::NamedTempFile::new().expect("packet file must open");
    packet_file
        .write_all(b"raw(text=hello)")
        .expect("packet file must write");
    let packet_path = packet_file
        .path()
        .to_str()
        .expect("packet path must be UTF-8");
    let packet = run_with_open_stdin(&["--output", "hex", "build", "--packet-file", packet_path]);
    assert!(packet.status.success(), "{:?}", packet.stderr);
    assert_eq!(String::from_utf8_lossy(&packet.stdout).trim(), "68656c6c6f");

    let mut frame_file = tempfile::NamedTempFile::new().expect("frame file must open");
    frame_file
        .write_all(&decode_hex(IPV4_FRAME_HEX))
        .expect("frame file must write");
    let frame_path = frame_file
        .path()
        .to_str()
        .expect("frame path must be UTF-8");
    let frame = run_with_open_stdin(&[
        "--output",
        "json",
        "dissect",
        "--link-type",
        "228",
        "--file",
        frame_path,
    ]);
    assert!(frame.status.success(), "{:?}", frame.stderr);
    assert_eq!(parse_json(&frame)["result"]["bytes_hex"], IPV4_FRAME_HEX);
}

fn decode_hex(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let pair = std::str::from_utf8(pair).expect("fixture hex must be UTF-8");
            u8::from_str_radix(pair, 16).expect("fixture hex must be valid")
        })
        .collect()
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
