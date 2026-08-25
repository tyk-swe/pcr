// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::io::{Cursor, Write};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use packetcraftr::analysis::pcap::{Format as CaptureFormat, Reader};
use serde_json::Value;

#[path = "support/process.rs"]
mod process_support;
mod support;

use process_support::{append_truncated_record, decode_hex, run_with_stdin};
use support::{assert_contiguous, parse_json, parse_ndjson, run, run_success};

const IPV4_FRAME_HEX: &str = "45000014000000004001f6e7c0000201c6336402";

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

fn malformed_raw_frame_capture() -> tempfile::NamedTempFile {
    let mut capture = tempfile::NamedTempFile::new().expect("temporary capture must open");
    capture
        .write_all(&[
            0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 101, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0,
        ])
        .expect("valid frame must write");
    capture
}

fn partial_capture() -> tempfile::NamedTempFile {
    let mut capture = malformed_raw_frame_capture();
    append_truncated_record(&mut capture);
    capture
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
fn invalid_input_has_a_structured_exit_code() {
    let invalid = run(&[
        "--output", "json", "--color", "always", "dissect", "--hex", "zz",
    ]);
    assert_eq!(invalid.status.code(), Some(2));
    assert_no_terminal_style(&invalid.stdout);
    let value = parse_json(&invalid);
    assert_eq!(value["status"], "error");
    assert_eq!(value["error"]["kind"], "cli");
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
    assert_eq!(
        parse_json(&output)["result"]["dissection"]["bytes_hex"],
        IPV4_FRAME_HEX
    );
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
    assert_eq!(
        parse_json(&frame)["result"]["dissection"]["bytes_hex"],
        IPV4_FRAME_HEX
    );
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
    assert_eq!(
        parse_json(&frame)["result"]["dissection"]["bytes_hex"],
        IPV4_FRAME_HEX
    );
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

#[test]
fn runtime_stream_error_follows_every_preserved_record() {
    let capture = partial_capture();
    let path = capture.path().to_str().expect("temporary path is UTF-8");
    let failure = run(&["--output", "ndjson", "read", path, "--max-frames", "2"]);
    assert!(!failure.status.success());

    let records = parse_ndjson(&failure);
    assert_contiguous(&records);
    assert_eq!(records.len(), 2);
    assert_eq!(records[0]["status"], "success");
    assert_eq!(records[0]["result"]["event"], "frame");
    assert_eq!(records[0]["result"]["source_frame"], 1);
    assert_eq!(records[1]["status"], "error");
    assert_eq!(records[1]["sequence"], 1);
    assert!(
        records
            .iter()
            .all(|record| record["result"]["event"] != "complete")
    );
}

#[test]
fn progressive_live_commands_emit_one_sequence_zero_error_when_preparation_fails() {
    let commands: &[&[&str]] = &[
        &["--output", "ndjson", "scan", "8.8.8.8", "--ports", "80"],
        &[
            "--output",
            "ndjson",
            "traceroute",
            "8.8.8.8",
            "--strategy",
            "icmp",
            "--max-hops",
            "1",
            "--attempts",
            "1",
        ],
        &[
            "--output",
            "ndjson",
            "dns",
            "8.8.8.8",
            "example.com",
            "--transaction-id",
            "7",
            "--source-port",
            "49152",
        ],
    ];

    for arguments in commands {
        let failure = run(arguments);
        assert_eq!(failure.status.code(), Some(6), "{arguments:?}");
        let records = parse_ndjson(&failure);
        assert_contiguous(&records);
        assert_eq!(records.len(), 1, "{arguments:?}");
        assert_eq!(records[0]["sequence"], 0, "{arguments:?}");
        assert_eq!(records[0]["status"], "error", "{arguments:?}");
        assert!(records[0].get("result").is_none(), "{arguments:?}");
    }
}

#[test]
fn replay_rejects_malformed_capture_before_emitting_transmission_evidence() {
    let capture = malformed_raw_frame_capture();
    let path = capture.path().to_str().expect("temporary path is UTF-8");

    for format in ["text", "json", "ndjson", "pcap", "pcapng"] {
        let failure = run(&[
            "--output",
            format,
            "replay",
            path,
            "--interface",
            "fixture0",
            "--timing",
            "immediate",
        ]);
        assert_eq!(failure.status.code(), Some(3), "{format}: {failure:?}");

        match format {
            "json" => {
                let value = parse_json(&failure);
                assert_eq!(value["command"], "replay");
                assert_eq!(value["error"]["code"], "packet.replay_network");
            }
            "ndjson" => {
                let records = parse_ndjson(&failure);
                assert_contiguous(&records);
                assert_eq!(records.len(), 1);
                assert_eq!(records[0]["sequence"], 0);
                assert_eq!(records[0]["error"]["code"], "packet.replay_network");
            }
            "pcap" => {
                let mut reader = Reader::new(Cursor::new(failure.stdout.as_slice()))
                    .expect("failure output remains a valid classic capture");
                assert_eq!(reader.format(), CaptureFormat::Pcap);
                assert!(
                    reader
                        .next_frame()
                        .expect("capture remains readable")
                        .is_none(),
                    "no frame evidence may be written"
                );
                assert!(
                    String::from_utf8_lossy(&failure.stderr).contains("packet.replay_network"),
                    "{:?}",
                    failure.stderr
                );
            }
            "pcapng" => {
                let mut reader = Reader::new(Cursor::new(failure.stdout.as_slice()))
                    .expect("failure output remains a valid PCAPNG capture");
                assert_eq!(reader.format(), CaptureFormat::PcapNg);
                assert!(
                    reader
                        .next_frame()
                        .expect("capture remains readable")
                        .is_none(),
                    "no frame evidence may be written"
                );
                assert!(
                    String::from_utf8_lossy(&failure.stderr).contains("packet.replay_network"),
                    "{:?}",
                    failure.stderr
                );
            }
            "text" => {
                assert!(failure.stdout.is_empty());
                assert!(
                    String::from_utf8_lossy(&failure.stderr).contains("packet.replay_network"),
                    "{:?}",
                    failure.stderr
                );
            }
            _ => unreachable!("the fixture enumerates every asserted format"),
        }
    }
}

#[test]
fn unsupported_output_formats_fail_before_a_capture_is_read() {
    let capture = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/captures/tls-handshake.pcapng");
    let path = capture.to_str().expect("example capture path is UTF-8");

    for format in ["hex", "raw", "pcap", "pcapng"] {
        let refused = run(&["--output", format, "tls", path]);
        assert_eq!(refused.status.code(), Some(2), "{format}");
        assert!(refused.stdout.is_empty(), "{format}");
        let rendered = String::from_utf8_lossy(&refused.stderr);
        assert!(
            rendered.contains(&format!("tls does not support {format} output")),
            "{rendered}"
        );
        assert!(rendered.contains("choose text, json, ndjson"), "{rendered}");
    }
}
