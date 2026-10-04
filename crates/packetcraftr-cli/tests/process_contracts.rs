// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::io::{Cursor, Write};
#[cfg(packetcraftr_test_util_linux)]
use std::process::{Command, Output, Stdio};
#[cfg(packetcraftr_test_util_linux)]
use std::time::{Duration, Instant};

use packetcraftr_core::capture_file::Format as CaptureFormat;
use packetcraftr_core::capture_file::Reader;

mod common;
#[path = "common/process.rs"]
mod process_support;

use common::{assert_contiguous, parse_json, parse_ndjson, run};

#[cfg(packetcraftr_test_util_linux)]
fn run_command_with_open_stdin(mut command: Command) -> Output {
    let mut child = command
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
                    "command {command:?} waited for stdin: status={:?}, stdout={:?}, stderr={:?}",
                    output.status,
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr),
                );
            }
            Err(error) => {
                drop(stdin_writer);
                let _ = child.kill();
                let _ = child.wait();
                panic!("could not poll command {command:?}: {error}");
            }
        }
    }
}

#[cfg(packetcraftr_test_util_linux)]
#[test]
fn capture_commands_reject_before_reading() {
    common::require_util_linux_script();
    for arguments in [
        "read -",
        "expert -",
        "follow - --stream tcp:0",
        "stats -",
        "tls -",
    ] {
        let mut command = Command::new("script");
        command.env(
            "CAPTURE_STDIN_TEST_BINARY",
            env!("CARGO_BIN_EXE_packetcraftr"),
        );
        command.args([
            "--quiet",
            "--return",
            "--command",
            &format!("exec \"$CAPTURE_STDIN_TEST_BINARY\" {arguments}"),
            "/dev/null",
        ]);
        let output = run_command_with_open_stdin(command);
        assert_eq!(output.status.code(), Some(2), "{arguments}: {output:?}");
        let terminal = String::from_utf8_lossy(&output.stdout);
        assert!(terminal.contains("cli.input_source"), "{terminal}");
        assert!(terminal.contains("capture path"), "{terminal}");
    }
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

#[test]
fn replay_reject_bad_capture_before_tx_ev() {
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
fn unsup_formats_fail_before_command_work() {
    let directory = tempfile::tempdir().expect("temporary directory must open");
    let missing = directory.path().join("missing");
    let missing = missing.to_str().expect("temporary path is UTF-8");
    let cases: &[(&str, &[&str])] = &[
        ("pcap", &["dissect", "--file", missing]),
        ("pcap", &["protocols", "unknown-protocol"]),
        ("raw", &["read", missing]),
        ("pcap", &["interfaces", "--interface", "missing-interface"]),
        ("pcap", &["plan", "--packet-file", missing]),
        ("ndjson", &["send", "--packet-file", missing]),
        ("raw", &["exchange", "--packet-file", missing]),
        (
            "raw",
            &[
                "capture",
                "--interface",
                "missing-interface",
                "--timeout-ms",
                "0",
            ],
        ),
        ("pcap", &["expert", missing]),
        ("pcap", &["follow", missing, "--stream", "invalid"]),
        (
            "raw",
            &["replay", missing, "--interface", "missing-interface"],
        ),
        ("pcap", &["scan", "192.0.2.1", "--attempts", "0"]),
        ("pcap", &["stats", missing]),
        ("pcap", &["tls", missing]),
        ("pcap", &["traceroute", "192.0.2.1", "--max-hops", "0"]),
        (
            "pcap",
            &["dns", "192.0.2.1", "example.test", "--attempts", "0"],
        ),
        ("pcap", &["fuzz", "--packet-file", missing]),
        ("pcap", &["routes"]),
    ];

    for &(format, command) in cases {
        let mut arguments = vec!["--output", format];
        arguments.extend_from_slice(command);
        let refused = run(&arguments);
        assert_eq!(refused.status.code(), Some(2), "{arguments:?}: {refused:?}");
        let rendered = if format == "ndjson" {
            assert!(refused.stderr.is_empty(), "{arguments:?}");
            let records = parse_ndjson(&refused);
            assert_eq!(records.len(), 1, "{arguments:?}");
            assert_eq!(records[0]["error"]["code"], "cli.output_format");
            records[0]["error"]["message"].as_str().unwrap().to_owned()
        } else {
            assert!(refused.stdout.is_empty(), "{arguments:?}");
            let rendered = String::from_utf8_lossy(&refused.stderr).into_owned();
            assert!(rendered.contains("error[cli.output_format]"), "{rendered}");
            rendered
        };
        assert!(
            rendered.contains(&format!("{} does not support {format} output", command[0])),
            "{rendered}"
        );
        assert!(rendered.contains("choose "), "{rendered}");
    }
}

#[cfg(all(packetcraftr_test_util_linux, packetcraftr_test_dev_full))]
#[test]
fn binary_terminal_refusal_stderr_write_fails() {
    common::require_util_linux_script();
    common::require_dev_full();
    let mut command = Command::new("script");
    command.env(
        "BINARY_STDOUT_TEST_BINARY",
        env!("CARGO_BIN_EXE_packetcraftr"),
    );
    command.args([
        "--quiet",
        "--return",
        "--command",
        "exec \"$BINARY_STDOUT_TEST_BINARY\" --output raw build --packet 'raw(text=a)' 2>/dev/full",
        "/dev/null",
    ]);
    let output = run_command_with_open_stdin(command);
    assert_eq!(output.status.code(), Some(5), "{output:?}");
    assert!(output.stdout.is_empty(), "{output:?}");
}
