// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
// Test code indexes fixtures and counts by hand; the fail-closed lints are
// for library paths.
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

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
    let version = String::from_utf8_lossy(&version.stdout);
    assert!(
        version.contains(concat!("packetcraftr ", env!("CARGO_PKG_VERSION"))),
        "missing version in:\n{version}"
    );
    assert!(
        version.contains("native features:"),
        "missing native feature line in:\n{version}"
    );
    for (name, enabled) in [
        ("native-interfaces", cfg!(feature = "native-interfaces")),
        ("native-route", cfg!(feature = "native-route")),
        ("native-layer2", cfg!(feature = "native-layer2")),
        ("native-layer3", cfg!(feature = "native-layer3")),
    ] {
        if enabled {
            assert!(
                version.contains(name),
                "missing enabled feature {name:?} in:\n{version}"
            );
        }
    }
}

#[test]
fn dns_help_documents_bounded_tcp_fallback_without_network_access() {
    let help = run_success(&["dns", "--help"]);
    let help = String::from_utf8_lossy(&help.stdout);
    for expected in [
        "DNS-over-TCP continuation",
        "--udp-only",
        "share the same --timeout-ms attempt window",
        "DNS server port for UDP and any TCP fallback",
    ] {
        assert!(help.contains(expected), "missing {expected:?} in:\n{help}");
    }
}

#[test]
fn dns_fallback_rejects_raw_route_overrides_before_network_access() {
    let output = run(&[
        "--output",
        "json",
        "dns",
        "192.0.2.53",
        "example.test",
        "--interface",
        "fixture0",
    ]);
    assert_eq!(output.status.code(), Some(2));
    let error = parse_json(&output)["error"].clone();
    assert_eq!(error["kind"], "cli");
    assert!(error["message"].as_str().unwrap().contains("--udp-only"));
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

// These commands intentionally name a public destination. Keep them in the
// feature profile where the CLI has no native I/O implementation to invoke.
#[cfg(not(any(
    feature = "native-interfaces",
    feature = "native-route",
    feature = "native-layer2",
    feature = "native-layer3"
)))]
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

#[test]
fn dissect_rejects_byte_oriented_output_and_names_the_format() {
    let capture = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/captures/tls-handshake.pcapng");
    let path = capture.to_str().expect("example capture path is UTF-8");

    for format in ["hex", "pcap"] {
        let refused = run(&["--output", format, "read", path, "--dissect"]);
        assert_eq!(refused.status.code(), Some(2), "{format}");
        assert!(refused.stdout.is_empty(), "{format}");
        let rendered = String::from_utf8_lossy(&refused.stderr);
        assert!(
            rendered.contains("error[cli.dissect_unsupported_format]"),
            "{format}: {rendered}"
        );
        assert!(
            rendered.contains(&format!("--dissect has no effect on {format} output")),
            "{format}: {rendered}"
        );
    }
}

#[test]
fn build_enforces_configurable_layer_and_packet_budgets() {
    run_success(&["build", "--packet", "ipv4(dst=8.8.8.8)/udp(dport=9)"]);

    let expanded_recipe = ["raw"; 65].join("/");
    run_success(&["build", "--packet", &expanded_recipe, "--max-layers", "65"]);

    let expanded_over_budget = run(&["build", "--packet", &expanded_recipe, "--max-layers", "1"]);
    assert_eq!(
        expanded_over_budget.status.code(),
        Some(3),
        "{expanded_over_budget:?}"
    );
    assert!(
        String::from_utf8_lossy(&expanded_over_budget.stderr)
            .contains("packet.build_resource_limit"),
        "{expanded_over_budget:?}"
    );

    let mut document = tempfile::NamedTempFile::new().expect("packet document must open");
    let layers = (0..65)
        .map(|_| serde_json::json!({ "protocol": "raw", "fields": {} }))
        .collect::<Vec<_>>();
    serde_json::to_writer(
        &mut document,
        &serde_json::json!({
            "schema": "packetcraftr.packet/v1",
            "layers": layers,
        }),
    )
    .expect("packet document must write");
    document.flush().expect("packet document must flush");
    run_success(&[
        "build",
        "--packet-file",
        document.path().to_str().expect("packet path must be UTF-8"),
        "--max-layers",
        "65",
    ]);

    let layered = run(&[
        "build",
        "--packet",
        "ipv4(dst=8.8.8.8)/udp(dport=9)",
        "--max-layers",
        "1",
    ]);
    assert_eq!(layered.status.code(), Some(3), "{layered:?}");
    assert!(
        String::from_utf8_lossy(&layered.stderr).contains("packet.build_resource_limit"),
        "{layered:?}"
    );

    let oversized = run(&[
        "build",
        "--packet",
        "raw(text=hi)",
        "--max-packet-size",
        "1",
    ]);
    assert_eq!(oversized.status.code(), Some(3), "{oversized:?}");
    assert!(
        String::from_utf8_lossy(&oversized.stderr).contains("packet.build_resource_limit"),
        "{oversized:?}"
    );
}

#[test]
fn dissect_enforces_configurable_decode_budgets() {
    run_success(&["dissect", "--hex", IPV4_FRAME_HEX]);

    // Two layers (IPv4 plus ICMP echo) breach a one-layer budget.
    let layered = run(&[
        "dissect",
        "--hex",
        "4500001c0000000040017cdf7f0000017f0000010800f7ff00000000",
        "--max-layers",
        "1",
    ]);
    assert_eq!(layered.status.code(), Some(6), "{layered:?}");
    assert!(
        String::from_utf8_lossy(&layered.stderr).contains("policy.decode_resource_limit"),
        "{layered:?}"
    );

    let oversized = run(&["dissect", "--hex", IPV4_FRAME_HEX, "--max-packet-size", "1"]);
    assert_eq!(oversized.status.code(), Some(6), "{oversized:?}");
    assert!(
        String::from_utf8_lossy(&oversized.stderr).contains("policy.decode_resource_limit"),
        "{oversized:?}"
    );
}

#[test]
fn dissect_uses_the_packet_budget_for_file_and_stdin_reads() {
    let default_packet_size = packetcraftr::core::layout::DEFAULT_MAX_PACKET_SIZE;
    let packet_size = default_packet_size + 1;
    let packet_size_arg = packet_size.to_string();
    let frame = vec![0; packet_size];

    let mut frame_file = tempfile::NamedTempFile::new().expect("frame file must open");
    frame_file.write_all(&frame).expect("frame file must write");
    frame_file.flush().expect("frame file must flush");
    let from_file = run(&[
        "dissect",
        "--file",
        frame_file
            .path()
            .to_str()
            .expect("frame path must be UTF-8"),
        "--max-packet-size",
        &packet_size_arg,
    ]);
    assert!(from_file.status.success(), "{from_file:?}");

    let from_stdin = run_with_stdin(&["dissect", "--max-packet-size", &packet_size_arg], &frame);
    assert!(from_stdin.status.success(), "{from_stdin:?}");

    let default_packet_size_arg = default_packet_size.to_string();
    let oversized_file = run(&[
        "dissect",
        "--file",
        frame_file
            .path()
            .to_str()
            .expect("frame path must be UTF-8"),
        "--max-packet-size",
        &default_packet_size_arg,
    ]);
    let oversized_stdin = run_with_stdin(
        &["dissect", "--max-packet-size", &default_packet_size_arg],
        &frame,
    );
    for output in [oversized_file, oversized_stdin] {
        assert_eq!(output.status.code(), Some(6), "{output:?}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("policy.decode_resource_limit"),
            "{output:?}"
        );
    }

    let maximum_packet_size = usize::MAX.to_string();
    let maximum = run(&[
        "dissect",
        "--file",
        frame_file
            .path()
            .to_str()
            .expect("frame path must be UTF-8"),
        "--max-packet-size",
        &maximum_packet_size,
    ]);
    assert!(maximum.status.success(), "{maximum:?}");
}

#[test]
fn missing_input_file_reports_the_same_io_failure_for_every_reader() {
    let absent = tempfile::TempDir::new().expect("temporary directory must open");
    let missing = absent.path().join("packetcraftr-does-not-exist.pcap");
    let missing = missing.to_str().expect("temp path is UTF-8");
    let commands: [&[&str]; 6] = [
        &["--output", "json", "expert", missing],
        &["--output", "json", "follow", missing, "--stream", "tcp:0"],
        &["--output", "json", "stats", missing],
        &["--output", "json", "tls", missing],
        &["--output", "json", "build", "--packet-file", missing],
        &["--output", "json", "dissect", "--file", missing],
    ];
    for arguments in commands {
        let output = run(arguments);
        assert_eq!(output.status.code(), Some(5), "{arguments:?}");
        let error = parse_json(&output)["error"].clone();
        assert_eq!(error["code"], "io.runtime", "{arguments:?}");
        assert!(
            error["message"].as_str().unwrap().starts_with("open "),
            "{arguments:?}: {error}"
        );
    }
}
