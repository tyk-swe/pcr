// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn binary() -> Command {
    Command::new(env!("CARGO_BIN_EXE_packetcraftr"))
}

fn example(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("examples/documents")
        .join(name)
}

fn json_file(name: &str) -> serde_json::Value {
    serde_json::from_slice(&fs::read(example(name)).unwrap()).unwrap()
}

#[test]
fn packet_document_example_builds_through_the_public_cli() {
    let output = binary()
        .args([
            "--output",
            "json",
            "build",
            "--packet-file",
            example("packet-ipv4-udp.json").to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["schema"], "packetcraftr.output/v1");
    assert_eq!(value["status"], "success");
    assert_eq!(value["result"]["length"], 47);
}

#[test]
fn published_build_success_output_matches_the_cli() {
    let output = binary()
        .args(["--output", "json", "build", "--packet", "raw(hex=deadbeef)"])
        .output()
        .unwrap();

    assert!(output.status.success());
    let actual: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(actual, json_file("output-build-success.json"));
}

#[test]
fn published_build_error_output_matches_the_cli() {
    let output = binary()
        .args(["--output", "json", "build", "--packet", "ethernet()/udp()"])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(3));
    let actual: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(actual, json_file("output-build-error.json"));
}

#[test]
fn published_exchange_stream_event_matches_the_typed_contract() {
    let event = packetcraftr::StreamRecord::success(
        packetcraftr::CommandName::Exchange,
        3,
        packetcraftr::ExchangeStreamCommandResult::Complete {
            unanswered: vec![1, 2],
        },
        Vec::new(),
    );

    assert_eq!(
        serde_json::to_value(event).unwrap(),
        json_file("output-exchange-event.json")
    );
}

#[test]
fn published_capture_stream_event_matches_the_typed_contract() {
    let mut frame = packetcraftr::CapturedFrame::new(
        std::time::UNIX_EPOCH
            + std::time::Duration::from_secs(1_783_555_200)
            + std::time::Duration::from_millis(125),
        packetcraftr::LinkType(147),
        vec![0xde, 0xad, 0xbe, 0xef],
    )
    .unwrap();
    frame.interface = Some(0);
    frame.direction = Some(packetcraftr::CaptureDirection::Inbound);
    let event = packetcraftr::StreamRecord::success(
        packetcraftr::CommandName::Capture,
        0,
        packetcraftr::CaptureFrameCommandResult::Frame {
            frame: packetcraftr::FrameOutput::try_from_frame(frame).unwrap(),
        },
        vec![packetcraftr::Diagnostic::warning(
            "decode.unsupported_link_type",
            "no root binding for link type 147",
        )],
    )
    .with_stats(packetcraftr::OperationStats {
        packets_attempted: 1,
        packets_completed: 1,
        bytes: 4,
        elapsed: std::time::Duration::from_micros(250),
        capture: packetcraftr::CaptureStatistics {
            received_frames: 1,
            received_bytes: 4,
            ..packetcraftr::CaptureStatistics::default()
        },
    });

    assert_eq!(
        serde_json::to_value(event).unwrap(),
        json_file("output-capture-event.json")
    );
}

#[test]
fn published_dns_stream_event_matches_the_typed_contract() {
    let event = packetcraftr::StreamRecord::success(
        packetcraftr::CommandName::Dns,
        0,
        packetcraftr::DnsStreamCommandResult::Attempt {
            server: "resolver.lab".to_owned(),
            server_port: 53,
            query_name: "www.example.test.".to_owned(),
            query_type: "a".to_owned(),
            evidence: packetcraftr::DnsAttemptOutput {
                attempt: 1,
                server_address: "192.168.56.53".parse().unwrap(),
                source_port: 50_000,
                status: packetcraftr::DnsAttemptStatus::Timeout,
                sent_at: packetcraftr::OutputTimestamp {
                    unix_seconds: 1_770_000_000,
                    nanoseconds: 0,
                },
                received_at: None,
                latency: None,
                frame: None,
                response_code: None,
                reason: "no checksum-valid, tuple-correlated DNS response before the deadline"
                    .to_owned(),
            },
        },
        Vec::new(),
    );

    assert_eq!(
        serde_json::to_value(event).unwrap(),
        json_file("output-dns-event.json")
    );
}

#[test]
fn published_fuzz_outputs_match_the_deterministic_offline_cli() {
    let aggregate = binary()
        .args([
            "--output",
            "json",
            "fuzz",
            "--packet",
            "raw(hex=\"00\")",
            "--seed",
            "1",
            "--cases",
            "1",
            "--strategy",
            "bit-flip",
            "--field",
            "0.bytes",
        ])
        .output()
        .unwrap();
    assert!(
        aggregate.status.success(),
        "{}",
        String::from_utf8_lossy(&aggregate.stderr)
    );
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&aggregate.stdout).unwrap(),
        json_file("output-fuzz-success.json")
    );

    let stream = binary()
        .args([
            "--output",
            "ndjson",
            "fuzz",
            "--packet",
            "raw(hex=\"00\")",
            "--seed",
            "1",
            "--cases",
            "1",
            "--strategy",
            "bit-flip",
            "--field",
            "0.bytes",
        ])
        .output()
        .unwrap();
    assert!(stream.status.success());
    let records = String::from_utf8(stream.stdout)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(records.len(), 2);
    assert_eq!(records[0], json_file("output-fuzz-event.json"));
    assert_eq!(records[1], json_file("output-fuzz-complete.json"));
}

#[test]
fn published_replay_output_matches_the_typed_contract() {
    let result = packetcraftr::ReplayCommandResult::from_summary(
        packetcraftr::ReplaySummary {
            source_format: packetcraftr::CaptureFileFormat::Pcap,
            timing: packetcraftr::ReplayTiming::Immediate,
            frames_attempted: 0,
            frames_completed: 0,
            bytes_completed: 0,
            scheduled_duration: std::time::Duration::ZERO,
        },
        packetcraftr::InterfaceId {
            name: "lab0".to_owned(),
            index: 2,
        },
        packetcraftr::LinkMode::Auto,
        Vec::new(),
    );
    let output = packetcraftr::AggregateOutput::success(
        packetcraftr::CommandName::Replay,
        result,
        Vec::new(),
    );

    assert_eq!(
        serde_json::to_value(output).unwrap(),
        json_file("output-replay-success.json")
    );
}
