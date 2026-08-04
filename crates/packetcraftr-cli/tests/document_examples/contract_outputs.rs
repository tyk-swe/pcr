// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::{
    AggregateOutput, CaptureDirection, CaptureFileFormat, CaptureFrameCommandResult,
    CaptureStatistics, CapturedFrame, CommandName, Diagnostic, DnsAttemptOutput, DnsAttemptStatus,
    DnsOutcome, DnsStreamCommandResult, ExchangeStreamCommandResult, FrameOutput, InterfaceId,
    LinkMode, LinkType, OperationStats, OutputTimestamp, ReplayCommandResult, ReplaySummary,
    ReplayTiming, StreamRecord, binary, json_file,
};

#[test]
fn published_error_outputs_match_every_command_cli_path() {
    let cases: &[(&str, i32, &[&str])] = &[
        (
            "build",
            3,
            &["--output", "json", "build", "--packet", "ethernet()/udp()"],
        ),
        (
            "dissect",
            2,
            &["--output", "json", "dissect", "--hex", "zz"],
        ),
        (
            "plan",
            2,
            &["--output", "json", "plan", "--packet", "raw()"],
        ),
        (
            "send",
            6,
            &[
                "--output",
                "json",
                "send",
                "--packet",
                "ipv4(src=192.0.2.1,dst=8.8.8.8)/udp(dport=9)",
            ],
        ),
        (
            "exchange",
            6,
            &[
                "--output",
                "json",
                "exchange",
                "--packet",
                "ipv4(src=192.0.2.1,dst=8.8.8.8)/udp(dport=9)",
            ],
        ),
        (
            "capture",
            6,
            &[
                "--output",
                "ndjson",
                "capture",
                "--packet",
                "ipv4(src=192.0.2.1,dst=8.8.8.8)/udp(dport=9)",
            ],
        ),
        (
            "read",
            2,
            &[
                "--output",
                "ndjson",
                "read",
                "missing.pcap",
                "--max-frames",
                "0",
            ],
        ),
        (
            "replay",
            2,
            &[
                "--output",
                "json",
                "replay",
                "missing.pcap",
                "--interface",
                "lab0",
                "--max-packets",
                "0",
            ],
        ),
        (
            "scan",
            6,
            &["--output", "json", "scan", "8.8.8.8", "--ports", "80"],
        ),
        (
            "traceroute",
            6,
            &["--output", "json", "traceroute", "8.8.8.8"],
        ),
        (
            "dns",
            6,
            &["--output", "json", "dns", "8.8.8.8", "example.com"],
        ),
        (
            "fuzz",
            2,
            &[
                "--output", "json", "fuzz", "--packet", "raw()", "--cases", "0",
            ],
        ),
        ("interfaces", 2, &["--output", "ndjson", "interfaces"]),
        ("routes", 2, &["--output", "ndjson", "routes"]),
    ];

    for (command, exit_code, arguments) in cases {
        let output = binary().args(*arguments).output().unwrap();
        assert_eq!(output.status.code(), Some(*exit_code), "{command}");
        let actual: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(
            actual,
            json_file(&format!("output-{command}-error.json")),
            "{command}"
        );
    }
}

#[test]
fn published_exchange_stream_event_matches_the_typed_contract() {
    let event = StreamRecord::success(
        CommandName::Exchange,
        3,
        ExchangeStreamCommandResult::Complete {
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
    let mut frame = CapturedFrame::new(
        std::time::UNIX_EPOCH
            + std::time::Duration::from_secs(1_783_555_200)
            + std::time::Duration::from_millis(125),
        LinkType(147),
        vec![0xde, 0xad, 0xbe, 0xef],
    )
    .unwrap();
    frame.interface = Some(0);
    frame.direction = Some(CaptureDirection::Inbound);
    let event = StreamRecord::success(
        CommandName::Capture,
        0,
        CaptureFrameCommandResult::Frame {
            frame: FrameOutput::try_from_frame(frame).unwrap(),
        },
        vec![Diagnostic::warning(
            "decode.unsupported_link_type",
            "no root binding for link type 147",
        )],
    )
    .with_stats(OperationStats {
        packets_attempted: 1,
        packets_completed: 1,
        bytes: 4,
        elapsed: std::time::Duration::from_micros(250),
        capture: CaptureStatistics {
            received_frames: 1,
            received_bytes: 4,
            ..CaptureStatistics::default()
        },
    });

    assert_eq!(
        serde_json::to_value(event).unwrap(),
        json_file("output-capture-event.json")
    );
}

#[test]
fn published_dns_stream_outputs_match_typed_contracts() {
    let event = StreamRecord::success(
        CommandName::Dns,
        0,
        DnsStreamCommandResult::Attempt {
            server: "resolver.lab".to_owned(),
            server_port: 53,
            query_name: "www.example.test.".to_owned(),
            query_type: "a".to_owned(),
            evidence: DnsAttemptOutput {
                attempt: 1,
                server_address: "192.168.56.53".parse().unwrap(),
                source_port: 50_000,
                status: DnsAttemptStatus::Timeout,
                sent_at: OutputTimestamp {
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

    let complete = StreamRecord::success(
        CommandName::Dns,
        2,
        DnsStreamCommandResult::Complete {
            server: "resolver.lab".to_owned(),
            server_port: 53,
            resolved_addresses: vec![
                "192.168.56.53".parse().unwrap(),
                "192.168.56.54".parse().unwrap(),
            ],
            query_name: "www.example.test.".to_owned(),
            query_type: "a".to_owned(),
            transaction_id: 20_547,
            transport: "udp".to_owned(),
            outcome: DnsOutcome::Response,
            response_code: Some(0),
            response_code_name: Some("no_error".to_owned()),
            edns: None,
            authoritative: Some(false),
            truncated: Some(false),
            recursion_desired: Some(true),
            recursion_available: Some(true),
            authenticated_data: Some(false),
            checking_disabled: Some(false),
            rejected_record_count: 0,
        },
        Vec::new(),
    )
    .with_stats(OperationStats {
        packets_attempted: 2,
        packets_completed: 2,
        bytes: 116,
        elapsed: std::time::Duration::new(1, 5_000_000),
        capture: CaptureStatistics {
            received_frames: 1,
            received_bytes: 86,
            ..CaptureStatistics::default()
        },
    });
    assert_eq!(
        serde_json::to_value(complete).unwrap(),
        json_file("output-dns-complete.json")
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
    let result = ReplayCommandResult::from_summary(
        ReplaySummary {
            source_format: CaptureFileFormat::Pcap,
            timing: ReplayTiming::Immediate,
            frames_attempted: 0,
            frames_completed: 0,
            bytes_completed: 0,
            scheduled_duration: std::time::Duration::ZERO,
        },
        InterfaceId {
            name: "lab0".to_owned(),
            index: 2,
        },
        LinkMode::Auto,
        Vec::new(),
    );
    let output = AggregateOutput::success(CommandName::Replay, result, Vec::new());

    assert_eq!(
        serde_json::to_value(output).unwrap(),
        json_file("output-replay-success.json")
    );
}
