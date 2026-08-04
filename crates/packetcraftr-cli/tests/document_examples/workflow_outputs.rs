// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::{
    AggregateOutput, CaptureDirection, CaptureStatistics, CapturedFrame, CommandName,
    DnsAttemptOutput, DnsAttemptStatus, DnsCommandResult, DnsOutcome, DnsRecordData,
    DnsRecordOutput, DnsRejectedRecordOutput, DnsSection, FrameOutput, LinkType, OperationStats,
    OutputTimestamp, ProbeEvidenceOutput, ScanClassification, ScanCommandResult, ScanPortOutput,
    ScanProbeStatus, ScanStreamCommandResult, StreamRecord, TraceCompletionReason, TraceHopOutput,
    TraceProbeOutput, TraceProbeStatus, TraceResponseKind, TracerouteCommandResult,
    TracerouteStreamCommandResult, json_file,
};

#[test]
fn published_tool_aggregate_success_outputs_match_typed_contracts() {
    let destination = "192.168.56.10".parse().unwrap();
    let scan = AggregateOutput::success(
        CommandName::Scan,
        ScanCommandResult {
            target: "192.168.56.10".to_owned(),
            resolved_addresses: vec![destination],
            ports: vec![ScanPortOutput {
                port: 443,
                transport: "tcp".to_owned(),
                classification: ScanClassification::Timeout,
                evidence: vec![ProbeEvidenceOutput {
                    protocol: "tcp".to_owned(),
                    destination,
                    destination_port: Some(443),
                    attempt: 1,
                    status: ScanProbeStatus::Timeout,
                    classification: ScanClassification::Timeout,
                    responder: None,
                    sent_at: OutputTimestamp {
                        unix_seconds: 1_770_000_000,
                        nanoseconds: 0,
                    },
                    received_at: None,
                    latency: None,
                    frame: None,
                    reason: "no checksum-valid, protocol-consistent response before the deadline"
                        .to_owned(),
                }],
            }],
            undecoded: Vec::new(),
        },
        Vec::new(),
    )
    .with_stats(OperationStats {
        packets_attempted: 1,
        packets_completed: 1,
        bytes: 40,
        elapsed: std::time::Duration::from_secs(1),
        capture: CaptureStatistics::default(),
    });
    assert_eq!(
        serde_json::to_value(scan).unwrap(),
        json_file("output-scan-success.json")
    );

    let mut response_frame = CapturedFrame::new(
        std::time::UNIX_EPOCH
            + std::time::Duration::from_secs(1_770_000_000)
            + std::time::Duration::from_millis(4),
        LinkType(147),
        vec![0xde, 0xad, 0xbe, 0xef],
    )
    .unwrap();
    response_frame.interface = Some(0);
    response_frame.direction = Some(CaptureDirection::Inbound);
    let traceroute = AggregateOutput::success(
        CommandName::Traceroute,
        TracerouteCommandResult {
            target: "router.lab".to_owned(),
            resolved_addresses: vec![destination],
            destination,
            strategy: "udp".to_owned(),
            destination_port: Some(33_434),
            hops: vec![
                TraceHopOutput {
                    hop_limit: 1,
                    probes: vec![
                        TraceProbeOutput {
                            sequence: 0,
                            hop_limit: 1,
                            attempt: 1,
                            strategy: "udp".to_owned(),
                            destination,
                            destination_port: Some(33_434),
                            status: TraceProbeStatus::Response,
                            response_kind: Some(
                                TraceResponseKind::Intermediate,
                            ),
                            responder: Some("192.168.56.1".parse().unwrap()),
                            sent_at: OutputTimestamp {
                                unix_seconds: 1_770_000_000,
                                nanoseconds: 0,
                            },
                            received_at: Some(OutputTimestamp {
                                unix_seconds: 1_770_000_000,
                                nanoseconds: 4_000_000,
                            }),
                            latency: Some(std::time::Duration::from_millis(4)),
                            frame: Some(
                                FrameOutput::try_from_frame(response_frame).unwrap(),
                            ),
                            reason: "ICMPv4 time exceeded before reaching the endpoint".to_owned(),
                        },
                        TraceProbeOutput {
                            sequence: 1,
                            hop_limit: 1,
                            attempt: 2,
                            strategy: "udp".to_owned(),
                            destination,
                            destination_port: Some(33_435),
                            status: TraceProbeStatus::Timeout,
                            response_kind: None,
                            responder: None,
                            sent_at: OutputTimestamp {
                                unix_seconds: 1_770_000_000,
                                nanoseconds: 10_000_000,
                            },
                            received_at: None,
                            latency: None,
                            frame: None,
                            reason:
                                "no checksum-valid, protocol-consistent response before the deadline"
                                    .to_owned(),
                        },
                    ],
                },
                TraceHopOutput {
                    hop_limit: 2,
                    probes: vec![TraceProbeOutput {
                        sequence: 2,
                        hop_limit: 2,
                        attempt: 1,
                        strategy: "udp".to_owned(),
                        destination,
                        destination_port: Some(33_436),
                        status: TraceProbeStatus::Response,
                        response_kind: Some(
                            TraceResponseKind::DestinationReached,
                        ),
                        responder: Some(destination),
                        sent_at: OutputTimestamp {
                            unix_seconds: 1_770_000_001,
                            nanoseconds: 0,
                        },
                        received_at: Some(OutputTimestamp {
                            unix_seconds: 1_770_000_001,
                            nanoseconds: 5_000_000,
                        }),
                        latency: Some(std::time::Duration::from_millis(5)),
                        frame: None,
                        reason: "ICMPv4 port unreachable".to_owned(),
                    }],
                },
            ],
            undecoded: Vec::new(),
            completion: TraceCompletionReason::DestinationReached,
        },
        Vec::new(),
    )
    .with_stats(OperationStats {
        packets_attempted: 3,
        packets_completed: 3,
        bytes: 126,
        elapsed: std::time::Duration::new(1, 15_000_000),
        capture: CaptureStatistics {
            received_frames: 2,
            received_bytes: 8,
            ..CaptureStatistics::default()
        },
    });
    assert_eq!(
        serde_json::to_value(traceroute).unwrap(),
        json_file("output-traceroute-success.json")
    );

    let dns = AggregateOutput::success(
        CommandName::Dns,
        DnsCommandResult {
            server: "resolver.lab".to_owned(),
            server_port: 53,
            resolved_addresses: vec!["192.168.56.53".parse().unwrap()],
            query_name: "txt.example.test.".to_owned(),
            query_type: "txt".to_owned(),
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
            answers: vec![DnsRecordOutput {
                owner: "txt.example.test.".to_owned(),
                class: 1,
                ttl: 60,
                data: DnsRecordData::Txt {
                    strings: vec!["remote\u{1b}[31m".to_owned()],
                    strings_hex: vec!["72656d6f74651b5b33316d".to_owned()],
                },
            }],
            authorities: Vec::new(),
            additionals: Vec::new(),
            rejected_records: vec![DnsRejectedRecordOutput {
                section: DnsSection::Additional,
                index: 0,
                owner: "unrelated.example.test.".to_owned(),
                type_code: 1,
                reason:
                    "additional record is not IN-class address glue referenced by accepted data"
                        .to_owned(),
            }],
            rejected_record_count: 1,
            attempts: vec![DnsAttemptOutput {
                attempt: 1,
                server_address: "192.168.56.53".parse().unwrap(),
                source_port: 50_000,
                status: DnsAttemptStatus::Response,
                sent_at: OutputTimestamp {
                    unix_seconds: 1_770_000_000,
                    nanoseconds: 0,
                },
                received_at: Some(OutputTimestamp {
                    unix_seconds: 1_770_000_000,
                    nanoseconds: 5_000_000,
                }),
                latency: Some(std::time::Duration::from_millis(5)),
                frame: None,
                response_code: Some(0),
                reason: "validated DNS response with code no_error".to_owned(),
            }],
            undecoded: Vec::new(),
        },
        Vec::new(),
    )
    .with_stats(OperationStats {
        packets_attempted: 1,
        packets_completed: 1,
        bytes: 58,
        elapsed: std::time::Duration::from_millis(5),
        capture: CaptureStatistics {
            received_frames: 1,
            received_bytes: 96,
            ..CaptureStatistics::default()
        },
    });
    assert_eq!(
        serde_json::to_value(dns).unwrap(),
        json_file("output-dns-success.json")
    );
}

#[test]
fn published_scan_stream_outputs_match_typed_contracts() {
    let destination = "192.168.56.10".parse().unwrap();
    let event = StreamRecord::success(
        CommandName::Scan,
        0,
        ScanStreamCommandResult::Port {
            target: "192.168.56.10".to_owned(),
            resolved_address: destination,
            port: ScanPortOutput {
                port: 443,
                transport: "tcp".to_owned(),
                classification: ScanClassification::Timeout,
                evidence: vec![ProbeEvidenceOutput {
                    protocol: "tcp".to_owned(),
                    destination,
                    destination_port: Some(443),
                    attempt: 1,
                    status: ScanProbeStatus::Timeout,
                    classification: ScanClassification::Timeout,
                    responder: None,
                    sent_at: OutputTimestamp {
                        unix_seconds: 1_770_000_000,
                        nanoseconds: 0,
                    },
                    received_at: None,
                    latency: None,
                    frame: None,
                    reason: "no checksum-valid, protocol-consistent response before the deadline"
                        .to_owned(),
                }],
            },
        },
        Vec::new(),
    );
    assert_eq!(
        serde_json::to_value(event).unwrap(),
        json_file("output-scan-event.json")
    );

    let complete = StreamRecord::success(
        CommandName::Scan,
        1,
        ScanStreamCommandResult::Complete {
            target: "192.168.56.10".to_owned(),
            resolved_addresses: vec![destination],
        },
        Vec::new(),
    )
    .with_stats(OperationStats {
        packets_attempted: 1,
        packets_completed: 1,
        bytes: 40,
        elapsed: std::time::Duration::from_secs(1),
        capture: CaptureStatistics::default(),
    });
    assert_eq!(
        serde_json::to_value(complete).unwrap(),
        json_file("output-scan-complete.json")
    );
}

#[test]
fn published_traceroute_stream_outputs_match_typed_contracts() {
    let destination = "192.168.56.10".parse().unwrap();
    let event = StreamRecord::success(
        CommandName::Traceroute,
        0,
        TracerouteStreamCommandResult::Hop {
            target: "router.lab".to_owned(),
            destination,
            hop: TraceHopOutput {
                hop_limit: 1,
                probes: vec![TraceProbeOutput {
                    sequence: 0,
                    hop_limit: 1,
                    attempt: 1,
                    strategy: "udp".to_owned(),
                    destination,
                    destination_port: Some(33_434),
                    status: TraceProbeStatus::Response,
                    response_kind: Some(TraceResponseKind::Intermediate),
                    responder: Some("192.168.56.1".parse().unwrap()),
                    sent_at: OutputTimestamp {
                        unix_seconds: 1_770_000_000,
                        nanoseconds: 0,
                    },
                    received_at: Some(OutputTimestamp {
                        unix_seconds: 1_770_000_000,
                        nanoseconds: 4_000_000,
                    }),
                    latency: Some(std::time::Duration::from_millis(4)),
                    frame: None,
                    reason: "ICMPv4 time exceeded before reaching the endpoint".to_owned(),
                }],
            },
        },
        Vec::new(),
    );
    assert_eq!(
        serde_json::to_value(event).unwrap(),
        json_file("output-traceroute-event.json")
    );

    let complete = StreamRecord::success(
        CommandName::Traceroute,
        2,
        TracerouteStreamCommandResult::Complete {
            target: "router.lab".to_owned(),
            resolved_addresses: vec![destination],
            destination,
            strategy: "udp".to_owned(),
            destination_port: Some(33_434),
            completion: TraceCompletionReason::DestinationReached,
        },
        Vec::new(),
    )
    .with_stats(OperationStats {
        packets_attempted: 3,
        packets_completed: 3,
        bytes: 126,
        elapsed: std::time::Duration::new(1, 15_000_000),
        capture: CaptureStatistics {
            received_frames: 2,
            received_bytes: 8,
            ..CaptureStatistics::default()
        },
    });
    assert_eq!(
        serde_json::to_value(complete).unwrap(),
        json_file("output-traceroute-complete.json")
    );
}
