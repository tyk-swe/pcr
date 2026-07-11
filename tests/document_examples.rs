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

fn route_decision() -> packetcraftr::RouteDecision {
    packetcraftr::RouteDecision {
        interface: packetcraftr::InterfaceId {
            name: "lab0".to_owned(),
            index: 2,
        },
        source_mac: Some(packetcraftr::MacAddress([2, 0, 0, 0, 0, 1])),
        selected_address: Some("192.168.56.2".parse().unwrap()),
        preferred_source: None,
        next_hop: Some("192.168.56.1".parse().unwrap()),
        selection_reason: packetcraftr::RouteSelectionReason::Gateway,
        destination_scope: packetcraftr::DestinationScope::Private,
        mtu: 1500,
        capability: packetcraftr::LinkCapability::Layer2And3,
        link_type: packetcraftr::LinkType::ETHERNET,
    }
}

fn planned_route() -> packetcraftr::PlannedRoute {
    packetcraftr::PlannedRoute {
        route: route_decision(),
        mode: packetcraftr::LinkMode::Layer2,
        lookup_destination: Some("192.168.56.9".parse().unwrap()),
        final_destination: Some("192.168.56.9".parse().unwrap()),
        visited_destinations: vec!["192.168.56.9".parse().unwrap()],
        packet_source: Some("192.168.56.2".parse().unwrap()),
        neighbor_source: Some("192.168.56.2".parse().unwrap()),
        neighbor_target: Some("192.168.56.1".parse().unwrap()),
        destination_mac: Some(packetcraftr::MacAddress([2, 0, 0, 0, 0, 2])),
        source_mac: Some(packetcraftr::MacAddress([2, 0, 0, 0, 0, 1])),
        neighbor_vlan_tags: vec![packetcraftr::NeighborVlanTag {
            kind: packetcraftr::NeighborVlanKind::Ieee8021Q,
            priority: 0,
            drop_eligible: false,
            vlan_id: 42,
        }],
        synthesized_ethernet: true,
    }
}

fn operation_stats() -> packetcraftr::OperationStats {
    packetcraftr::OperationStats {
        packets_attempted: 1,
        packets_completed: 1,
        bytes: 4,
        elapsed: std::time::Duration::ZERO,
        capture: packetcraftr::CaptureStatistics::default(),
    }
}

fn exact_frame() -> packetcraftr::CapturedFrame {
    packetcraftr::CapturedFrame::new(
        std::time::UNIX_EPOCH,
        packetcraftr::LinkType(147),
        vec![0xde, 0xad, 0xbe, 0xef],
    )
    .unwrap()
}

#[test]
fn every_command_has_published_success_and_error_goldens() {
    for contract in packetcraftr::COMMAND_OUTPUT_CONTRACTS {
        let command = contract.command.as_str();
        let success = example(&format!("output-{command}-success.json"));
        let event = example(&format!("output-{command}-event.json"));
        assert!(
            success.is_file() || event.is_file(),
            "{command} has no success/event golden"
        );
        assert!(
            example(&format!("output-{command}-error.json")).is_file(),
            "{command} has no error golden"
        );
    }
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
fn published_dissect_success_output_matches_the_cli() {
    let output = binary()
        .args([
            "--output",
            "json",
            "dissect",
            "--hex",
            "deadbeef",
            "--link-type",
            "147",
        ])
        .output()
        .unwrap();

    assert!(output.status.success());
    let actual: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(actual, json_file("output-dissect-success.json"));
}

#[test]
fn published_route_and_live_success_outputs_match_typed_contracts() {
    let plan = packetcraftr::AggregateOutput::success(
        packetcraftr::CommandName::Plan,
        packetcraftr::PlanCommandResult {
            route: planned_route(),
        },
        Vec::new(),
    );
    assert_eq!(
        serde_json::to_value(plan).unwrap(),
        json_file("output-plan-success.json")
    );

    let routes = packetcraftr::AggregateOutput::success(
        packetcraftr::CommandName::Routes,
        packetcraftr::RoutesCommandResult {
            routes: vec![route_decision()],
        },
        Vec::new(),
    );
    assert_eq!(
        serde_json::to_value(routes).unwrap(),
        json_file("output-routes-success.json")
    );

    let interfaces = packetcraftr::AggregateOutput::success(
        packetcraftr::CommandName::Interfaces,
        packetcraftr::InterfacesCommandResult {
            interfaces: vec![packetcraftr::InterfaceOutput {
                name: "lab0".to_owned(),
                index: 2,
                description: Some("isolated test interface".to_owned()),
                mac: Some("02:00:00:00:00:01".to_owned()),
                addresses: vec!["192.168.56.2/24".to_owned()],
                flags: packetcraftr::InterfaceFlags {
                    up: true,
                    broadcast: true,
                    loopback: false,
                    point_to_point: false,
                    multicast: true,
                },
                mtu: Some(1500),
                capability: packetcraftr::LinkCapability::Layer2And3,
                link_type: 1,
            }],
        },
        Vec::new(),
    );
    assert_eq!(
        serde_json::to_value(interfaces).unwrap(),
        json_file("output-interfaces-success.json")
    );

    let send = packetcraftr::AggregateOutput::success(
        packetcraftr::CommandName::Send,
        packetcraftr::SendCommandResult {
            frame: packetcraftr::WireFrameOutput::new(vec![0xde, 0xad, 0xbe, 0xef]),
            route: packetcraftr::MaterializedRouteOutput {
                plan: planned_route(),
                neighbor: None,
            },
        },
        Vec::new(),
    )
    .with_stats(operation_stats());
    assert_eq!(
        serde_json::to_value(send).unwrap(),
        json_file("output-send-success.json")
    );

    let exchange = packetcraftr::AggregateOutput::success(
        packetcraftr::CommandName::Exchange,
        packetcraftr::ExchangeCommandResult {
            sent: vec![packetcraftr::WireFrameOutput::new(vec![
                0xde, 0xad, 0xbe, 0xef,
            ])],
            responses: Vec::new(),
            unanswered: vec![0],
            unsolicited: Vec::new(),
            undecoded: Vec::new(),
        },
        Vec::new(),
    )
    .with_stats(operation_stats());
    assert_eq!(
        serde_json::to_value(exchange).unwrap(),
        json_file("output-exchange-success.json")
    );
}

#[test]
fn published_read_and_replay_stream_events_match_typed_contracts() {
    let read = packetcraftr::StreamRecord::success(
        packetcraftr::CommandName::Read,
        0,
        packetcraftr::ReadFrameCommandResult::try_from_frame(exact_frame()).unwrap(),
        Vec::new(),
    );
    assert_eq!(
        serde_json::to_value(read).unwrap(),
        json_file("output-read-event.json")
    );

    let replay = packetcraftr::StreamRecord::success(
        packetcraftr::CommandName::Replay,
        0,
        packetcraftr::ReplayFrameCommandResult {
            source_sequence: 0,
            interface: packetcraftr::InterfaceId {
                name: "lab0".to_owned(),
                index: 2,
            },
            link_mode: packetcraftr::LinkMode::Auto,
            scheduled_delay: std::time::Duration::ZERO,
            bytes_sent: 4,
            frame: packetcraftr::FrameOutput::try_from_frame(exact_frame()).unwrap(),
            transmitted: true,
        },
        Vec::new(),
    );
    assert_eq!(
        serde_json::to_value(replay).unwrap(),
        json_file("output-replay-event.json")
    );
}

#[test]
fn published_tool_aggregate_success_outputs_match_typed_contracts() {
    let destination = "192.168.56.10".parse().unwrap();
    let scan = packetcraftr::AggregateOutput::success(
        packetcraftr::CommandName::Scan,
        packetcraftr::ScanCommandResult {
            target: "192.168.56.10".to_owned(),
            resolved_addresses: vec![destination],
            ports: vec![packetcraftr::ScanPortOutput {
                port: 443,
                transport: "tcp".to_owned(),
                classification: packetcraftr::ScanClassification::Timeout,
                evidence: vec![packetcraftr::ProbeEvidenceOutput {
                    protocol: "tcp".to_owned(),
                    destination,
                    destination_port: Some(443),
                    attempt: 1,
                    status: packetcraftr::ScanProbeStatus::Timeout,
                    classification: packetcraftr::ScanClassification::Timeout,
                    responder: None,
                    sent_at: packetcraftr::OutputTimestamp {
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
    .with_stats(packetcraftr::OperationStats {
        packets_attempted: 1,
        packets_completed: 1,
        bytes: 40,
        elapsed: std::time::Duration::from_secs(1),
        capture: packetcraftr::CaptureStatistics::default(),
    });
    assert_eq!(
        serde_json::to_value(scan).unwrap(),
        json_file("output-scan-success.json")
    );

    let mut response_frame = packetcraftr::CapturedFrame::new(
        std::time::UNIX_EPOCH
            + std::time::Duration::from_secs(1_770_000_000)
            + std::time::Duration::from_millis(4),
        packetcraftr::LinkType(147),
        vec![0xde, 0xad, 0xbe, 0xef],
    )
    .unwrap();
    response_frame.interface = Some(0);
    response_frame.direction = Some(packetcraftr::CaptureDirection::Inbound);
    let traceroute = packetcraftr::AggregateOutput::success(
        packetcraftr::CommandName::Traceroute,
        packetcraftr::TracerouteCommandResult {
            target: "router.lab".to_owned(),
            resolved_addresses: vec![destination],
            destination,
            strategy: "udp".to_owned(),
            destination_port: Some(33_434),
            hops: vec![
                packetcraftr::TraceHopOutput {
                    hop_limit: 1,
                    probes: vec![
                        packetcraftr::TraceProbeOutput {
                            sequence: 0,
                            hop_limit: 1,
                            attempt: 1,
                            strategy: "udp".to_owned(),
                            destination,
                            destination_port: Some(33_434),
                            status: packetcraftr::TraceProbeStatus::Response,
                            response_kind: Some(
                                packetcraftr::TraceResponseKind::Intermediate,
                            ),
                            responder: Some("192.168.56.1".parse().unwrap()),
                            sent_at: packetcraftr::OutputTimestamp {
                                unix_seconds: 1_770_000_000,
                                nanoseconds: 0,
                            },
                            received_at: Some(packetcraftr::OutputTimestamp {
                                unix_seconds: 1_770_000_000,
                                nanoseconds: 4_000_000,
                            }),
                            latency: Some(std::time::Duration::from_millis(4)),
                            frame: Some(
                                packetcraftr::FrameOutput::try_from_frame(response_frame).unwrap(),
                            ),
                            reason: "ICMPv4 time exceeded before reaching the endpoint".to_owned(),
                        },
                        packetcraftr::TraceProbeOutput {
                            sequence: 1,
                            hop_limit: 1,
                            attempt: 2,
                            strategy: "udp".to_owned(),
                            destination,
                            destination_port: Some(33_435),
                            status: packetcraftr::TraceProbeStatus::Timeout,
                            response_kind: None,
                            responder: None,
                            sent_at: packetcraftr::OutputTimestamp {
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
                packetcraftr::TraceHopOutput {
                    hop_limit: 2,
                    probes: vec![packetcraftr::TraceProbeOutput {
                        sequence: 2,
                        hop_limit: 2,
                        attempt: 1,
                        strategy: "udp".to_owned(),
                        destination,
                        destination_port: Some(33_436),
                        status: packetcraftr::TraceProbeStatus::Response,
                        response_kind: Some(
                            packetcraftr::TraceResponseKind::DestinationReached,
                        ),
                        responder: Some(destination),
                        sent_at: packetcraftr::OutputTimestamp {
                            unix_seconds: 1_770_000_001,
                            nanoseconds: 0,
                        },
                        received_at: Some(packetcraftr::OutputTimestamp {
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
            completion: packetcraftr::TraceCompletionReason::DestinationReached,
        },
        Vec::new(),
    )
    .with_stats(packetcraftr::OperationStats {
        packets_attempted: 3,
        packets_completed: 3,
        bytes: 126,
        elapsed: std::time::Duration::new(1, 15_000_000),
        capture: packetcraftr::CaptureStatistics {
            received_frames: 2,
            received_bytes: 8,
            ..packetcraftr::CaptureStatistics::default()
        },
    });
    assert_eq!(
        serde_json::to_value(traceroute).unwrap(),
        json_file("output-traceroute-success.json")
    );

    let dns = packetcraftr::AggregateOutput::success(
        packetcraftr::CommandName::Dns,
        packetcraftr::DnsCommandResult {
            server: "resolver.lab".to_owned(),
            server_port: 53,
            resolved_addresses: vec!["192.168.56.53".parse().unwrap()],
            query_name: "txt.example.test.".to_owned(),
            query_type: "txt".to_owned(),
            transaction_id: 20_547,
            transport: "udp".to_owned(),
            outcome: packetcraftr::DnsOutcome::Response,
            response_code: Some(0),
            response_code_name: Some("no_error".to_owned()),
            authoritative: Some(false),
            truncated: Some(false),
            recursion_desired: Some(true),
            recursion_available: Some(true),
            authenticated_data: Some(false),
            checking_disabled: Some(false),
            answers: vec![packetcraftr::DnsRecordOutput {
                owner: "txt.example.test.".to_owned(),
                class: 1,
                ttl: 60,
                data: packetcraftr::DnsRecordData::Txt {
                    strings: vec!["remote\u{1b}[31m".to_owned()],
                    strings_hex: vec!["72656d6f74651b5b33316d".to_owned()],
                },
            }],
            authorities: Vec::new(),
            additionals: Vec::new(),
            rejected_records: vec![packetcraftr::DnsRejectedRecordOutput {
                section: packetcraftr::DnsSection::Additional,
                index: 0,
                owner: "unrelated.example.test.".to_owned(),
                type_code: 1,
                reason:
                    "additional record is not IN-class address glue referenced by accepted data"
                        .to_owned(),
            }],
            rejected_record_count: 1,
            attempts: vec![packetcraftr::DnsAttemptOutput {
                attempt: 1,
                server_address: "192.168.56.53".parse().unwrap(),
                source_port: 50_000,
                status: packetcraftr::DnsAttemptStatus::Response,
                sent_at: packetcraftr::OutputTimestamp {
                    unix_seconds: 1_770_000_000,
                    nanoseconds: 0,
                },
                received_at: Some(packetcraftr::OutputTimestamp {
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
    .with_stats(packetcraftr::OperationStats {
        packets_attempted: 1,
        packets_completed: 1,
        bytes: 58,
        elapsed: std::time::Duration::from_millis(5),
        capture: packetcraftr::CaptureStatistics {
            received_frames: 1,
            received_bytes: 96,
            ..packetcraftr::CaptureStatistics::default()
        },
    });
    assert_eq!(
        serde_json::to_value(dns).unwrap(),
        json_file("output-dns-success.json")
    );
}

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
