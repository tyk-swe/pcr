// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::fs;
use std::path::PathBuf;
use std::process::Command;

use packetcraftr::{
    capture::{
        Direction as CaptureDirection, Format as CaptureFileFormat, Frame as CapturedFrame,
        LinkType,
    },
    net::{
        interface::Id as InterfaceId,
        link::{Capability as LinkCapability, MacAddress, Mode as LinkMode},
        neighbor::{VlanKind as NeighborVlanKind, VlanTag as NeighborVlanTag},
        route::{
            Decision as RouteDecision, Plan as PlannedRoute, Scope as DestinationScope,
            SelectionReason as RouteSelectionReason,
        },
    },
    output::{
        capture::{Event as CaptureFrameCommandResult, Read as ReadFrameCommandResult},
        contract::{CONTRACTS as COMMAND_OUTPUT_CONTRACTS, Command as CommandName},
        dns::{
            Attempt as DnsAttemptOutput, AttemptStatus as DnsAttemptStatus,
            Event as DnsStreamCommandResult, Outcome as DnsOutcome, Record as DnsRecordOutput,
            RecordData as DnsRecordData, RejectedRecord as DnsRejectedRecordOutput,
            Result as DnsCommandResult, Section as DnsSection,
        },
        envelope::{
            Aggregate as AggregateOutput, CaptureStats as CaptureStatistics,
            Stats as OperationStats, Stream as StreamRecord,
        },
        frame::{Captured as FrameOutput, Timestamp as OutputTimestamp, Wire as WireFrameOutput},
        network::{
            exchange::{Event as ExchangeStreamCommandResult, Result as ExchangeCommandResult},
            interfaces::{
                Capability as InterfaceCapability, Flags as InterfaceFlags,
                Interface as InterfaceOutput, Result as InterfacesCommandResult,
            },
            plan::Result as PlanCommandResult,
            routes::Result as RoutesCommandResult,
            send::{MaterializedRoute as MaterializedRouteOutput, Result as SendCommandResult},
        },
        replay::{Frame as ReplayFrameCommandResult, Result as ReplayCommandResult},
        scan::{
            Classification as ScanClassification, Event as ScanStreamCommandResult,
            Evidence as ProbeEvidenceOutput, Port as ScanPortOutput,
            ProbeStatus as ScanProbeStatus, Result as ScanCommandResult,
        },
        traceroute::{
            Completion as TraceCompletionReason, Event as TracerouteStreamCommandResult,
            Hop as TraceHopOutput, Probe as TraceProbeOutput, ProbeStatus as TraceProbeStatus,
            ResponseKind as TraceResponseKind, Result as TracerouteCommandResult,
        },
    },
    packet::diagnostic::Diagnostic,
    workflow::replay::{Summary as ReplaySummary, Timing as ReplayTiming},
};

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

fn route_decision() -> RouteDecision {
    RouteDecision {
        interface: InterfaceId {
            name: "lab0".to_owned(),
            index: 2,
        },
        source_mac: Some(MacAddress([2, 0, 0, 0, 0, 1])),
        selected_address: Some("192.168.56.2".parse().unwrap()),
        preferred_source: None,
        next_hop: Some("192.168.56.1".parse().unwrap()),
        selection_reason: RouteSelectionReason::Gateway,
        destination_scope: DestinationScope::Private,
        mtu: 1500,
        capability: LinkCapability::Layer2And3,
        link_type: LinkType::ETHERNET,
    }
}

fn planned_route() -> PlannedRoute {
    PlannedRoute {
        route: route_decision(),
        mode: LinkMode::Layer2,
        lookup_destination: Some("192.168.56.9".parse().unwrap()),
        final_destination: Some("192.168.56.9".parse().unwrap()),
        visited_destinations: vec!["192.168.56.9".parse().unwrap()],
        packet_source: Some("192.168.56.2".parse().unwrap()),
        neighbor_source: Some("192.168.56.2".parse().unwrap()),
        neighbor_target: Some("192.168.56.1".parse().unwrap()),
        destination_mac: Some(MacAddress([2, 0, 0, 0, 0, 2])),
        source_mac: Some(MacAddress([2, 0, 0, 0, 0, 1])),
        neighbor_vlan_tags: vec![NeighborVlanTag {
            kind: NeighborVlanKind::Ieee8021Q,
            priority: 0,
            drop_eligible: false,
            vlan_id: 42,
        }],
        synthesized_ethernet: true,
    }
}

fn operation_stats() -> OperationStats {
    OperationStats {
        packets_attempted: 1,
        packets_completed: 1,
        bytes: 4,
        elapsed: std::time::Duration::ZERO,
        capture: CaptureStatistics::default(),
    }
}

fn exact_frame() -> CapturedFrame {
    CapturedFrame::new(
        std::time::UNIX_EPOCH,
        LinkType(147),
        vec![0xde, 0xad, 0xbe, 0xef],
    )
    .unwrap()
}

fn packet_protocols(value: &serde_json::Value) -> Vec<&str> {
    value["result"]["packet"]["layers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|layer| layer["protocol"].as_str().unwrap())
        .collect()
}

fn assert_gre_sctp_example(value: &serde_json::Value) {
    assert_eq!(
        packet_protocols(value),
        ["ipv4", "gre", "ipv6", "sctp", "raw"]
    );
    assert_eq!(
        value["result"]["packet"]["layers"][0]["fields"]["protocol"]["value"],
        47
    );
    assert_eq!(
        value["result"]["packet"]["layers"][1]["fields"]["protocol_type"]["value"],
        0x86dd
    );
    assert_eq!(
        value["result"]["packet"]["layers"][2]["fields"]["next_header"]["value"],
        132
    );
    assert_eq!(
        value["result"]["packet"]["layers"][3]["fields"]["checksum"]["type"],
        "unsigned"
    );
    assert_eq!(
        value["result"]["layout"]["layers"]
            .as_array()
            .unwrap()
            .len(),
        5
    );
}

fn assert_igmp_example(value: &serde_json::Value) {
    assert_eq!(packet_protocols(value), ["ipv4", "igmp"]);
    assert_eq!(
        value["result"]["packet"]["layers"][0]["fields"]["ttl"]["type"],
        "unsigned"
    );
    assert_eq!(
        value["result"]["packet"]["layers"][0]["fields"]["ttl"]["value"],
        1
    );
    assert_eq!(
        value["result"]["packet"]["layers"][0]["fields"]["protocol"]["value"],
        2
    );
    assert_eq!(
        value["result"]["packet"]["layers"][1]["fields"]["checksum"]["type"],
        "unsigned"
    );
}

#[test]
fn every_command_has_published_success_and_error_goldens() {
    for contract in COMMAND_OUTPUT_CONTRACTS {
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
fn packet_document_examples_build_through_the_public_cli() {
    type ResultAssertion = fn(&serde_json::Value);
    for (name, expected_length, assert_result) in [
        ("packet-ipv4-udp.json", 47, None),
        (
            "packet-gre-sctp.json",
            108,
            Some(assert_gre_sctp_example as ResultAssertion),
        ),
        (
            "packet-igmp.json",
            28,
            Some(assert_igmp_example as ResultAssertion),
        ),
        ("packet-raw.yaml", 4, None),
    ] {
        let output = binary()
            .args([
                "--output",
                "json",
                "build",
                "--packet-file",
                example(name).to_str().unwrap(),
            ])
            .output()
            .unwrap();

        assert!(
            output.status.success(),
            "{name}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(value["schema"], "packetcraftr.output/v1", "{name}");
        assert_eq!(value["status"], "success", "{name}");
        assert_eq!(value["result"]["length"], expected_length, "{name}");
        if let Some(assert_result) = assert_result {
            assert_result(&value);
        }
    }
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
    let plan = AggregateOutput::success(
        CommandName::Plan,
        PlanCommandResult {
            route: planned_route().into(),
        },
        Vec::new(),
    );
    assert_eq!(
        serde_json::to_value(plan).unwrap(),
        json_file("output-plan-success.json")
    );

    let routes = AggregateOutput::success(
        CommandName::Routes,
        RoutesCommandResult {
            routes: vec![route_decision().into()],
        },
        Vec::new(),
    );
    assert_eq!(
        serde_json::to_value(routes).unwrap(),
        json_file("output-routes-success.json")
    );

    let interfaces = AggregateOutput::success(
        CommandName::Interfaces,
        InterfacesCommandResult {
            interfaces: vec![InterfaceOutput {
                name: "lab0".to_owned(),
                index: 2,
                description: Some("isolated test interface".to_owned()),
                mac: Some("02:00:00:00:00:01".to_owned()),
                addresses: vec!["192.168.56.2/24".to_owned()],
                flags: InterfaceFlags {
                    up: true,
                    broadcast: true,
                    loopback: false,
                    point_to_point: false,
                    multicast: true,
                },
                mtu: Some(1500),
                capability: InterfaceCapability::Layer2And3,
                link_type: 1,
            }],
        },
        Vec::new(),
    );
    assert_eq!(
        serde_json::to_value(interfaces).unwrap(),
        json_file("output-interfaces-success.json")
    );

    let send = AggregateOutput::success(
        CommandName::Send,
        SendCommandResult {
            frame: WireFrameOutput::new(vec![0xde, 0xad, 0xbe, 0xef]),
            route: MaterializedRouteOutput {
                plan: planned_route().into(),
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

    let exchange = AggregateOutput::success(
        CommandName::Exchange,
        ExchangeCommandResult {
            sent: vec![WireFrameOutput::new(vec![0xde, 0xad, 0xbe, 0xef])],
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
    let read = StreamRecord::success(
        CommandName::Read,
        0,
        ReadFrameCommandResult::try_from_frame(exact_frame()).unwrap(),
        Vec::new(),
    );
    assert_eq!(
        serde_json::to_value(read).unwrap(),
        json_file("output-read-event.json")
    );

    let replay = StreamRecord::success(
        CommandName::Replay,
        0,
        ReplayFrameCommandResult {
            source_sequence: 0,
            interface: InterfaceId {
                name: "lab0".to_owned(),
                index: 2,
            }
            .into(),
            link_mode: LinkMode::Auto.into(),
            scheduled_delay: std::time::Duration::ZERO,
            bytes_sent: 4,
            frame: FrameOutput::try_from_frame(exact_frame()).unwrap(),
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
