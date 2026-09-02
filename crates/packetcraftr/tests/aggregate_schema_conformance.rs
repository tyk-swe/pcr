// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
// Test code indexes fixtures and counts by hand; the fail-closed lints are
// for library paths.
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

//! Serializes a real Rust aggregate payload for every command that publishes
//! one and validates the emitted envelope against the published v1 schema.
//!
//! The published-example tests validate hand-written JSON, so they cannot see
//! a Rust type drifting away from the contract. This file closes that hole:
//! `additionalProperties: false` throughout the schema means one new `pub`
//! field on any payload breaks every consumer, and that break now fails here.

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};

use bytes::Bytes;
use packetcraftr::core::analysis::follow::{
    Chunk as AnalysisChunk, Direction as AnalysisDirection, Summary as FollowSummary,
};
use packetcraftr::core::analysis::reassembly::tcp::FlowKey;
use packetcraftr::core::analysis::stats::{
    ConversationStat, EndpointStat, IoBucketStat, PortStat, ProtocolStat,
};
use packetcraftr::core::analysis::{IpReassemblyReport, StreamTransport};
use packetcraftr::core::diagnostic::Diagnostic;
use packetcraftr::core::frame::{Direction as CaptureDirection, Frame, LinkType};
use packetcraftr::core::protocol::{BuiltinProtocol, builtin, network::Ipv4, transport::Udp};
use packetcraftr::core::{Packet, build, decode, fuzz as packet_fuzz, layer::Raw};
use packetcraftr::netio::capture::Statistics as CaptureStatistics;
use packetcraftr::netio::interface::{Address, Flags, Id as InterfaceId, Info};
use packetcraftr::netio::link::{Capability, MacAddress, Mode as LinkMode, VlanKind, VlanTag};
use packetcraftr::netio::route::{Decision, Materialized, Plan, Scope, SelectionReason};
use packetcraftr::output::contract::{Command, Format};
use packetcraftr::output::envelope::{Aggregate, Stats};
use packetcraftr::output::{
    build as build_output, dissect as dissect_output, dns as dns_output,
    exchange as exchange_output, expert as expert_output, follow as follow_output,
    fuzz as fuzz_output, interfaces as interfaces_output, network as network_output,
    plan as plan_output, protocols as protocols_output, reassembly as reassembly_output,
    replay as replay_output, routes as routes_output, scan as scan_output, send as send_output,
    stats as stats_output, tls as tls_output, traceroute as traceroute_output,
};
use serde_json::Value;

mod support;

use support::{output_schema, output_schema_validator};

/// One representative aggregate payload, already wrapped in its envelope.
type Case = fn() -> Value;

/// Every aggregate payload the CLI can publish, keyed by its command and a
/// name for the branch it exercises.
const CASES: &[(Command, &str, Case)] = &[
    (Command::Build, "built packet", build_case),
    (Command::Dissect, "matched dissection", dissect_case),
    (Command::Dissect, "filtered out", dissect_unmatched_case),
    (Command::Protocols, "list", protocols_list_case),
    (Command::Protocols, "detail", protocols_detail_case),
    (Command::Plan, "planned route", plan_case),
    (Command::Send, "sent frame", send_case),
    (Command::Send, "no neighbor", send_without_neighbor_case),
    (Command::Exchange, "responses", exchange_case),
    (Command::Exchange, "nothing sent", exchange_empty_case),
    (Command::Replay, "transmitted frames", replay_case),
    (Command::Scan, "endpoints", scan_case),
    (Command::Scan, "icmp sweep", scan_icmp_case),
    (Command::Stats, "conversations", stats_conversations_case),
    (Command::Stats, "endpoints", stats_endpoints_case),
    (Command::Stats, "protocols", stats_protocols_case),
    (Command::Stats, "ports", stats_ports_case),
    (Command::Stats, "io", stats_io_case),
    (Command::Stats, "fragments", stats_fragments_case),
    (Command::Expert, "findings", expert_case),
    (Command::Follow, "chunks", follow_case),
    (Command::Follow, "no frames", follow_empty_case),
    (Command::Tls, "sessions", tls_case),
    (Command::Tls, "gap session", tls_gap_case),
    (Command::Traceroute, "hops", traceroute_case),
    (Command::Dns, "timeout", dns_timeout_case),
    (Command::Dns, "validated response", dns_response_case),
    (Command::Fuzz, "offline campaign", fuzz_offline_case),
    (Command::Fuzz, "rejected case", fuzz_rejected_case),
    (Command::Fuzz, "live campaign", fuzz_live_case),
    (Command::Interfaces, "interfaces", interfaces_case),
    (Command::Routes, "routes", routes_case),
];

#[test]
fn every_aggregate_payload_serializes_to_a_schema_valid_envelope() {
    let validator = output_schema_validator();
    for (command, branch, case) in CASES {
        let document = case();
        validator.validate(&document).unwrap_or_else(|error| {
            panic!(
                "{command} ({branch}) must validate against the output schema: {error}\n{}",
                serde_json::to_string_pretty(&document).expect("document renders")
            )
        });
    }
}

#[test]
fn the_case_table_covers_every_command_that_publishes_an_aggregate() {
    let expected = Command::ALL
        .iter()
        .copied()
        .filter(|command| command.formats().contains(&Format::Json))
        .map(Command::as_str)
        .collect::<BTreeSet<_>>();
    let covered = CASES
        .iter()
        .map(|(command, _, _)| command.as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        covered, expected,
        "every command whose formats() offers JSON needs an aggregate conformance case"
    );
}

// ---------------------------------------------------------------- envelopes

fn envelope<T: serde::Serialize>(
    command: Command,
    payload: T,
    diagnostics: Vec<Diagnostic>,
) -> Value {
    serde_json::to_value(Aggregate::success(command, payload, diagnostics))
        .expect("aggregate envelope serializes")
}

fn envelope_with_stats<T: serde::Serialize>(
    command: Command,
    payload: T,
    diagnostics: Vec<Diagnostic>,
    stats: Stats,
) -> Value {
    serde_json::to_value(Aggregate::success(command, payload, diagnostics).with_stats(stats))
        .expect("aggregate envelope serializes")
}

// ---------------------------------------------------------------- fixtures

fn diagnostic() -> Diagnostic {
    let mut diagnostic = Diagnostic::warning("fixture.conformance", "representative warning");
    diagnostic.layer = Some(0);
    diagnostic.field = Some("length");
    diagnostic
}

fn udp_packet() -> Packet {
    let mut packet = Packet::new();
    packet.push(Ipv4 {
        source: Ipv4Addr::new(192, 0, 2, 1),
        destination: Ipv4Addr::new(198, 51, 100, 2),
        ..Ipv4::default()
    });
    packet.push(Udp {
        source_port: 40_000,
        destination_port: 8_080,
        ..Udp::default()
    });
    packet.push(Raw::new(b"payload".to_vec()));
    packet
}

fn built_packet() -> build::BuiltPacket {
    build::Builder::new(builtin::registry())
        .build(
            udp_packet(),
            build::Context::default(),
            build::Options::default(),
        )
        .expect("representative packet builds")
}

fn evidence_frame() -> Frame {
    let mut frame = Frame::new(
        UNIX_EPOCH + Duration::from_secs(7),
        LinkType::IPV4,
        built_packet().bytes,
    )
    .expect("built bytes form a capture frame");
    frame.interface = Some(3);
    frame.direction = Some(CaptureDirection::Inbound);
    frame
}

fn decoded_frame() -> decode::DecodedPacket {
    decode::Dissector::new(builtin::registry())
        .decode(evidence_frame(), decode::Options::default())
        .expect("representative frame dissects")
}

fn capture_statistics() -> CaptureStatistics {
    CaptureStatistics {
        received_frames: 4,
        received_bytes: 512,
        dropped_frames: 1,
        dropped_bytes: 64,
        overflow_events: 1,
        receiver_dropped_frames: 2,
    }
}

fn workflow_stats() -> packetcraftr::Stats {
    packetcraftr::Stats {
        packets_attempted: 2,
        packets_completed: 1,
        bytes: 128,
        elapsed: Duration::from_millis(25),
        capture: capture_statistics(),
    }
}

fn route_decision() -> Decision {
    Decision {
        interface: InterfaceId {
            name: "eth0".to_owned(),
            index: 3,
        },
        source_mac: Some(MacAddress([0, 1, 2, 3, 4, 5])),
        selected_source: Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))),
        preferred_source: Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))),
        next_hop: Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 254))),
        selection_reason: SelectionReason::Gateway,
        destination_scope: Scope::Private,
        mtu: 1_500,
        capability: Capability::Layer2AndLayer3,
        link_type: LinkType::ETHERNET,
    }
}

fn route_plan() -> Plan {
    Plan {
        decision: route_decision(),
        mode: LinkMode::Layer2,
        lookup_destination: Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2))),
        final_destination: Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2))),
        visited_destinations: vec![IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2))],
        packet_source: Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))),
        neighbor_source: Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))),
        neighbor_target: Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 254))),
        destination_mac: Some(MacAddress([6, 7, 8, 9, 10, 11])),
        source_mac: Some(MacAddress([0, 1, 2, 3, 4, 5])),
        neighbor_vlan_tags: vec![VlanTag {
            kind: VlanKind::Ieee8021Q,
            priority: 5,
            drop_eligible: true,
            vlan_id: 42,
        }],
        synthesized_ethernet: true,
    }
}

fn materialized_route() -> Materialized {
    Materialized {
        plan: route_plan(),
        neighbor_resolution: Some(packetcraftr::netio::neighbor::Resolution {
            mac_address: MacAddress([6, 7, 8, 9, 10, 11]),
            attempts: 2,
            cache_hit: false,
            captured: vec![evidence_frame()],
            evidence_truncated: true,
            capture_statistics: capture_statistics(),
        }),
    }
}

fn sent_packet() -> packetcraftr::SentPacket {
    let built = built_packet();
    let report = packetcraftr::netio::transmit::Submission::start()
        .complete(built.bytes.len(), built.bytes.clone());
    packetcraftr::SentPacket::try_new(built, materialized_route(), report)
        .expect("trusted transmission receipt")
}

fn analysis_stats_report() -> packetcraftr::core::analysis::stats::Report {
    use packetcraftr::core::analysis::reassembly::ip::{
        DatagramKey, IncompleteDatagram, IncompleteReason, Ipv4DatagramKey, Ipv6DatagramKey,
    };
    use packetcraftr::core::analysis::scope::Interner;
    use packetcraftr::core::analysis::{IpCounters, IpDatagramOutcome, IpFamilyCounters};

    let first = UNIX_EPOCH + Duration::from_secs(5);
    let last = first + Duration::from_millis(3_250);
    let mut scopes = Interner::new();
    let scope = scopes
        .intern(None, Vec::new())
        .expect("representative scope fits");
    packetcraftr::core::analysis::stats::Report {
        interval: Duration::from_secs(2),
        frames: 7,
        bytes: 321,
        first_timestamp: Some(first),
        last_timestamp: Some(last),
        protocols: vec![ProtocolStat {
            protocol: "ipv4".to_owned(),
            frames: 7,
            bytes: 321,
        }],
        conversations: vec![ConversationStat {
            transport: StreamTransport::Tcp,
            stream: 4,
            address_a: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            port_a: 40_000,
            address_b: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2)),
            port_b: 443,
            frames_a_to_b: 3,
            bytes_a_to_b: 120,
            frames_b_to_a: 4,
            bytes_b_to_a: 201,
            first_timestamp: first,
            last_timestamp: last,
        }],
        endpoints: vec![EndpointStat {
            address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            tx_frames: 3,
            tx_bytes: 120,
            rx_frames: 4,
            rx_bytes: 201,
        }],
        ports: vec![PortStat {
            transport: StreamTransport::Udp,
            port: 53,
            frames: 2,
            bytes: 80,
        }],
        io: vec![IoBucketStat {
            offset: Duration::from_secs(2),
            frames: 5,
            bytes: 240,
        }],
        ip_reassembly: IpReassemblyReport {
            counters: IpCounters {
                ipv4: IpFamilyCounters {
                    physical_fragments: 3,
                    admitted_fragments: 3,
                    completing_fragments: 1,
                    completed_datagrams: 1,
                    overlap_bytes: 2,
                    derived_datagram_bytes: 44,
                    derived_payload_bytes: 24,
                    ..IpFamilyCounters::default()
                },
                ipv6: IpFamilyCounters {
                    physical_fragments: 1,
                    admitted_fragments: 1,
                    incomplete_datagrams: 1,
                    end_of_capture_datagrams: 1,
                    ..IpFamilyCounters::default()
                },
            },
            outcomes: vec![
                IpDatagramOutcome::Completed {
                    key: DatagramKey::Ipv4(Ipv4DatagramKey {
                        scope,
                        source: Ipv4Addr::new(192, 0, 2, 1),
                        destination: Ipv4Addr::new(198, 51, 100, 2),
                        identification: 42,
                        protocol: 17,
                    }),
                    fragment_count: 3,
                    unique_bytes: 24,
                    final_payload_length: 24,
                    datagram_bytes: 44,
                    duplicate_fragments: 1,
                    overlap_bytes: 2,
                },
                IpDatagramOutcome::Incomplete(IncompleteDatagram {
                    key: DatagramKey::Ipv6(Ipv6DatagramKey {
                        scope,
                        source: Ipv6Addr::LOCALHOST,
                        destination: "2001:db8::2".parse().expect("documentation address"),
                        identification: 7,
                    }),
                    reason: IncompleteReason::EndOfCapture,
                    fragment_count: 1,
                    unique_bytes: 16,
                    known_final_length: Some(48),
                    duplicate_fragments: 0,
                    overlap_bytes: 0,
                }),
            ],
            outcomes_omitted: 2,
        },
    }
}

// ------------------------------------------------------------------- cases

fn build_case() -> Value {
    let mut built = built_packet();
    built.diagnostics.push(diagnostic());
    let (report, diagnostics) = build_output::Report::from_built(built);
    envelope(Command::Build, report, diagnostics)
}

fn dissect_case() -> Value {
    let mut decoded = decoded_frame();
    decoded.diagnostics.push(diagnostic());
    let (report, diagnostics) = dissect_output::Report::from_decoded(decoded);
    envelope(
        Command::Dissect,
        dissect_output::AggregateResult::new(Some(report)),
        diagnostics,
    )
}

fn dissect_unmatched_case() -> Value {
    let (_, diagnostics) = dissect_output::Report::from_decoded(decoded_frame());
    envelope(
        Command::Dissect,
        dissect_output::AggregateResult::new(None),
        diagnostics,
    )
}

fn protocols_list_case() -> Value {
    envelope(
        Command::Protocols,
        protocols_output::ListResult {
            protocols: BuiltinProtocol::ALL
                .iter()
                .copied()
                .map(protocols_output::Summary::from)
                .collect(),
        },
        Vec::new(),
    )
}

fn protocols_detail_case() -> Value {
    let registry = builtin::registry();
    let protocol = BuiltinProtocol::Ipv4;
    let fields = registry
        .schema(protocol.as_str())
        .map(|schema| {
            schema
                .fields
                .iter()
                .map(protocols_output::Field::try_from)
                .collect::<Result<Vec<_>, _>>()
                .expect("every built-in field kind has a v1 representation")
        })
        .unwrap_or_default();
    let bindings = registry
        .parent_bindings(protocol.as_str())
        .into_iter()
        .map(|(parent, discriminator)| protocols_output::Binding {
            parent: parent.as_str().to_owned(),
            discriminator: discriminator.0,
        })
        .collect();
    envelope(
        Command::Protocols,
        protocols_output::DetailResult {
            protocol: protocols_output::Detail::new(
                protocols_output::Summary::from(protocol),
                fields,
                bindings,
            ),
        },
        Vec::new(),
    )
}

fn plan_case() -> Value {
    envelope(
        Command::Plan,
        plan_output::Report {
            plan: network_output::Plan::from(route_plan()),
        },
        Vec::new(),
    )
}

fn send_case() -> Value {
    let (report, diagnostics, stats) =
        send_output::Report::try_from_report(packetcraftr::send::Report {
            sent: sent_packet(),
            stats: workflow_stats(),
        })
        .expect("in-range send evidence converts");
    envelope_with_stats(Command::Send, report, diagnostics, stats)
}

fn send_without_neighbor_case() -> Value {
    let built = built_packet();
    let report = packetcraftr::netio::transmit::Submission::start()
        .complete(built.bytes.len(), built.bytes.clone());
    let route = Materialized {
        plan: route_plan(),
        neighbor_resolution: None,
    };
    let sent = packetcraftr::SentPacket::try_new(built, route, report)
        .expect("trusted transmission receipt");
    let (report, diagnostics, stats) =
        send_output::Report::try_from_report(packetcraftr::send::Report {
            sent,
            stats: workflow_stats(),
        })
        .expect("in-range send evidence converts");
    envelope_with_stats(Command::Send, report, diagnostics, stats)
}

fn exchange_case() -> Value {
    let (report, diagnostics, stats) =
        exchange_output::Report::try_from_exchange(packetcraftr::exchange::Report {
            sent: vec![Arc::new(sent_packet())],
            responses: vec![packetcraftr::exchange::Response {
                request_index: 0,
                response: decoded_frame(),
                latency: Duration::from_millis(3),
            }],
            unanswered: vec![1],
            unsolicited: vec![decoded_frame()],
            undecoded: vec![evidence_frame()],
            diagnostics: vec![diagnostic()],
            stats: workflow_stats(),
        })
        .expect("in-range exchange evidence converts");
    envelope_with_stats(Command::Exchange, report, diagnostics, stats)
}

fn exchange_empty_case() -> Value {
    let (report, diagnostics, stats) =
        exchange_output::Report::try_from_exchange(packetcraftr::exchange::Report {
            sent: Vec::new(),
            responses: Vec::new(),
            unanswered: Vec::new(),
            unsolicited: Vec::new(),
            undecoded: Vec::new(),
            diagnostics: Vec::new(),
            stats: packetcraftr::Stats::default(),
        })
        .expect("an empty exchange converts");
    envelope_with_stats(Command::Exchange, report, diagnostics, stats)
}

fn replay_case() -> Value {
    let frames = vec![replay_output::Frame {
        source_index: 1,
        interface: replay_output::InterfaceId {
            name: "lab0".to_owned(),
            index: 2,
        },
        link_mode: replay_output::LinkMode::Layer3,
        scheduled_delay: Duration::from_millis(5),
        bytes_sent: 29,
        frame: packetcraftr::output::frame::Captured::try_from_frame(evidence_frame())
            .expect("in-range capture evidence converts"),
        transmitted: true,
    }];
    let report = replay_output::Report::from_summary(
        packetcraftr::replay::Summary {
            source_format: replay_output::SourceFormat::Pcap,
            timing: replay_output::Timing::Immediate,
            frames_read: 1,
            frames_transmitted: 1,
            bytes_transmitted: 29,
            scheduled_duration: Duration::from_millis(5),
        },
        InterfaceId {
            name: "lab0".to_owned(),
            index: 2,
        },
        LinkMode::Auto,
        frames,
    );
    envelope_with_stats(
        Command::Replay,
        report,
        Vec::new(),
        Stats::from(workflow_stats()),
    )
}

fn scan_probe(responded: bool) -> packetcraftr::scan::ProbeEvidence {
    let address = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
    packetcraftr::scan::ProbeEvidence {
        sequence: 0,
        address,
        transport: packetcraftr::scan::Transport::Tcp,
        port: Some(443),
        attempt: 1,
        status: if responded {
            packetcraftr::scan::ProbeStatus::Response
        } else {
            packetcraftr::scan::ProbeStatus::Timeout
        },
        classification: if responded {
            packetcraftr::scan::Classification::Open
        } else {
            packetcraftr::scan::Classification::Timeout
        },
        responder: responded.then_some(address),
        sent_at: UNIX_EPOCH,
        received_at: responded.then(|| UNIX_EPOCH + Duration::from_millis(5)),
        latency: responded.then(|| Duration::from_millis(5)),
        response: responded.then(evidence_frame),
        reason: if responded { "syn-ack" } else { "timeout" }.to_owned(),
    }
}

fn scan_case() -> Value {
    let address = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
    let (report, diagnostics, stats) =
        scan_output::Report::try_from_scan(packetcraftr::scan::Report {
            target: "host.example".to_owned(),
            resolved_addresses: vec![address],
            endpoints: vec![packetcraftr::scan::Endpoint {
                address,
                transport: packetcraftr::scan::Transport::Tcp,
                port: Some(443),
                classification: packetcraftr::scan::Classification::Open,
                probes: vec![scan_probe(true), scan_probe(false)],
            }],
            undecoded: vec![evidence_frame()],
            diagnostics: vec![diagnostic()],
            stats: workflow_stats(),
        })
        .expect("in-range scan evidence converts");
    envelope_with_stats(Command::Scan, report, diagnostics, stats)
}

fn scan_icmp_case() -> Value {
    let ipv6 = IpAddr::V6(Ipv6Addr::LOCALHOST);
    let probe = |address: IpAddr| packetcraftr::scan::ProbeEvidence {
        sequence: 1,
        address,
        transport: packetcraftr::scan::Transport::Icmp,
        port: None,
        attempt: 1,
        status: packetcraftr::scan::ProbeStatus::Response,
        classification: packetcraftr::scan::Classification::Open,
        responder: Some(address),
        sent_at: UNIX_EPOCH,
        received_at: Some(UNIX_EPOCH + Duration::from_millis(2)),
        latency: Some(Duration::from_millis(2)),
        response: Some(evidence_frame()),
        reason: "echo reply".to_owned(),
    };
    let endpoint = |address: IpAddr| packetcraftr::scan::Endpoint {
        address,
        transport: packetcraftr::scan::Transport::Icmp,
        port: None,
        classification: packetcraftr::scan::Classification::Open,
        probes: vec![probe(address)],
    };
    let ipv4 = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
    let (report, diagnostics, stats) =
        scan_output::Report::try_from_scan(packetcraftr::scan::Report {
            target: "host.example".to_owned(),
            resolved_addresses: vec![ipv4, ipv6],
            endpoints: vec![endpoint(ipv4), endpoint(ipv6)],
            undecoded: Vec::new(),
            diagnostics: Vec::new(),
            stats: workflow_stats(),
        })
        .expect("in-range scan evidence converts");
    envelope_with_stats(Command::Scan, report, diagnostics, stats)
}

fn stats_case(table: stats_output::Table) -> Value {
    let report = stats_output::Report::try_from_report(table, &analysis_stats_report(), 9)
        .expect("in-range statistics convert");
    envelope(Command::Stats, report, Vec::new())
}

fn stats_conversations_case() -> Value {
    stats_case(stats_output::Table::Conversations)
}

fn stats_endpoints_case() -> Value {
    stats_case(stats_output::Table::Endpoints)
}

fn stats_protocols_case() -> Value {
    stats_case(stats_output::Table::Protocols)
}

fn stats_ports_case() -> Value {
    stats_case(stats_output::Table::Ports)
}

fn stats_io_case() -> Value {
    stats_case(stats_output::Table::Io)
}

fn stats_fragments_case() -> Value {
    stats_case(stats_output::Table::Fragments)
}

fn expert_case() -> Value {
    use packetcraftr::core::analysis::StreamRef;
    use packetcraftr::core::analysis::expert::{Finding as AnalysisFinding, Summary};

    let findings = vec![
        AnalysisFinding {
            severity: packetcraftr::core::diagnostic::Severity::Error,
            code: "tcp.reset".to_owned(),
            number: 8,
            stream: Some(StreamRef {
                transport: StreamTransport::Tcp,
                index: 2,
            }),
            message: "connection reset".to_owned(),
        },
        AnalysisFinding {
            severity: packetcraftr::core::diagnostic::Severity::Info,
            code: "capture.note".to_owned(),
            number: 10,
            stream: None,
            message: "capture note".to_owned(),
        },
    ]
    .into_iter()
    .map(expert_output::Finding::from)
    .collect();
    let report = expert_output::Report::from_summary(
        Summary {
            findings: 2,
            errors: 1,
            warnings: 0,
            notes: 1,
            codes: [("capture.note".to_owned(), 1), ("tcp.reset".to_owned(), 1)]
                .into_iter()
                .collect(),
        },
        12,
        11,
        findings,
        &analysis_stats_report().ip_reassembly,
    );
    envelope(Command::Expert, report, Vec::new())
}

fn follow_case() -> Value {
    let chunks = [
        AnalysisChunk {
            direction: AnalysisDirection::ClientToServer,
            number: 2,
            bytes: Bytes::from_static(&[0x00, 0xff]),
        },
        AnalysisChunk {
            direction: AnalysisDirection::ServerToClient,
            number: 3,
            bytes: Bytes::from_static(b"ok"),
        },
    ]
    .into_iter()
    .map(follow_output::Chunk::from)
    .collect();
    let report = follow_output::Report::from_summary(
        expert_output::StreamTransport::Tcp,
        2,
        FollowSummary {
            client_flow: Some(FlowKey {
                source: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
                source_port: 40_000,
                destination: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2)),
                destination_port: 443,
            }),
            frames: 2,
            client_bytes: 2,
            server_bytes: 2,
            undelivered_bytes: 4,
        },
        chunks,
        &analysis_stats_report().ip_reassembly,
    );
    envelope(Command::Follow, report, Vec::new())
}

fn follow_empty_case() -> Value {
    let report = follow_output::Report::from_summary(
        expert_output::StreamTransport::Udp,
        99,
        FollowSummary::default(),
        Vec::new(),
        &IpReassemblyReport::default(),
    );
    envelope(Command::Follow, report, Vec::new())
}

fn tls_case() -> Value {
    let endpoint = |last: u8, port: u16| tls_output::Endpoint {
        address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, last)),
        port,
    };
    let session = tls_output::Session {
        session: 0,
        tcp_stream: 4,
        client_endpoint: endpoint(1, 40_000),
        server_endpoint: endpoint(2, 443),
        first_frame: 2,
        last_frame: 5,
        handshake_rtt_ms: Some(1.25),
        client: Some(tls_output::Client {
            legacy_version: 0x0303,
            legacy_version_name: Some("tls1.2"),
            sni: Some("example.test".to_owned()),
            sni_raw_hex: Some("6578616d706c652e74657374".to_owned()),
            sni_is_outer: false,
            ech: false,
            alpn: vec!["h2".to_owned()],
            supported_versions: vec![0x0304, 0x0303],
            cipher_suites: vec![0x1301],
            supported_groups: vec![0x001d],
            key_share_groups: vec![0x001d],
            signature_algorithms: vec![0x0403],
            ja3: "00112233445566778899aabbccddeeff".to_owned(),
            ja3_raw: "771,4865,0-23,29,0".to_owned(),
            ja4: "t13d1516h2_8daaf6152771_e5627efa2ab1".to_owned(),
        }),
        server: Some(tls_output::Server {
            selected_version: 0x0304,
            selected_version_name: Some("tls1.3"),
            cipher_suite: 0x1301,
            cipher_suite_name: Some("TLS_AES_128_GCM_SHA256"),
            alpn: None,
            key_share_group: Some(0x001d),
            key_share_group_name: Some("x25519"),
            ja3s: "ffeeddccbbaa99887766554433221100".to_owned(),
            ja3s_raw: "771,4865,".to_owned(),
        }),
        hello_retry: false,
        alerts: vec![tls_output::Alert {
            level: 2,
            description: 40,
            description_name: Some("handshake_failure"),
        }],
        alerts_dropped: 2,
        status: tls_output::Status::Alert,
        reason: None,
    };
    envelope(
        Command::Tls,
        tls_output::Report {
            sessions: vec![session],
            summary: tls_output::Summary {
                frames_read: 12,
                frames_matched: 8,
                sessions: 1,
                sessions_selected: 1,
                by_status: tls_output::StatusCounts {
                    alert: 1,
                    ..tls_output::StatusCounts::default()
                },
                tcp_streams: 1,
                sessions_evicted: 0,
                sessions_omitted: 0,
                buffer_limit_hits: 0,
                udp_443_frames: 0,
                ip_reassembly: reassembly_output::Report::from_analysis(
                    &analysis_stats_report().ip_reassembly,
                ),
            },
        },
        Vec::new(),
    )
}

fn tls_gap_case() -> Value {
    let endpoint = |last: u8, port: u16| tls_output::Endpoint {
        address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, last)),
        port,
    };
    envelope(
        Command::Tls,
        tls_output::Report {
            sessions: vec![tls_output::Session {
                session: 0,
                tcp_stream: 4,
                client_endpoint: endpoint(1, 40_000),
                server_endpoint: endpoint(2, 443),
                first_frame: 2,
                last_frame: 3,
                handshake_rtt_ms: None,
                client: None,
                server: None,
                hello_retry: false,
                alerts: Vec::new(),
                alerts_dropped: 0,
                status: tls_output::Status::Gap,
                reason: Some("no ClientHello observed".to_owned()),
            }],
            summary: tls_output::Summary::default(),
        },
        Vec::new(),
    )
}

fn trace_probe(responded: bool) -> packetcraftr::traceroute::ProbeEvidence {
    packetcraftr::traceroute::ProbeEvidence {
        sequence: 0,
        hop_limit: 1,
        attempt: 1,
        destination: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2)),
        strategy: packetcraftr::traceroute::Strategy::Udp,
        destination_port: Some(33_434),
        status: if responded {
            packetcraftr::traceroute::ProbeStatus::Response
        } else {
            packetcraftr::traceroute::ProbeStatus::Timeout
        },
        response_kind: responded.then_some(packetcraftr::traceroute::ResponseKind::Intermediate),
        responder: responded.then_some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 254))),
        sent_at: UNIX_EPOCH,
        received_at: responded.then(|| UNIX_EPOCH + Duration::from_millis(4)),
        latency: responded.then(|| Duration::from_millis(4)),
        response: responded.then(evidence_frame),
        reason: if responded {
            "time exceeded"
        } else {
            "timeout"
        }
        .to_owned(),
    }
}

fn traceroute_case() -> Value {
    let (report, diagnostics, stats) =
        traceroute_output::Report::try_from_traceroute(packetcraftr::traceroute::Report {
            target: "host.example".to_owned(),
            resolved_addresses: vec![IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2))],
            destination: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2)),
            strategy: packetcraftr::traceroute::Strategy::Udp,
            destination_port: Some(33_434),
            hops: vec![packetcraftr::traceroute::Hop {
                hop_limit: 1,
                probes: vec![trace_probe(true), trace_probe(false)],
            }],
            undecoded: vec![packetcraftr::traceroute::UndecodedEvidence {
                hop_limit: 1,
                frame: evidence_frame(),
            }],
            completion: packetcraftr::traceroute::Completion::DestinationReached,
            diagnostics: vec![diagnostic()],
            stats: workflow_stats(),
        })
        .expect("in-range traceroute evidence converts");
    envelope_with_stats(Command::Traceroute, report, diagnostics, stats)
}

fn dns_timeout_case() -> Value {
    let server_address = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53));
    let (report, diagnostics, stats) =
        dns_output::Report::try_from_dns(packetcraftr::dns::Report {
            server: "resolver.example.test".to_owned(),
            server_port: 53,
            resolved_addresses: vec![server_address],
            query_name: "example.test".to_owned(),
            query_type: packetcraftr::dns::QueryType::A,
            transaction_id: 0x4a5b,
            outcome: packetcraftr::dns::Outcome::Timeout,
            fallback_attempted: false,
            accepted_transport: None,
            response: None,
            attempts: vec![packetcraftr::dns::AttemptEvidence {
                attempt: 1,
                transport: packetcraftr::dns::Transport::Udp,
                server_address,
                source_port: Some(49_152),
                status: packetcraftr::dns::Outcome::Timeout,
                sent_at: Some(UNIX_EPOCH),
                received_at: None,
                latency: None,
                response: None,
                response_code: None,
                reason: "timeout".to_owned(),
            }],
            undecoded: vec![packetcraftr::dns::UndecodedEvidence {
                attempt: 1,
                frame: evidence_frame(),
            }],
            diagnostics: vec![diagnostic()],
            stats: workflow_stats(),
        })
        .expect("in-range DNS evidence converts");
    envelope_with_stats(Command::Dns, report, diagnostics, stats)
}

fn dns_name(value: &str) -> packetcraftr::dns::Name {
    packetcraftr::dns::Name::from_labels(
        value
            .trim_end_matches('.')
            .split('.')
            .map(|label| label.as_bytes().to_vec()),
    )
    .expect("fixture name is a valid DNS name")
}

fn dns_edns() -> packetcraftr::dns::Edns {
    packetcraftr::dns::Edns {
        udp_payload_size: 1_232,
        extended_response_code: 1,
        version: 0,
        dnssec_ok: true,
        flags: 0x8000,
        options: vec![packetcraftr::dns::EdnsOption {
            code: 10,

            data: Bytes::from_static(&[0xaa, 0xbb]),
        }],
    }
}

/// Every `RecordValue` shape the v1 contract publishes, so a record variant
/// the schema does not know about fails here.
fn dns_records() -> Vec<packetcraftr::dns::Record> {
    let record = |value| packetcraftr::dns::Record {
        owner: dns_name("example.test."),
        class: 1,
        ttl: 300,
        value,
    };
    vec![
        record(packetcraftr::dns::RecordValue::A(Ipv4Addr::new(
            192, 0, 2, 1,
        ))),
        record(packetcraftr::dns::RecordValue::Aaaa(
            "2001:db8::1".parse().expect("documentation address"),
        )),
        record(packetcraftr::dns::RecordValue::Cname(dns_name(
            "alias.example.test.",
        ))),
        record(packetcraftr::dns::RecordValue::Mx {
            preference: 10,
            exchange: dns_name("mail.example.test."),
        }),
        record(packetcraftr::dns::RecordValue::Ns(dns_name(
            "ns.example.test.",
        ))),
        record(packetcraftr::dns::RecordValue::Ptr(dns_name(
            "ptr.example.test.",
        ))),
        record(packetcraftr::dns::RecordValue::Soa {
            primary_name_server: dns_name("ns.example.test."),
            responsible_mailbox: dns_name("hostmaster.example.test."),
            serial: 1,
            refresh: 2,
            retry: 3,
            expire: 4,
            minimum: 5,
        }),
        record(packetcraftr::dns::RecordValue::Srv {
            priority: 1,
            weight: 2,
            port: 443,
            target: dns_name("service.example.test."),
        }),
        record(packetcraftr::dns::RecordValue::Txt(vec![
            Bytes::from_static(b"abc"),
            Bytes::from_static(&[0xff]),
        ])),
        record(packetcraftr::dns::RecordValue::Unknown {
            type_code: 65_000,
            rdata: Bytes::from_static(&[9, 8, 7]),
        }),
    ]
}

fn dns_response_case() -> Value {
    let server_address = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53));
    let response = packetcraftr::dns::ValidatedResponse {
        metadata: packetcraftr::dns::ResponseMetadata {
            response_code: 18,
            edns: Some(dns_edns()),
            authoritative: true,
            truncated: false,
            recursion_desired: true,
            recursion_available: true,
            authenticated_data: true,
            checking_disabled: true,
            rejected_record_count: 1,
        },
        answers: dns_records(),
        authorities: Vec::new(),
        additionals: vec![packetcraftr::dns::Record {
            owner: dns_name("example.test."),
            class: 1_232,
            ttl: 0,
            value: packetcraftr::dns::RecordValue::Opt(dns_edns()),
        }],
        rejected_records: vec![packetcraftr::dns::RejectedRecord {
            section: packetcraftr::dns::Section::Authority,
            index: 4,
            owner: "ignored.example.test.".to_owned(),
            type_code: 65_001,
            reason: "unrelated fixture record".to_owned(),
        }],
    };
    let attempt = |transport, attempt| packetcraftr::dns::AttemptEvidence {
        attempt,
        transport,
        server_address,
        source_port: Some(49_152),
        status: packetcraftr::dns::Outcome::Response,
        sent_at: Some(UNIX_EPOCH),
        received_at: Some(UNIX_EPOCH + Duration::from_millis(3)),
        latency: Some(Duration::from_millis(3)),
        response: None,
        response_code: Some(18),
        reason: "validated DNS response".to_owned(),
    };
    let (report, diagnostics, stats) =
        dns_output::Report::try_from_dns(packetcraftr::dns::Report {
            server: "resolver.example.test".to_owned(),
            server_port: 53,
            resolved_addresses: vec![server_address],
            query_name: "example.test".to_owned(),
            query_type: packetcraftr::dns::QueryType::Any,
            transaction_id: 0x4a5b,
            outcome: packetcraftr::dns::Outcome::Response,
            fallback_attempted: true,
            accepted_transport: Some(packetcraftr::dns::Transport::Tcp),
            response: Some(response),
            attempts: vec![
                packetcraftr::dns::AttemptEvidence {
                    status: packetcraftr::dns::Outcome::Truncated,
                    response: Some(evidence_frame()),
                    ..attempt(packetcraftr::dns::Transport::Udp, 1)
                },
                attempt(packetcraftr::dns::Transport::Tcp, 2),
            ],
            undecoded: vec![packetcraftr::dns::UndecodedEvidence {
                attempt: 1,
                frame: evidence_frame(),
            }],
            diagnostics: Vec::new(),
            stats: workflow_stats(),
        })
        .expect("in-range DNS evidence converts");
    envelope_with_stats(Command::Dns, report, diagnostics, stats)
}

/// A campaign over the IPv4 fixture: an IPv4 root has a registered capture
/// link type, so each built case also carries the `decoded` evidence the
/// schema declares.
fn offline_fuzz_report() -> packet_fuzz::Report {
    let request = packet_fuzz::Request {
        cases: 2,
        targets: vec!["0.ttl".parse().expect("ipv4 fuzz target")],
        ..packet_fuzz::Request::default()
    };
    packet_fuzz::run(&request, udp_packet(), builtin::registry())
        .expect("offline fuzz campaign runs")
}

fn fuzz_offline_case() -> Value {
    let (report, diagnostics, stats) = fuzz_output::Report::try_from_offline(offline_fuzz_report())
        .expect("offline fuzz campaign converts");
    envelope_with_stats(Command::Fuzz, report, diagnostics, stats)
}

fn fuzz_rejected_case() -> Value {
    let mut report = offline_fuzz_report();
    report.cases.truncate(1);
    let case = report.cases.first_mut().expect("one generated case");
    case.built = None;
    case.decoded = None;
    case.outcome = packet_fuzz::CaseOutcome::Rejected;
    case.error = Some(packet_fuzz::CaseFailure::new(
        "mutated field is out of range",
        packetcraftr::core::error::Classification::new(
            "packet.field_range",
            packetcraftr::core::error::Kind::Packet,
            Some("choose a narrower mutation range"),
        ),
        vec!["field length exceeds the declared width".to_owned()],
    ));
    report.stats.cases_generated = 1;
    report.stats.cases_built = 0;
    let (report, diagnostics, stats) =
        fuzz_output::Report::try_from_offline(report).expect("a rejected-only campaign converts");
    envelope_with_stats(Command::Fuzz, report, diagnostics, stats)
}

fn fuzz_live_case() -> Value {
    let offline = offline_fuzz_report();
    let stats = packetcraftr::fuzz::Stats {
        cases_generated: offline.stats.cases_generated,
        cases_built: offline.stats.cases_built,
        packets_attempted: offline.stats.cases_built,
        packets_completed: offline.stats.cases_built,
        bytes: offline.stats.bytes,
        elapsed: Duration::from_millis(9),
        capture: capture_statistics(),
    };
    let cases = offline
        .cases
        .into_iter()
        .map(|case| {
            let mut live = packetcraftr::fuzz::Case::from(case);
            if live.outcome == packetcraftr::fuzz::CaseOutcome::Built {
                live.outcome = packetcraftr::fuzz::CaseOutcome::Response;
                live.sent = Some(evidence_frame());
                live.responses = vec![evidence_frame()];
                live.unmatched = vec![evidence_frame()];
                live.undecoded = vec![evidence_frame()];
            }
            live
        })
        .collect();
    let (report, diagnostics, stats) =
        fuzz_output::Report::try_from_live(packetcraftr::fuzz::Report {
            seed: offline.seed,
            first_case: offline.first_case,
            cases,
            stats,
        })
        .expect("live fuzz campaign converts");
    envelope_with_stats(Command::Fuzz, report, diagnostics, stats)
}

fn interfaces_case() -> Value {
    envelope(
        Command::Interfaces,
        interfaces_output::Report::new(vec![
            Info {
                id: InterfaceId {
                    name: "eth0".to_owned(),
                    index: 3,
                },
                description: Some("lab interface".to_owned()),
                mac_address: Some(MacAddress([0, 1, 2, 3, 4, 5])),
                addresses: vec![
                    Address {
                        address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
                        prefix_length: 24,
                    },
                    Address {
                        address: IpAddr::V6(Ipv6Addr::LOCALHOST),
                        prefix_length: 128,
                    },
                ],
                flags: Flags {
                    up: true,
                    broadcast: true,
                    loopback: false,
                    point_to_point: false,
                    multicast: true,
                },
                mtu: Some(1_500),
                capability: Capability::Layer2AndLayer3,
                link_type: LinkType::ETHERNET,
            },
            Info {
                id: InterfaceId {
                    name: "lo".to_owned(),
                    index: 1,
                },
                description: None,
                mac_address: None,
                addresses: vec![Address {
                    address: IpAddr::V4(Ipv4Addr::LOCALHOST),
                    prefix_length: 8,
                }],
                flags: Flags {
                    loopback: true,
                    ..Flags::default()
                },
                mtu: None,
                capability: Capability::Layer3,
                link_type: LinkType::NULL,
            },
        ]),
        Vec::new(),
    )
}

fn routes_case() -> Value {
    envelope(
        Command::Routes,
        routes_output::Report {
            routes: vec![network_output::Decision::from(route_decision())],
        },
        Vec::new(),
    )
}

/// The guard above is only worth having if it fails on drift, and every
/// aggregate `$def` closes its property set. One stray key at either level
/// must be rejected.
#[test]
fn an_undeclared_field_fails_validation_at_the_payload_and_the_envelope() {
    for pointer in ["result", ""] {
        let mut document = plan_case();
        document
            .pointer_mut(if pointer.is_empty() { "" } else { "/result" })
            .expect("fixture has the addressed object")
            .as_object_mut()
            .expect("addressed value is an object")
            .insert("undeclared".to_owned(), Value::from(1));
        assert!(
            output_schema_validator().validate(&document).is_err(),
            "an undeclared key under {pointer:?} must fail validation"
        );
    }
}

// --------------------------------------------------------- frozen vocabulary

/// One enum whose serialized names the schema pins: where its vocabulary lives
/// in the schema, and every variant the Rust type can produce.
struct Vocabulary {
    name: &'static str,
    pointer: &'static str,
    variants: Vec<Value>,
}

fn vocabulary<T: serde::Serialize>(
    name: &'static str,
    pointer: &'static str,
    variants: impl IntoIterator<Item = T>,
) -> Vocabulary {
    Vocabulary {
        name,
        pointer,
        variants: variants
            .into_iter()
            .map(|variant| serde_json::to_value(variant).expect("a vocabulary member serializes"))
            .collect(),
    }
}

/// Ten of these types are re-exported straight out of a domain module, so a
/// variant renamed there is a wire break here with nothing in between. The
/// aggregate fixtures above only exercise the variants they happen to carry;
/// this pins every one.
fn frozen_vocabularies() -> Vec<Vocabulary> {
    use packetcraftr::core::diagnostic::Severity;
    use packetcraftr::core::frame::Direction;
    use packetcraftr::core::fuzz::Strategy as FuzzStrategy;
    use packetcraftr::dns::{Outcome as DnsOutcome, Section, Transport as DnsTransport};
    use packetcraftr::fuzz::CaseOutcome;
    use packetcraftr::scan::{
        Classification, ProbeStatus as ScanStatus, Transport as ScanTransport,
    };
    use packetcraftr::traceroute::{
        Completion, ProbeStatus as TraceStatus, ResponseKind, Strategy as TraceStrategy,
    };

    vec![
        vocabulary(
            "diagnostic::Severity",
            "/$defs/diagnostic/properties/severity/enum",
            [Severity::Info, Severity::Warning, Severity::Error],
        ),
        vocabulary(
            "frame::Direction",
            "/$defs/frame/properties/direction/enum",
            [Direction::Inbound, Direction::Outbound, Direction::Unknown],
        ),
        vocabulary(
            "fuzz::Outcome",
            "/$defs/fuzzCase/properties/outcome/enum",
            [
                CaseOutcome::Built,
                CaseOutcome::Rejected,
                CaseOutcome::Response,
                CaseOutcome::Timeout,
            ],
        ),
        vocabulary(
            "fuzz::Strategy",
            "/$defs/fuzzMutation/properties/strategy/enum",
            [
                FuzzStrategy::Boundary,
                FuzzStrategy::Random,
                FuzzStrategy::BitFlip,
                FuzzStrategy::Malformed,
            ],
        ),
        vocabulary(
            "dns::Section",
            "/$defs/dnsSection/enum",
            [Section::Answer, Section::Authority, Section::Additional],
        ),
        vocabulary(
            "dns::Outcome",
            "/$defs/dnsOutcome/enum",
            [
                DnsOutcome::Response,
                DnsOutcome::Truncated,
                DnsOutcome::Timeout,
                DnsOutcome::Unrelated,
                DnsOutcome::DecodeFailure,
                DnsOutcome::NetworkFailure,
            ],
        ),
        vocabulary(
            "dns::Transport",
            "/$defs/dnsTransport/enum",
            [DnsTransport::Udp, DnsTransport::Tcp],
        ),
        vocabulary(
            "replay::SourceFormat",
            "/$defs/replayResult/properties/source_format/enum",
            [
                replay_output::SourceFormat::Pcap,
                replay_output::SourceFormat::PcapNg,
            ],
        ),
        vocabulary(
            "scan::Classification",
            "/$defs/scanProbe/properties/classification/enum",
            [
                Classification::Open,
                Classification::Closed,
                Classification::Filtered,
                Classification::Unreachable,
                Classification::Unknown,
                Classification::Timeout,
            ],
        ),
        vocabulary(
            "scan::ProbeStatus",
            "/$defs/scanProbe/properties/status/enum",
            [ScanStatus::Response, ScanStatus::Timeout],
        ),
        vocabulary(
            "scan::Protocol",
            "/$defs/scanProbe/properties/protocol/enum",
            [
                scan_output::Protocol::Tcp,
                scan_output::Protocol::Udp,
                scan_output::Protocol::Icmpv4,
                scan_output::Protocol::Icmpv6,
            ],
        ),
        vocabulary(
            "scan::Transport",
            "/$defs/scanEndpoint/properties/transport/enum",
            [ScanTransport::Tcp, ScanTransport::Udp, ScanTransport::Icmp],
        ),
        vocabulary(
            "traceroute::ProbeStatus",
            "/$defs/traceProbe/properties/status/enum",
            [TraceStatus::Response, TraceStatus::Timeout],
        ),
        vocabulary(
            "traceroute::ResponseKind",
            "/$defs/traceProbe/properties/response_kind/enum",
            [
                ResponseKind::Intermediate,
                ResponseKind::DestinationReached,
                ResponseKind::Unreachable,
            ],
        ),
        vocabulary(
            "traceroute::Strategy",
            "/$defs/traceProbe/properties/strategy/enum",
            [TraceStrategy::Udp, TraceStrategy::Icmp, TraceStrategy::Tcp],
        ),
        vocabulary(
            "traceroute::Completion",
            "/$defs/tracerouteResult/properties/completion/enum",
            [
                Completion::DestinationReached,
                Completion::Unreachable,
                Completion::MaximumHops,
                Completion::Timeout,
            ],
        ),
        vocabulary(
            "follow::Direction",
            "/$defs/followChunk/properties/direction/enum",
            [
                follow_output::Direction::Client,
                follow_output::Direction::Server,
            ],
        ),
        vocabulary(
            "network::LinkMode",
            "/$defs/linkMode/enum",
            [
                network_output::LinkMode::Auto,
                network_output::LinkMode::Layer2,
                network_output::LinkMode::Layer3,
            ],
        ),
    ]
}

#[test]
fn every_frozen_enum_serializes_exactly_the_vocabulary_the_schema_declares() {
    for Vocabulary {
        name,
        pointer,
        variants,
    } in frozen_vocabularies()
    {
        let declared = output_schema()
            .pointer(pointer)
            .unwrap_or_else(|| panic!("{name}: the schema has no vocabulary at {pointer}"))
            .as_array()
            .unwrap_or_else(|| panic!("{name}: {pointer} must be an enum list"));
        assert_eq!(
            &variants, declared,
            "{name}: serialized names differ from {pointer}, in value or in order"
        );
    }
}

/// `tls::Status` publishes its vocabulary as annotated `const`s rather than a
/// bare `enum` list, so it is compared against those.
#[test]
fn tls_status_serializes_exactly_the_vocabulary_the_schema_declares() {
    let declared = output_schema()["$defs"]["tlsStatus"]["oneOf"]
        .as_array()
        .expect("tlsStatus enumerates its members")
        .iter()
        .map(|member| member["const"].clone())
        .collect::<Vec<_>>();
    let variants = [
        tls_output::Status::Complete,
        tls_output::Status::ClientOnly,
        tls_output::Status::Retry,
        tls_output::Status::Alert,
        tls_output::Status::Malformed,
        tls_output::Status::Gap,
        tls_output::Status::Truncated,
    ]
    .into_iter()
    .map(|status| serde_json::to_value(status).expect("a status serializes"))
    .collect::<Vec<_>>();
    assert_eq!(variants, declared);
}
