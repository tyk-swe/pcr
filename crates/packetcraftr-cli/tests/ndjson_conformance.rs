// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
// Test code indexes fixtures and counts by hand; the fail-closed lints are
// for library paths.
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};

use packetcraftr::{core, output};
use serde_json::{Value, json};

mod support;

// The CLI ships no library target, so compile its error module into this test
// binary to exercise the real cleanup composition.
#[allow(dead_code)]
#[path = "../src/errors.rs"]
mod cli_errors;

use support::{assert_contiguous, schema_validator, stream};

const COMPLETION_FIXTURES: &[(output::contract::Command, bool, &str)] = &[
    (
        output::contract::Command::Read,
        false,
        include_str!("../../../examples/documents/output-read-complete.json"),
    ),
    (
        output::contract::Command::Capture,
        true,
        include_str!("../../../examples/documents/output-capture-complete.json"),
    ),
    (
        output::contract::Command::Replay,
        false,
        include_str!("../../../examples/documents/output-replay-success.json"),
    ),
    (
        output::contract::Command::Follow,
        false,
        include_str!("../../../examples/documents/output-follow-complete.json"),
    ),
    (
        output::contract::Command::Expert,
        false,
        include_str!("../../../examples/documents/output-expert-success.json"),
    ),
    (
        output::contract::Command::Scan,
        false,
        include_str!("../../../examples/documents/output-scan-complete.json"),
    ),
    (
        output::contract::Command::Traceroute,
        false,
        include_str!("../../../examples/documents/output-traceroute-complete.json"),
    ),
    (
        output::contract::Command::Dns,
        false,
        include_str!("../../../examples/documents/output-dns-complete.json"),
    ),
    (
        output::contract::Command::Fuzz,
        true,
        include_str!("../../../examples/documents/output-fuzz-complete.json"),
    ),
    (
        output::contract::Command::Exchange,
        true,
        include_str!("../../../examples/documents/output-exchange-complete.json"),
    ),
    (
        output::contract::Command::Tls,
        false,
        include_str!("../../../examples/documents/output-tls-complete.json"),
    ),
];

fn result(document: &str) -> Value {
    serde_json::from_str::<Value>(document).expect("published example must parse")["result"].clone()
}

fn validate_records(validator: &jsonschema::Validator, records: &[Value]) {
    assert_contiguous(records);
    for record in records {
        validator
            .validate(record)
            .unwrap_or_else(|error| panic!("stream record must match the schema: {error}"));
    }
}

fn validate_typed_event<T: serde::Serialize>(
    command: output::contract::Command,
    event: T,
    diagnostics: Vec<core::diagnostic::Diagnostic>,
) {
    let (sink, bytes) = stream(command);
    sink.emit_data(event, diagnostics)
        .expect("typed production event must render");
    let records = bytes.records();
    validate_records(schema_validator(), &records);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["status"], "success");
}

#[test]
fn published_completion_fixtures_are_schema_valid() {
    let expected = output::contract::Command::ALL
        .iter()
        .copied()
        .filter(|command| {
            command
                .formats()
                .contains(&output::contract::Format::Ndjson)
        })
        .collect::<std::collections::HashSet<_>>();
    let actual = COMPLETION_FIXTURES
        .iter()
        .map(|(command, _, _)| *command)
        .collect::<std::collections::HashSet<_>>();
    assert_eq!(actual, expected, "fixture inventory must be complete");
    assert_eq!(
        COMPLETION_FIXTURES.len(),
        actual.len(),
        "fixtures must be unique"
    );

    for &(command, requires_terminal_stats, document) in COMPLETION_FIXTURES {
        let (sink, bytes) = stream(command);
        complete(&sink, requires_terminal_stats, result(document))
            .expect("published completion must render");
        let records = bytes.records();
        validate_records(schema_validator(), &records);
        assert_eq!(records.len(), 1, "{command:?}");
        assert_eq!(records[0]["status"], "success", "{command:?}");
    }
}

fn frame(bytes: &[u8]) -> core::frame::Frame {
    core::frame::Frame::new(UNIX_EPOCH, core::frame::LinkType::RAW, bytes.to_vec())
        .expect("typed event frame")
}

fn decoded(bytes: &[u8]) -> core::decode::DecodedPacket {
    let frame = frame(bytes);
    let mut packet = core::Packet::new();
    packet.push(core::layer::Raw::new(bytes.to_vec()));
    core::decode::DecodedPacket {
        packet,
        original: frame.bytes().clone(),
        frame,
        layout: core::layout::PacketLayout::default(),
        diagnostics: Vec::new(),
    }
}

fn scan_probe(sequence: u64) -> packetcraftr::scan::ProbeEvidence {
    let address = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
    packetcraftr::scan::ProbeEvidence {
        sequence,
        address,
        transport: packetcraftr::scan::Transport::Tcp,
        port: Some(443),
        attempt: 1,
        status: packetcraftr::scan::ProbeStatus::Timeout,
        classification: packetcraftr::scan::Classification::Timeout,
        responder: None,
        sent_at: UNIX_EPOCH,
        received_at: None,
        latency: None,
        response: None,
        reason: "timeout".to_owned(),
    }
}

fn trace_probe(sequence: u64) -> packetcraftr::traceroute::ProbeEvidence {
    packetcraftr::traceroute::ProbeEvidence {
        sequence,
        hop_limit: 1,
        attempt: 1,
        destination: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 20)),
        strategy: packetcraftr::traceroute::Strategy::Udp,
        destination_port: Some(33_434),
        status: packetcraftr::traceroute::ProbeStatus::Timeout,
        response_kind: None,
        responder: None,
        sent_at: UNIX_EPOCH,
        received_at: None,
        latency: None,
        response: None,
        reason: "timeout".to_owned(),
    }
}

fn dns_context() -> Arc<packetcraftr::dns::EventContext> {
    Arc::new(packetcraftr::dns::EventContext {
        server: Arc::from("resolver.test"),
        server_port: 53,
        query_name: Arc::from("example.test."),
        query_type: packetcraftr::dns::QueryType::A,
    })
}

fn dns_attempt() -> packetcraftr::dns::AttemptEvidence {
    packetcraftr::dns::AttemptEvidence {
        attempt: 1,
        transport: packetcraftr::dns::Transport::Udp,
        server_address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53)),
        source_port: Some(49_152),
        status: packetcraftr::dns::Outcome::Timeout,
        sent_at: Some(UNIX_EPOCH),
        received_at: None,
        latency: None,
        response: None,
        response_code: None,
        reason: "timeout".to_owned(),
    }
}

fn fuzz_cases() -> (core::fuzz::Case, packetcraftr::fuzz::Case) {
    let mut packet = core::Packet::new();
    packet.push(core::layer::Raw::new(vec![0_u8]));
    let request = core::fuzz::Request {
        cases: 1,
        strategies: vec![core::fuzz::Strategy::BitFlip],
        targets: vec!["0.bytes".parse().expect("raw fuzz target")],
        ..core::fuzz::Request::default()
    };
    let registry = core::protocol::builtin::registry();
    let case = core::fuzz::run(&request, packet, registry)
        .expect("offline fuzz fixture")
        .cases
        .into_iter()
        .next()
        .expect("one fuzz case");
    (case.clone(), packetcraftr::fuzz::Case::from(case))
}

fn sent_packet() -> packetcraftr::SentPacket {
    use packetcraftr::netio::link::{Capability, Mode};
    use packetcraftr::netio::route::{Decision, Materialized, Plan, Scope, SelectionReason};

    let mut packet = core::Packet::new();
    packet.push(core::layer::Raw::new(vec![0_u8]));
    let registry = core::protocol::builtin::registry();
    let built = core::build::Builder::new(registry)
        .build(
            packet,
            core::build::Context::default(),
            core::build::Options::default(),
        )
        .expect("sent fixture builds");
    let route = Materialized {
        plan: Plan {
            decision: Decision {
                interface: packetcraftr::netio::interface::Id {
                    name: "fixture0".to_owned(),
                    index: 1,
                },
                source_mac: None,
                selected_source: None,
                preferred_source: None,
                next_hop: None,
                selection_reason: SelectionReason::InterfaceOnly,
                destination_scope: Scope::Link,
                mtu: u32::MAX,
                capability: Capability::Layer3,
                link_type: core::frame::LinkType::RAW,
            },
            mode: Mode::Layer3,
            lookup_destination: None,
            final_destination: None,
            visited_destinations: Vec::new(),
            packet_source: None,
            neighbor_source: None,
            neighbor_target: None,
            destination_mac: None,
            source_mac: None,
            neighbor_vlan_tags: Vec::new(),
            synthesized_ethernet: false,
        },
        neighbor_resolution: None,
    };
    let report = packetcraftr::netio::transmit::Submission::start()
        .complete(built.bytes.len(), built.bytes.clone());
    packetcraftr::SentPacket::try_new(built, route, report).expect("trusted sent fixture")
}

#[test]
fn production_typed_event_variants_are_schema_valid() {
    let read =
        output::read::Event::Frame(output::read::Frame::try_from_frame(1, frame(&[1])).unwrap());
    validate_typed_event(output::contract::Command::Read, read, Vec::new());
    let capture = output::capture::Event::try_from_frame(1, frame(&[1])).unwrap();
    validate_typed_event(output::contract::Command::Capture, capture, Vec::new());
    validate_typed_event(
        output::contract::Command::Replay,
        output::replay::Frame {
            source_index: 1,
            interface: output::replay::InterfaceId {
                name: "fixture0".to_owned(),
                index: 1,
            },
            link_mode: output::replay::LinkMode::Layer3,
            scheduled_delay: Duration::ZERO,
            bytes_sent: 1,
            frame: output::frame::Captured::try_from_frame(frame(&[1])).unwrap(),
            transmitted: true,
        },
        Vec::new(),
    );
    validate_typed_event(
        output::contract::Command::Follow,
        output::follow::Chunk {
            direction: output::follow::Direction::Client,
            frame: 1,
            bytes_hex: "01".to_owned(),
        },
        Vec::new(),
    );
    validate_typed_event(
        output::contract::Command::Expert,
        output::expert::Finding {
            severity: output::expert::Severity::Warning,
            code: "fixture.warning".to_owned(),
            frame: 1,
            transport: None,
            stream: None,
            message: "warning".to_owned(),
        },
        Vec::new(),
    );
    validate_typed_event(
        output::contract::Command::Tls,
        tls_session_event(),
        Vec::new(),
    );
    validate_active_event_variants();
    validate_fuzz_event_variants();
    validate_exchange_event_variants();
}

fn ip_reassembly_events() -> [output::reassembly::Event; 3] {
    let ipv4 = output::reassembly::DatagramKey {
        family: output::reassembly::Family::Ipv4,
        scope: 0,
        source: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
        destination: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2)),
        identification: 42,
        protocol: Some(17),
    };
    let ipv6 = output::reassembly::DatagramKey {
        family: output::reassembly::Family::Ipv6,
        scope: 1,
        source: "2001:db8::1".parse().expect("documentation address"),
        destination: "2001:db8::2".parse().expect("documentation address"),
        identification: 70_000,
        protocol: None,
    };
    [
        output::reassembly::Event::IpDatagramCompleted {
            frame: 2,
            outcome: output::reassembly::DatagramOutcome::Completed {
                key: ipv4.clone(),
                fragment_count: 2,
                unique_bytes: 24,
                final_payload_length: 24,
                datagram_bytes: 44,
                duplicate_fragments: 0,
                overlap_bytes: 0,
            },
        },
        output::reassembly::Event::IpDatagramIncomplete {
            frame: 7,
            outcome: output::reassembly::DatagramOutcome::Incomplete {
                key: ipv6,
                reason: output::reassembly::IncompleteReason::IdleExpired,
                fragment_count: 3,
                unique_bytes: 32,
                known_final_length: Some(48),
                duplicate_fragments: 1,
                overlap_bytes: 0,
            },
        },
        output::reassembly::Event::IpOverlapResolved {
            frame: 8,
            key: ipv4,
            policy: output::reassembly::OverlapPolicy::Last,
            affected_bytes: 8,
            fragment_count: 3,
            unique_bytes: 24,
        },
    ]
}

fn validate_ip_event_stream<T: serde::Serialize>(command: output::contract::Command, terminal: T) {
    let (sink, bytes) = stream(command);
    for event in ip_reassembly_events() {
        sink.emit_data(event, Vec::new())
            .expect("IP lifecycle event must render");
    }
    sink.complete(terminal, Vec::new())
        .expect("terminal report must render");

    let records = bytes.records();
    validate_records(schema_validator(), &records);
    assert_eq!(records.len(), 4);
    assert_eq!(records[0]["result"]["event"], "ip_datagram_completed");
    assert_eq!(records[1]["result"]["event"], "ip_datagram_incomplete");
    assert_eq!(records[2]["result"]["event"], "ip_overlap_resolved");
    assert!(records[3]["result"]["ip_reassembly"].is_object());
    assert_eq!(
        records[3]["result"]["ip_reassembly"]["families"][0]["family"],
        "ipv4"
    );
    assert_eq!(
        records[3]["result"]["ip_reassembly"]["families"][1]["family"],
        "ipv6"
    );
    assert!(sink.is_terminal());
    assert!(
        sink.emit_data(ip_reassembly_events()[0].clone(), Vec::new())
            .is_err(),
        "a second terminal tail must not be writable"
    );
    assert_eq!(bytes.records(), records);
}

#[test]
fn ip_reassembly_events_and_terminal_reports_are_valid_for_every_offline_stream() {
    validate_ip_event_stream(
        output::contract::Command::Follow,
        output::follow::Report {
            transport: output::expert::StreamTransport::Udp,
            stream: 0,
            client: None,
            server: None,
            frames: 0,
            client_bytes: 0,
            server_bytes: 0,
            undelivered_bytes: 0,
            chunks: Vec::new(),
            ip_reassembly: output::reassembly::Report::default(),
        },
    );
    validate_ip_event_stream(
        output::contract::Command::Expert,
        output::expert::Report {
            frames_read: 0,
            frames_matched: 0,
            errors: 0,
            warnings: 0,
            notes: 0,
            codes: Vec::new(),
            findings: Vec::new(),
            ip_reassembly: output::reassembly::Report::default(),
        },
    );
    validate_ip_event_stream(
        output::contract::Command::Tls,
        output::tls::Event::complete(output::tls::Summary::default()),
    );
}

/// A minimal session record: the shape a `gap` session takes when the capture
/// started after the ClientHello, so the optional halves are exercised too.
fn tls_session_event() -> output::tls::Event {
    let endpoint = |last: u8, port: u16| output::tls::Endpoint {
        address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, last)),
        port,
    };
    output::tls::Event::session(output::tls::Session {
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
        alerts: vec![output::tls::Alert {
            level: 2,
            description: 40,
            description_name: Some("handshake_failure"),
        }],
        alerts_dropped: 2,
        status: output::tls::Status::Gap,
        reason: Some("no ClientHello observed".to_owned()),
    })
}

fn validate_active_event_variants() {
    for event in [
        packetcraftr::scan::Event::Probe {
            target: Arc::from("scan.test"),
            probe: scan_probe(9),
        },
        packetcraftr::scan::Event::Undecoded { frame: frame(&[2]) },
        packetcraftr::scan::Event::Diagnostic(core::diagnostic::Diagnostic::warning(
            "scan.fixture",
            "warning",
        )),
    ] {
        let (event, diagnostics) = output::scan::Event::try_from_scan(event).unwrap();
        validate_typed_event(output::contract::Command::Scan, event, diagnostics);
    }
    for event in [
        packetcraftr::traceroute::Event::Probe {
            target: Arc::from("trace.test"),
            probe: trace_probe(9),
        },
        packetcraftr::traceroute::Event::Undecoded(packetcraftr::traceroute::UndecodedEvidence {
            hop_limit: 1,
            frame: frame(&[3]),
        }),
        packetcraftr::traceroute::Event::Diagnostic(core::diagnostic::Diagnostic::warning(
            "trace.fixture",
            "warning",
        )),
    ] {
        let (event, diagnostics) = output::traceroute::Event::try_from_traceroute(event).unwrap();
        validate_typed_event(output::contract::Command::Traceroute, event, diagnostics);
    }
    validate_dns_event_variants();
}

fn validate_dns_event_variants() {
    let context = dns_context();
    let owner = packetcraftr::dns::Name::from_labels([vec![b'a']]).unwrap();
    let record = packetcraftr::dns::Record {
        owner,
        class: 1,
        ttl: 1,
        value: packetcraftr::dns::RecordValue::A(Ipv4Addr::new(192, 0, 2, 1)),
    };
    let events = vec![
        packetcraftr::dns::Event::Attempt {
            context: Arc::clone(&context),
            evidence: dns_attempt(),
        },
        packetcraftr::dns::Event::Attempt {
            context: Arc::clone(&context),
            evidence: packetcraftr::dns::AttemptEvidence {
                transport: packetcraftr::dns::Transport::Tcp,
                source_port: None,
                status: packetcraftr::dns::Outcome::Response,
                received_at: Some(UNIX_EPOCH + Duration::from_millis(1)),
                latency: Some(Duration::from_millis(1)),
                response_code: Some(0),
                reason: "validated DNS-over-TCP response".to_owned(),
                ..dns_attempt()
            },
        },
        packetcraftr::dns::Event::Record {
            attempt: 1,
            transport: packetcraftr::dns::Transport::Tcp,
            context: Arc::clone(&context),
            section: packetcraftr::dns::Section::Answer,
            record,
        },
        packetcraftr::dns::Event::Rejected {
            attempt: 1,
            transport: packetcraftr::dns::Transport::Tcp,
            context,
            record: packetcraftr::dns::RejectedRecord {
                section: packetcraftr::dns::Section::Answer,
                index: 0,
                owner: "a.".to_owned(),
                type_code: 1,
                reason: "irrelevant".to_owned(),
            },
        },
        packetcraftr::dns::Event::Undecoded(packetcraftr::dns::UndecodedEvidence {
            attempt: 1,
            frame: frame(&[4]),
        }),
        packetcraftr::dns::Event::Diagnostic(core::diagnostic::Diagnostic::warning(
            "dns.fixture",
            "warning",
        )),
    ];
    for event in events {
        let (event, diagnostics) = output::dns::Event::try_from_dns(event).unwrap();
        validate_typed_event(output::contract::Command::Dns, event, diagnostics);
    }
}

#[test]
fn dns_schema_forbids_capture_frames_on_tcp_attempts() {
    let mut evidence = dns_attempt();
    evidence.response = Some(frame(&[4]));
    let (event, diagnostics) =
        output::dns::Event::try_from_dns(packetcraftr::dns::Event::Attempt {
            context: dns_context(),
            evidence,
        })
        .unwrap();
    let (sink, bytes) = stream(output::contract::Command::Dns);
    sink.emit_data(event, diagnostics).unwrap();
    let mut record = bytes.records().remove(0);
    schema_validator()
        .validate(&record)
        .expect("UDP captured evidence is valid");
    record["result"]["evidence"]["transport"] = json!("tcp");
    assert!(schema_validator().validate(&record).is_err());
}

#[test]
fn dns_schema_enforces_fallback_transport_consistency() {
    let document: Value = serde_json::from_str(include_str!(
        "../../../examples/documents/output-dns-success.json"
    ))
    .unwrap();
    schema_validator()
        .validate(&document)
        .expect("published fallback aggregate is valid");

    let mut no_fallback = document.clone();
    no_fallback["result"]["fallback_attempted"] = json!(false);
    no_fallback["result"]["accepted_transport"] = json!("udp");
    assert!(schema_validator().validate(&no_fallback).is_err());

    let mut no_tcp_attempt = document.clone();
    no_tcp_attempt["result"]["attempts"]
        .as_array_mut()
        .unwrap()
        .pop();
    assert!(schema_validator().validate(&no_tcp_attempt).is_err());

    let mut no_transport = document.clone();
    no_transport["result"]
        .as_object_mut()
        .unwrap()
        .remove("accepted_transport");
    assert!(schema_validator().validate(&no_transport).is_err());

    let mut no_udp_source = document;
    no_udp_source["result"]["attempts"][0]
        .as_object_mut()
        .unwrap()
        .remove("source_port");
    assert!(schema_validator().validate(&no_udp_source).is_err());
}

#[test]
fn dns_schema_rejects_truncated_tcp_results() {
    for document in [
        include_str!("../../../examples/documents/output-dns-success.json"),
        include_str!("../../../examples/documents/output-dns-complete.json"),
    ] {
        let mut document: Value = serde_json::from_str(document).unwrap();
        document["result"]["outcome"] = json!("truncated");
        assert!(schema_validator().validate(&document).is_err());
    }
}

fn validate_fuzz_event_variants() {
    let (offline, live) = fuzz_cases();
    let event = output::fuzz::Event::try_from_offline(offline).unwrap();
    validate_typed_event(output::contract::Command::Fuzz, event, Vec::new());
    let event = output::fuzz::Event::try_from_live(live).unwrap();
    validate_typed_event(output::contract::Command::Fuzz, event, Vec::new());
}

fn validate_exchange_event_variants() {
    let events = vec![
        packetcraftr::exchange::Event::Sent {
            request_index: 0,
            sent: Arc::new(sent_packet()),
        },
        packetcraftr::exchange::Event::Response(packetcraftr::exchange::Response {
            request_index: 0,
            response: decoded(&[5]),
            latency: Duration::from_millis(1),
        }),
        packetcraftr::exchange::Event::Unanswered { request_index: 0 },
        packetcraftr::exchange::Event::Unsolicited {
            frame: decoded(&[6]),
        },
        packetcraftr::exchange::Event::Undecoded { frame: frame(&[7]) },
        packetcraftr::exchange::Event::Diagnostic(core::diagnostic::Diagnostic::warning(
            "exchange.fixture",
            "warning",
        )),
    ];
    for event in events {
        let (event, diagnostics) = output::exchange::Event::try_from_exchange(event).unwrap();
        validate_typed_event(output::contract::Command::Exchange, event, diagnostics);
    }
}

fn complete(
    sink: &output::envelope::StreamEncoder,
    requires_terminal_stats: bool,
    result: Value,
) -> Result<(), output::envelope::EncodeError> {
    if requires_terminal_stats {
        sink.complete_with_stats(result, Vec::new(), output::envelope::Stats::default())
    } else {
        sink.complete(result, Vec::new())
    }
}

#[test]
fn cleanup_failure_augments_the_primary_error_at_the_next_position() {
    let (sink, output) = stream(output::contract::Command::Exchange);
    sink.emit_data(
        json!({
            "event": "sent",
            "request_index": 77,
            "frame": { "bytes_hex": "00", "length": 1 }
        }),
        Vec::new(),
    )
    .unwrap();
    let cleanup = packetcraftr::netio::Error::Capture {
        message: "cleanup failure".to_owned(),
        source: None,
    };
    // Composed by the renderer under test rather than restated here, so the
    // record covers what `CliError::with_cleanup` actually produces.
    let primary = cli_errors::CliError::from_classification(
        packetcraftr::core::error::Classification::new(
            "io.primary",
            packetcraftr::core::error::Kind::Io,
            None,
        ),
        "primary capture failure",
        vec!["primary cause".to_owned()],
    )
    .with_cleanup(cleanup.clone());
    assert_eq!(
        primary.message,
        format!("primary capture failure; capture shutdown also failed: {cleanup}")
    );
    sink.emit_error(primary.output_error()).unwrap();

    let records = output.records();
    validate_records(schema_validator(), &records);
    assert_eq!(records[1]["sequence"], 1);
    assert_eq!(records[1]["error"]["code"], "io.primary");
    assert_eq!(records[1]["error"]["causes"][0], "primary cause");
    assert!(
        records[1]["error"]["causes"][1]
            .as_str()
            .unwrap()
            .contains("cleanup failure")
    );
}
