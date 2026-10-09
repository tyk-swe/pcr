// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
#![allow(dead_code)]

use packetcraftr_core::protocol::application::dns as dns_wire;

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};

use packetcraftr_core as core;

use packetcraftr_cli::output;
use packetcraftr_cli::test_support::sent_packet_with;
use serde_json::{Value, json};

use crate::common;

use common::{assert_contiguous, schema_validator, stream};

const COMPLETION_FIXTURES: &[(output::contract::Command, bool, &str)] = &[
    (
        output::contract::Command::Rewrite,
        false,
        include_str!("../../../../examples/documents/output-rewrite-complete.json"),
    ),
    (
        output::contract::Command::Export,
        false,
        include_str!("../../../../examples/documents/output-export-complete.json"),
    ),
    (
        output::contract::Command::Http,
        false,
        include_str!("../../../../examples/documents/output-http-complete.json"),
    ),
    (
        output::contract::Command::Http2,
        false,
        include_str!("../../../../examples/documents/output-http2-complete.json"),
    ),
    (
        output::contract::Command::DnsRead,
        false,
        include_str!("../../../../examples/documents/output-dns-read-complete.json"),
    ),
    (
        output::contract::Command::Fragment,
        false,
        include_str!("../../../../examples/documents/output-fragment-complete.json"),
    ),
    (
        output::contract::Command::Merge,
        false,
        include_str!("../../../../examples/documents/output-merge-complete.json"),
    ),
    (
        output::contract::Command::Dissect,
        false,
        include_str!("../../../../examples/documents/output-dissect-complete.json"),
    ),
    (
        output::contract::Command::Build,
        false,
        include_str!("../../../../examples/documents/output-build-complete.json"),
    ),
    (
        output::contract::Command::Read,
        false,
        include_str!("../../../../examples/documents/output-read-complete.json"),
    ),
    (
        output::contract::Command::Capture,
        true,
        include_str!("../../../../examples/documents/output-capture-complete.json"),
    ),
    (
        output::contract::Command::Replay,
        false,
        include_str!("../../../../examples/documents/output-replay-success.json"),
    ),
    (
        output::contract::Command::Follow,
        false,
        include_str!("../../../../examples/documents/output-follow-complete.json"),
    ),
    (
        output::contract::Command::Expert,
        false,
        include_str!("../../../../examples/documents/output-expert-success.json"),
    ),
    (
        output::contract::Command::Scan,
        false,
        include_str!("../../../../examples/documents/output-scan-complete.json"),
    ),
    (
        output::contract::Command::Traceroute,
        false,
        include_str!("../../../../examples/documents/output-traceroute-complete.json"),
    ),
    (
        output::contract::Command::Dns,
        false,
        include_str!("../../../../examples/documents/output-dns-complete.json"),
    ),
    (
        output::contract::Command::Fuzz,
        true,
        include_str!("../../../../examples/documents/output-fuzz-complete.json"),
    ),
    (
        output::contract::Command::Exchange,
        true,
        include_str!("../../../../examples/documents/output-exchange-complete.json"),
    ),
    (
        output::contract::Command::Tls,
        false,
        include_str!("../../../../examples/documents/output-tls-complete.json"),
    ),
    (
        output::contract::Command::VerifyForwarding,
        false,
        include_str!("../../../../examples/documents/output-verify-forwarding-complete.json"),
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

fn validate_published<T: output::stream::StreamRecord>(
    command: output::contract::Command,
    published: output::envelope::Published<T>,
) {
    let (sink, bytes) = stream(command);
    sink.emit_published(published)
        .expect("typed production event must render");
    let records = bytes.records();
    validate_records(schema_validator(), &records);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["status"], "success");
}

fn validate_typed_event<T: output::stream::StreamRecord>(
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

fn frame(bytes: &[u8]) -> core::frame::Frame {
    core::frame::Frame::new(UNIX_EPOCH, core::frame::LinkType::RAW, bytes.to_vec())
        .expect("typed event frame")
}

fn decoded(bytes: &[u8]) -> core::decode::DecodedPacket {
    let frame = frame(bytes);
    let mut packet = core::packet::Packet::new();
    packet.push(core::layer::Raw::new(bytes.to_vec()));
    core::decode::DecodedPacket {
        packet,
        frame,
        layout: core::layout::PacketLayout::default(),
        diagnostics: Vec::new(),
    }
}

fn scan_probe(sequence: u64) -> packetcraftr::scan::ProbeEvidence {
    let address = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
    packetcraftr::scan::ProbeEvidence {
        scope: None,
        application: None,
        sequence,
        stage: packetcraftr::scan::Stage::Scan,
        address,
        transport: packetcraftr::probe::Transport::Tcp,
        port: Some(443),
        attempt: 1,
        status: packetcraftr::probe::ProbeStatus::Timeout,
        classification: packetcraftr::scan::Classification::Timeout,
        reply: None,
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
        strategy: packetcraftr::probe::Transport::Udp,
        destination_port: Some(33_434),
        status: packetcraftr::probe::ProbeStatus::Timeout,
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
        server_address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53)),
        status: packetcraftr::dns::Outcome::Timeout,
        received_at: None,
        latency: None,
        response_code: None,
        reason: "timeout".to_owned(),
        transport_evidence: packetcraftr::dns::TransportEvidence::Udp {
            source_port: 49_152,
            sent_at: UNIX_EPOCH,
            response: None,
        },
    }
}

fn fuzz_cases() -> (core::fuzz::Case, packetcraftr::fuzz::Event) {
    let mut packet = core::packet::Packet::new();
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
    let live = packetcraftr::fuzz::Event::Case(packetcraftr::fuzz::Trial {
        case: case.clone(),
        evidence: None,
    });
    (case, live)
}

fn ip_reassembly_events() -> [output::reassembly::Event; 3] {
    use packetcraftr_core::analysis::reassembly::ip::{
        DatagramKey, IncompleteDatagram, Ipv4DatagramKey, Ipv6DatagramKey,
    };
    use packetcraftr_core::analysis::scope::ScopeId;
    let ipv4 = DatagramKey::Ipv4(Ipv4DatagramKey {
        scope: serde_json::from_str::<ScopeId>("0").unwrap(),
        source: Ipv4Addr::new(192, 0, 2, 1),
        destination: Ipv4Addr::new(198, 51, 100, 2),
        identification: 42,
        protocol: 17,
    });
    let ipv6 = DatagramKey::Ipv6(Ipv6DatagramKey {
        scope: serde_json::from_str::<ScopeId>("0").unwrap(),
        source: "2001:db8::1".parse().unwrap(),
        destination: "2001:db8::2".parse().unwrap(),
        identification: 70_000,
    });
    [
        output::reassembly::Event::IpDatagramCompleted {
            frame: 2,
            outcome: packetcraftr_core::analysis::IpDatagramOutcome::Completed {
                key: ipv4.clone(),
                fragment_count: 2,
                unique_bytes: 24,
                final_payload_length: 24,
                datagram_bytes: 44,
                duplicate_fragments: 0,
                overlap_bytes: 0,
            }
            .into(),
        },
        output::reassembly::Event::IpDatagramIncomplete {
            frame: 7,
            outcome: packetcraftr_core::analysis::IpDatagramOutcome::Incomplete(
                IncompleteDatagram {
                    key: ipv6,
                    reason:
                        packetcraftr_core::analysis::reassembly::ip::IncompleteReason::IdleExpired,
                    fragment_count: 3,
                    unique_bytes: 32,
                    known_final_length: Some(48),
                    duplicate_fragments: 1,
                    overlap_bytes: 0,
                },
            )
            .into(),
        },
        output::reassembly::Event::IpOverlapResolved {
            frame: 8,
            key: ipv4.into(),
            policy: packetcraftr_core::analysis::reassembly::ip::OverlapPolicy::Last.into(),
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
    assert_eq!(records[0]["event"], "ip_datagram_completed");
    assert_eq!(records[1]["event"], "ip_datagram_incomplete");
    assert_eq!(records[2]["event"], "ip_overlap_resolved");
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

fn tls_session_event() -> output::tls::Event {
    let endpoint = |last: u8, port: u16| output::analysis::Endpoint {
        address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, last)),
        port,
    };
    let mut scopes = packetcraftr_core::analysis::scope::Interner::new();
    let id = scopes.intern(None, Vec::new()).unwrap();
    output::tls::Event::from(output::tls::Session {
        scope: scopes.definition(id).unwrap().try_into().unwrap(),
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
        packetcraftr::scan::Event::Sent(packetcraftr::scan::SentProbe {
            probe: packetcraftr::scan::Probe {
                scope: None,
                udp_profile: None,
                sequence: 0,
                stage: packetcraftr::scan::Stage::Discovery,
                address: "192.0.2.2".parse().unwrap(),
                endpoint: packetcraftr::probe::ProbeEndpoint::Tcp { port: 80 },
                attempt: 1,
                udp_payload: bytes::Bytes::new(),
            },
            sent: sent_packet_with(Vec::new()),
        }),
        packetcraftr::scan::Event::Probe {
            target: Arc::from("scan.test"),
            probe: scan_probe(9),
        },
        packetcraftr::scan::Event::Undecoded { frame: frame(&[2]) },
        packetcraftr::scan::Event::Unattributed(packetcraftr::scan::Unattributed {
            attribution: packetcraftr::scan::Attribution::Late,
            sequence: Some(9),
            frame: frame(&[4]),
        }),
        packetcraftr::scan::Event::Diagnostic(core::diagnostic::Diagnostic::warning(
            "scan.fixture",
            "warning",
        )),
    ] {
        let event = output::envelope::Published::<output::scan::Event>::try_from(event).unwrap();
        validate_published(output::contract::Command::Scan, event);
    }
    let probe = scan_probe(9);
    validate_published(
        output::contract::Command::Scan,
        output::envelope::Published::<output::scan::Event>::from(packetcraftr::scan::Endpoint {
            address: probe.address,
            scope: None,
            transport: probe.transport,
            port: probe.port,
            classification: probe.classification,
            port_hint: Some("http"),
            inference: Some(packetcraftr::scan::Inference {
                state: Some(packetcraftr::scan::State::OpenOrFiltered),
                rule: packetcraftr::scan::Rule::UdpSilence,
                supporting: vec![9],
                conflicting: Vec::new(),
                unanswered: Vec::new(),
                failed: Vec::new(),
            }),
            probes: vec![probe],
        }),
    );
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
        let event =
            output::envelope::Published::<output::traceroute::Event>::try_from(event).unwrap();
        validate_published(output::contract::Command::Traceroute, event);
    }
    validate_dns_event_variants();
}

fn validate_dns_event_variants() {
    let context = dns_context();
    let owner = dns_wire::Name::from_labels([vec![b'a']]).unwrap();
    let record = dns_wire::Record {
        owner,
        class: 1,
        ttl: 1,
        value: dns_wire::RecordValue::A(Ipv4Addr::new(192, 0, 2, 1)),
    };
    let events = vec![
        packetcraftr::dns::Event::Attempt {
            context: Arc::clone(&context),
            evidence: dns_attempt(),
        },
        packetcraftr::dns::Event::Attempt {
            context: Arc::clone(&context),
            evidence: packetcraftr::dns::AttemptEvidence {
                transport_evidence: packetcraftr::dns::TransportEvidence::Tcp {
                    source_port: None,
                    sent_at: dns_attempt().sent_at(),
                },
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
        let event = output::envelope::Published::<output::dns::Event>::try_from(event).unwrap();
        validate_published(output::contract::Command::Dns, event);
    }
    // `complete` is reserved for the terminal record, so it emits through the
    // terminal path rather than `emit_data`.
    let (sink, bytes) = stream(output::contract::Command::Dns);
    sink.complete_with_stats(
        output::dns::Event::BatchComplete {
            server: "192.0.2.53".to_owned(),
            server_port: 53,
            questions: vec![
                output::dns::QuestionComplete {
                    query_name: "1.2.0.192.in-addr.arpa".to_owned(),
                    query_type: packetcraftr::dns::QueryType::PTR.code(),
                    transaction_id: 0x1234,
                    status: output::dns::QuestionStatus::Completed,
                    outcome: Some(output::dns::Outcome::Response),
                    error: None,
                },
                output::dns::QuestionComplete {
                    query_name: "unreachable.test".to_owned(),
                    query_type: packetcraftr::dns::QueryType::A.code(),
                    transaction_id: 0x1235,
                    status: output::dns::QuestionStatus::Failed,
                    outcome: None,
                    error: Some("induced failure".to_owned()),
                },
                output::dns::QuestionComplete {
                    query_name: "never.test".to_owned(),
                    query_type: packetcraftr::dns::QueryType::A.code(),
                    transaction_id: 0x1236,
                    status: output::dns::QuestionStatus::Unattempted,
                    outcome: None,
                    error: None,
                },
            ],
        },
        Vec::new(),
        packetcraftr::Stats::default(),
    )
    .expect("batch terminal record renders");
    validate_records(schema_validator(), &bytes.records());
}

#[test]
fn dns_schema_reject_trunc_tcp_results() {
    for document in [
        include_str!("../../../../examples/documents/output-dns-success.json"),
        include_str!("../../../../examples/documents/output-dns-complete.json"),
    ] {
        let mut document: Value = serde_json::from_str(document).unwrap();
        document["result"]["outcome"] = json!("truncated");
        assert!(schema_validator().validate(&document).is_err());
    }
}

fn validate_fuzz_event_variants() {
    let (offline, live) = fuzz_cases();
    let event = output::fuzz::Event::try_from(offline).unwrap();
    validate_typed_event(output::contract::Command::Fuzz, event, Vec::new());
    let event = output::fuzz::Event::try_from(live).unwrap();
    validate_typed_event(output::contract::Command::Fuzz, event, Vec::new());
}

fn validate_exchange_event_variants() {
    let events = vec![
        packetcraftr::exchange::Event::Sent {
            request_index: 0,
            sent: sent_packet_with(Vec::new()),
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
        let event =
            output::envelope::Published::<output::exchange::Event>::try_from(event).unwrap();
        validate_published(output::contract::Command::Exchange, event);
    }
}

fn complete(
    sink: &output::stream::StreamEncoder,
    requires_terminal_stats: bool,
    result: Value,
) -> Result<(), output::stream::EncodeError> {
    if requires_terminal_stats {
        sink.complete_with_stats(result, Vec::new(), packetcraftr::Stats::default())
    } else {
        sink.complete(result, Vec::new())
    }
}

#[test]
fn schema_reject_event_unknown_root_discs() {
    let original: Value = serde_json::from_str(include_str!(
        "../../../../examples/documents/output-tls-event.json"
    ))
    .unwrap();
    common::frozen_v10_schema_validator()
        .validate(&original)
        .unwrap();
    for (validator, family) in [
        (
            common::frozen_v10_schema_validator(),
            output::contract::SCHEMA_V10,
        ),
        (schema_validator(), output::contract::SCHEMA_V11),
    ] {
        let mut document = original.clone();
        document["schema"] = family.into();
        validator.validate(&document).unwrap();
        let mut legacy = document.clone();
        let event = legacy.as_object_mut().unwrap().remove("event").unwrap();
        legacy["result"]["event"] = event;
        assert!(validator.validate(&legacy).is_err());
        document["event"] = "future_unknown_event".into();
        assert!(validator.validate(&document).is_err());
    }
}
