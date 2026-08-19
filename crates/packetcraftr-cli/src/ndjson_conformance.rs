// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, UNIX_EPOCH};

use packetcraftr::{core, output};
use serde_json::{Value, json};

use crate::errors::CliError;
use crate::rendering::NdjsonStream;
use crate::rendering::ndjson_test_support::{assert_contiguous, stream};

struct Fixture {
    command: output::contract::Command,
    requires_terminal_stats: bool,
    sparse_identifier: SparseIdentifier,
    event: Value,
    complete: Value,
}

#[derive(Clone, Copy)]
enum SparseIdentifier {
    SourceFrame,
    SourceSequence,
    Frame,
    ScanProbe,
    TraceProbe,
    DnsAttempt,
    FuzzCase,
    RequestIndex,
}

fn result(document: &str) -> Value {
    serde_json::from_str::<Value>(document).expect("published example must parse")["result"].clone()
}

fn offline_fixtures() -> Vec<Fixture> {
    vec![
        Fixture {
            command: output::contract::Command::Read,
            requires_terminal_stats: false,
            sparse_identifier: SparseIdentifier::SourceFrame,
            event: result(include_str!(
                "../../../examples/documents/output-read-event.json"
            )),
            complete: result(include_str!(
                "../../../examples/documents/output-read-complete.json"
            )),
        },
        Fixture {
            command: output::contract::Command::Capture,
            requires_terminal_stats: true,
            sparse_identifier: SparseIdentifier::SourceFrame,
            event: result(include_str!(
                "../../../examples/documents/output-capture-event.json"
            )),
            complete: result(include_str!(
                "../../../examples/documents/output-capture-complete.json"
            )),
        },
        Fixture {
            command: output::contract::Command::Replay,
            requires_terminal_stats: false,
            sparse_identifier: SparseIdentifier::SourceSequence,
            event: result(include_str!(
                "../../../examples/documents/output-replay-event.json"
            )),
            complete: result(include_str!(
                "../../../examples/documents/output-replay-success.json"
            )),
        },
        Fixture {
            command: output::contract::Command::Follow,
            requires_terminal_stats: false,
            sparse_identifier: SparseIdentifier::Frame,
            event: result(include_str!(
                "../../../examples/documents/output-follow-event.json"
            )),
            complete: result(include_str!(
                "../../../examples/documents/output-follow-complete.json"
            )),
        },
        Fixture {
            command: output::contract::Command::Expert,
            requires_terminal_stats: false,
            sparse_identifier: SparseIdentifier::Frame,
            event: result(include_str!(
                "../../../examples/documents/output-expert-event.json"
            )),
            complete: result(include_str!(
                "../../../examples/documents/output-expert-success.json"
            )),
        },
    ]
}

fn active_fixtures() -> Vec<Fixture> {
    vec![
        Fixture {
            command: output::contract::Command::Scan,
            requires_terminal_stats: false,
            sparse_identifier: SparseIdentifier::ScanProbe,
            event: result(include_str!(
                "../../../examples/documents/output-scan-event.json"
            )),
            complete: result(include_str!(
                "../../../examples/documents/output-scan-complete.json"
            )),
        },
        Fixture {
            command: output::contract::Command::Traceroute,
            requires_terminal_stats: false,
            sparse_identifier: SparseIdentifier::TraceProbe,
            event: result(include_str!(
                "../../../examples/documents/output-traceroute-event.json"
            )),
            complete: result(include_str!(
                "../../../examples/documents/output-traceroute-complete.json"
            )),
        },
        Fixture {
            command: output::contract::Command::Dns,
            requires_terminal_stats: false,
            sparse_identifier: SparseIdentifier::DnsAttempt,
            event: result(include_str!(
                "../../../examples/documents/output-dns-event.json"
            )),
            complete: result(include_str!(
                "../../../examples/documents/output-dns-complete.json"
            )),
        },
        Fixture {
            command: output::contract::Command::Fuzz,
            requires_terminal_stats: true,
            sparse_identifier: SparseIdentifier::FuzzCase,
            event: result(include_str!(
                "../../../examples/documents/output-fuzz-event.json"
            )),
            complete: result(include_str!(
                "../../../examples/documents/output-fuzz-complete.json"
            )),
        },
        Fixture {
            command: output::contract::Command::Exchange,
            requires_terminal_stats: true,
            sparse_identifier: SparseIdentifier::RequestIndex,
            event: result(include_str!(
                "../../../examples/documents/output-exchange-sent-event.json"
            )),
            complete: result(include_str!(
                "../../../examples/documents/output-exchange-complete.json"
            )),
        },
    ]
}

fn fixtures() -> Vec<Fixture> {
    let fixtures = offline_fixtures()
        .into_iter()
        .chain(active_fixtures())
        .collect::<Vec<_>>();
    let expected = output::contract::Command::ALL
        .iter()
        .copied()
        .filter(|command| {
            command
                .formats()
                .contains(&output::contract::Format::Ndjson)
        })
        .collect::<std::collections::HashSet<_>>();
    let actual = fixtures
        .iter()
        .map(|fixture| fixture.command)
        .collect::<std::collections::HashSet<_>>();
    assert_eq!(
        actual, expected,
        "NDJSON fixture inventory must be complete"
    );
    assert_eq!(
        fixtures.len(),
        actual.len(),
        "NDJSON fixtures must be unique"
    );
    fixtures
}

fn validate_records(validator: &jsonschema::Validator, records: &[Value]) {
    assert_contiguous(records);
    for record in records {
        validator
            .validate(record)
            .unwrap_or_else(|error| panic!("stream record must match the schema: {error}"));
    }
}

fn validate_typed_event<T: serde::Serialize + Clone>(
    command: output::contract::Command,
    event: T,
    diagnostics: Vec<core::diagnostic::Diagnostic>,
) {
    let fixture = fixtures()
        .into_iter()
        .find(|fixture| fixture.command == command)
        .expect("typed event command has a completion fixture");
    let (success, bytes) = stream(command);
    crate::commands::progressive::render_event(event.clone(), diagnostics.clone(), &success)
        .expect("typed production event must render");
    complete(&success, fixture.requires_terminal_stats, fixture.complete)
        .expect("typed production stream must complete");
    let records = bytes.records();
    validate_records(crate::test_support::schema_validator(), &records);
    assert_eq!(records.len(), 2);
    assert!(records.iter().all(|record| record["status"] == "success"));

    let (sink, bytes) = stream(command);
    crate::commands::progressive::render_event(event, diagnostics, &sink)
        .expect("typed production event must render");
    sink.emit_error(CliError::new(5, "typed partial failure").output_error())
        .expect("typed partial stream must terminate");
    let records = bytes.records();
    validate_records(crate::test_support::schema_validator(), &records);
    assert_eq!(records.len(), 2);
    assert_eq!(records[0]["status"], "success");
    assert_eq!(records[1]["status"], "error");
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
        server_address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53)),
        source_port: 49_152,
        status: packetcraftr::dns::Outcome::Timeout,
        sent_at: UNIX_EPOCH,
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
    let registry = Arc::new(core::protocol::builtin::registry().expect("built-in registry"));
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
    let registry = Arc::new(core::protocol::builtin::registry().expect("built-in registry"));
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
    let read = output::read::Event::try_from_frame(1, frame(&[1])).unwrap();
    validate_typed_event(output::contract::Command::Read, read, Vec::new());
    let capture = output::capture::Event::try_from_frame(1, frame(&[1])).unwrap();
    validate_typed_event(output::contract::Command::Capture, capture, Vec::new());
    validate_typed_event(
        output::contract::Command::Replay,
        output::replay::Frame {
            source_index: 1,
            interface: output::replay::Interface {
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
    validate_active_event_variants();
    validate_fuzz_event_variants();
    validate_exchange_event_variants();
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
        packetcraftr::dns::Event::Record {
            attempt: 1,
            context: Arc::clone(&context),
            section: packetcraftr::dns::Section::Answer,
            record,
        },
        packetcraftr::dns::Event::Rejected {
            attempt: 1,
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
    sink: &NdjsonStream,
    requires_terminal_stats: bool,
    result: Value,
) -> Result<(), CliError> {
    if requires_terminal_stats {
        sink.complete_with_stats(result, Vec::new(), output::envelope::Stats::default())
    } else {
        sink.complete(result, Vec::new())
    }
}

#[test]
fn every_command_stream_is_schema_valid_contiguous_and_terminal() {
    let validator = crate::test_support::schema_validator();
    for fixture in fixtures() {
        let (sink, output) = stream(fixture.command);
        sink.emit_data(fixture.event, Vec::new()).unwrap();
        complete(&sink, fixture.requires_terminal_stats, fixture.complete).unwrap();
        let terminal_bytes = output.bytes();
        let records = output.records();

        validate_records(validator, &records);
        assert_eq!(records.len(), 2);
        assert_eq!(records[0]["status"], "success");
        assert_eq!(records[1]["status"], "success");
        assert!(sink.emit_data(json!({"late": true}), Vec::new()).is_err());
        assert!(
            sink.emit_error(CliError::new(5, "late").output_error())
                .is_err()
        );
        assert_eq!(output.bytes(), terminal_bytes);
    }
}

#[test]
fn every_command_empty_success_completes_at_zero() {
    let validator = crate::test_support::schema_validator();
    for fixture in fixtures() {
        let (sink, output) = stream(fixture.command);
        complete(&sink, fixture.requires_terminal_stats, fixture.complete).unwrap();
        let records = output.records();

        validate_records(validator, &records);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["sequence"], 0);
        assert_eq!(records[0]["status"], "success");
    }
}

#[test]
fn every_command_early_and_late_failure_is_the_only_terminal_record() {
    let validator = crate::test_support::schema_validator();
    for fixture in fixtures() {
        let (empty, output) = stream(fixture.command);
        empty
            .emit_error(CliError::new(5, "early failure").output_error())
            .unwrap();
        let records = output.records();
        validate_records(validator, &records);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["sequence"], 0);
        assert_eq!(records[0]["status"], "error");

        let (partial, output) = stream(fixture.command);
        partial.emit_data(fixture.event, Vec::new()).unwrap();
        partial
            .emit_error(CliError::new(5, "late failure").output_error())
            .unwrap();
        let terminal_bytes = output.bytes();
        let records = output.records();
        validate_records(validator, &records);
        assert_eq!(records.len(), 2);
        assert_eq!(records[1]["sequence"], 1);
        assert_eq!(records[1]["status"], "error");
        assert!(partial.emit_data(fixture.complete, Vec::new()).is_err());
        assert_eq!(output.bytes(), terminal_bytes);
    }
}

#[test]
fn sparse_domain_identifiers_never_select_envelope_sequence() {
    let validator = crate::test_support::schema_validator();
    for mut fixture in fixtures() {
        set_sparse_domain_identifier(fixture.sparse_identifier, &mut fixture.event);
        let (sink, output) = stream(fixture.command);
        sink.emit_data(fixture.event, Vec::new()).unwrap();
        complete(&sink, fixture.requires_terminal_stats, fixture.complete).unwrap();
        let records = output.records();

        validate_records(validator, &records);
        assert_eq!(records[0]["sequence"], 0);
        assert_eq!(records[1]["sequence"], 1);
    }
}

fn set_sparse_domain_identifier(identifier: SparseIdentifier, event: &mut Value) {
    let sparse = json!(9_000_000_007_u64);
    match identifier {
        SparseIdentifier::SourceFrame => {
            event["source_frame"] = sparse;
        }
        SparseIdentifier::SourceSequence => event["source_sequence"] = sparse,
        SparseIdentifier::Frame => {
            event["frame"] = sparse;
        }
        SparseIdentifier::ScanProbe | SparseIdentifier::TraceProbe => {
            event["probe"]["sequence"] = sparse;
        }
        SparseIdentifier::DnsAttempt => event["evidence"]["attempt"] = json!(31),
        SparseIdentifier::FuzzCase => {
            event["case"]["index"] = sparse.clone();
            event["case"]["reproduction"]["case_index"] = sparse;
        }
        SparseIdentifier::RequestIndex => event["request_index"] = sparse,
    }
}

#[derive(Clone, Default)]
struct SharedBytes(Arc<Mutex<Vec<u8>>>);

impl io::Write for SharedBytes {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Err(io::Error::other("induced flush failure"))
    }
}

#[test]
fn sink_failure_never_appends_a_second_stdout_document() {
    let validator = crate::test_support::schema_validator();
    for fixture in fixtures() {
        let output = SharedBytes::default();
        let sink = NdjsonStream::new(Some(fixture.command), output.clone());
        let error = sink
            .emit_data(fixture.event, Vec::new())
            .expect_err("the record flush must fail");
        assert!(error.message.contains("sequence 0"));
        let bytes_after_failure = output.0.lock().unwrap().clone();
        let records = std::str::from_utf8(&bytes_after_failure)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .collect::<Vec<_>>();
        validate_records(validator, &records);
        assert_eq!(records.len(), 1);

        assert!(
            sink.emit_error(CliError::new(5, "secondary error").output_error())
                .is_err()
        );
        assert_eq!(*output.0.lock().unwrap(), bytes_after_failure);
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
    let primary = CliError::from_classification(
        packetcraftr::core::error::Classification::new(
            "io.primary",
            packetcraftr::core::error::Kind::Io,
            None,
        ),
        "primary capture failure",
        vec!["primary cause".to_owned()],
    )
    .with_cleanup(packetcraftr::netio::Error::Capture {
        message: "cleanup failure".to_owned(),
    });
    sink.emit_error(primary.output_error()).unwrap();

    let records = output.records();
    validate_records(crate::test_support::schema_validator(), &records);
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
