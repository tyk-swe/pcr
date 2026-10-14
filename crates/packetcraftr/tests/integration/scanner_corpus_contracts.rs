// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#![allow(clippy::missing_panics_doc)]

use crate::common::scanner_fixture;

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use packetcraftr::CaptureProviders;
use packetcraftr::probe::{ProbeEndpoint, Transport};
use packetcraftr_core::budget::{Cancellation, Deadline};
use packetcraftr_netio::capture;
use packetcraftr_netio::capture::Session as _;

use packetcraftr::target::{Family, Selection, Specification, Target};
use packetcraftr::{Client, scan, traceroute};

use scanner_fixture::conditions::{ScriptedReply, Scripts};
use scanner_fixture::providers::{Condition, FamilyAddresses, Io, Providers};

const CORPUS: &str = include_str!("../../../../docs/scanner-corpus.v1.json");

const PORT: u16 = 443;
const TIMEOUT: Duration = Duration::from_millis(500);
const MAX_DURATION: Duration = Duration::from_secs(2);
const MAX_PROBES: usize = 1;
const MAX_EVIDENCE_BYTES: usize = 65536;

#[derive(serde::Deserialize)]
struct Corpus {
    fixture_addresses: std::collections::HashMap<String, FixtureAddresses>,
    request: CorpusRequest,
    scenarios: Vec<Scenario>,
    traceroute_scenarios: Vec<TraceScenario>,
    inference_scenarios: Vec<InferenceScenario>,
}

#[derive(serde::Deserialize)]
struct FixtureAddresses {
    source: IpAddr,
    destination: IpAddr,
    router: IpAddr,
}

#[derive(serde::Deserialize)]
struct CorpusRequest {
    attempts: u32,
    ports: Vec<u16>,
    timeout_ms: u64,
    max_duration_ms: u64,
    max_probes: usize,
    max_evidence_bytes: usize,
    windows: Vec<usize>,
}

#[derive(serde::Deserialize)]
struct Scenario {
    id: String,
    expected: Expected,
    #[serde(default)]
    expected_by_transport: std::collections::HashMap<String, Expected>,
}

#[derive(serde::Deserialize)]
struct Expected {
    attempt_classification: String,
    status: String,
    attributed_response: bool,
}

#[derive(serde::Deserialize)]
struct TraceScenario {
    id: String,
    expected_termination: String,
    expected_status: String,
    expected_attributed_response: bool,
}

/// One independently authored port-inference scenario. Only the fields the
/// scan consumes are read: the schema owns the rest.
#[derive(serde::Deserialize)]
struct InferenceScenario {
    id: String,
    families: Vec<String>,
    request: InferenceRequest,
    endpoints: Vec<InferenceEndpoint>,
}

#[derive(serde::Deserialize)]
struct InferenceRequest {
    attempts: u32,
    max_in_flight: usize,
    timeout_ms: u64,
    max_duration_ms: u64,
    max_probes: usize,
    max_evidence_bytes: usize,
}

#[derive(serde::Deserialize)]
struct InferenceEndpoint {
    transport: String,
    port: u16,
    script: Vec<String>,
    expected: InferenceExpectation,
}

#[derive(serde::Deserialize)]
struct InferenceExpectation {
    attempts: Vec<InferenceAttempt>,
    state: String,
    rule: String,
    partitions: InferencePartitions,
}

/// Attempt evidence is authored by ordinal: the runtime sequence number is an
/// operation-local coordinate and is not part of the expectation.
#[derive(serde::Deserialize)]
struct InferenceAttempt {
    ordinal: u32,
    status: String,
    classification: String,
    reply: Option<String>,
}

#[derive(serde::Deserialize)]
struct InferencePartitions {
    supporting: Vec<u32>,
    conflicting: Vec<u32>,
    unanswered: Vec<u32>,
    failed: Vec<u32>,
}

fn corpus() -> Corpus {
    let corpus: Corpus = serde_json::from_str(CORPUS).expect("the bundled corpus parses");
    for family in ["ipv4", "ipv6"] {
        let authored = &corpus.fixture_addresses[family];
        let fixture = addresses(family);
        assert_eq!(authored.source, fixture.source, "{family} source");
        assert_eq!(
            authored.destination, fixture.destination,
            "{family} destination"
        );
        assert_eq!(authored.router, fixture.router, "{family} router");
    }
    assert_eq!(corpus.request.attempts, 1);
    assert_eq!(corpus.request.ports, [PORT]);
    assert_eq!(corpus.request.timeout_ms, 20);
    assert_eq!(
        corpus.request.max_duration_ms,
        MAX_DURATION.as_millis() as u64
    );
    assert_eq!(corpus.request.max_probes, MAX_PROBES);
    assert_eq!(corpus.request.max_evidence_bytes, MAX_EVIDENCE_BYTES);
    assert_eq!(corpus.request.windows, [1, 2]);
    corpus
}

fn parse_condition(id: &str) -> Condition {
    Condition::parse(id).expect("corpus ids are fixture conditions")
}

fn addresses(family: &str) -> FamilyAddresses {
    match family {
        "ipv4" => FamilyAddresses::IPV4,
        "ipv6" => FamilyAddresses::IPV6,
        other => panic!("corpus family {other}"),
    }
}

fn family_of(addresses: FamilyAddresses) -> Family {
    match addresses.destination {
        IpAddr::V4(_) => Family::Ipv4,
        IpAddr::V6(_) => Family::Ipv6,
    }
}

fn transport(name: &str) -> Transport {
    match name {
        "tcp" => Transport::Tcp,
        "udp" => Transport::Udp,
        "icmp" => Transport::Icmp,
        other => panic!("corpus transport {other}"),
    }
}

fn endpoint(transport: Transport) -> ProbeEndpoint {
    match transport {
        Transport::Tcp => ProbeEndpoint::Tcp { port: PORT },
        Transport::Udp => ProbeEndpoint::Udp { port: PORT },
        Transport::Sctp => ProbeEndpoint::Sctp { port: PORT },
        Transport::Icmp => ProbeEndpoint::Icmp,
        Transport::Ip => ProbeEndpoint::Ip { protocol: 47 },
    }
}

fn collection() -> packetcraftr::exchange::Collection {
    let mut collection = packetcraftr::exchange::Collection::default();
    collection.capture.snap_length = 65535;
    collection.capture.max_bytes = MAX_EVIDENCE_BYTES;
    collection
}

struct ScanOutcome {
    aggregate: scan::Aggregate,
    sent: Vec<Vec<u8>>,
    send_timings: Vec<packetcraftr_netio::transmit::Timing>,
    delivered: Vec<(std::time::SystemTime, Vec<u8>)>,
    armed: usize,
    readied: usize,
    shutdowns: usize,
}

fn run_scan(
    condition: Condition,
    family: &str,
    transport_name: &str,
    window: usize,
) -> ScanOutcome {
    let addresses = addresses(family);
    let io = Io::default();
    let providers = Providers::new(
        io.clone(),
        addresses,
        Arc::new(move |sent: &[u8]| {
            scanner_fixture::conditions::respond(condition, addresses, sent)
        }),
    );
    let client = Client::new(
        packetcraftr_core::protocol::builtin::registry(),
        packetcraftr::policy::Policy::default(),
        providers,
    );
    let route = packetcraftr::route::Options {
        link_mode: packetcraftr_netio::link::Mode::Layer3,
        ..packetcraftr::route::Options::default()
    };
    let collector = scan::Collector::default();
    let aggregate = client
        .scan(
            scan::Request {
                tcp_scan: Default::default(),
                sctp_scan: Default::default(),
                target_sources: Vec::new(),
                targets: Selection {
                    include: vec![Specification::Target(Target::Address(
                        addresses.destination,
                    ))],
                    exclude: Vec::new(),
                },
                udp_payload: bytes::Bytes::new(),
                udp_profiles: Default::default(),
                address_family: family_of(addresses),
                endpoints: vec![endpoint(transport(transport_name))],
                discovery: Default::default(),
                attempts: 1,
                adaptive: None,
                timeout: TIMEOUT,
                probes_per_second: None,
                max_in_flight: window,
                limits: scan::Limits {
                    max_duration: MAX_DURATION,
                    max_probes: MAX_PROBES,
                    evidence: packetcraftr::evidence::Limits {
                        max_bytes: MAX_EVIDENCE_BYTES,
                        ..Default::default()
                    },
                    ..scan::Limits::default()
                },
                route,
                collection: collection(),
            },
            collector.clone(),
        )
        .and_then(|report| collector.finish(report))
        .expect("fixture scan succeeds");
    let (armed, readied, shutdowns) = io.counts();
    ScanOutcome {
        aggregate,
        sent: io.sent(),
        send_timings: io.send_timings(),
        delivered: io.delivered(),
        armed,
        readied,
        shutdowns,
    }
}

fn run_trace(
    condition: Condition,
    family: &str,
    transport_name: &str,
) -> (traceroute::Aggregate, Vec<Vec<u8>>, (usize, usize, usize)) {
    let addresses = addresses(family);
    let io = Io::default();
    let providers = Providers::new(
        io.clone(),
        addresses,
        Arc::new(move |sent: &[u8]| {
            scanner_fixture::conditions::respond(condition, addresses, sent)
        }),
    );
    let client = Client::new(
        packetcraftr_core::protocol::builtin::registry(),
        packetcraftr::policy::Policy::default(),
        providers,
    );
    let route = packetcraftr::route::Options {
        link_mode: packetcraftr_netio::link::Mode::Layer3,
        ..packetcraftr::route::Options::default()
    };
    let collector = traceroute::Collector::default();
    let aggregate = client
        .traceroute(
            traceroute::Request {
                target: Target::Address(addresses.destination),
                strategy: transport(transport_name),
                address_family: family_of(addresses),
                destination_port: match transport_name {
                    "icmp" => None,
                    _ => Some(PORT),
                },
                source_port: None,
                payload_size: 0,
                dont_fragment: false,
                dscp: 0,
                first_hop: 1,
                max_hops: 1,
                probes_per_hop: 1,
                timeout: TIMEOUT,
                probes_per_second: None,
                limits: traceroute::Limits {
                    max_probes: MAX_PROBES,
                    max_duration: MAX_DURATION,
                    evidence: packetcraftr::evidence::Limits {
                        max_bytes: MAX_EVIDENCE_BYTES,
                        ..Default::default()
                    },
                },
                route,
                collection: collection(),
            },
            collector.clone(),
        )
        .and_then(|report| collector.finish(report))
        .expect("fixture traceroute succeeds");
    (aggregate, io.sent(), io.counts())
}

#[test]
fn every_scan_cell_matches_the_corpus_expectation() {
    let corpus = corpus();
    assert_eq!(corpus.scenarios.len(), 6);
    let mut cells = 0;
    for scenario in &corpus.scenarios {
        for family in ["ipv4", "ipv6"] {
            for transport in ["tcp", "udp", "icmp"] {
                for window in [1, 2] {
                    cells += 1;
                    let outcome =
                        run_scan(parse_condition(&scenario.id), family, transport, window);
                    assert_eq!(outcome.sent.len(), 1, "exactly one real send");
                    assert_eq!(outcome.armed, outcome.readied);
                    assert_eq!(outcome.shutdowns, outcome.armed);
                    let [endpoint] = outcome.aggregate.endpoints.as_slice() else {
                        panic!("one endpoint per fixture scan");
                    };
                    let [probe] = endpoint.probes.as_slice() else {
                        panic!("one attempt per fixture scan");
                    };
                    let note = format!(
                        "{} {family} {transport} window {window}: {:?}",
                        scenario.id, probe.classification
                    );
                    let expected = scenario
                        .expected_by_transport
                        .get(transport)
                        .unwrap_or(&scenario.expected);
                    assert_eq!(
                        probe.classification.as_str(),
                        expected.attempt_classification,
                        "{note}"
                    );
                    assert_eq!(probe.status.as_str(), expected.status, "{note}");
                    assert_eq!(
                        probe.response.is_some(),
                        expected.attributed_response,
                        "{note}"
                    );
                    assert_eq!(
                        probe.sent_at,
                        outcome.send_timings[0].freshness_marker().wall_clock(),
                        "{note}: sent_at is the committed report marker"
                    );
                    if probe.response.is_some() {
                        assert!(
                            outcome
                                .delivered
                                .iter()
                                .any(|(timestamp, _)| Some(*timestamp) == probe.received_at),
                            "{note}: received_at is a delivered frame timestamp"
                        );
                    }
                    let retained_frames = probe
                        .response
                        .as_ref()
                        .map(|frame| frame.bytes().len())
                        .unwrap_or(0)
                        + outcome
                            .aggregate
                            .undecoded
                            .iter()
                            .map(|frame| frame.bytes().len())
                            .sum::<usize>();
                    assert_eq!(
                        outcome.aggregate.retained_evidence_bytes, retained_frames,
                        "retained bytes equal the retained frames"
                    );
                }
            }
        }
    }
    assert_eq!(cells, 72, "the raw matrix covers 72 cells");
}

#[test]
fn responders_identify_the_router_or_endpoint() {
    let corpus = corpus();
    for scenario in &corpus.scenarios {
        for family in ["ipv4", "ipv6"] {
            let outcome = run_scan(parse_condition(&scenario.id), family, "tcp", 1);
            let probe = &outcome.aggregate.endpoints[0].probes[0];
            match scenario.id.as_str() {
                "responsive" | "closed" => {
                    assert_eq!(
                        probe.responder,
                        Some(addresses(family).destination),
                        "{}: direct responder is the endpoint",
                        scenario.id
                    );
                }
                "blocked" => {
                    assert_eq!(
                        probe.responder,
                        Some(addresses(family).router),
                        "blocked: responder is the router"
                    );
                }
                _ => {}
            }
        }
    }
}

#[test]
fn udp_and_icmp_closed_quote_the_probe_from_the_endpoint() {
    for transport in ["udp", "icmp"] {
        for family in ["ipv4", "ipv6"] {
            let outcome = run_scan(Condition::Closed, family, transport, 1);
            let probe = &outcome.aggregate.endpoints[0].probes[0];
            assert_eq!(
                probe.responder,
                Some(addresses(family).destination),
                "{transport}/{family} closed answers come from the endpoint"
            );
        }
    }
}

#[test]
fn malformed_delivers_exactly_one_byte_and_unrelated_is_never_attributed() {
    for family in ["ipv4", "ipv6"] {
        let outcome = run_scan(Condition::Malformed, family, "tcp", 1);
        let [(_, delivered)] = outcome.delivered.as_slice() else {
            panic!("exactly one delivered frame");
        };
        assert_eq!(delivered.len(), 1, "the malformed frame is one byte");
        assert!(outcome.aggregate.undecoded.is_empty());
        assert_eq!(
            outcome.aggregate.endpoints[0].probes[0]
                .classification
                .as_str(),
            "timeout"
        );

        let outcome = run_scan(Condition::Unrelated, family, "tcp", 1);
        let probe = &outcome.aggregate.endpoints[0].probes[0];
        assert!(
            probe.response.is_none(),
            "an unrelated frame is never attributed"
        );
        assert_eq!(probe.classification.as_str(), "timeout");
    }
}

#[test]
fn window_two_publishes_sent_before_the_probe_event() {
    let events = Arc::new(std::sync::Mutex::new(Vec::new()));
    let addresses = addresses("ipv4");
    let io = Io::default();
    let providers = Providers::new(
        io.clone(),
        addresses,
        Arc::new(move |sent: &[u8]| {
            scanner_fixture::conditions::respond(Condition::Silent, addresses, sent)
        }),
    );
    let client = Client::new(
        packetcraftr_core::protocol::builtin::registry(),
        packetcraftr::policy::Policy::default(),
        providers,
    );
    let route = packetcraftr::route::Options {
        link_mode: packetcraftr_netio::link::Mode::Layer3,
        ..packetcraftr::route::Options::default()
    };
    let record = events.clone();
    client
        .scan(
            scan::Request {
                tcp_scan: Default::default(),
                sctp_scan: Default::default(),
                target_sources: Vec::new(),
                targets: Selection {
                    include: vec![Specification::Target(Target::Address(
                        addresses.destination,
                    ))],
                    exclude: Vec::new(),
                },
                udp_payload: bytes::Bytes::new(),
                udp_profiles: Default::default(),
                address_family: Family::Ipv4,
                endpoints: vec![packetcraftr::probe::ProbeEndpoint::Tcp { port: PORT }],
                discovery: Default::default(),
                attempts: 1,
                adaptive: None,
                timeout: TIMEOUT,
                probes_per_second: None,
                max_in_flight: 2,
                limits: scan::Limits {
                    max_duration: MAX_DURATION,
                    max_probes: MAX_PROBES,
                    evidence: packetcraftr::evidence::Limits {
                        max_bytes: MAX_EVIDENCE_BYTES,
                        ..Default::default()
                    },
                    ..scan::Limits::default()
                },
                route,
                collection: collection(),
            },
            move |event| {
                record.lock().expect("events").push(match event {
                    scan::Event::Sent(_) => "sent",
                    scan::Event::Probe { .. } => "probe",
                    scan::Event::Undecoded { .. } => "undecoded",
                    scan::Event::Unattributed(_) => "unattributed",
                    scan::Event::Diagnostic(_) => "diagnostic",
                });
                Ok(())
            },
        )
        .expect("window-2 fixture scan");
    let events = events.lock().expect("events");
    assert_eq!(
        events.as_slice(),
        ["sent", "probe"],
        "window two emits the Sent receipt before the Probe"
    );
}

#[test]
fn every_traceroute_cell_matches_the_corpus_expectation() {
    let corpus = corpus();
    assert_eq!(corpus.traceroute_scenarios.len(), 2);
    let mut cells = 0;
    for scenario in &corpus.traceroute_scenarios {
        for family in ["ipv4", "ipv6"] {
            for transport in ["tcp", "udp", "icmp"] {
                cells += 1;
                let (aggregate, sent, (armed, readied, shutdowns)) =
                    run_trace(parse_condition(&scenario.id), family, transport);
                assert_eq!(sent.len(), 1, "one hop sends exactly one packet");
                assert_eq!(armed, readied);
                assert_eq!(shutdowns, armed);
                let [hop] = aggregate.hops.as_slice() else {
                    panic!("one hop per fixture trace");
                };
                let [probe] = hop.probes.as_slice() else {
                    panic!("one probe per fixture trace");
                };
                assert_eq!(
                    aggregate.termination.as_str(),
                    scenario.expected_termination,
                    "{} {family} {transport}",
                    scenario.id
                );
                assert_eq!(probe.status.as_str(), scenario.expected_status);
                assert_eq!(
                    probe.response.is_some(),
                    scenario.expected_attributed_response
                );
                let retained_frames = probe
                    .response
                    .as_ref()
                    .map(|frame| frame.bytes().len())
                    .unwrap_or(0)
                    + aggregate
                        .undecoded
                        .iter()
                        .map(|entry| entry.frame.bytes().len())
                        .sum::<usize>();
                assert_eq!(
                    aggregate.retained_evidence_bytes, retained_frames,
                    "traceroute retained bytes equal the retained frames"
                );
            }
        }
    }
    assert_eq!(cells, 12, "the traceroute matrix covers 12 cells");
}

#[test]
fn corpus_schema_declares_the_complete_cell_inventory() {
    let corpus = corpus();
    let mut scenarios = corpus
        .scenarios
        .iter()
        .map(|s| s.id.as_str())
        .collect::<Vec<_>>();
    scenarios.sort_unstable();
    assert_eq!(
        scenarios,
        [
            "blocked",
            "closed",
            "malformed",
            "responsive",
            "silent",
            "unrelated"
        ]
    );
}

fn scripted_reply(name: &str) -> ScriptedReply {
    match name {
        "direct_reply" => ScriptedReply::DirectReply,
        "refusal" => ScriptedReply::Refusal,
        "silence" => ScriptedReply::Silence,
        other => panic!("corpus scripted reply {other}"),
    }
}

fn authored_endpoint(endpoint: &InferenceEndpoint) -> ProbeEndpoint {
    match endpoint.transport.as_str() {
        "tcp" => ProbeEndpoint::Tcp {
            port: endpoint.port,
        },
        "udp" => ProbeEndpoint::Udp {
            port: endpoint.port,
        },
        other => panic!("corpus inference transport {other}"),
    }
}

fn authored_reply(name: &str) -> scan::Reply {
    match name {
        "tcp_syn_ack" => scan::Reply::TcpSynAck,
        "udp_payload" => scan::Reply::UdpPayload,
        "icmp_port_unreachable" => scan::Reply::IcmpPortUnreachable,
        other => panic!("corpus inference reply {other}"),
    }
}

/// The corpus authors each scenario's scripted responses, attempt outcomes,
/// inferred state and rule, and evidence partitions independently; the real
/// `Client::scan` workflow must reproduce them on the scripted fixture.
#[test]
fn inference_scenarios_match_the_corpus_through_the_scan_workflow() {
    let corpus = corpus();
    let ids: Vec<_> = corpus
        .inference_scenarios
        .iter()
        .map(|scenario| scenario.id.as_str())
        .collect();
    assert_eq!(ids, ["mixed-same-port", "silent-udp", "contradictory-udp"]);
    let mut cells = 0;
    for scenario in &corpus.inference_scenarios {
        assert_eq!(scenario.families, ["ipv4", "ipv6"]);
        for family in &scenario.families {
            cells += 1;
            assert_inference_scenario(scenario, family);
        }
    }
    assert_eq!(cells, 6, "three scenarios across both address families");
}

fn assert_inference_scenario(scenario: &InferenceScenario, family: &str) {
    let addresses = addresses(family);
    let note = format!("{} {family}", scenario.id);
    let io = Io::default();
    let registry = packetcraftr_core::protocol::builtin::registry();
    let scripts = Scripts::new(scenario.endpoints.iter().map(|endpoint| {
        (
            authored_endpoint(endpoint),
            endpoint
                .script
                .iter()
                .map(|reply| scripted_reply(reply))
                .collect(),
        )
    }));
    let providers = Providers::new(io.clone(), addresses, scripts.responder(addresses));
    let client = Client::new(registry, packetcraftr::policy::Policy::default(), providers);
    let route = packetcraftr::route::Options {
        link_mode: packetcraftr_netio::link::Mode::Layer3,
        ..packetcraftr::route::Options::default()
    };
    let collector = scan::Collector::default();
    let aggregate = client
        .scan(
            scan::Request {
                tcp_scan: Default::default(),
                sctp_scan: Default::default(),
                target_sources: Vec::new(),
                targets: Selection {
                    include: vec![Specification::Target(Target::Address(
                        addresses.destination,
                    ))],
                    exclude: Vec::new(),
                },
                udp_payload: bytes::Bytes::new(),
                udp_profiles: Default::default(),
                address_family: family_of(addresses),
                endpoints: scenario.endpoints.iter().map(authored_endpoint).collect(),
                discovery: Default::default(),
                // Fixed scheduling transmits every authorized attempt, so an
                // early decisive reply cannot end the contradictory sequence.
                attempts: scenario.request.attempts,
                adaptive: None,
                timeout: Duration::from_millis(scenario.request.timeout_ms),
                probes_per_second: None,
                max_in_flight: scenario.request.max_in_flight,
                limits: scan::Limits {
                    max_duration: Duration::from_millis(scenario.request.max_duration_ms),
                    max_probes: scenario.request.max_probes,
                    evidence: packetcraftr::evidence::Limits {
                        max_bytes: scenario.request.max_evidence_bytes,
                        ..Default::default()
                    },
                    ..scan::Limits::default()
                },
                route,
                collection: collection(),
            },
            collector.clone(),
        )
        .and_then(|report| collector.finish(report))
        .expect("the scripted inference scan aggregates");

    let attempts = scenario.request.attempts;
    let transmissions = scenario.endpoints.len() * attempts as usize;
    let sent = io.sent();
    let send_timings = io.send_timings();
    assert_eq!(
        sent.len(),
        transmissions,
        "{note}: every authorized attempt is transmitted once"
    );
    assert_eq!(
        aggregate.stats.packets_attempted, transmissions as u64,
        "{note}"
    );
    assert_eq!(
        aggregate.stats.packets_completed, transmissions as u64,
        "{note}"
    );
    assert_eq!(aggregate.rtt.sent, transmissions as u64, "{note}");
    assert!(
        transmissions <= scenario.request.max_probes,
        "{note}: transmissions stay within the configured probe ceiling"
    );
    assert!(
        aggregate.planned_duration <= Duration::from_millis(scenario.request.max_duration_ms),
        "{note}: the planned duration stays within the configured ceiling"
    );
    assert!(
        aggregate.retained_evidence_bytes <= scenario.request.max_evidence_bytes,
        "{note}: retained evidence stays within the configured ceiling"
    );
    let (armed, readied, shutdowns) = io.counts();
    assert_eq!(armed, readied, "{note}: capture armed and reported ready");
    assert_eq!(shutdowns, armed, "{note}: capture shut down");
    assert_eq!(
        aggregate.endpoints.len(),
        scenario.endpoints.len(),
        "{note}: endpoint identity is never merged"
    );
    let mut sequences: Vec<u64> = aggregate
        .endpoints
        .iter()
        .flat_map(|endpoint| endpoint.probes.iter().map(|probe| probe.sequence))
        .collect();
    sequences.sort_unstable();
    assert_eq!(
        sequences,
        (0..transmissions as u64).collect::<Vec<_>>(),
        "{note}: every probe occupies one operation sequence"
    );

    for authored in &scenario.endpoints {
        let transport = transport(&authored.transport);
        let endpoint = aggregate
            .endpoints
            .iter()
            .find(|endpoint| {
                endpoint.transport == transport && endpoint.port == Some(authored.port)
            })
            .unwrap_or_else(|| panic!("{note}: the {transport} endpoint is collected"));
        let note = format!("{note}: {transport}/{}", authored.port);
        assert_eq!(
            endpoint
                .probes
                .iter()
                .map(|probe| probe.attempt)
                .collect::<Vec<_>>(),
            (1..=attempts).collect::<Vec<_>>(),
            "{note}: every attempt is probed once, in attempt order"
        );
        let inference = endpoint
            .inference
            .as_ref()
            .expect("a port endpoint always infers");
        assert_eq!(
            inference.state.map(scan::State::as_str),
            Some(authored.expected.state.as_str()),
            "{note}: inferred state"
        );
        assert_eq!(inference.rule.as_str(), authored.expected.rule, "{note}");
        for expected in &authored.expected.attempts {
            let probe = endpoint
                .probes
                .iter()
                .find(|probe| probe.attempt == expected.ordinal)
                .expect("every authored ordinal names a probed attempt");
            let attempt = format!("{note} attempt {}", expected.ordinal);
            assert_eq!(probe.status.as_str(), expected.status, "{attempt}");
            assert_eq!(
                probe.classification.as_str(),
                expected.classification,
                "{attempt}"
            );
            assert_eq!(
                probe.reply,
                expected.reply.as_deref().map(authored_reply),
                "{attempt}: the retained reply is the authored one"
            );
            assert_eq!(
                probe.responder,
                probe.reply.map(|_| addresses.destination),
                "{attempt}: only a reply answers, and it answers from the endpoint"
            );
            // The plan numbers one target's batches from zero, so the probe's
            // sequence indexes the transmissions in commit order.
            let index = usize::try_from(probe.sequence).expect("a bounded sequence");
            assert_eq!(
                probe.sent_at,
                send_timings[index].freshness_marker().wall_clock(),
                "{attempt}: sent_at is that transmission's committed marker"
            );
        }

        let ordinal = |sequence: u64| -> u32 {
            endpoint
                .probes
                .iter()
                .find(|probe| probe.sequence == sequence)
                .expect("a partition sequence names one of the endpoint's attempts")
                .attempt
        };
        let partition = |sequences: &[u64]| -> Vec<u32> {
            let mut ordinals: Vec<u32> = sequences.iter().copied().map(ordinal).collect();
            ordinals.sort_unstable();
            ordinals
        };
        for (label, sequences, expected) in [
            (
                "supporting",
                &inference.supporting,
                &authored.expected.partitions.supporting,
            ),
            (
                "conflicting",
                &inference.conflicting,
                &authored.expected.partitions.conflicting,
            ),
            (
                "unanswered",
                &inference.unanswered,
                &authored.expected.partitions.unanswered,
            ),
            (
                "failed",
                &inference.failed,
                &authored.expected.partitions.failed,
            ),
        ] {
            assert_eq!(partition(sequences), *expected, "{note}: {label} attempts");
        }
        let mut accounted: Vec<u32> = [
            inference.supporting.as_slice(),
            inference.conflicting.as_slice(),
            inference.unanswered.as_slice(),
            inference.failed.as_slice(),
        ]
        .concat()
        .iter()
        .copied()
        .map(ordinal)
        .collect();
        accounted.sort_unstable();
        assert_eq!(
            accounted,
            (1..=attempts).collect::<Vec<_>>(),
            "{note}: every attempt belongs to exactly one partition"
        );
    }
}

fn fixture_session() -> scanner_fixture::providers::Session {
    let providers = Providers::new(
        Io::default(),
        FamilyAddresses::IPV4,
        Arc::new(|_: &[u8]| Vec::new()),
    );
    capture::Provider::arm_capture(
        providers.capture(),
        &capture::Request {
            interface: scanner_fixture::providers::fixture_interface(),
            limits: capture::Limits {
                max_frames: 64,
                max_bytes: 65536,
                snap_length: 2048,
                overflow_policy: capture::OverflowPolicy::Fail,
            },
            filter: None,
            promiscuous: false,
            native: Default::default(),
        },
        &Deadline::new(Duration::from_secs(2)),
    )
    .expect("fixture session")
}

#[test]
fn an_empty_capture_queue_waits_for_the_full_caller_deadline() {
    let mut session = fixture_session();
    let started = std::time::Instant::now();
    let deadline = Deadline::new(Duration::from_millis(60));
    let frame = session
        .next_captured_frame(&deadline)
        .expect("an expired wait is not an error");
    assert!(frame.is_none());
    assert!(
        started.elapsed() >= Duration::from_millis(60),
        "an empty queue must not return before the supplied deadline"
    );
}

#[test]
fn a_queued_capture_frame_returns_promptly_and_cancellation_interrupts() {
    let io = Io::default();
    let providers = Providers::new(
        io.clone(),
        FamilyAddresses::IPV4,
        Arc::new(|_: &[u8]| Vec::new()),
    );
    let mut session = capture::Provider::arm_capture(
        providers.capture(),
        &capture::Request {
            interface: scanner_fixture::providers::fixture_interface(),
            limits: capture::Limits {
                max_frames: 64,
                max_bytes: 65536,
                snap_length: 2048,
                overflow_policy: capture::OverflowPolicy::Fail,
            },
            filter: None,
            promiscuous: false,
            native: Default::default(),
        },
        &Deadline::new(Duration::from_secs(2)),
    )
    .expect("fixture session");

    io.deliver_frame(vec![0x45]);
    let started = std::time::Instant::now();
    let frame = session
        .next_captured_frame(&Deadline::new(Duration::from_secs(5)))
        .expect("queued frame")
        .expect("a queued frame is delivered");
    assert!(
        started.elapsed() < Duration::from_millis(50),
        "a queued frame must not wait out the deadline"
    );
    drop(frame);

    let signal = Cancellation::default();
    let deadline = Deadline::new(Duration::from_secs(5)).with_cancellation(Some(signal.clone()));
    let canceller = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(30));
        signal.cancel();
    });
    let started = std::time::Instant::now();
    let error = session
        .next_captured_frame(&deadline)
        .expect_err("cancellation is a typed error");
    assert!(started.elapsed() < Duration::from_secs(2));
    canceller.join().expect("canceller");
    assert!(
        matches!(error, packetcraftr_netio::Error::Cancelled(_)),
        "cancellation must be the typed error, got {error:?}"
    );
}

#[test]
fn a_queued_frame_keeps_its_recorded_ingress_timestamp() {
    let io = Io::default();
    let providers = Providers::new(
        io.clone(),
        FamilyAddresses::IPV4,
        Arc::new(|_: &[u8]| Vec::new()),
    );
    let mut session = fixture_session_for(&providers);
    let expected = vec![0x45, 0xAA];
    io.deliver_frame(expected.clone());
    std::thread::sleep(Duration::from_millis(1));
    let captured = session
        .next_captured_frame(&Deadline::new(Duration::from_secs(5)))
        .expect("queued frame")
        .expect("delivered");
    let delivered = io.delivered();
    let [(recorded_at, bytes)] = delivered.as_slice() else {
        panic!("one delivered frame");
    };
    assert_eq!(
        captured.frame.timestamp,
        Some(*recorded_at),
        "the frame timestamp is the recorded ingress time, not delivery time"
    );
    assert_eq!(*bytes, expected);
}

#[test]
fn fixture_ready_and_shutdown_counters_are_idempotent() {
    let io = Io::default();
    let providers = Providers::new(
        io.clone(),
        FamilyAddresses::IPV4,
        Arc::new(|_: &[u8]| Vec::new()),
    );
    let mut session = fixture_session_for(&providers);
    session
        .wait_ready(&Deadline::new(Duration::from_secs(2)))
        .expect("ready");
    session
        .wait_ready(&Deadline::new(Duration::from_secs(2)))
        .expect("repeated readiness is a no-op");
    session.shutdown().expect("shutdown");
    session.shutdown().expect("repeated shutdown is a no-op");
    assert_eq!(io.counts(), (1, 1, 1));
}

fn fixture_session_for(providers: &Providers) -> scanner_fixture::providers::Session {
    capture::Provider::arm_capture(
        providers.capture(),
        &capture::Request {
            interface: scanner_fixture::providers::fixture_interface(),
            limits: capture::Limits {
                max_frames: 64,
                max_bytes: 65536,
                snap_length: 2048,
                overflow_policy: capture::OverflowPolicy::Fail,
            },
            filter: None,
            promiscuous: false,
            native: Default::default(),
        },
        &Deadline::new(Duration::from_secs(2)),
    )
    .expect("fixture session")
}
