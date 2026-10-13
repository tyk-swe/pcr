// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime};

use bytes::Bytes;
use packetcraftr::{
    Client, ProviderSet,
    clock::Clock,
    policy::Policy,
    probe::{ProbeEndpoint, ProbeStatus},
    scan::{self, Classification, Request, State, TcpScan},
    target::{Family, Selection, Specification, Target},
};
use packetcraftr_core::{
    budget::Deadline,
    build::Builder,
    decode::Dissector,
    frame::{Frame, LinkType},
    packet::Packet,
    protocol::{
        builtin,
        network::{Icmpv4, Icmpv6, Ipv4, Ipv6},
        transport::{Tcp, Udp},
    },
};
use packetcraftr_netio::{self as net, capture, link::Mode, route, transmit};

use crate::common::{self, clock::VirtualClock, responder};

const RESET_ZERO: u16 = 1000;
const RESET_POSITIVE: u16 = 1001;
const SILENT: u16 = 1002;
const PROHIBITED: u16 = 1003;
const UNEXPECTED: u16 = 1004;
const RESET_AND_PROHIBITED: u16 = 1005;
const PORT_UNREACHABLE: u16 = 1006;
const TIME_EXCEEDED: u16 = 1007;
const PORTS: [u16; 8] = [
    RESET_ZERO,
    RESET_POSITIVE,
    SILENT,
    PROHIBITED,
    UNEXPECTED,
    RESET_AND_PROHIBITED,
    PORT_UNREACHABLE,
    TIME_EXCEEDED,
];
const POSITIVE_WINDOW: u16 = 4096;
const UNEXPECTED_WINDOW: u16 = 29_200;
const MODES: [TcpScan; 7] = [
    TcpScan::Ack,
    TcpScan::Window,
    TcpScan::Fin,
    TcpScan::Null,
    TcpScan::Xmas,
    TcpScan::Maimon,
    TcpScan::Custom { flags: 0x001 },
];

#[derive(Clone, Copy, PartialEq, Eq)]
enum Schedule {
    Serial,
    Pipelined,
    Adaptive,
}

#[derive(Clone, Copy, Default)]
struct Script {
    noise: bool,
    duplicate: bool,
    reverse: bool,
    fail_at: Option<usize>,
    icmp_first: bool,
    syn_ack_delta: i32,
}

struct Scripted {
    script: Script,
    wires: Mutex<Vec<Bytes>>,
}

#[derive(Clone)]
struct ScriptedIo {
    inner: responder::Io,
    scripted: Arc<Scripted>,
}

#[derive(Clone, Default)]
struct Routes {
    lookups: Arc<AtomicUsize>,
}

impl route::Provider for Routes {
    type Error = Infallible;

    fn lookup_with_preferences(
        &self,
        destination: IpAddr,
        _: Option<&net::interface::Id>,
        _: Option<IpAddr>,
        _: &Deadline,
    ) -> Result<route::Decision, Infallible> {
        self.lookups.fetch_add(1, Ordering::SeqCst);
        let source = match destination {
            IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            IpAddr::V6(_) => IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().unwrap()),
        };
        Ok(route::Decision {
            interface: net::interface::Id {
                index: 1,
                name: "fixture0".to_owned(),
            },
            source_mac: None,
            selected_source: Some(source),
            preferred_source: None,
            next_hop: None,
            selection_reason: route::SelectionReason::OnLink,
            destination_scope: route::Scope::Link,
            mtu: 1500,
            capability: net::link::Capability::Layer3,
            link_type: LinkType::RAW,
        })
    }
}

type Fixtures = ProviderSet<
    Routes,
    common::Interfaces,
    ScriptedIo,
    ScriptedIo,
    common::ScriptedTcp,
    common::ScriptedResolver,
>;

fn frame(packet: Packet) -> Frame {
    let wire = Builder::new(builtin::registry())
        .build(packet, Default::default(), Default::default())
        .expect("fixture packet builds")
        .bytes;
    Frame::new(SystemTime::now(), LinkType::RAW, wire).expect("fixture frame")
}

fn expected_acknowledgment(tcp: &Tcp) -> u32 {
    tcp.sequence
        .wrapping_add(u32::from(tcp.flags & Tcp::SYN != 0))
        .wrapping_add(u32::from(tcp.flags & Tcp::FIN != 0))
}

fn reverse_ports(probe: &Tcp, window: u16) -> Tcp {
    Tcp {
        source_port: probe.destination_port,
        destination_port: probe.source_port,
        window,
        ..Tcp::default()
    }
}

fn reset(probe: &Tcp, window: u16) -> Tcp {
    if probe.flags & Tcp::ACK != 0 {
        Tcp {
            flags: Tcp::RST,
            sequence: probe.acknowledgment,
            acknowledgment: 0,
            ..reverse_ports(probe, window)
        }
    } else {
        Tcp {
            flags: Tcp::RST | Tcp::ACK,
            sequence: 0,
            acknowledgment: expected_acknowledgment(probe),
            ..reverse_ports(probe, window)
        }
    }
}

fn syn_ack(probe: &Tcp, window: u16) -> Tcp {
    Tcp {
        flags: Tcp::SYN | Tcp::ACK,
        sequence: 100,
        acknowledgment: expected_acknowledgment(probe),
        ..reverse_ports(probe, window)
    }
}

fn reply_frame(sent: &Packet, tcp: Tcp) -> Frame {
    let mut response = Packet::new();
    if let Some(ip) = sent.get::<Ipv4>() {
        response.push(Ipv4 {
            source: ip.destination,
            destination: ip.source,
            ..Default::default()
        });
    } else {
        let ip = sent.get::<Ipv6>().expect("IP probe");
        response.push(Ipv6 {
            source: ip.destination,
            destination: ip.source,
            ..Default::default()
        });
    }
    response.push(tcp);
    frame(response)
}

fn icmp_error(sent: &Packet, wire: &Bytes, unreachable_code: u8) -> Frame {
    icmp_packet(sent, wire, unreachable_code, false)
}

fn icmp_packet(sent: &Packet, wire: &Bytes, code: u8, expired: bool) -> Frame {
    let mut response = Packet::new();
    if let Some(ip) = sent.get::<Ipv4>() {
        let mut body = vec![0_u8; 4];
        body.extend_from_slice(&wire[..28]);
        response.push(Ipv4 {
            source: ip.destination,
            destination: ip.source,
            ..Default::default()
        });
        response.push(Icmpv4 {
            icmp_type: if expired { 11 } else { 3 },
            code,
            body: Bytes::from(body),
            ..Default::default()
        });
    } else {
        let ip = sent.get::<Ipv6>().expect("IP probe");
        let mut body = vec![0_u8; 4];
        body.extend_from_slice(&wire[..48]);
        response.push(Ipv6 {
            source: ip.destination,
            destination: ip.source,
            ..Default::default()
        });
        response.push(Icmpv6 {
            icmp_type: if expired { 3 } else { 1 },
            code,
            body: Bytes::from(body),
            ..Default::default()
        });
    }
    frame(response)
}

fn answers(sent: &Packet, wire: &Bytes, script: Script) -> Vec<Frame> {
    let Some(probe) = sent.get::<Tcp>() else {
        let _ = sent.get::<Udp>().expect("TCP or UDP probe");
        return vec![icmp_error(
            sent,
            wire,
            if sent.get::<Ipv4>().is_some() { 3 } else { 4 },
        )];
    };
    if probe.flags & Tcp::SYN != 0 {
        let mut reply = syn_ack(probe, UNEXPECTED_WINDOW);
        reply.acknowledgment = reply
            .acknowledgment
            .wrapping_add_signed(script.syn_ack_delta);
        return vec![reply_frame(sent, reply)];
    }
    match probe.destination_port {
        RESET_AND_PROHIBITED => {
            let reset = reply_frame(sent, reset(probe, POSITIVE_WINDOW));
            let prohibited = icmp_error(
                sent,
                wire,
                if sent.get::<Ipv4>().is_some() { 13 } else { 1 },
            );
            if script.icmp_first {
                vec![prohibited, reset]
            } else {
                vec![reset, prohibited]
            }
        }
        RESET_ZERO => vec![reply_frame(sent, reset(probe, 0))],
        RESET_POSITIVE => vec![reply_frame(sent, reset(probe, POSITIVE_WINDOW))],
        PROHIBITED => vec![icmp_error(
            sent,
            wire,
            if sent.get::<Ipv4>().is_some() { 13 } else { 1 },
        )],
        UNEXPECTED => vec![reply_frame(sent, syn_ack(probe, UNEXPECTED_WINDOW))],
        PORT_UNREACHABLE => vec![icmp_error(
            sent,
            wire,
            if sent.get::<Ipv4>().is_some() { 3 } else { 4 },
        )],
        TIME_EXCEEDED => vec![icmp_packet(sent, wire, 0, true)],
        _ => Vec::new(),
    }
}

const NOISE_WINDOW: u16 = 777;

fn noise(sent: &Packet) -> Vec<Frame> {
    let probe = sent.get::<Tcp>().expect("TCP probe");
    let mut other_tuple = reset(probe, NOISE_WINDOW);
    other_tuple.source_port = other_tuple.source_port.wrapping_add(1);
    let mut wrong_identity = reset(probe, NOISE_WINDOW);
    if probe.flags & Tcp::ACK != 0 {
        wrong_identity.sequence = wrong_identity.sequence.wrapping_add(7);
    } else {
        wrong_identity.acknowledgment = wrong_identity.acknowledgment.wrapping_add(7);
    }
    let valid = reply_frame(sent, reset(probe, NOISE_WINDOW));
    let mut bytes = valid.bytes().to_vec();
    let checksum = if sent.get::<Ipv4>().is_some() { 20 } else { 40 } + 16;
    bytes[checksum] ^= 0xff;
    let corrupt = Frame::new(SystemTime::now(), LinkType::RAW, Bytes::from(bytes)).unwrap();
    let mut frames: Vec<_> = [other_tuple, wrong_identity]
        .into_iter()
        .map(|tcp| reply_frame(sent, tcp))
        .collect();
    frames.push(corrupt);
    frames
}

impl transmit::Provider for ScriptedIo {
    fn send(&self, outbound: transmit::Outbound<'_>) -> Result<transmit::Report, net::Error> {
        let wire = outbound.bytes().clone();
        let report = transmit::Report::committed(wire.len(), wire.clone());
        let mut state = self.inner.0.lock().expect("fixture io");
        assert!(state.ready, "capture must be ready before every send");
        let mut wires = self.scripted.wires.lock().expect("fixture wires");
        if self.scripted.script.fail_at == Some(wires.len()) {
            return Err(net::Error::Capture {
                message: "fixture send failure".to_owned(),
                source: None,
            });
        }
        wires.push(wire.clone());
        let decoded = Dissector::new(builtin::registry())
            .decode(
                Frame::new(SystemTime::now(), LinkType::RAW, wire.clone()).expect("sent wire"),
                Default::default(),
            )
            .expect("fixture decodes its own probes");
        let mut frames = Vec::new();
        if self.scripted.script.noise && decoded.packet.get::<Tcp>().is_some() {
            frames.extend(noise(&decoded.packet));
        }
        frames.extend(answers(&decoded.packet, &wire, self.scripted.script));
        if self.scripted.script.duplicate {
            frames.extend(frames.clone());
        }
        let ingress = state.late_ingress.flatten().unwrap_or_else(Instant::now);
        for frame in frames {
            let captured = capture::Captured::new(frame, ingress);
            if self.scripted.script.reverse {
                state.replies.push_front(captured);
            } else {
                state.replies.push_back(captured);
            }
            state.pending += 1;
        }
        state.sends += 1;
        state.peak = state.peak.max(state.pending);
        Ok(report)
    }
}

impl capture::Provider for ScriptedIo {
    type Capture = <responder::Io as capture::Provider>::Capture;

    fn arm_capture(
        &self,
        request: &capture::Request,
        deadline: &Deadline,
    ) -> Result<Self::Capture, net::Error> {
        self.inner.arm_capture(request, deadline)
    }
}

struct Fixture {
    io: responder::Io,
    scripted: Arc<Scripted>,
    routes: Routes,
}

impl Fixture {
    fn new(script: Script, state: responder::State) -> Self {
        Self {
            io: responder::Io(Arc::new(Mutex::new(state))),
            scripted: Arc::new(Scripted {
                script,
                wires: Mutex::new(Vec::new()),
            }),
            routes: Routes::default(),
        }
    }

    fn client(&self, policy: Policy) -> Client<Fixtures> {
        let io = ScriptedIo {
            inner: self.io.clone(),
            scripted: Arc::clone(&self.scripted),
        };
        Client::new(
            builtin::registry(),
            policy,
            ProviderSet {
                udp: (),
                route: self.routes.clone(),
                interface: common::Interfaces::default(),
                capture: io.clone(),
                transmit: io,
                tcp: common::ScriptedTcp::default(),
                resolver: common::ScriptedResolver::default(),
            },
        )
    }

    fn sent(&self) -> Vec<Packet> {
        self.scripted
            .wires
            .lock()
            .unwrap()
            .iter()
            .map(|wire| {
                Dissector::new(builtin::registry())
                    .decode(
                        Frame::new(SystemTime::now(), LinkType::RAW, wire.clone()).unwrap(),
                        Default::default(),
                    )
                    .unwrap()
                    .packet
            })
            .collect()
    }

    fn sends(&self) -> usize {
        self.scripted.wires.lock().unwrap().len()
    }

    fn armed(&self) -> usize {
        self.io.0.lock().unwrap().armed
    }
}

fn policy() -> Policy {
    Policy {
        max_packets_per_operation: 64,
        max_bytes_per_operation: 64 * 1500,
        ..Default::default()
    }
}

fn address(ipv6: bool) -> IpAddr {
    if ipv6 {
        IpAddr::V6("2001:db8::2".parse().unwrap())
    } else {
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2))
    }
}

fn request(ipv6: bool, mode: TcpScan, schedule: Schedule) -> Request {
    Request {
        tcp_scan: mode,
        target_sources: Vec::new(),
        max_in_flight: if schedule == Schedule::Serial { 1 } else { 4 },
        targets: Selection {
            include: vec![Specification::Target(Target::Address(address(ipv6)))],
            exclude: Vec::new(),
        },
        address_family: Family::Any,
        endpoints: PORTS.map(|port| ProbeEndpoint::Tcp { port }).to_vec(),
        discovery: Default::default(),
        attempts: 1,
        adaptive: (schedule == Schedule::Adaptive).then(|| scan::Adaptive {
            min_timeout: Duration::from_millis(40),
            max_timeout: Duration::from_millis(40),
            min_window: 1,
            initial_window: 2,
            host_timeout: Duration::from_secs(5),
            retry_backoff: Duration::from_millis(10),
            max_backoff: Duration::from_millis(50),
        }),
        timeout: Duration::from_millis(40),
        probes_per_second: None,
        udp_payload: Default::default(),
        udp_profiles: Default::default(),
        limits: scan::Limits {
            max_duration: Duration::from_secs(10),
            max_probes: 8,
            evidence: packetcraftr::evidence::Limits {
                max_bytes: 65536,
                ..Default::default()
            },
            ..Default::default()
        },
        route: packetcraftr::route::Options {
            link_mode: Mode::Layer3,
            ..Default::default()
        },
        collection: packetcraftr::exchange::Collection {
            capture: packetcraftr_netio::capture::Limits {
                max_bytes: 65536,
                snap_length: 1500,
                ..Default::default()
            },
            ..Default::default()
        },
    }
}

fn run<K: Clock>(
    client: &Client<Fixtures, K>,
    request: Request,
) -> Result<scan::Aggregate, scan::Error> {
    let collector = scan::Collector::default();
    let report = client.scan(request, collector.clone())?;
    collector.finish(report)
}

fn execute(request: Request, script: Script) -> (Fixture, Result<scan::Aggregate, scan::Error>) {
    let fixture = Fixture::new(script, responder::State::default());
    let result = run(&fixture.client(policy()), request);
    (fixture, result)
}

fn corpus() -> &'static serde_json::Value {
    static CORPUS: OnceLock<serde_json::Value> = OnceLock::new();
    CORPUS.get_or_init(|| {
        serde_json::from_str(include_str!("../../../../docs/scanner-corpus.v1.json")).unwrap()
    })
}

fn expected(mode: TcpScan, port: u16) -> serde_json::Value {
    let corpus = corpus();
    let case = corpus["tcp_diagnostic_scenarios"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["port"] == port)
        .unwrap();
    case["expected"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["mode"] == mode.as_str())
        .unwrap()
        .clone()
}

fn reply_name(reply: scan::Reply) -> &'static str {
    match reply {
        scan::Reply::TcpReset => "tcp_reset",
        scan::Reply::TcpSynAck => "tcp_syn_ack",
        scan::Reply::TcpOther => "tcp_other",
        scan::Reply::IcmpPortUnreachable => "icmp_port_unreachable",
        scan::Reply::IcmpAdministrativelyProhibited => "icmp_administratively_prohibited",
        scan::Reply::IcmpTimeExceeded => "icmp_time_exceeded",
        scan::Reply::IcmpDestinationUnreachable => "icmp_destination_unreachable",
        _ => panic!("not an authored diagnostic reply"),
    }
}

fn assert_wire(mode: TcpScan, sent: &[Packet], attempts: usize) {
    let tcp: Vec<_> = sent
        .iter()
        .filter_map(|packet| packet.get::<Tcp>())
        .collect();
    assert_eq!(tcp.len(), PORTS.len() * attempts);
    let mut sequences = std::collections::HashSet::new();
    let mut acknowledgments = std::collections::HashSet::new();
    for probe in &tcp {
        assert_eq!(
            serde_json::json!(probe.flags),
            expected(mode, RESET_ZERO)["flags"],
            "{mode:?}"
        );
        assert!(probe.options.is_empty());
        assert!(sequences.insert(probe.sequence));
        if mode.flags() & Tcp::ACK == 0 {
            assert_eq!(probe.acknowledgment, 0, "{mode:?}");
        } else {
            assert_ne!(probe.acknowledgment, 0, "{mode:?}");
            assert_eq!(
                probe.acknowledgment,
                probe.sequence.wrapping_add(0x5043_5201)
            );
            assert!(acknowledgments.insert(probe.acknowledgment));
        }
    }
}

fn check(aggregate: &scan::Aggregate, mode: TcpScan, label: &str) {
    assert_eq!(aggregate.endpoints.len(), PORTS.len(), "{label}");
    for endpoint in &aggregate.endpoints {
        let port = endpoint.port.unwrap();
        let row = expected(mode, port);
        let inference = endpoint.inference.as_ref().expect("TCP endpoints infer");
        assert_eq!(
            inference.state.unwrap().as_str(),
            row["state"],
            "{label} port {port}"
        );
        assert_eq!(inference.rule.as_str(), row["rule"], "{label} port {port}");
        let [probe] = endpoint.probes.as_slice() else {
            panic!("{label}: one attempt per endpoint");
        };
        assert_eq!(
            probe.classification.as_str(),
            row["classification"],
            "{label} port {port}"
        );
        assert_eq!(
            endpoint.classification.as_str(),
            row["classification"],
            "{label} port {port}"
        );
        assert_eq!(probe.tcp_scan, Some(mode), "{label} port {port}");
        assert_eq!(
            serde_json::json!(probe.tcp_window),
            row["tcp_window"],
            "{label} port {port}"
        );
        assert_eq!(
            serde_json::json!(probe.reply.map(reply_name)),
            row["reply"],
            "{label} port {port}"
        );
        assert_eq!(
            serde_json::json!(probe.status),
            row["status"],
            "{label} port {port}"
        );
        assert_eq!(
            inference.supporting,
            vec![probe.sequence],
            "{label} port {port}"
        );
        assert!(inference.conflicting.is_empty());
        assert!(inference.unanswered.is_empty());
        assert!(inference.failed.is_empty());
    }
}

#[test]
fn every_mode_sends_exact_wire_and_infers_per_table_on_every_schedule() {
    for ipv6 in [false, true] {
        for schedule in [Schedule::Serial, Schedule::Pipelined, Schedule::Adaptive] {
            for mode in MODES {
                let label = format!("{mode:?} ipv6={ipv6} {}", schedule as u8);
                let (fixture, result) = execute(request(ipv6, mode, schedule), Script::default());
                let aggregate = result.unwrap_or_else(|error| panic!("{label}: {error}"));
                assert_wire(mode, &fixture.sent(), 1);
                check(&aggregate, mode, &label);
            }
        }
    }
}

#[test]
fn unrelated_noise_duplicates_and_reordering_never_change_evidence() {
    for ipv6 in [false, true] {
        for mode in MODES {
            for schedule in [Schedule::Serial, Schedule::Pipelined, Schedule::Adaptive] {
                for (noise, reverse, duplicate) in [
                    (true, false, false),
                    (false, true, false),
                    (true, true, false),
                    (false, false, true),
                ] {
                    let label = format!(
                        "{mode:?} ipv6={ipv6} noise={noise} reverse={reverse} duplicate={duplicate} {}",
                        schedule as u8
                    );
                    let script = Script {
                        noise,
                        reverse,
                        duplicate,
                        ..Script::default()
                    };
                    let (fixture, result) = execute(request(ipv6, mode, schedule), script);
                    let aggregate = result.unwrap_or_else(|error| panic!("{label}: {error}"));
                    assert_wire(mode, &fixture.sent(), 1);
                    check(&aggregate, mode, &label);
                    if duplicate {
                        assert!(!aggregate.unattributed.is_empty(), "duplicates retained");
                    }
                    for probe in aggregate
                        .endpoints
                        .iter()
                        .flat_map(|endpoint| &endpoint.probes)
                    {
                        assert_ne!(probe.tcp_window, Some(NOISE_WINDOW), "{label}");
                    }
                }
            }
        }
    }
}

#[test]
fn late_replies_remain_evidence_without_changing_silent_inference() {
    for ipv6 in [false, true] {
        for mode in MODES {
            for schedule in [Schedule::Serial, Schedule::Pipelined, Schedule::Adaptive] {
                for port in PORTS {
                    let mut request = request(ipv6, mode, schedule);
                    request.endpoints = vec![ProbeEndpoint::Tcp { port }];
                    let clock = VirtualClock::default();
                    let ingress = clock.now() + request.timeout * 2;
                    let fixture = Fixture::new(
                        Script::default(),
                        responder::State {
                            idle_clock: Some(clock.clone()),
                            release_replies_after: Some(ingress),
                            late_ingress: Some(Some(ingress)),
                            ..responder::State::default()
                        },
                    );
                    let client = fixture.client(policy()).with_clock(clock);
                    let aggregate = run(&client, request).unwrap();
                    let endpoint = &aggregate.endpoints[0];
                    let probe = &endpoint.probes[0];
                    let row = expected(mode, SILENT);
                    assert_eq!(
                        probe.status,
                        ProbeStatus::Timeout,
                        "mode={mode:?} ipv6={ipv6} port={port} schedule={}",
                        schedule as u8
                    );
                    assert_eq!(probe.tcp_window, None);
                    assert_eq!(probe.reply, None);
                    assert_eq!(probe.classification, Classification::Timeout);
                    let inference = endpoint.inference.as_ref().unwrap();
                    assert_eq!(inference.state.unwrap().as_str(), row["state"]);
                    assert_eq!(inference.rule.as_str(), row["rule"]);
                    assert!(
                        aggregate
                            .unattributed
                            .iter()
                            .all(|late| late.attribution == scan::Attribution::Late)
                    );
                    if port == SILENT {
                        assert!(aggregate.unattributed.is_empty());
                    } else {
                        assert!(!aggregate.unattributed.is_empty(), "late response retained");
                        assert!(
                            aggregate.unattributed.len()
                                <= if port == RESET_AND_PROHIBITED { 2 } else { 1 }
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn retries_use_distinct_acknowledgment_identities() {
    let mut request = request(false, TcpScan::Ack, Schedule::Serial);
    request.endpoints = vec![ProbeEndpoint::Tcp { port: RESET_ZERO }];
    request.attempts = 3;
    let (fixture, result) = execute(request, Script::default());
    let aggregate = result.unwrap();
    let sent = fixture.sent();
    let acknowledgments: Vec<_> = sent
        .iter()
        .map(|packet| packet.get::<Tcp>().unwrap().acknowledgment)
        .collect();
    assert_eq!(acknowledgments.len(), 3);
    assert_eq!(
        acknowledgments
            .iter()
            .collect::<std::collections::HashSet<_>>()
            .len(),
        3
    );
    let inference = aggregate.endpoints[0].inference.as_ref().unwrap();
    assert_eq!(inference.rule.as_str(), "tcp_ack.reset");
    assert_eq!(inference.supporting.len(), 3);
}

#[test]
fn discovery_stays_syn_while_scan_probes_use_the_mode() {
    let mut request = request(false, TcpScan::Xmas, Schedule::Serial);
    request.limits.max_probes = 9;
    request.discovery = scan::discovery::Options {
        mode: scan::discovery::Mode::Before,
        probes: vec![ProbeEndpoint::Tcp { port: 2000 }],
        neighbor: false,
        unresponsive: scan::discovery::Unresponsive::Skip,
    };
    let (fixture, result) = execute(request, Script::default());
    let aggregate = result.unwrap();
    let sent = fixture.sent();
    let flags: Vec<_> = sent
        .iter()
        .map(|packet| packet.get::<Tcp>().unwrap().flags)
        .collect();
    assert_eq!(flags[0], Tcp::SYN);
    assert!(
        flags[1..]
            .iter()
            .all(|flags| *flags == TcpScan::Xmas.flags())
    );
    assert_eq!(aggregate.discovery.len(), 1);
    assert_eq!(aggregate.discovery[0].tcp_scan, Some(TcpScan::Syn));
    assert_eq!(aggregate.discovery[0].tcp_window, Some(UNEXPECTED_WINDOW));
    check(&aggregate, TcpScan::Xmas, "discovery");
}

#[test]
fn udp_endpoints_and_default_syn_are_unaffected() {
    let mut mixed = request(false, TcpScan::Ack, Schedule::Serial);
    mixed.endpoints = vec![
        ProbeEndpoint::Tcp { port: RESET_ZERO },
        ProbeEndpoint::Udp { port: 53 },
    ];
    let (fixture, result) = execute(mixed, Script::default());
    let aggregate = result.unwrap();
    let sent = fixture.sent();
    assert_eq!(sent[0].get::<Tcp>().unwrap().flags, Tcp::ACK);
    assert!(sent[1].get::<Udp>().is_some());
    let udp = aggregate
        .endpoints
        .iter()
        .find(|endpoint| endpoint.port == Some(53))
        .unwrap();
    assert_eq!(udp.probes[0].tcp_scan, None);
    assert_eq!(udp.probes[0].tcp_window, None);
    assert_eq!(
        udp.inference.as_ref().unwrap().rule.as_str(),
        "udp.port_unreachable"
    );
    assert_eq!(udp.inference.as_ref().unwrap().state, Some(State::Closed));

    let mut syn = request(true, TcpScan::default(), Schedule::Pipelined);
    syn.endpoints = vec![ProbeEndpoint::Tcp { port: RESET_ZERO }];
    let (fixture, result) = execute(syn, Script::default());
    let aggregate = result.unwrap();
    let probe = fixture.sent()[0].get::<Tcp>().unwrap().clone();
    assert_eq!((probe.flags, probe.acknowledgment), (Tcp::SYN, 0));
    let endpoint = &aggregate.endpoints[0];
    assert_eq!(endpoint.classification, Classification::Open);
    assert_eq!(
        endpoint.inference.as_ref().unwrap().rule.as_str(),
        "tcp_syn.syn_ack"
    );
    assert_eq!(endpoint.probes[0].tcp_scan, Some(TcpScan::Syn));
}

#[test]
fn invalid_requests_fail_before_any_provider_work() {
    let invalid_custom = request(false, TcpScan::Custom { flags: 0x200 }, Schedule::Serial);
    let mut udp_only = request(false, TcpScan::Fin, Schedule::Serial);
    udp_only.endpoints = vec![ProbeEndpoint::Udp { port: 53 }];
    let mut icmp_only = request(false, TcpScan::Null, Schedule::Serial);
    icmp_only.endpoints = vec![ProbeEndpoint::Icmp];
    let mut discovery_only = request(false, TcpScan::Ack, Schedule::Serial);
    discovery_only.endpoints.clear();
    discovery_only.discovery = scan::discovery::Options {
        mode: scan::discovery::Mode::Only,
        probes: vec![ProbeEndpoint::Tcp { port: 2000 }],
        neighbor: false,
        unresponsive: scan::discovery::Unresponsive::Skip,
    };
    for request in [invalid_custom, udp_only, icmp_only, discovery_only] {
        let (fixture, result) = execute(request, Script::default());
        let error = result.expect_err("invalid diagnostic request");
        assert!(matches!(error, scan::Error::InvalidLimit { .. }), "{error}");
        assert_eq!(fixture.routes.lookups.load(Ordering::SeqCst), 0);
        assert_eq!((fixture.sends(), fixture.armed()), (0, 0));
    }
}

#[test]
fn policy_denial_precedes_provider_discovery() {
    let mut request = request(false, TcpScan::Ack, Schedule::Serial);
    request.targets = Selection {
        include: vec![Specification::Target(Target::Address(
            "8.8.8.8".parse().unwrap(),
        ))],
        exclude: Vec::new(),
    };
    let (fixture, result) = execute(request, Script::default());
    assert!(result.is_err());
    assert_eq!(fixture.routes.lookups.load(Ordering::SeqCst), 0);
    assert_eq!((fixture.sends(), fixture.armed()), (0, 0));
}

#[test]
fn preparation_probe_byte_and_deadline_ceilings_send_nothing() {
    let base = || request(false, TcpScan::Maimon, Schedule::Pipelined);
    let mut prepared = base();
    prepared.limits.max_prepared_bytes = 1;
    let mut probes = base();
    probes.limits.max_probes = 2;
    let mut deadline = base();
    deadline.limits.max_duration = Duration::from_millis(1);
    for request in [prepared, probes, deadline] {
        let (fixture, result) = execute(request, Script::default());
        assert!(result.is_err());
        assert_eq!(fixture.sends(), 0);
    }
    let fixture = Fixture::new(Script::default(), responder::State::default());
    let tight = Policy {
        max_bytes_per_operation: 1,
        ..policy()
    };
    assert!(run(&fixture.client(tight), base()).is_err());
    assert_eq!(fixture.sends(), 0);
}

#[test]
fn evidence_ceiling_fails_without_hidden_fallback() {
    let mut request = request(false, TcpScan::Ack, Schedule::Serial);
    request.limits.evidence.max_frames = 1;
    let (fixture, result) = execute(request, Script::default());
    assert!(result.is_err());
    assert!(fixture.sends() < PORTS.len());
}

#[test]
fn a_mid_flight_failure_preserves_partial_evidence_and_never_connects() {
    for schedule in [Schedule::Serial, Schedule::Pipelined] {
        let fixture = Fixture::new(
            Script {
                fail_at: Some(2),
                ..Script::default()
            },
            responder::State::default(),
        );
        let events = Arc::new(Mutex::new(Vec::new()));
        let sink = {
            let events = Arc::clone(&events);
            move |event: scan::Event| {
                events.lock().unwrap().push(event);
                Ok::<(), packetcraftr_core::error::BoundaryError>(())
            }
        };
        let client = fixture.client(policy());
        client
            .scan(request(false, TcpScan::Ack, schedule), sink)
            .expect_err("the third send fails");
        assert_eq!(fixture.sends(), 2);
        assert!(client.providers().tcp.steps.take().is_empty());
        let events = events.lock().unwrap();
        let modes: Vec<_> = events
            .iter()
            .filter_map(|event| match event {
                scan::Event::Probe { probe, .. } => Some(probe.tcp_scan),
                scan::Event::Sent(sent) => Some(Some(sent.probe.tcp_scan)),
                _ => None,
            })
            .collect();
        assert!(!modes.is_empty());
        assert!(modes.iter().all(|mode| *mode == Some(TcpScan::Ack)));
    }
}

#[test]
fn a_reset_outranks_router_evidence_in_the_same_probe_window_in_either_order() {
    for ipv6 in [false, true] {
        for schedule in [Schedule::Serial, Schedule::Pipelined, Schedule::Adaptive] {
            for icmp_first in [false, true] {
                for (mode, state, rule) in [
                    (TcpScan::Ack, State::Unfiltered, "tcp_ack.reset"),
                    (TcpScan::Window, State::Open, "tcp_window.reset_nonzero"),
                    (TcpScan::Fin, State::Closed, "tcp_fin.reset"),
                ] {
                    let label = format!(
                        "{mode:?} ipv6={ipv6} icmp_first={icmp_first} {}",
                        schedule as u8
                    );
                    let mut request = request(ipv6, mode, schedule);
                    request.endpoints = vec![ProbeEndpoint::Tcp {
                        port: RESET_AND_PROHIBITED,
                    }];
                    let (_fixture, result) = execute(
                        request,
                        Script {
                            icmp_first,
                            ..Script::default()
                        },
                    );
                    let aggregate = result.unwrap_or_else(|error| panic!("{label}: {error}"));
                    let [endpoint] = aggregate.endpoints.as_slice() else {
                        panic!("{label}: one endpoint");
                    };
                    let [probe] = endpoint.probes.as_slice() else {
                        panic!("{label}: one attempt");
                    };
                    assert_eq!(probe.reply, Some(scan::Reply::TcpReset), "{label}");
                    assert_eq!(probe.tcp_window, Some(POSITIVE_WINDOW), "{label}");
                    let inference = endpoint.inference.as_ref().unwrap();
                    assert_eq!(inference.state, Some(state), "{label}");
                    assert_eq!(inference.rule.as_str(), rule, "{label}");
                    assert!(
                        aggregate
                            .unattributed
                            .iter()
                            .all(|frame| frame.attribution == scan::Attribution::Duplicate),
                        "{label}: a displaced response is retained as a duplicate"
                    );
                    assert!(aggregate.unattributed.len() <= 1, "{label}");
                }
            }
        }
    }
}

#[test]
fn custom_syn_bearing_probes_accept_only_the_exact_sequence_space_acknowledgment() {
    for flags in [0x002, 0x003, 0x013] {
        for ipv6 in [false, true] {
            let mode = TcpScan::Custom { flags };
            let mut matching = request(ipv6, mode, Schedule::Serial);
            matching.endpoints = vec![ProbeEndpoint::Tcp { port: RESET_ZERO }];
            let (_fixture, result) = execute(matching, Script::default());
            let aggregate = result.unwrap();
            let endpoint = &aggregate.endpoints[0];
            let probe = &endpoint.probes[0];
            assert_eq!(probe.reply, Some(scan::Reply::TcpSynAck), "{flags:#x}");
            assert_eq!(probe.classification, Classification::Unknown, "{flags:#x}");
            assert_eq!(probe.tcp_window, Some(UNEXPECTED_WINDOW), "{flags:#x}");
            let inference = endpoint.inference.as_ref().unwrap();
            assert_eq!(inference.rule.as_str(), "tcp_custom.reply", "{flags:#x}");
            assert_eq!(inference.state, Some(State::Unknown), "{flags:#x}");
            assert_ne!(endpoint.classification, Classification::Open, "{flags:#x}");

            for delta in [-1, 1] {
                let mut wrong = request(ipv6, mode, Schedule::Serial);
                wrong.endpoints = vec![ProbeEndpoint::Tcp { port: RESET_ZERO }];
                let (_fixture, result) = execute(
                    wrong,
                    Script {
                        syn_ack_delta: delta,
                        ..Script::default()
                    },
                );
                let aggregate = result.unwrap();
                let endpoint = &aggregate.endpoints[0];
                assert_eq!(
                    endpoint.probes[0].status,
                    ProbeStatus::Timeout,
                    "{flags:#x} delta {delta}"
                );
                assert_eq!(
                    endpoint.inference.as_ref().unwrap().rule.as_str(),
                    "tcp_custom.silence"
                );
            }
        }
    }
}

#[test]
fn a_syn_scan_still_rejects_a_wrong_syn_ack_acknowledgment() {
    for delta in [-1, 1] {
        let mut request = request(false, TcpScan::Syn, Schedule::Serial);
        request.endpoints = vec![ProbeEndpoint::Tcp { port: RESET_ZERO }];
        let (_fixture, result) = execute(
            request,
            Script {
                syn_ack_delta: delta,
                ..Script::default()
            },
        );
        let endpoint = &result.unwrap().endpoints[0];
        assert_eq!(endpoint.probes[0].status, ProbeStatus::Timeout);
        assert_eq!(
            endpoint.inference.as_ref().unwrap().rule.as_str(),
            "tcp_syn.silence"
        );
    }
}
