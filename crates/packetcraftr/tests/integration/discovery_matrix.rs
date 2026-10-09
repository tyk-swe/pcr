// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Every discovery probe under every host behavior, in both address families
//! and for each choice of what follows discovery.

use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use bytes::Bytes;
use packetcraftr::policy::Policy;
use packetcraftr::probe::ProbeEndpoint;
use packetcraftr::scan::discovery::{
    Basis, Evidence, Mode, Options, ReasonKind, Scan, State, Unresponsive,
};
use packetcraftr::scan::{self, Reply, Request, Stage};
use packetcraftr::target::{Family, Selection, Specification, Target};
use packetcraftr::{Client, ProviderSet, route};
use packetcraftr_core::build::Builder;
use packetcraftr_core::decode::Dissector;
use packetcraftr_core::frame::{Frame, LinkType};
use packetcraftr_core::packet::Packet;
use packetcraftr_core::protocol::builtin;
use packetcraftr_core::protocol::network::{Icmpv4, Icmpv6, Ipv4, Ipv6};
use packetcraftr_core::protocol::transport::{Tcp, Udp};
use packetcraftr_netio::link::Mode as LinkMode;
use packetcraftr_netio::{self as net, capture, transmit};

use crate::common::discovery::{Routes, corpus, family_addresses};
use crate::common::responder::{Io, State as Responder};
use crate::common::{Interfaces, ScriptedResolver, ScriptedTcp};

const SCAN_PORT: u16 = 80;

#[derive(Clone, Copy, Debug)]
enum Host {
    /// Echo replies, TCP resets, and port unreachables from the target.
    Answers,
    Responsive,
    Blocked,
    Silent,
    /// A router reports the target unreachable.
    Unreachable,
}

#[derive(Clone, Copy, Debug)]
enum Then {
    ScanResponders,
    ScanEveryHost,
    Nothing,
}

/// Answers each probe as `host` and records what was sent, so the matrix can
/// check that no probe goes out beyond the request's.
#[derive(Clone)]
struct Wire {
    state: Arc<Mutex<Responder>>,
    host: Host,
    sent: Arc<Mutex<Vec<(IpAddr, ProbeEndpoint)>>>,
}

fn frame(packet: Packet) -> Frame {
    let wire = Builder::new(builtin::registry())
        .build(packet, Default::default(), Default::default())
        .unwrap()
        .bytes;
    Frame::new(SystemTime::now(), LinkType::RAW, wire).unwrap()
}

fn ip(packet: &mut Packet, source: IpAddr, destination: IpAddr) {
    match (source, destination) {
        (IpAddr::V4(source), IpAddr::V4(destination)) => packet.push(Ipv4 {
            source,
            destination,
            ..Default::default()
        }),
        (IpAddr::V6(source), IpAddr::V6(destination)) => packet.push(Ipv6 {
            hop_limit: 64,
            source,
            destination,
            ..Default::default()
        }),
        _ => unreachable!("replies stay in the probe's family"),
    };
}

fn icmp(packet: &mut Packet, v4: bool, (v4_type, v6_type): (u8, u8), code: u8, body: Bytes) {
    if v4 {
        packet.push(Icmpv4 {
            icmp_type: v4_type,
            code,
            body,
            ..Default::default()
        });
    } else {
        packet.push(Icmpv6 {
            icmp_type: v6_type,
            code,
            body,
            ..Default::default()
        });
    }
}

impl Wire {
    fn replies(&self, wire: &Bytes) -> (IpAddr, ProbeEndpoint, Vec<Frame>) {
        let decoded = Dissector::new(builtin::registry())
            .decode(
                Frame::new(SystemTime::now(), LinkType::RAW, wire.clone()).unwrap(),
                Default::default(),
            )
            .unwrap();
        let packet = &decoded.packet;
        let (source, destination) = match (packet.get::<Ipv4>(), packet.get::<Ipv6>()) {
            (Some(ip), _) => (IpAddr::V4(ip.source), IpAddr::V4(ip.destination)),
            (None, Some(ip)) => (IpAddr::V6(ip.source), IpAddr::V6(ip.destination)),
            (None, None) => panic!("probes are IP packets"),
        };
        let v4 = destination.is_ipv4();
        let tcp = packet.get::<Tcp>();
        let udp = packet.get::<Udp>();
        let endpoint = match (tcp, udp) {
            (Some(tcp), _) => ProbeEndpoint::Tcp {
                port: tcp.destination_port,
            },
            (None, Some(udp)) => ProbeEndpoint::Udp {
                port: udp.destination_port,
            },
            (None, None) => ProbeEndpoint::Icmp,
        };
        // ICMP errors quote the whole probe, well within both minimums.
        let quoted = || {
            let mut body = vec![0_u8; 4];
            body.extend_from_slice(wire);
            Bytes::from(body)
        };
        let mut reply = Packet::new();
        match (self.host, endpoint) {
            (Host::Silent, _) => return (destination, endpoint, Vec::new()),
            (Host::Blocked, _) => {
                ip(&mut reply, family_addresses(v4)[2], source);
                icmp(&mut reply, v4, (3, 1), if v4 { 13 } else { 1 }, quoted());
            }
            (Host::Unreachable, _) => {
                ip(&mut reply, family_addresses(v4)[2], source);
                // Host unreachable (ICMPv4) and address unreachable (ICMPv6).
                icmp(&mut reply, v4, (3, 1), if v4 { 1 } else { 3 }, quoted());
            }
            (Host::Answers | Host::Responsive, ProbeEndpoint::Tcp { .. }) => {
                let tcp = tcp.unwrap();
                ip(&mut reply, destination, source);
                reply.push(Tcp {
                    source_port: tcp.destination_port,
                    destination_port: tcp.source_port,
                    sequence: 100,
                    acknowledgment: tcp.sequence.wrapping_add(1),
                    flags: if matches!(self.host, Host::Responsive) {
                        Tcp::SYN | Tcp::ACK
                    } else {
                        Tcp::RST | Tcp::ACK
                    },
                    ..Default::default()
                });
            }
            (Host::Responsive, ProbeEndpoint::Udp { .. }) => {
                let udp = udp.unwrap();
                ip(&mut reply, destination, source);
                reply.push(Udp {
                    source_port: udp.destination_port,
                    destination_port: udp.source_port,
                    ..Default::default()
                });
            }
            (Host::Answers, ProbeEndpoint::Udp { .. }) => {
                ip(&mut reply, destination, source);
                icmp(&mut reply, v4, (3, 1), if v4 { 3 } else { 4 }, quoted());
            }
            (Host::Answers | Host::Responsive, ProbeEndpoint::Icmp) => {
                let body = match (packet.get::<Icmpv4>(), packet.get::<Icmpv6>()) {
                    (Some(echo), _) => echo.body.clone(),
                    (None, Some(echo)) => echo.body.clone(),
                    (None, None) => panic!("portless probes are echo requests"),
                };
                ip(&mut reply, destination, source);
                icmp(&mut reply, v4, (0, 129), 0, body);
            }
        }
        (destination, endpoint, vec![frame(reply)])
    }
}

impl transmit::Provider for Wire {
    fn send(&self, outbound: transmit::Outbound<'_>) -> Result<transmit::Report, net::Error> {
        let submission = transmit::Submission::start();
        let wire = outbound.bytes().clone();
        let (destination, endpoint, replies) = self.replies(&wire);
        self.sent.lock().unwrap().push((destination, endpoint));
        let mut state = self.state.lock().unwrap();
        assert!(state.ready, "capture must be ready before every send");
        let ingress = Instant::now();
        for reply in replies {
            state
                .replies
                .push_back(capture::Captured::new(reply, ingress));
            state.pending += 1;
        }
        state.sends += 1;
        // Native replies can arrive while the successful send is still in
        // progress. Preserve that ordering instead of hiding it in fixtures.
        Ok(submission.complete(wire.len(), wire))
    }
}

fn request(target: IpAddr, probe: ProbeEndpoint, then: Then) -> Request {
    let (mode, unresponsive, endpoints) = match then {
        Then::ScanResponders => (
            Mode::Before,
            Unresponsive::Skip,
            vec![ProbeEndpoint::Tcp { port: SCAN_PORT }],
        ),
        Then::ScanEveryHost => (
            Mode::Before,
            Unresponsive::Scan,
            vec![ProbeEndpoint::Tcp { port: SCAN_PORT }],
        ),
        Then::Nothing => (Mode::Only, Unresponsive::Skip, Vec::new()),
    };
    Request {
        max_in_flight: 1,
        targets: Selection {
            include: vec![Specification::Target(Target::Address(target))],
            exclude: Vec::new(),
        },
        target_sources: Vec::new(),
        endpoints,
        discovery: Options {
            mode,
            probes: vec![probe],
            neighbor: false,
            unresponsive,
        },
        udp_payload: Default::default(),
        udp_profiles: Default::default(),
        address_family: Family::Any,
        attempts: 1,
        adaptive: None,
        // This matrix checks host states, not preparation latency under
        // parallel test load. Preserve real send and capture timestamps.
        timeout: Duration::from_millis(200),
        probes_per_second: None,
        limits: scan::Limits {
            max_duration: Duration::from_secs(3),
            ..Default::default()
        },
        route: route::Options {
            link_mode: LinkMode::Layer3,
            ..Default::default()
        },
        collection: {
            let mut collection = packetcraftr::exchange::Collection::default();
            collection.capture.snap_length = 1500;
            collection
        },
    }
}

fn run(
    request: Request,
    host: Host,
) -> (
    Result<scan::Aggregate, scan::Error>,
    Vec<(IpAddr, ProbeEndpoint)>,
) {
    let state = Arc::new(Mutex::new(Responder::default()));
    let sent = Arc::new(Mutex::new(Vec::new()));
    let client = Client::new(
        builtin::registry(),
        Policy::default(),
        ProviderSet {
            route: Routes {
                routed: matches!(host, Host::Unreachable),
                ..Routes::default()
            },
            interface: Interfaces::default(),
            capture: Io(Arc::clone(&state)),
            transmit: Wire {
                state,
                host,
                sent: Arc::clone(&sent),
            },
            tcp: ScriptedTcp::default(),
            resolver: ScriptedResolver::default(),
        },
    );
    let collector = scan::Collector::default();
    let result = client
        .scan(request, collector.clone())
        .and_then(|report| collector.finish(report));
    let sent = sent.lock().unwrap().clone();
    (result, sent)
}

#[test]
fn discovery_states_follow_the_host_in_both_families() {
    let corpus = corpus();
    let cases = corpus["discovery_scenarios"].as_array().unwrap();
    let probes = [
        (ProbeEndpoint::Icmp, "icmp"),
        (ProbeEndpoint::Tcp { port: 22 }, "tcp"),
        (ProbeEndpoint::Udp { port: 53 }, "udp"),
    ];
    for v4 in [true, false] {
        let [_, target, router] = family_addresses(v4);
        for (probe, probe_id) in probes {
            for authored in &cases[..5] {
                let host = match authored["id"].as_str().unwrap() {
                    "discovery-responsive" => Host::Responsive,
                    "discovery-closed-but-responsive" => Host::Answers,
                    "discovery-silent" => Host::Silent,
                    "discovery-blocked" => Host::Blocked,
                    "discovery-routed" => Host::Unreachable,
                    other => panic!("unprovisioned discovery condition {other}"),
                };
                let expected_reply = match authored["expected"]["reply_by_probe"][probe_id].as_str()
                {
                    Some("icmp_echo_reply") => Some(Reply::IcmpEchoReply),
                    Some("tcp_syn_ack") => Some(Reply::TcpSynAck),
                    Some("tcp_reset") => Some(Reply::TcpReset),
                    Some("udp_payload") => Some(Reply::UdpPayload),
                    Some("icmp_port_unreachable") => Some(Reply::IcmpPortUnreachable),
                    Some("icmp_administratively_prohibited") => {
                        Some(Reply::IcmpAdministrativelyProhibited)
                    }
                    Some("icmp_destination_unreachable") => Some(Reply::IcmpDestinationUnreachable),
                    None => None,
                    other => panic!("unknown authored reply {other:?}"),
                };
                for then in [Then::ScanResponders, Then::ScanEveryHost, Then::Nothing] {
                    let case = format!("{target} {probe} {host:?} {then:?}");
                    let (result, sent) = run(request(target, probe, then), host);
                    let report = result.unwrap_or_else(|error| panic!("{case}: {error}"));
                    let [record] = report.hosts.as_slice() else {
                        panic!("{case}: one host record per target");
                    };
                    let [discovered] = report.discovery.as_slice() else {
                        panic!("{case}: one discovery probe");
                    };
                    assert_eq!(
                        (discovered.sequence, discovered.stage, &record.probes[..]),
                        (0, Stage::Discovery, &[0][..]),
                        "{case}"
                    );

                    let answered = authored["expected"]["state"] == "responded";
                    assert_eq!(
                        record.reasons.len(),
                        authored["expected"]["responded_reasons"].as_u64().unwrap() as usize,
                        "{case}"
                    );
                    assert_eq!(discovered.reply, expected_reply, "{case}");
                    let reasons: Vec<_> = record
                        .reasons
                        .iter()
                        .map(|reason| {
                            (
                                reason.kind,
                                reason.kind.evidence(),
                                reason.basis,
                                reason.probe,
                                reason.link_address,
                            )
                        })
                        .collect();
                    if answered {
                        assert_eq!(record.state, State::Responded, "{case}");
                        assert_eq!(
                            reasons,
                            [(
                                ReasonKind::Reply(expected_reply.unwrap()),
                                Evidence::Wire,
                                Basis::Direct,
                                Some(0),
                                None
                            )],
                            "{case}"
                        );
                    } else {
                        // Silence and a router's error are observations of
                        // uncertainty, never absence or host evidence.
                        assert_eq!(record.state, State::NoResponse, "{case}");
                        assert!(reasons.is_empty(), "{case}");
                        let responder =
                            matches!(host, Host::Unreachable | Host::Blocked).then_some(router);
                        assert_eq!(discovered.responder, responder, "{case}");
                    }

                    let scanned = match then {
                        Then::ScanResponders if answered => Scan::Scanned,
                        Then::ScanResponders => Scan::Skipped,
                        Then::ScanEveryHost => Scan::Scanned,
                        Then::Nothing => Scan::NotRequested,
                    };
                    assert_eq!(record.scan, scanned, "{case}");
                    let mut expected = vec![(target, probe)];
                    if scanned == Scan::Scanned {
                        expected.push((target, ProbeEndpoint::Tcp { port: SCAN_PORT }));
                    }
                    assert_eq!(sent, expected, "{case}: only requested probes are sent");
                    assert_eq!(report.endpoints.len(), expected.len() - 1, "{case}");
                }
            }
        }
    }
}
