// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use bytes::Bytes;
use packetcraftr::{
    Client, ProviderSet,
    policy::Policy,
    probe::{ProbeEndpoint, ProbeStatus},
    scan::{
        self, Classification, IpProtocolSelection, IpProtocolSpec, Request, SctpScan, State,
        discovery, select_ip_protocols,
    },
    target::{Family, Selection, Specification, Target},
};
use packetcraftr_core::{
    budget::Deadline,
    build::Builder,
    decode::Dissector,
    field::WireValue,
    frame::{Frame, LinkType},
    layer::Raw,
    packet::Packet,
    protocol::{
        builtin,
        network::{Icmpv4, Icmpv6, Ipv4, Ipv6},
        transport::{Sctp, Tcp},
    },
};
use packetcraftr_netio::{self as net, capture, link::Mode, route, transmit};

use crate::common::{self, responder};

const SCTP_PORTS: [u16; 6] = [2000, 2001, 2002, 2003, 2004, 2005];
const IP_PROTOCOLS: [u8; 5] = [47, 50, 112, 115, 254];

#[derive(Clone, Copy, PartialEq, Eq)]
enum Schedule {
    Serial,
    Pipelined,
    Adaptive,
}

#[derive(Clone, Default)]
struct Routes;

impl route::Provider for Routes {
    type Error = Infallible;

    fn lookup_with_preferences(
        &self,
        destination: IpAddr,
        _: Option<&net::interface::Id>,
        _: Option<IpAddr>,
        _: &Deadline,
    ) -> Result<route::Decision, Infallible> {
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

#[derive(Clone)]
struct ScriptedIo {
    inner: responder::Io,
    sent: Arc<Mutex<Vec<Packet>>>,
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

impl transmit::Provider for ScriptedIo {
    fn send(&self, outbound: transmit::Outbound<'_>) -> Result<transmit::Report, net::Error> {
        let wire = Bytes::copy_from_slice(outbound.bytes());
        let decoded = decode(&wire);
        self.sent.lock().unwrap().push(decoded.clone());
        let frames = respond(&decoded, &wire);
        let report = transmit::Submission::start().complete(wire.len(), wire);
        let mut state = self.inner.0.lock().unwrap();
        let ingress = Instant::now();
        for frame in frames {
            state
                .replies
                .push_back(capture::Captured::new(frame, ingress));
            state.pending += 1;
        }
        state.sends += 1;
        state.peak = state.peak.max(state.pending);
        Ok(report)
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

fn decode(bytes: &Bytes) -> Packet {
    Dissector::new(builtin::registry())
        .decode(
            Frame::new(SystemTime::UNIX_EPOCH, LinkType::RAW, bytes.clone()).unwrap(),
            Default::default(),
        )
        .unwrap()
        .packet
}

fn encode(packet: Packet) -> Bytes {
    Builder::new(builtin::registry())
        .build(packet, Default::default(), Default::default())
        .unwrap()
        .bytes
}

fn frame(packet: Packet) -> Frame {
    Frame::new(
        SystemTime::UNIX_EPOCH + Duration::from_millis(2),
        LinkType::RAW,
        encode(packet),
    )
    .unwrap()
}

fn ip_envelope(source: IpAddr, destination: IpAddr, protocol: Option<u8>) -> Packet {
    let mut packet = Packet::new();
    match (source, destination) {
        (IpAddr::V4(source), IpAddr::V4(destination)) => {
            packet.push(Ipv4 {
                source,
                destination,
                protocol: protocol.map_or(WireValue::Auto, WireValue::Exact),
                ..Ipv4::default()
            });
        }
        (IpAddr::V6(source), IpAddr::V6(destination)) => {
            packet.push(Ipv6 {
                source,
                destination,
                next_header: protocol.map_or(WireValue::Auto, WireValue::Exact),
                ..Ipv6::default()
            });
        }
        _ => unreachable!(),
    }
    packet
}

fn icmp_error(
    ipv6: bool,
    router: IpAddr,
    destination: IpAddr,
    v4: (u8, u8),
    v6: (u8, u8),
    pointer: u32,
    quoted: &Bytes,
) -> Packet {
    let mut body = pointer.to_be_bytes().to_vec();
    body.extend_from_slice(quoted);
    let mut packet = ip_envelope(router, destination, None);
    if ipv6 {
        packet.push(Icmpv6 {
            icmp_type: v6.0,
            code: v6.1,
            body: Bytes::from(body),
            ..Icmpv6::default()
        });
    } else {
        packet.push(Icmpv4 {
            icmp_type: v4.0,
            code: v4.1,
            body: Bytes::from(body),
            ..Icmpv4::default()
        });
    }
    packet
}

fn sctp_init_ack_chunk(tag: u32) -> Bytes {
    let mut chunk = vec![2, 0, 0, 20];
    chunk.extend_from_slice(&tag.to_be_bytes());
    chunk.extend_from_slice(&[0, 1, 0, 0, 0, 10, 0, 10]);
    chunk.extend_from_slice(&tag.to_be_bytes());
    Bytes::from(chunk)
}

fn respond(sent: &Packet, wire: &Bytes) -> Vec<Frame> {
    let (ipv6, source, destination, router) = if let Some(ipv4) = sent.get::<Ipv4>() {
        (
            false,
            IpAddr::V4(ipv4.source),
            IpAddr::V4(ipv4.destination),
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 254)),
        )
    } else if let Some(ipv6) = sent.get::<Ipv6>() {
        (
            true,
            IpAddr::V6(ipv6.source),
            IpAddr::V6(ipv6.destination),
            IpAddr::V6("2001:db8::ffff".parse().unwrap()),
        )
    } else {
        return Vec::new();
    };

    if let Some(sctp) = sent.get::<Sctp>() {
        let raw_chunk = sent.get::<Raw>().unwrap();
        let tag = if sctp.verification_tag == 0 {
            u32::from_be_bytes([
                raw_chunk.bytes[4],
                raw_chunk.bytes[5],
                raw_chunk.bytes[6],
                raw_chunk.bytes[7],
            ])
        } else {
            sctp.verification_tag
        };
        let sctp_reply = |vtag: u32, chunk: Bytes| {
            let mut reply = ip_envelope(destination, source, None);
            reply.push(Sctp {
                source_port: sctp.destination_port,
                destination_port: sctp.source_port,
                verification_tag: vtag,
                ..Sctp::default()
            });
            reply.push(Raw::new(chunk));
            frame(reply)
        };
        return match sctp.destination_port {
            2000 | 9899 => vec![sctp_reply(tag, sctp_init_ack_chunk(0x1122_3344))],
            2001 => vec![sctp_reply(tag, Bytes::from_static(&[6, 1, 0, 4]))],
            2002 => vec![sctp_reply(tag, Bytes::from_static(&[9, 0, 0, 4]))],
            2003 => vec![frame(icmp_error(
                ipv6,
                router,
                source,
                (3, 13),
                (1, 1),
                0,
                wire,
            ))],
            2004 => vec![frame(icmp_error(
                ipv6,
                router,
                source,
                (11, 0),
                (3, 0),
                0,
                wire,
            ))],
            2006 => vec![
                // Unrelated tag and malformed truncated SCTP frame before ABORT, plus ICMP prohibited.
                sctp_reply(tag ^ 1, Bytes::from_static(&[6, 1, 0, 4])),
                Frame::new(
                    SystemTime::UNIX_EPOCH + Duration::from_millis(1),
                    LinkType::RAW,
                    Bytes::from_static(&[0x45, 0, 0, 28, 0, 1, 0, 0, 64, 132]),
                )
                .unwrap(),
                frame(icmp_error(ipv6, router, source, (3, 13), (1, 1), 0, wire)),
                sctp_reply(tag, Bytes::from_static(&[6, 1, 0, 4])),
            ],
            _ => Vec::new(),
        };
    }

    if let Some(tcp) = sent.get::<Tcp>() {
        if tcp.flags == Tcp::ACK {
            let mut reply = ip_envelope(destination, source, None);
            reply.push(Tcp {
                source_port: tcp.destination_port,
                destination_port: tcp.source_port,
                sequence: tcp.acknowledgment,
                flags: Tcp::RST,
                ..Tcp::default()
            });
            return vec![frame(reply)];
        }
        return Vec::new();
    }

    if let Some(icmp) = sent.get::<Icmpv4>() {
        let mut reply = ip_envelope(destination, source, None);
        let reply_type = match icmp.icmp_type {
            13 => 14,
            17 => 18,
            _ => 0,
        };
        reply.push(Icmpv4 {
            icmp_type: reply_type,
            code: 0,
            body: icmp.body.clone(),
            ..Icmpv4::default()
        });
        return vec![frame(reply)];
    }

    if sent.get::<Icmpv6>().is_some() {
        return Vec::new();
    }

    // Empty-payload IP-protocol probe.
    let proto = sent
        .get::<Ipv4>()
        .and_then(|ip| match ip.protocol {
            WireValue::Exact(p) => Some(p),
            _ => None,
        })
        .or_else(|| {
            sent.get::<Ipv6>().and_then(|ip| match ip.next_header {
                WireValue::Exact(p) => Some(p),
                _ => None,
            })
        });
    let Some(protocol) = proto else {
        return Vec::new();
    };
    match protocol {
        47 => vec![frame(ip_envelope(destination, source, Some(47)))],
        50 => vec![frame(icmp_error(
            ipv6,
            destination,
            source,
            (3, 2),
            (4, 1),
            if ipv6 { 6 } else { 0 },
            wire,
        ))],
        112 => vec![frame(icmp_error(
            ipv6,
            router,
            source,
            (3, 13),
            (1, 1),
            0,
            wire,
        ))],
        115 => vec![frame(icmp_error(
            ipv6,
            router,
            source,
            (11, 0),
            (3, 0),
            0,
            wire,
        ))],
        _ => Vec::new(),
    }
}

fn client() -> (Client<Fixtures>, Arc<Mutex<Vec<Packet>>>) {
    let sent = Arc::new(Mutex::new(Vec::new()));
    let io = ScriptedIo {
        inner: responder::Io(Arc::new(Mutex::new(responder::State::default()))),
        sent: Arc::clone(&sent),
    };
    let providers = ProviderSet {
        udp: (),
        route: Routes,
        interface: common::Interfaces::default(),
        capture: io.clone(),
        transmit: io,
        tcp: common::ScriptedTcp::default(),
        resolver: common::ScriptedResolver::default(),
    };
    let policy = Policy {
        max_packets_per_operation: 64,
        max_bytes_per_operation: 64 * 1500,
        ..Default::default()
    };
    (Client::new(builtin::registry(), policy, providers), sent)
}

fn target(ipv6: bool) -> IpAddr {
    if ipv6 {
        IpAddr::V6("2001:db8::2".parse().unwrap())
    } else {
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2))
    }
}

fn base_request(ipv6: bool, endpoints: Vec<ProbeEndpoint>, schedule: Schedule) -> Request {
    Request {
        tcp_scan: Default::default(),
        sctp_scan: Default::default(),
        target_sources: Vec::new(),
        max_in_flight: if schedule == Schedule::Serial { 1 } else { 4 },
        targets: Selection {
            include: vec![Specification::Target(Target::Address(target(ipv6)))],
            exclude: Vec::new(),
        },
        address_family: Family::Any,
        endpoints,
        discovery: Default::default(),
        attempts: 1,
        adaptive: (schedule == Schedule::Adaptive).then(|| scan::Adaptive {
            min_timeout: Duration::from_millis(20),
            max_timeout: Duration::from_millis(20),
            min_window: 1,
            initial_window: 2,
            host_timeout: Duration::from_secs(5),
            retry_backoff: Duration::from_millis(10),
            max_backoff: Duration::from_millis(50),
        }),
        timeout: Duration::from_millis(20),
        probes_per_second: None,
        udp_payload: Default::default(),
        udp_profiles: Default::default(),
        limits: scan::Limits {
            max_duration: Duration::from_secs(10),
            max_probes: 32,
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
            capture: capture::Limits {
                snap_length: 1500,
                max_frames: 64,
                max_bytes: 65536,
                ..Default::default()
            },
            max_responses: 32,
            max_unmatched_frames: 32,
            ..Default::default()
        },
    }
}

#[test]
fn sctp_init_cookie_echo_and_ip_protocol_match_corpus_across_schedules_and_families() {
    let corpus: serde_json::Value =
        serde_json::from_str(include_str!("../../../../docs/scanner-corpus.v1.json")).unwrap();
    let scenarios = corpus["sctp_ip_protocol_scenarios"].as_array().unwrap();

    for ipv6 in [false, true] {
        for schedule in [Schedule::Serial, Schedule::Pipelined, Schedule::Adaptive] {
            for mode in [SctpScan::Init, SctpScan::CookieEcho] {
                let id = if mode.is_init() {
                    "sctp-init"
                } else {
                    "sctp-cookie-echo"
                };
                let expected = scenarios.iter().find(|case| case["id"] == id).unwrap()["endpoints"]
                    .as_array()
                    .unwrap();
                let mut request = base_request(
                    ipv6,
                    SCTP_PORTS.map(|port| ProbeEndpoint::Sctp { port }).to_vec(),
                    schedule,
                );
                request.sctp_scan = mode;
                let (client, sent) = client();
                let collector = scan::Collector::default();
                let report = client.scan(request, collector.clone()).unwrap();
                let aggregate = collector.finish(report).unwrap();
                assert_eq!(aggregate.endpoints.len(), SCTP_PORTS.len());
                assert_eq!(sent.lock().unwrap().len(), SCTP_PORTS.len());

                for (endpoint, row) in aggregate.endpoints.iter().zip(expected) {
                    let probe = &endpoint.probes[0];
                    assert_eq!(endpoint.port, row["port"].as_u64().map(|p| p as u16));
                    assert_eq!(probe.sctp_scan, Some(mode));
                    assert_eq!(probe.status.as_str(), row["status"].as_str().unwrap());
                    assert_eq!(
                        probe.classification.as_str(),
                        row["classification"].as_str().unwrap()
                    );
                    let inference = endpoint.inference.as_ref().unwrap();
                    assert_eq!(inference.state.map(State::as_str), row["state"].as_str());
                    assert_eq!(inference.rule.as_str(), row["rule"].as_str().unwrap());
                    assert_eq!(inference.supporting, vec![probe.sequence]);
                }
            }

            // Standalone IP-protocol inventory (plus protocol 1/58 beside ICMP error on 50).
            let expected = scenarios
                .iter()
                .find(|case| case["id"] == "ip-protocol")
                .unwrap()["endpoints"]
                .as_array()
                .unwrap();
            let selected = select_ip_protocols(
                &IpProtocolSelection {
                    include: IP_PROTOCOLS
                        .map(IpProtocolSpec::Single)
                        .into_iter()
                        .chain([IpProtocolSpec::Single(99)])
                        .collect(),
                    exclude: vec![IpProtocolSpec::Single(99)],
                },
                16,
            )
            .unwrap();
            assert_eq!(selected.excluded, 1);
            let request = base_request(ipv6, selected.endpoints, schedule);
            let (client, sent) = client();
            let collector = scan::Collector::default();
            let report = client.scan(request, collector.clone()).unwrap();
            let aggregate = collector.finish(report).unwrap();
            assert_eq!(aggregate.endpoints.len(), IP_PROTOCOLS.len());
            assert_eq!(sent.lock().unwrap().len(), IP_PROTOCOLS.len());
            for (endpoint, row) in aggregate.endpoints.iter().zip(expected) {
                let probe = &endpoint.probes[0];
                assert_eq!(
                    endpoint.ip_protocol,
                    row["ip_protocol"].as_u64().map(|p| p as u8)
                );
                assert_eq!(endpoint.port, None);
                assert_eq!(probe.status.as_str(), row["status"].as_str().unwrap());
                assert_eq!(
                    probe.classification.as_str(),
                    row["classification"].as_str().unwrap()
                );
                let inference = endpoint.inference.as_ref().unwrap();
                assert_eq!(inference.state.map(State::as_str), row["state"].as_str());
                assert_eq!(inference.rule.as_str(), row["rule"].as_str().unwrap());
            }
        }
    }
}

#[test]
fn sctp_abort_outranks_router_icmp_and_ignores_wrong_tag_while_retaining_superseded() {
    for mode in [SctpScan::Init, SctpScan::CookieEcho] {
        let mut request = base_request(
            false,
            vec![ProbeEndpoint::Sctp { port: 2006 }],
            Schedule::Serial,
        );
        request.sctp_scan = mode;
        let (client, _) = client();
        let collector = scan::Collector::default();
        let report = client.scan(request, collector.clone()).unwrap();
        let aggregate = collector.finish(report).unwrap();
        let endpoint = &aggregate.endpoints[0];
        assert_eq!(endpoint.probes[0].reply, Some(scan::Reply::SctpAbort));
        assert_eq!(endpoint.probes[0].classification, Classification::Closed);
        assert_eq!(
            endpoint.inference.as_ref().unwrap().state,
            Some(State::Closed)
        );
        assert_eq!(aggregate.unattributed.len(), 1);
        assert_eq!(
            aggregate.unattributed[0].attribution,
            scan::Attribution::Duplicate
        );
    }
}

#[test]
fn icmp_errors_quoting_other_ip_protocols_never_mark_icmp_protocol_open() {
    for (ipv6, icmp_proto) in [(false, 1_u8), (true, 58_u8)] {
        let request = base_request(
            ipv6,
            vec![
                ProbeEndpoint::Ip {
                    protocol: icmp_proto,
                },
                ProbeEndpoint::Ip { protocol: 50 },
            ],
            Schedule::Pipelined,
        );
        let (client, _) = client();
        let collector = scan::Collector::default();
        let report = client.scan(request, collector.clone()).unwrap();
        let aggregate = collector.finish(report).unwrap();
        assert_eq!(aggregate.endpoints[0].ip_protocol, Some(icmp_proto));
        assert_eq!(
            aggregate.endpoints[0].probes[0].status,
            ProbeStatus::Timeout
        );
        assert_eq!(
            aggregate.endpoints[0].inference.as_ref().unwrap().state,
            Some(State::OpenOrFiltered)
        );
        assert_eq!(aggregate.endpoints[1].ip_protocol, Some(50));
        assert_eq!(
            aggregate.endpoints[1].inference.as_ref().unwrap().state,
            Some(State::Closed)
        );
    }
}

#[test]
fn extra_discovery_probes_record_host_reasons_and_reject_ipv6_timestamp_or_netmask() {
    let mut request = base_request(
        false,
        vec![ProbeEndpoint::Tcp { port: 80 }],
        Schedule::Serial,
    );
    request.discovery = discovery::Options {
        mode: discovery::Mode::Before,
        probes: vec![
            ProbeEndpoint::IcmpTimestamp,
            ProbeEndpoint::IcmpNetmask,
            ProbeEndpoint::TcpAck { port: 80 },
            ProbeEndpoint::Sctp { port: 9899 },
            ProbeEndpoint::Ip { protocol: 47 },
        ],
        neighbor: false,
        unresponsive: discovery::Unresponsive::Skip,
    };
    let (client, _) = client();
    let collector = scan::Collector::default();
    let report = client.scan(request, collector.clone()).unwrap();
    let aggregate = collector.finish(report).unwrap();
    let host = &aggregate.hosts[0];
    assert_eq!(host.state, discovery::State::Responded);
    assert_eq!(host.scan, discovery::Scan::Scanned);
    let replies: Vec<_> = host.reasons.iter().map(|reason| reason.kind).collect();
    assert_eq!(
        replies,
        vec![
            discovery::ReasonKind::Reply(scan::Reply::IcmpTimestampReply),
            discovery::ReasonKind::Reply(scan::Reply::IcmpNetmaskReply),
            discovery::ReasonKind::Reply(scan::Reply::TcpReset),
            discovery::ReasonKind::Reply(scan::Reply::SctpInitAck),
            discovery::ReasonKind::Reply(scan::Reply::IpProtocolPayload),
        ]
    );

    // IPv4-only ICMP timestamp and netmask discovery probes fail typed on IPv6 targets.
    for probe in [ProbeEndpoint::IcmpTimestamp, ProbeEndpoint::IcmpNetmask] {
        let mut ipv6_request = base_request(
            true,
            vec![ProbeEndpoint::Sctp { port: 9899 }],
            Schedule::Serial,
        );
        ipv6_request.discovery = discovery::Options {
            mode: discovery::Mode::Before,
            probes: vec![probe],
            neighbor: false,
            unresponsive: discovery::Unresponsive::Skip,
        };
        let (client, sent) = self::client();
        let error = client
            .scan(ipv6_request, scan::Collector::default())
            .unwrap_err();
        assert!(matches!(error, scan::Error::InvalidDiscovery { .. }));
        assert!(sent.lock().unwrap().is_empty());
    }
}
