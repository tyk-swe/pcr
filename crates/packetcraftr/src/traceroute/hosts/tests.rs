// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, UNIX_EPOCH};

use bytes::Bytes;
use packetcraftr_core::budget::{Cancellation, Deadline};
use packetcraftr_core::decode::DecodedPacket;
use packetcraftr_core::error::{BoundaryError, Classification, Kind};
use packetcraftr_core::packet::Packet;
use packetcraftr_core::protocol::network::{Icmpv4, Ipv4};
use packetcraftr_core::protocol::transport::Tcp;
use packetcraftr_netio::interface::Id as InterfaceId;

use super::engine::run;
use super::{
    Aggregate, Basis, Collector, Event, Host, NotTraced, Observed, Report, Request, Reuse,
    Selection as HostSelection, State, Strategy, observed,
};
use crate::clock::Clock;
use crate::execution::Executor;
use crate::policy::{Authorizer, Operation};
use crate::probe::{Batch, Evidence, ProbeStatus, Transport};
use crate::scan::{self, Classification as ScanClassification, Reply, Stage};
use crate::target::{
    Authorized, Family, ResolveTarget, ResolvedZone, SelectedAddress, Selection, Target,
};
use crate::test_support::{RecordingClock, decoded_packet, sent_packet};
use crate::traceroute::plan::build_batches;
use crate::traceroute::plan::packet::probe_packet;
use crate::traceroute::{Error, Limits, Probe, ProbeEvidence, ResponseKind, Termination};
use crate::{Sink, Stats};

const LOCAL: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);

fn host(octet: u8) -> Ipv4Addr {
    Ipv4Addr::new(192, 0, 2, octet)
}

fn router(octet: u8) -> Ipv4Addr {
    Ipv4Addr::new(198, 51, 100, octet)
}

#[derive(Clone, Copy)]
enum End {
    Reply,
    Reset,
    Unreachable,
    Silent,
}

#[derive(Clone)]
struct Path {
    hops: Vec<Option<Ipv4Addr>>,
    end: End,
}

fn path(hops: &[u8], end: End) -> Path {
    Path {
        hops: hops
            .iter()
            .map(|octet| (*octet != 0).then(|| router(*octet)))
            .collect(),
        end,
    }
}

struct Network {
    paths: HashMap<Ipv4Addr, Path>,
    clock: RecordingClock,
    batch_time: Duration,
    sent: Vec<Probe>,
    batches: usize,
    cancel_after: Option<(usize, Cancellation)>,
    mismatch_batch: Option<usize>,
}

impl Network {
    fn new(paths: impl IntoIterator<Item = (Ipv4Addr, Path)>) -> Self {
        Self {
            paths: paths.into_iter().collect(),
            clock: RecordingClock::default(),
            batch_time: Duration::from_millis(1),
            sent: Vec::new(),
            batches: 0,
            cancel_after: None,
            mismatch_batch: None,
        }
    }

    fn response(&self, probe: &Probe, sent: &Packet, bytes: &Bytes) -> Option<DecodedPacket> {
        let IpAddr::V4(destination) = probe.address else {
            return None;
        };
        let path = self.paths.get(&destination)?;
        let hop = usize::from(probe.hop_limit);
        let quote = bytes[..28].to_vec();
        let error = |source: Ipv4Addr, icmp_type: u8, code: u8| {
            let mut body = vec![0_u8; 4];
            body.extend_from_slice(&quote);
            let mut packet = Packet::new();
            packet
                .push(Ipv4 {
                    source,
                    destination: LOCAL,
                    ..Ipv4::default()
                })
                .push(Icmpv4 {
                    icmp_type,
                    code,
                    body: Bytes::from(body),
                    ..Icmpv4::default()
                });
            packet
        };
        let packet = if hop <= path.hops.len() {
            error(path.hops[hop - 1]?, 11, 0)
        } else {
            match (path.end, probe.target.transport()) {
                (End::Silent, _) => return None,
                (End::Unreachable, _) => error(router(250), 3, 1),
                (_, Transport::Udp) => error(destination, 3, 3),
                (end, Transport::Tcp) => {
                    let tcp = sent.get::<Tcp>().expect("TCP probe");
                    let mut packet = Packet::new();
                    packet
                        .push(Ipv4 {
                            source: destination,
                            destination: LOCAL,
                            ..Ipv4::default()
                        })
                        .push(Tcp {
                            source_port: tcp.destination_port,
                            destination_port: tcp.source_port,
                            sequence: 100,
                            acknowledgment: tcp.sequence.wrapping_add(1),
                            flags: if matches!(end, End::Reset) {
                                Tcp::RST | Tcp::ACK
                            } else {
                                Tcp::SYN | Tcp::ACK
                            },
                            ..Tcp::default()
                        });
                    packet
                }
                (_, Transport::Icmp) => {
                    let echo = sent.get::<Icmpv4>().expect("ICMP probe");
                    let mut packet = Packet::new();
                    packet
                        .push(Ipv4 {
                            source: destination,
                            destination: LOCAL,
                            ..Ipv4::default()
                        })
                        .push(Icmpv4 {
                            icmp_type: 0,
                            code: 0,
                            body: echo.body.clone(),
                            ..Icmpv4::default()
                        });
                    packet
                }
            }
        };
        Some(decoded_packet(
            packet,
            UNIX_EPOCH + Duration::from_secs(1_000 + probe.sequence),
            &[0x45],
            Vec::new(),
        ))
    }
}

impl Executor<Batch<Probe>> for Network {
    fn execute(&mut self, batch: &Batch<Probe>) -> Result<Evidence, BoundaryError> {
        self.batches += 1;
        let mut sent = Vec::new();
        let mut responses = Vec::new();
        let mut bytes = 0_u64;
        for (index, probe) in batch.probes.iter().enumerate() {
            let mut packet = probe_packet(probe);
            if let Some(ipv4) = packet.get_mut::<Ipv4>() {
                ipv4.source = LOCAL;
                if self.mismatch_batch == Some(self.batches) {
                    ipv4.ttl = ipv4.ttl.wrapping_add(1);
                }
            }
            let receipt = sent_packet(packet);
            bytes += u64::try_from(receipt.bytes_sent()).unwrap();
            if let Some(response) =
                self.response(probe, &receipt.built().packet, &receipt.built().bytes)
            {
                responses.push(crate::exchange::Response {
                    request_index: index,
                    response,
                    latency: Duration::from_millis(1),
                });
            }
            sent.push(receipt);
            self.sent.push(*probe);
        }
        self.clock.advance(self.batch_time);
        if let Some((batches, cancellation)) = &self.cancel_after
            && self.batches >= *batches
        {
            cancellation.cancel();
        }
        let count = u64::try_from(batch.probes.len()).unwrap();
        Ok(Evidence {
            permit: batch.permit,
            sent,
            responses,
            unsolicited: Vec::new(),
            undecoded: Vec::new(),
            diagnostics: Vec::new(),
            stats: Stats {
                packets_attempted: count,
                packets_completed: count,
                bytes,
                elapsed: Duration::from_millis(1),
                capture: packetcraftr_netio::capture::Stats::default(),
            },
        })
    }
}

struct Resolver {
    targets: Vec<SelectedAddress>,
    operations: Vec<(u64, u64)>,
    deny_target: bool,
    deny_operation: bool,
}

impl Resolver {
    fn new(hosts: &[Ipv4Addr]) -> Self {
        Self {
            targets: hosts
                .iter()
                .map(|address| SelectedAddress::new(IpAddr::V4(*address)))
                .collect(),
            operations: Vec::new(),
            deny_target: false,
            deny_operation: false,
        }
    }
}

fn denial(message: &'static str) -> BoundaryError {
    BoundaryError::new(
        message,
        Classification::new("policy.fixture", Kind::Policy, None),
        Vec::new(),
    )
}

impl ResolveTarget for Resolver {
    fn resolve_and_authorize(
        &mut self,
        target: &Target,
        _deadline: &Deadline,
    ) -> Result<Authorized, BoundaryError> {
        if self.deny_target {
            return Err(denial("the fixture denied the target"));
        }
        Ok(Authorized {
            declared: target.clone(),
            selected: self.targets.clone(),
        })
    }
}

impl Authorizer for Resolver {
    fn authorize_operation(&mut self, operation: Operation<'_>) -> Result<(), BoundaryError> {
        let limits = operation.limits();
        self.operations
            .push((limits.packets(), limits.wire_bytes()));
        if self.deny_operation {
            return Err(denial("the fixture denied the operation"));
        }
        Ok(())
    }
}

fn tcp() -> Option<Strategy> {
    Some(Strategy {
        transport: Transport::Tcp,
        destination_port: Some(80),
    })
}

fn request(strategy: Option<Strategy>) -> Request {
    Request {
        targets: Selection::from(Target::Hostname("fixtures.invalid".parse().unwrap())),
        max_targets: 16,
        address_family: Family::Any,
        strategy,
        observed: Vec::new(),
        source_port: None,
        payload_size: 0,
        dont_fragment: false,
        dscp: 0,
        first_hop: 1,
        max_hops: 8,
        probes_per_hop: 1,
        timeout: Duration::from_millis(10),
        probes_per_second: None,
        paced_after: None,
        reuse: None,
        limits: Limits::default(),
        route: crate::route::Options::default(),
        collection: crate::exchange::Collection::default(),
    }
}

fn reusing(max_age: Duration) -> Request {
    Request {
        reuse: Some(Reuse { max_age }),
        ..request(tcp())
    }
}

struct Traced {
    report: Report,
    events: Vec<Event>,
}

impl Traced {
    fn aggregate(&self) -> Aggregate {
        let mut collector = Collector::default();
        for event in self.events.clone() {
            collector.publish(event).unwrap();
        }
        collector.clone().finish(self.report.clone()).unwrap()
    }

    fn host(&self, address: Ipv4Addr) -> &Host {
        self.report
            .hosts
            .iter()
            .find(|host| host.address == IpAddr::V4(address))
            .expect("host is reported")
    }

    fn probes(&self) -> Vec<&ProbeEvidence> {
        self.events
            .iter()
            .filter_map(|event| match event {
                Event::Probe(probe) => Some(probe),
                _ => None,
            })
            .collect()
    }

    fn host_probes(&self, address: Ipv4Addr) -> Vec<&ProbeEvidence> {
        self.probes()
            .into_iter()
            .filter(|probe| probe.destination == IpAddr::V4(address))
            .collect()
    }

    fn fresh_hops(&self, address: Ipv4Addr) -> Vec<u8> {
        self.host_probes(address)
            .iter()
            .map(|probe| probe.hop_limit)
            .collect()
    }
}

fn trace_with(
    request: &Request,
    resolver: &mut Resolver,
    network: &mut Network,
    mut deadline: Deadline,
) -> Result<Traced, Error> {
    let mut events = Vec::new();
    let mut clock = network.clock.clone();
    let report = run(
        request,
        resolver,
        &packetcraftr_core::protocol::builtin::registry(),
        network,
        &mut clock,
        &mut deadline,
        |event, _| {
            events.push(event);
            Ok(())
        },
    )?;
    Ok(Traced { report, events })
}

fn trace(request: &Request, network: &mut Network) -> Traced {
    let mut hosts: Vec<_> = network.paths.keys().copied().collect();
    hosts.sort();
    trace_hosts(request, &hosts, network)
}

fn trace_hosts(request: &Request, hosts: &[Ipv4Addr], network: &mut Network) -> Traced {
    let deadline = network.clock.deadline(request.limits.max_duration);
    let traced = trace_with(request, &mut Resolver::new(hosts), network, deadline)
        .expect("the trace completes");
    assert_sound(request, &traced, network);
    traced
}

fn trace_error(request: &Request, hosts: &[Ipv4Addr], network: &mut Network) -> Error {
    let mut resolver = Resolver::new(hosts);
    let deadline = network.clock.deadline(request.limits.max_duration);
    trace_with(request, &mut resolver, network, deadline)
        .err()
        .expect("the trace is rejected")
}

fn assert_sound(request: &Request, traced: &Traced, network: &Network) {
    let cap = request.hop_count() * usize::try_from(request.probes_per_hop).unwrap();
    let probes = traced.probes();
    assert_eq!(
        u64::try_from(probes.len()).unwrap(),
        traced.report.stats.packets_attempted,
        "every attempted probe is exactly one probe event"
    );
    for probe in &probes {
        if probe.response_kind == Some(ResponseKind::DestinationReached) {
            assert_eq!(
                probe.responder,
                Some(probe.destination),
                "only the destination itself can be reached"
            );
        }
    }
    let hosts_events: Vec<_> = traced
        .events
        .iter()
        .filter_map(|event| match event {
            Event::Host(host) => Some(host),
            _ => None,
        })
        .collect();
    assert_eq!(hosts_events.len(), traced.report.hosts.len());
    let mut sequences: Vec<u64> = Vec::new();
    for host in &traced.report.hosts {
        assert!(host.probes.len() <= cap, "{} exceeds its cap", host.address);
        sequences.extend(&host.probes);
        let IpAddr::V4(address) = host.address else {
            continue;
        };
        let Some(path) = network.paths.get(&address) else {
            continue;
        };
        let mut hops: BTreeMap<u8, Vec<IpAddr>> = BTreeMap::new();
        let fresh: Vec<_> = traced.host_probes(address);
        let mut probed = Vec::new();
        for probe in &fresh {
            probed.push(probe.hop_limit);
            if probe.response_kind == Some(ResponseKind::Intermediate) {
                hops.entry(probe.hop_limit)
                    .or_default()
                    .push(probe.responder.unwrap());
            }
        }
        for reused in &host.reused {
            assert!(
                !probed.contains(&reused.hop_limit),
                "a reused hop is never also probed"
            );
            hops.insert(reused.hop_limit, reused.responders.clone());
        }
        for (hop_limit, responders) in hops {
            let truth = path.hops[usize::from(hop_limit) - 1].expect("a silent hop answers");
            assert!(
                responders
                    .iter()
                    .all(|responder| *responder == IpAddr::V4(truth)),
                "{address} hop {hop_limit} is {responders:?}, not {truth}"
            );
        }
    }
    sequences.sort_unstable();
    assert_eq!(
        sequences,
        (0..u64::try_from(probes.len()).unwrap()).collect::<Vec<_>>(),
        "sequences are global and contiguous"
    );
}

#[test]
fn silent_hops_time_out_and_the_trace_continues() {
    let mut network = Network::new([(host(9), path(&[1, 0, 3], End::Reply))]);

    let traced = trace(&request(tcp()), &mut network);

    let host = traced.host(host(9));
    assert_eq!(host.state, State::Complete);
    assert_eq!(host.termination, Some(Termination::DestinationReached));
    assert_eq!(traced.fresh_hops(self::host(9)), [1, 2, 3, 4]);
    let statuses: Vec<_> = traced.probes().iter().map(|probe| probe.status).collect();
    assert_eq!(
        statuses,
        [
            ProbeStatus::Response,
            ProbeStatus::Timeout,
            ProbeStatus::Response,
            ProbeStatus::Response
        ]
    );
    let aggregate = traced.aggregate();
    assert_eq!(aggregate.hosts[0].hops.len(), 4);
}

#[test]
fn every_transport_ends_at_the_destination() {
    for (transport, port, end) in [
        (Transport::Tcp, Some(80), End::Reply),
        (Transport::Tcp, Some(80), End::Reset),
        (Transport::Udp, Some(33_434), End::Reply),
        (Transport::Icmp, None, End::Reply),
    ] {
        let mut network = Network::new([(host(9), path(&[1, 2], end))]);
        let strategy = Strategy {
            transport,
            destination_port: port,
        };

        let traced = trace(&request(Some(strategy)), &mut network);

        let record = traced.host(host(9));
        assert_eq!(record.state, State::Complete, "{transport}");
        assert_eq!(record.termination, Some(Termination::DestinationReached));
        assert_eq!(traced.fresh_hops(host(9)), [1, 2, 3], "{transport}");
    }
}

#[test]
fn unreachable_ends_the_trace() {
    let mut network = Network::new([(host(9), path(&[1], End::Unreachable))]);

    let traced = trace(&request(tcp()), &mut network);

    let record = traced.host(host(9));
    assert_eq!(record.state, State::Complete);
    assert_eq!(record.termination, Some(Termination::Unreachable));
    assert_eq!(traced.fresh_hops(host(9)), [1, 2]);
}

#[test]
fn exhausted_hop_bounds_are_incomplete() {
    let mut network = Network::new([
        (host(9), path(&[1, 2, 3, 4, 5, 6, 7, 8, 9], End::Reply)),
        (host(10), path(&[0; 9], End::Reply)),
    ]);
    let mut bounded = request(tcp());
    bounded.max_hops = 4;

    let traced = trace(&bounded, &mut network);

    let responsive = traced.host(host(9));
    assert_eq!(responsive.state, State::Incomplete);
    assert_eq!(responsive.termination, Some(Termination::MaximumHops));
    assert_eq!(responsive.probes.len(), 4);
    let silent = traced.host(host(10));
    assert_eq!(silent.state, State::Incomplete);
    assert_eq!(silent.termination, Some(Termination::Timeout));
}

fn scan_probe(
    address: Ipv4Addr,
    sequence: u64,
    transport: Transport,
    port: Option<u16>,
    reply: Option<Reply>,
    responder: Option<IpAddr>,
) -> scan::ProbeEvidence {
    scan::ProbeEvidence {
        sequence,
        stage: if sequence < 10 {
            Stage::Discovery
        } else {
            Stage::Scan
        },
        address: IpAddr::V4(address),
        scope: None,
        transport,
        port,
        attempt: 1,
        status: if reply.is_some() {
            ProbeStatus::Response
        } else {
            ProbeStatus::Timeout
        },
        classification: ScanClassification::Open,
        reply,
        responder,
        sent_at: UNIX_EPOCH,
        received_at: reply.map(|_| UNIX_EPOCH + Duration::from_secs(sequence)),
        latency: None,
        response: None,
        reason: String::new(),
        application: None,
    }
}

fn scan_endpoint(probe: scan::ProbeEvidence) -> scan::Endpoint {
    scan::Endpoint {
        address: probe.address,
        scope: None,
        transport: probe.transport,
        port: probe.port,
        classification: probe.classification,
        port_hint: None,
        inference: None,
        probes: vec![probe],
    }
}

fn scan_aggregate(
    discovery: Vec<scan::ProbeEvidence>,
    endpoints: Vec<scan::ProbeEvidence>,
) -> scan::Aggregate {
    scan::Aggregate {
        planned_duration: Duration::ZERO,
        target: String::new(),
        resolved_addresses: Vec::new(),
        hosts: Vec::new(),
        discovery,
        endpoints: endpoints.into_iter().map(scan_endpoint).collect(),
        undecoded: Vec::new(),
        unattributed: Vec::new(),
        diagnostics: Vec::new(),
        retained_evidence_bytes: 0,
        stats: Stats::default(),
        rtt: scan::Rtt::default(),
    }
}

fn answered(
    address: Ipv4Addr,
    sequence: u64,
    transport: Transport,
    port: Option<u16>,
    reply: Reply,
) -> scan::ProbeEvidence {
    scan_probe(
        address,
        sequence,
        transport,
        port,
        Some(reply),
        Some(IpAddr::V4(address)),
    )
}

#[test]
fn scan_observations_select_the_strongest_probe_per_host() {
    let a = host(1);
    let b = host(2);
    let c = host(3);
    let d = host(4);
    let e = host(5);
    let scoped = {
        let mut probe = answered(host(6), 31, Transport::Tcp, Some(80), Reply::TcpSynAck);
        probe.scope = Some(ResolvedZone {
            zone: "eth0".parse().unwrap(),
            interface: InterfaceId {
                index: 1,
                name: "eth0".to_owned(),
            },
        });
        probe
    };
    let aggregate = scan_aggregate(
        vec![
            answered(a, 0, Transport::Icmp, None, Reply::IcmpEchoReply),
            answered(c, 1, Transport::Icmp, None, Reply::IcmpEchoReply),
            scan_probe(d, 2, Transport::Icmp, None, None, None),
        ],
        vec![
            answered(a, 10, Transport::Tcp, Some(81), Reply::TcpReset),
            answered(a, 12, Transport::Tcp, Some(443), Reply::TcpSynAck),
            answered(a, 11, Transport::Tcp, Some(22), Reply::TcpSynAck),
            answered(b, 14, Transport::Tcp, Some(23), Reply::TcpReset),
            answered(b, 13, Transport::Tcp, Some(21), Reply::TcpReset),
            scan_probe(
                d,
                15,
                Transport::Tcp,
                Some(80),
                Some(Reply::IcmpTimeExceeded),
                Some(IpAddr::V4(router(1))),
            ),
            scan_probe(
                d,
                16,
                Transport::Tcp,
                Some(81),
                Some(Reply::IcmpPortUnreachable),
                Some(IpAddr::V4(router(1))),
            ),
            answered(d, 17, Transport::Udp, Some(53), Reply::UdpPayload),
            answered(e, 18, Transport::Tcp, Some(80), Reply::TcpOther),
            scan_probe(
                e,
                19,
                Transport::Tcp,
                Some(25),
                Some(Reply::TcpSynAck),
                Some(IpAddr::V4(router(2))),
            ),
            scoped,
        ],
    );

    let chosen = observed(&aggregate);

    let summary: Vec<_> = chosen
        .iter()
        .map(|observed| {
            (
                observed.address,
                observed.transport,
                observed.destination_port,
                observed.sequence,
                observed.reply,
                observed.stage,
            )
        })
        .collect();
    assert_eq!(
        summary,
        [
            (
                IpAddr::V4(c),
                Transport::Icmp,
                None,
                1,
                Reply::IcmpEchoReply,
                Stage::Discovery
            ),
            (
                IpAddr::V4(a),
                Transport::Tcp,
                Some(22),
                11,
                Reply::TcpSynAck,
                Stage::Scan
            ),
            (
                IpAddr::V4(b),
                Transport::Tcp,
                Some(21),
                13,
                Reply::TcpReset,
                Stage::Scan
            ),
        ]
    );
    assert_eq!(
        chosen[1].observed_at,
        Some(UNIX_EPOCH + Duration::from_secs(11))
    );
}

#[test]
fn observation_or_fallback_selects_each_hosts_probe() {
    let mut network = Network::new([
        (host(1), path(&[1], End::Reply)),
        (host(2), path(&[1], End::Reply)),
        (host(3), path(&[1], End::Reply)),
    ]);
    let echo = Observed {
        address: IpAddr::V4(host(1)),
        transport: Transport::Icmp,
        destination_port: None,
        stage: Stage::Discovery,
        sequence: 4,
        reply: Reply::IcmpEchoReply,
        observed_at: None,
    };
    let mut with_fallback = request(tcp());
    with_fallback.observed = vec![echo.clone()];

    let traced = trace(&with_fallback, &mut network);

    let first = traced.host(host(1));
    assert_eq!(
        first.selection,
        Some(HostSelection {
            strategy: Strategy {
                transport: Transport::Icmp,
                destination_port: None
            },
            basis: Basis::Observed(echo.clone()),
        })
    );
    let second = traced.host(host(2));
    assert_eq!(second.selection.as_ref().unwrap().basis, Basis::Requested);
    assert!(
        traced
            .host_probes(host(1))
            .iter()
            .all(|probe| probe.strategy == Transport::Icmp)
    );
    assert!(
        traced
            .host_probes(host(2))
            .iter()
            .all(|probe| probe.strategy == Transport::Tcp && probe.destination_port == Some(80))
    );

    let mut without_fallback = request(None);
    without_fallback.observed = vec![echo];
    let mut network = Network::new([
        (host(1), path(&[1], End::Reply)),
        (host(2), path(&[1], End::Reply)),
    ]);
    let traced = trace(&without_fallback, &mut network);

    assert_eq!(traced.host(host(1)).state, State::Complete);
    let skipped = traced.host(host(2));
    assert_eq!(
        skipped.state,
        State::NotTraced(NotTraced::NoResponsiveProbe)
    );
    assert!(skipped.probes.is_empty() && skipped.selection.is_none());
    assert!(traced.host_probes(host(2)).is_empty());
}

#[test]
fn scoped_targets_are_not_traced() {
    let scoped = SelectedAddress {
        address: IpAddr::V6("fe80::1".parse::<Ipv6Addr>().unwrap()),
        scope: Some(ResolvedZone {
            zone: "eth0".parse().unwrap(),
            interface: InterfaceId {
                index: 1,
                name: "eth0".to_owned(),
            },
        }),
    };
    let mut resolver = Resolver::new(&[host(1)]);
    resolver.targets.insert(0, scoped);
    let mut network = Network::new([(host(1), path(&[1], End::Reply))]);
    let plan = request(tcp());
    let deadline = network.clock.deadline(plan.limits.max_duration);

    let traced = trace_with(&plan, &mut resolver, &mut network, deadline).unwrap();

    assert_eq!(
        traced.report.hosts[0].state,
        State::NotTraced(NotTraced::ScopedTarget)
    );
    assert_eq!(traced.report.hosts[1].state, State::Complete);
    assert_eq!(resolver.operations, [(8, 8 * 74)]);
    assert!(matches!(traced.events[0], Event::Host(_)));
}

#[test]
fn one_budget_covers_every_host() {
    let hosts = [host(1), host(2), host(3)];
    let new_network = || Network::new(hosts.map(|address| (address, path(&[], End::Silent))));

    let mut over = request(tcp());
    over.limits.max_probes = 23;
    let mut network = new_network();
    let mut resolver = Resolver::new(&hosts);
    let deadline = network.clock.deadline(over.limits.max_duration);
    let error = trace_with(&over, &mut resolver, &mut network, deadline)
        .err()
        .unwrap();
    assert!(matches!(
        error,
        Error::InvalidLimit {
            field: "probes",
            ..
        }
    ));
    assert!(network.sent.is_empty() && resolver.operations.is_empty());

    let mut exact = request(tcp());
    exact.limits.max_probes = 24;
    let mut network = new_network();
    let mut resolver = Resolver::new(&hosts);
    let deadline = network.clock.deadline(exact.limits.max_duration);
    let traced = trace_with(&exact, &mut resolver, &mut network, deadline).unwrap();
    assert_eq!(traced.probes().len(), 24);
    assert_eq!(resolver.operations, [(24, 24 * 74)]);
}

#[test]
fn worst_case_duration_includes_every_batch_and_the_first_pause() {
    let hosts = [host(1), host(2), host(3)];
    let silent = || Network::new(hosts.map(|address| (address, path(&[], End::Silent))));
    let mut paced = request(tcp());
    paced.probes_per_second = Some(10);
    let batches = 24;
    let worst = Duration::from_millis(10) * batches + Duration::from_millis(100) * (batches - 1);

    paced.limits.max_duration = worst;
    trace_hosts(&paced, &hosts, &mut silent());

    paced.limits.max_duration = worst - Duration::from_nanos(1);
    assert!(matches!(
        trace_error(&paced, &hosts, &mut silent()),
        Error::DurationLimit { .. }
    ));

    let mut network = silent();
    paced.paced_after = Some(network.clock.now());
    paced.limits.max_duration = worst;
    assert!(matches!(
        trace_error(&paced, &hosts, &mut network),
        Error::DurationLimit { .. }
    ));
    paced.limits.max_duration = worst + Duration::from_millis(100);
    trace_hosts(&paced, &hosts, &mut network);
}

#[test]
fn first_batch_follows_the_previous_transmission_by_one_interval() {
    let mut network = Network::new([(host(1), path(&[1], End::Reply))]);
    let mut paced = request(tcp());
    paced.probes_per_second = Some(10);
    paced.paced_after = Some(network.clock.now() - Duration::from_millis(30));

    trace(&paced, &mut network);

    assert_eq!(
        network.clock.delays(),
        [Duration::from_millis(70), Duration::from_millis(100)]
    );
}

#[test]
fn denials_and_invalid_plans_send_nothing() {
    let hosts = [host(1)];
    let mut network = Network::new([(host(1), path(&[1], End::Reply))]);
    let plan = request(tcp());

    let mut denied_target = Resolver::new(&hosts);
    denied_target.deny_target = true;
    let deadline = network.clock.deadline(plan.limits.max_duration);
    let error = trace_with(&plan, &mut denied_target, &mut network, deadline)
        .err()
        .unwrap();
    assert!(matches!(error, Error::Authorization(_)));
    assert!(denied_target.operations.is_empty());

    let mut denied_operation = Resolver::new(&hosts);
    denied_operation.deny_operation = true;
    let deadline = network.clock.deadline(plan.limits.max_duration);
    let error = trace_with(&plan, &mut denied_operation, &mut network, deadline)
        .err()
        .unwrap();
    assert!(matches!(error, Error::Authorization(_)));
    assert_eq!(denied_operation.operations, [(8, 8 * 74)]);

    let mut payload = request(tcp());
    payload.payload_size = 8;
    let mut dont_fragment = request(tcp());
    dont_fragment.dont_fragment = true;
    let mut udp_overflow = request(Some(Strategy {
        transport: Transport::Udp,
        destination_port: Some(u16::MAX - 6),
    }));
    udp_overflow.probes_per_hop = 2;
    for (invalid, hosts, expect) in [
        (payload, vec![IpAddr::V4(host(1))], "payload_size"),
        (
            dont_fragment,
            vec![IpAddr::V6("2001:db8::1".parse().unwrap())],
            "dont_fragment",
        ),
        (udp_overflow, vec![IpAddr::V4(host(1))], "port"),
    ] {
        let mut resolver = Resolver::new(&[]);
        resolver.targets = hosts.into_iter().map(SelectedAddress::new).collect();
        let deadline = network.clock.deadline(invalid.limits.max_duration);
        let error = trace_with(&invalid, &mut resolver, &mut network, deadline)
            .err()
            .unwrap();
        let named = match &error {
            Error::InvalidProbeOption { option, .. } => *option,
            Error::InvalidPort { .. } => "port",
            other => panic!("unexpected {other:?}"),
        };
        assert_eq!(named, expect);
        assert!(resolver.operations.is_empty());
    }
    assert!(network.sent.is_empty());
}

#[test]
fn zero_traced_hosts_approve_nothing_and_send_nothing() {
    let mut network = Network::new([(host(1), path(&[1], End::Reply))]);
    let mut resolver = Resolver::new(&[host(1), host(2)]);
    let plan = request(None);
    let deadline = network.clock.deadline(plan.limits.max_duration);

    let traced = trace_with(&plan, &mut resolver, &mut network, deadline).unwrap();

    assert_eq!(resolver.operations, [(0, 0)]);
    assert!(network.sent.is_empty());
    assert!(
        traced
            .report
            .hosts
            .iter()
            .all(|record| record.state == State::NotTraced(NotTraced::NoResponsiveProbe))
    );
    assert_eq!(traced.report.stats.packets_attempted, 0);
}

#[test]
fn invalid_requests_are_rejected_before_resolution() {
    let mut invalid = Vec::new();
    let mut base = request(tcp());
    base.observed = vec![Observed {
        address: IpAddr::V4(host(1)),
        transport: Transport::Udp,
        destination_port: Some(53),
        stage: Stage::Scan,
        sequence: 1,
        reply: Reply::UdpPayload,
        observed_at: None,
    }];
    invalid.push(base);
    for (transport, port) in [
        (Transport::Tcp, None),
        (Transport::Tcp, Some(0)),
        (Transport::Icmp, Some(7)),
    ] {
        let mut plan = request(tcp());
        plan.observed = vec![Observed {
            address: IpAddr::V4(host(1)),
            transport,
            destination_port: port,
            stage: Stage::Scan,
            sequence: 1,
            reply: Reply::TcpSynAck,
            observed_at: None,
        }];
        invalid.push(plan);
    }
    let mut duplicate = request(tcp());
    let echo = Observed {
        address: IpAddr::V4(host(1)),
        transport: Transport::Icmp,
        destination_port: None,
        stage: Stage::Discovery,
        sequence: 1,
        reply: Reply::IcmpEchoReply,
        observed_at: None,
    };
    duplicate.observed = vec![echo.clone(), echo];
    invalid.push(duplicate);
    for plan in invalid {
        assert!(
            matches!(plan.validate(), Err(Error::InvalidObservation { .. })),
            "{:?}",
            plan.observed
        );
    }

    let mut zero_age = request(tcp());
    zero_age.reuse = Some(Reuse {
        max_age: Duration::ZERO,
    });
    assert!(matches!(
        zero_age.validate(),
        Err(Error::InvalidLimit {
            field: "reuse_max_age",
            ..
        })
    ));
    let mut long_age = request(tcp());
    long_age.reuse = Some(Reuse {
        max_age: Duration::from_secs(86_400),
    });
    assert!(matches!(
        long_age.validate(),
        Err(Error::InvalidDuration { .. })
    ));
    let mut icmp_port = request(Some(Strategy {
        transport: Transport::Icmp,
        destination_port: Some(1),
    }));
    assert!(matches!(
        icmp_port.validate(),
        Err(Error::InvalidPort { .. })
    ));
    icmp_port.strategy = Some(Strategy {
        transport: Transport::Udp,
        destination_port: None,
    });
    assert!(matches!(
        icmp_port.validate(),
        Err(Error::InvalidPort { .. })
    ));
    let mut source = request(tcp());
    source.source_port = Some(0);
    assert!(matches!(source.validate(), Err(Error::InvalidSourcePort)));
    let mut no_targets = request(tcp());
    no_targets.max_targets = 0;
    assert!(matches!(
        no_targets.validate(),
        Err(Error::InvalidLimit {
            field: "max_targets",
            ..
        })
    ));
    request(tcp()).validate().expect("the baseline is valid");
}

fn shared_prefix() -> Network {
    let mut network =
        Network::new((1..=4).map(|octet| (host(octet), path(&[1, 2, 3, 4], End::Reply))));
    network.batch_time = Duration::from_secs(1);
    network
}

fn divergent() -> Network {
    let mut network = Network::new([
        (host(1), path(&[1, 2, 3, 4], End::Reply)),
        (host(2), path(&[1, 2, 13, 14], End::Reply)),
        (host(3), path(&[1, 22, 23, 24], End::Reply)),
    ]);
    network.batch_time = Duration::from_secs(1);
    network
}

fn total_probes(traced: &Traced) -> usize {
    traced
        .report
        .hosts
        .iter()
        .map(|host| host.probes.len())
        .sum()
}

#[test]
fn reuse_sends_fewer_probes_on_a_shared_prefix_without_a_wrong_hop() {
    let without = trace(&request(tcp()), &mut shared_prefix());
    let mut network = shared_prefix();
    let with = trace(&reusing(Duration::from_secs(600)), &mut network);

    assert_eq!(total_probes(&without), 20);
    assert_eq!(total_probes(&with), 11);
    assert!(
        without
            .report
            .hosts
            .iter()
            .all(|host| host.reused.is_empty())
    );
    let counts: Vec<_> = with
        .report
        .hosts
        .iter()
        .map(|host| (host.probes.len(), host.reused.len()))
        .collect();
    assert_eq!(counts, [(5, 0), (2, 3), (2, 3), (2, 3)]);
    for host in &with.report.hosts {
        assert_eq!(host.state, State::Complete);
        for reused in &host.reused {
            assert_eq!(reused.source, IpAddr::V4(self::host(1)));
            assert_eq!(reused.responders, [IpAddr::V4(router(reused.hop_limit))]);
            assert_eq!(reused.probes.len(), 1);
            assert!(reused.observed_at.is_some());
        }
    }
    assert_eq!(with.fresh_hops(host(2)), [4, 5]);
    let aggregate = with.aggregate();
    let hops: Vec<_> = aggregate.hosts[1]
        .hops
        .iter()
        .map(|hop| hop.hop_limit)
        .collect();
    assert_eq!(hops, [4, 5]);
}

#[test]
fn reuse_on_diverging_paths_probes_what_differs() {
    let without = trace(&request(tcp()), &mut divergent());
    let with = trace(&reusing(Duration::from_secs(600)), &mut divergent());

    assert_eq!(total_probes(&without), 15);
    assert_eq!(total_probes(&with), 14);
    assert_eq!(with.fresh_hops(host(2)), [4, 3, 2, 5]);
    assert_eq!(with.host(host(2)).reused.len(), 1);
    assert_eq!(with.host(host(2)).reused[0].hop_limit, 1);
    assert_eq!(with.fresh_hops(host(3)), [4, 3, 2, 1, 5]);
    assert!(with.host(host(3)).reused.is_empty());
    for record in &with.report.hosts {
        assert_eq!(record.state, State::Complete);
    }
}

#[test]
fn reused_hops_expire() {
    let mut some = shared_prefix();
    let partial = trace(&reusing(Duration::from_secs(4)), &mut some);
    let second = partial.host(host(2));
    assert_eq!(partial.fresh_hops(host(2)), [4, 2, 1, 5]);
    assert_eq!(second.reused.len(), 1);
    assert_eq!(second.reused[0].hop_limit, 3);
    assert_eq!(second.reused[0].age, Duration::from_secs(4));

    let mut all = shared_prefix();
    let expired = trace(&reusing(Duration::from_secs(1)), &mut all);
    for address in 1..=4 {
        assert!(expired.host(host(address)).reused.is_empty());
        assert_eq!(expired.fresh_hops(host(address)), [1, 2, 3, 4, 5]);
    }
    assert_eq!(total_probes(&expired), 20);
}

#[test]
fn reused_hops_stay_out_of_the_probe_events() {
    let traced = trace(&reusing(Duration::from_secs(600)), &mut shared_prefix());

    for record in &traced.report.hosts {
        let probed = traced.fresh_hops(match record.address {
            IpAddr::V4(address) => address,
            IpAddr::V6(_) => unreachable!(),
        });
        for reused in &record.reused {
            assert!(!probed.contains(&reused.hop_limit));
        }
    }
    assert_eq!(
        u64::try_from(traced.probes().len()).unwrap(),
        traced.report.stats.packets_attempted
    );
    let mut last_probe = HashMap::new();
    let mut host_record = HashMap::new();
    let published = traced
        .events
        .iter()
        .filter(|event| matches!(event, Event::Host(_) | Event::Probe(_)));
    for (index, event) in published.enumerate() {
        match event {
            Event::Probe(probe) => {
                last_probe.insert(probe.destination, index);
            }
            Event::Host(host) => {
                host_record.insert(host.address, index);
            }
            _ => unreachable!(),
        }
    }
    for (address, probe) in last_probe {
        assert_eq!(
            host_record[&address],
            probe + 1,
            "{address} is recorded right after its last probe"
        );
    }
}

#[test]
fn reuse_stays_within_one_transport() {
    let mut network = shared_prefix();
    let mut plan = reusing(Duration::from_secs(600));
    plan.observed = (2..=4)
        .map(|octet| Observed {
            address: IpAddr::V4(host(octet)),
            transport: Transport::Icmp,
            destination_port: None,
            stage: Stage::Discovery,
            sequence: u64::from(octet),
            reply: Reply::IcmpEchoReply,
            observed_at: None,
        })
        .collect();

    let traced = trace(&plan, &mut network);

    assert_eq!(traced.host(host(1)).probes.len(), 5);
    assert_eq!(traced.host(host(2)).probes.len(), 5);
    assert!(traced.host(host(2)).reused.is_empty());
    assert_eq!(traced.host(host(3)).probes.len(), 2);
    assert_eq!(traced.host(host(3)).reused.len(), 3);
    assert_eq!(traced.host(host(3)).reused[0].source, IpAddr::V4(host(2)));
}

#[test]
fn a_reused_hop_is_a_sourced_claim_on_reconvergent_paths() {
    let mut network = Network::new([
        (host(1), path(&[1, 2, 3, 4], End::Reply)),
        (host(2), path(&[1, 22, 3, 4], End::Reply)),
    ]);
    network.batch_time = Duration::from_secs(1);
    let plan = reusing(Duration::from_secs(600));
    let mut resolver = Resolver::new(&[host(1), host(2)]);
    let deadline = network.clock.deadline(plan.limits.max_duration);

    let traced = trace_with(&plan, &mut resolver, &mut network, deadline).unwrap();

    let second = traced.host(host(2));
    let claim = second
        .reused
        .iter()
        .find(|hop| hop.hop_limit == 2)
        .expect("hop 2 is reused");
    assert_eq!(claim.source, IpAddr::V4(host(1)));
    assert_eq!(claim.responders, [IpAddr::V4(router(2))]);
    assert_eq!(traced.fresh_hops(host(2)), [4, 5]);
}

#[test]
fn reuse_starts_empty_in_every_operation() {
    let mut network = shared_prefix();
    let first = trace(&reusing(Duration::from_secs(600)), &mut network);
    let mut again = shared_prefix();
    let second = trace(&reusing(Duration::from_secs(600)), &mut again);
    assert_eq!(total_probes(&first), total_probes(&second));
    assert!(second.host(host(1)).reused.is_empty());
}

#[test]
fn multiple_probes_per_hop_stay_within_the_host_cap() {
    let mut network = shared_prefix();
    let mut plan = reusing(Duration::from_secs(600));
    plan.probes_per_hop = 3;

    let traced = trace(&plan, &mut network);

    assert_eq!(traced.host(host(1)).probes.len(), 15);
    assert_eq!(traced.host(host(2)).probes.len(), 6);
    assert_eq!(traced.host(host(2)).reused.len(), 3);
}

#[test]
fn udp_ports_advance_per_host() {
    let mut network = Network::new([
        (host(1), path(&[1], End::Reply)),
        (host(2), path(&[1], End::Reply)),
    ]);
    let mut plan = request(Some(Strategy {
        transport: Transport::Udp,
        destination_port: Some(33_434),
    }));
    plan.probes_per_hop = 2;

    let traced = trace(&plan, &mut network);

    for (address, first_sequence) in [(1, 0), (2, 4)] {
        let ports: Vec<_> = traced
            .host_probes(host(address))
            .iter()
            .map(|probe| (probe.sequence, probe.destination_port.unwrap()))
            .collect();
        let expected: Vec<_> = (0..4)
            .map(|index| (first_sequence + index, 33_434 + index as u16))
            .collect();
        assert_eq!(ports, expected);
    }
}

#[test]
fn a_single_host_probes_exactly_like_standalone_traceroute() {
    for (transport, port) in [
        (Transport::Udp, Some(33_434)),
        (Transport::Tcp, Some(80)),
        (Transport::Icmp, None),
    ] {
        let mut network = Network::new([(host(1), path(&[], End::Silent))]);
        let mut plan = request(Some(Strategy {
            transport,
            destination_port: port,
        }));
        plan.probes_per_hop = 2;
        plan.max_hops = 4;
        let standalone = crate::traceroute::Request {
            target: Target::Address(IpAddr::V4(host(1))),
            strategy: transport,
            address_family: Family::Any,
            destination_port: port,
            source_port: None,
            payload_size: 0,
            dont_fragment: false,
            dscp: 0,
            first_hop: 1,
            max_hops: 4,
            probes_per_hop: 2,
            timeout: plan.timeout,
            probes_per_second: None,
            limits: Limits::default(),
            route: crate::route::Options::default(),
            collection: crate::exchange::Collection::default(),
        };

        trace(&plan, &mut network);

        let expected: Vec<_> = build_batches(&standalone, IpAddr::V4(host(1)))
            .unwrap()
            .into_iter()
            .flat_map(|batch| batch.probes)
            .collect();
        let sent: Vec<_> = network
            .sent
            .iter()
            .map(|probe| Probe {
                source_port: if transport == Transport::Icmp {
                    super::super::SOURCE_PORT
                } else {
                    probe.source_port
                },
                ..*probe
            })
            .collect();
        assert_eq!(sent, expected, "{transport}");
    }
}

#[test]
fn evidence_limits_are_shared_across_hosts() {
    let mut plan = request(tcp());
    plan.limits.max_evidence_frames = 3;
    plan.limits.max_undecoded = 3;
    plan.collection.capture.max_frames = 3;
    let mut network = Network::new([
        (host(1), path(&[1, 2], End::Reply)),
        (host(2), path(&[1, 2], End::Reply)),
    ]);

    let traced = trace(&plan, &mut network);

    let retained = traced
        .probes()
        .iter()
        .filter(|probe| probe.response.is_some())
        .count();
    assert_eq!(retained, 3);
    let limits = traced
        .events
        .iter()
        .filter(
            |event| matches!(event, Event::Diagnostic(d) if d.code == "traceroute.evidence_limit"),
        )
        .count();
    assert_eq!(limits, 1);
}

#[test]
fn cancellation_and_deadline_end_the_plan_with_typed_errors() {
    let hosts = [host(1), host(2), host(3)];
    let silent = || Network::new(hosts.map(|address| (address, path(&[], End::Silent))));
    let plan = request(tcp());

    let mut network = silent();
    let cancellation = Cancellation::default();
    network.cancel_after = Some((5, cancellation.clone()));
    let deadline = network
        .clock
        .deadline(plan.limits.max_duration)
        .with_cancellation(Some(cancellation));
    let error = trace_with(&plan, &mut Resolver::new(&hosts), &mut network, deadline)
        .err()
        .unwrap();
    assert!(matches!(error, Error::Cancelled(_)), "{error:?}");
    assert_eq!(network.batches, 5);

    let mut network = silent();
    network.batch_time = Duration::from_millis(10);
    let deadline = network.clock.deadline(Duration::from_millis(35));
    let error = trace_with(&plan, &mut Resolver::new(&hosts), &mut network, deadline)
        .err()
        .unwrap();
    assert!(matches!(error, Error::DurationLimit { .. }), "{error:?}");
    assert!(network.batches < 24);
}

#[test]
fn collector_rejects_events_that_disagree_with_the_report() {
    let traced = trace(
        &request(tcp()),
        &mut Network::new([(host(1), path(&[1], End::Reply))]),
    );
    let mut collector = Collector::default();
    for event in traced.events.clone() {
        collector.publish(event).unwrap();
    }
    let mut report = traced.report.clone();
    report.hosts[0].probes.push(99);

    assert!(matches!(
        collector.finish(report),
        Err(Error::IncoherentEvents { .. })
    ));
}

#[test]
fn a_sent_packet_that_differs_from_its_probe_fails_the_plan_at_that_probe() {
    let hosts = [host(1), host(2)];
    let mut network = Network::new(hosts.map(|address| (address, path(&[], End::Silent))));
    network.mismatch_batch = Some(3);
    let mut plan = request(tcp());
    plan.max_hops = 2;
    let mut resolver = Resolver::new(&hosts);
    let deadline = network.clock.deadline(plan.limits.max_duration);

    let error = trace_with(&plan, &mut resolver, &mut network, deadline)
        .err()
        .expect("the mismatched packet is rejected");

    assert!(
        matches!(error, Error::InvalidEvidence { sequence: 2, .. }),
        "{error:?}"
    );
    assert_eq!(network.batches, 3, "no batch follows the rejected one");
    assert_eq!(network.sent.len(), 3);
}
