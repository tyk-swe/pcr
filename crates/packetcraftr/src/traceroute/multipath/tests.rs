// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use crate::{
    Stats,
    clock::Clock,
    engine::execution::Grant,
    evidence::SentPacket,
    probe::{
        Transport,
        runner::{Evidence, UnsolicitedCapture},
    },
};
use packetcraftr_core::{
    budget::Deadline,
    build::{Builder, BuiltPacket},
    decode::{DecodedPacket, Dissector},
    diagnostic::Diagnostic,
    error::BoundaryError,
    frame::{Frame, LinkType},
    packet::Packet,
    protocol::{
        builtin,
        network::{Icmpv4, Icmpv6, Ipv4, Ipv6},
        transport::{Tcp, Udp},
    },
};
use std::{
    convert::Infallible,
    net::IpAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime},
};

fn request(strategy: Transport, v6: bool) -> Request {
    Request {
        flows: 2,
        trace: crate::traceroute::Request {
            target: crate::target::Target::Address(destination(v6)),
            strategy,
            address_family: crate::target::Family::Any,
            destination_port: match strategy {
                Transport::Udp => Some(33434),
                Transport::Tcp => Some(80),
                _ => None,
            },
            source_port: None,
            payload_size: 0,
            dont_fragment: false,
            dscp: 12,
            first_hop: 1,
            max_hops: 4,
            probes_per_hop: 2,
            timeout: Duration::from_millis(100),
            probes_per_second: None,
            limits: Default::default(),
            route: Default::default(),
            collection: Default::default(),
        },
    }
}
fn destination(v6: bool) -> IpAddr {
    if v6 { "fd00::9" } else { "10.0.0.9" }.parse().unwrap()
}
fn source(v6: bool) -> IpAddr {
    if v6 { "fd00::2" } else { "10.0.0.2" }.parse().unwrap()
}
fn build(mut packet: Packet) -> BuiltPacket {
    if let Some(ip) = packet.get_mut::<Ipv4>()
        && ip.source.is_unspecified()
    {
        ip.source = "10.0.0.2".parse().unwrap();
    }
    if let Some(ip) = packet.get_mut::<Ipv6>()
        && ip.source.is_unspecified()
    {
        ip.source = "fd00::2".parse().unwrap();
    }
    Builder::new(builtin::registry())
        .build(packet, Default::default(), Default::default())
        .unwrap()
}
fn decode(packet: Packet) -> DecodedPacket {
    let built = build(packet);
    Dissector::new(builtin::registry())
        .decode(
            Frame::new(SystemTime::UNIX_EPOCH, LinkType::RAW, built.bytes).unwrap(),
            Default::default(),
        )
        .unwrap()
}
fn quote(
    sent: &BuiltPacket,
    responder: IpAddr,
    terminal: bool,
    transport_bytes: usize,
) -> DecodedPacket {
    let mut reply = Packet::new();
    let v6 = responder.is_ipv6();
    let header = if v6 { 40 } else { 20 };
    let mut body = vec![0; 4];
    body.extend_from_slice(&sent.bytes[..sent.bytes.len().min(header + transport_bytes)]);
    match responder {
        IpAddr::V4(address) => {
            reply.push(Ipv4 {
                source: address,
                destination: sent.packet.get::<Ipv4>().unwrap().source,
                ..Default::default()
            });
            reply.push(Icmpv4 {
                icmp_type: if terminal { 3 } else { 11 },
                code: if terminal { 3 } else { 0 },
                body: body.into(),
                ..Default::default()
            });
        }
        IpAddr::V6(address) => {
            reply.push(Ipv6 {
                source: address,
                destination: sent.packet.get::<Ipv6>().unwrap().source,
                ..Default::default()
            });
            reply.push(Icmpv6 {
                icmp_type: if terminal { 1 } else { 3 },
                code: if terminal { 4 } else { 0 },
                body: body.into(),
                ..Default::default()
            });
        }
    }
    decode(reply)
}

#[test]
fn stable_flow_fields_checksums_and_stale_quote_rejection_all_strategies() {
    for v6 in [false, true] {
        for strategy in [Transport::Udp, Transport::Tcp, Transport::Icmp] {
            let mut request = request(strategy, v6);
            if strategy != Transport::Tcp {
                request.trace.payload_size = 3;
            }
            let flow = packet::flows(&request, destination(v6), u64::MAX)[0].clone();
            let first = packet::Probe::new(&request, flow.clone(), destination(v6), u64::MAX, 1, 1);
            let next = packet::Probe::new(&request, flow.clone(), destination(v6), u64::MAX, 1, 2);
            let repeated = packet::Probe::new(&request, flow, destination(v6), u64::MAX, 2, 1);
            let a = build(first.packet.clone());
            let b = build(next.packet.clone());
            let c = build(repeated.packet.clone());
            assert!(packet::sent_matches(&first, &a.packet));
            assert_eq!(a.bytes.len(), b.bytes.len());
            if v6 {
                assert_eq!(
                    a.packet.get::<Ipv6>().unwrap().flow_label,
                    b.packet.get::<Ipv6>().unwrap().flow_label
                );
            }
            match strategy {
                Transport::Udp => {
                    let left = a.packet.get::<Udp>().unwrap();
                    let right = b.packet.get::<Udp>().unwrap();
                    assert_eq!(left.source_port, right.source_port);
                    assert_eq!(left.destination_port, right.destination_port);
                    assert_eq!(left.checksum, right.checksum);
                }
                Transport::Icmp if v6 => assert_eq!(
                    a.packet.get::<Icmpv6>().unwrap().checksum,
                    b.packet.get::<Icmpv6>().unwrap().checksum
                ),
                Transport::Icmp => assert_eq!(
                    a.packet.get::<Icmpv4>().unwrap().checksum,
                    b.packet.get::<Icmpv4>().unwrap().checksum
                ),
                _ => assert_eq!(
                    a.packet.get::<Tcp>().unwrap().source_port,
                    b.packet.get::<Tcp>().unwrap().source_port
                ),
            }
            let response = quote(&a, destination(v6), false, usize::MAX - 40);
            let matched =
                packet::classify(&builtin::registry(), strategy, &a.packet, &response).unwrap();
            assert_eq!(matched.kind, crate::traceroute::ResponseKind::Intermediate);
            assert_eq!(matched.responder, destination(v6));
            assert!(
                packet::classify(&builtin::registry(), strategy, &b.packet, &response).is_none()
            );
            assert!(
                packet::classify(&builtin::registry(), strategy, &c.packet, &response).is_none()
            );
        }
    }
}

#[test]
fn udp_short_quotes_are_attributed_only_with_an_exact_identity() {
    for v6 in [false, true] {
        let request = request(Transport::Udp, v6);
        let probe = packet::Probe::new(
            &request,
            packet::flows(&request, destination(v6), 8)[0].clone(),
            destination(v6),
            8,
            1,
            1,
        );
        let sent = build(probe.packet);
        let reply = quote(&sent, destination(v6), false, 8);
        let matched = packet::classify(&builtin::registry(), Transport::Udp, &sent.packet, &reply);
        if v6 {
            assert!(matched.is_none());
        } else {
            let matched = matched.unwrap();
            assert_eq!(matched.kind, crate::traceroute::ResponseKind::Intermediate);
            assert_eq!(matched.responder, destination(false));
        }
        let reply = quote(&sent, destination(v6), false, 7);
        assert!(
            packet::classify(&builtin::registry(), Transport::Udp, &sent.packet, &reply).is_none()
        );
    }
}

fn direct(sent: &BuiltPacket, strategy: Transport, v6: bool) -> DecodedPacket {
    let mut reply = Packet::new();
    match (destination(v6), source(v6)) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            reply.push(Ipv4 {
                source: src,
                destination: dst,
                ..Default::default()
            });
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            reply.push(Ipv6 {
                source: src,
                destination: dst,
                ..Default::default()
            });
        }
        _ => unreachable!(),
    }
    match strategy {
        Transport::Tcp => {
            let syn = sent.packet.get::<Tcp>().unwrap();
            reply.push(Tcp {
                source_port: syn.destination_port,
                destination_port: syn.source_port,
                sequence: 456,
                acknowledgment: syn.sequence.wrapping_add(1),
                flags: Tcp::SYN | Tcp::ACK,
                ..Default::default()
            });
        }
        Transport::Icmp if v6 => {
            reply.push(Icmpv6 {
                icmp_type: 129,
                body: sent.packet.get::<Icmpv6>().unwrap().body.clone(),
                ..Default::default()
            });
        }
        Transport::Icmp => {
            reply.push(Icmpv4 {
                icmp_type: 0,
                body: sent.packet.get::<Icmpv4>().unwrap().body.clone(),
                ..Default::default()
            });
        }
        _ => unreachable!(),
    }
    decode(reply)
}

#[test]
fn direct_echo_and_syn_ack_correlate_and_tcp_cleanup_has_correct_sequence() {
    for v6 in [false, true] {
        for strategy in [Transport::Icmp, Transport::Tcp] {
            let request = request(strategy, v6);
            let probe = packet::Probe::new(
                &request,
                packet::flows(&request, destination(v6), 8)[0].clone(),
                destination(v6),
                8,
                1,
                1,
            );
            let sent = build(probe.packet);
            let reply = direct(&sent, strategy, v6);
            assert_eq!(
                packet::classify(&builtin::registry(), strategy, &sent.packet, &reply)
                    .unwrap()
                    .kind,
                crate::traceroute::ResponseKind::DestinationReached
            );
            if strategy == Transport::Tcp {
                let reset = build(packet::reset(&sent.packet, &reply).unwrap());
                let tcp = reset.packet.get::<Tcp>().unwrap();
                assert_eq!(tcp.flags, Tcp::RST);
                assert_eq!(
                    tcp.sequence,
                    reply.packet.get::<Tcp>().unwrap().acknowledgment
                );
            }
        }
    }
}

#[test]
fn tcp_cleanup_preserves_the_successful_probe_hop_limit() {
    for v6 in [false, true] {
        let mut request = request(Transport::Tcp, v6);
        request.trace.max_hops = u8::MAX;
        for hop in [1, 64, 65, 128, u8::MAX] {
            let probe = packet::Probe::new(
                &request,
                packet::flows(&request, destination(v6), 8)[0].clone(),
                destination(v6),
                8,
                1,
                hop,
            );
            let sent = build(probe.packet);
            let reply = direct(&sent, Transport::Tcp, v6);
            let reset = build(packet::reset(&sent.packet, &reply).unwrap());
            assert_eq!(reset.packet.get::<Tcp>().unwrap().flags, Tcp::RST);
            if v6 {
                assert_eq!(reset.packet.get::<Ipv6>().unwrap().hop_limit, hop);
            } else {
                assert_eq!(reset.packet.get::<Ipv4>().unwrap().ttl, hop);
            }
        }
    }
}

fn materialized(v6: bool) -> crate::route::Materialized {
    use packetcraftr_netio::{
        interface,
        link::{Capability, Mode},
        route::{Decision, Scope, SelectionReason},
    };
    crate::route::Materialized {
        plan: crate::route::Plan {
            decision: Decision {
                interface: interface::Id {
                    index: 1,
                    name: "test0".into(),
                },
                source_mac: None,
                selected_source: Some(source(v6)),
                preferred_source: None,
                next_hop: None,
                selection_reason: SelectionReason::OnLink,
                destination_scope: Scope::Private,
                mtu: 9000,
                capability: Capability::Layer2AndLayer3,
                link_type: LinkType::RAW,
            },
            mode: Mode::Layer3,
            lookup_destination: Some(destination(v6)),
            final_destination: Some(destination(v6)),
            visited_destinations: Vec::new(),
            packet_source: Some(source(v6)),
            neighbor_source: None,
            neighbor_target: None,
            destination_mac: None,
            source_mac: None,
            neighbor_vlan_tags: Vec::new(),
            synthesized_ethernet: false,
        },
        neighbor_resolution: None,
    }
}

#[derive(Clone, Copy)]
enum CorrelationExpiry {
    RetainedReply,
    UndecodedFrame,
}

struct NumericOnly;

impl crate::target::Resolver for NumericOnly {
    fn resolve(
        &self,
        _: &crate::target::Hostname,
        _: usize,
    ) -> Result<Vec<IpAddr>, crate::target::Error> {
        panic!("numeric fixtures must not invoke hostname resolution")
    }
}

#[derive(Clone)]
struct TestClock(Arc<Mutex<Instant>>);

impl TestClock {
    fn new() -> Self {
        Self(Arc::new(Mutex::new(Instant::now())))
    }

    fn deadline(&self) -> Deadline {
        let clock = self.clone();
        Deadline::with_time_source(Duration::from_secs(10), move || clock.now())
    }
}

impl Clock for TestClock {
    type Error = Infallible;

    fn now(&self) -> Instant {
        *self.0.lock().unwrap()
    }

    fn sleep(&self, delay: Duration, _: &Deadline) -> Result<(), Self::Error> {
        *self.0.lock().unwrap() += delay;
        Ok(())
    }
}

#[derive(Default)]
struct Lab {
    batches: Vec<Vec<(u16, u32, u8)>>,
    missing: bool,
    ambiguous: bool,
    unknown: bool,
    correlation_expiry: Option<CorrelationExpiry>,
}
impl engine::Runner for Lab {
    fn exchange(
        &mut self,
        probes: &[packet::Probe],
        grant: Grant,
        _: &Stats,
    ) -> Result<Evidence, BoundaryError> {
        self.batches
            .push(probes.iter().map(|p| (p.flow.id, p.sweep, p.hop)).collect());
        let mut sent = Vec::new();
        let mut responses = Vec::new();
        let mut unsolicited = Vec::new();
        let mut undecoded = Vec::new();
        let mut diagnostics = Vec::new();
        let mut stats = Stats::default();
        for (index, probe) in probes.iter().enumerate() {
            let built = build(probe.packet.clone());
            let v6 = probe.flow.destination.is_ipv6();
            let tx = packetcraftr_netio::transmit::Submission::start()
                .complete(built.bytes.len(), built.bytes.clone());
            let terminal = probe.hop == 3 + (probe.flow.id == 2) as u8;
            let responder: IpAddr = if terminal {
                destination(v6)
            } else {
                match (v6, probe.hop, probe.flow.id) {
                    (false, 1, _) => "10.0.1.1",
                    (false, 2, 1) => "10.0.2.1",
                    (false, 2, _) => "10.0.2.2",
                    (false, _, _) => "10.0.0.9",
                    (true, 1, _) => "fd00:1::1",
                    (true, 2, 1) => "fd00:2::1",
                    (true, 2, _) => "fd00:2::2",
                    _ => "fd00::9",
                }
                .parse()
                .unwrap()
            };
            if !(self.missing && probe.hop == 2) {
                let response = if terminal && probe.flow.strategy != Transport::Udp {
                    direct(&built, probe.flow.strategy, v6)
                } else {
                    quote(&built, responder, terminal, usize::MAX - 40)
                };
                responses.push(crate::exchange::Response {
                    request_index: index,
                    response,
                    latency: Duration::from_millis(2),
                });
                if self.ambiguous && probe.hop == 2 {
                    responses.push(crate::exchange::Response {
                        request_index: index,
                        response: quote(
                            &built,
                            if v6 { "fd00:2::3" } else { "10.0.2.3" }.parse().unwrap(),
                            false,
                            usize::MAX - 40,
                        ),
                        latency: Duration::from_millis(3),
                    });
                }
            }
            if probe.hop == 2
                && let Some(expiry) = self.correlation_expiry
            {
                let response = quote(
                    &built,
                    if v6 { "fd00:2::3" } else { "10.0.2.3" }.parse().unwrap(),
                    false,
                    usize::MAX - 40,
                );
                match expiry {
                    CorrelationExpiry::RetainedReply => {
                        let received_at = Instant::now();
                        unsolicited.push(UnsolicitedCapture {
                            decoded: response,
                            received_at: Some(received_at),
                            response_deadline: received_at + grant.timeout,
                            correlation_expired: true,
                        });
                    }
                    CorrelationExpiry::UndecodedFrame => undecoded.push(response.frame),
                }
            }
            stats.packets_attempted += 1;
            stats.packets_completed += 1;
            stats.bytes += built.bytes.len() as u64;
            sent.push(SentPacket::try_new(built, materialized(v6), tx).unwrap());
        }
        if !unsolicited.is_empty() || !undecoded.is_empty() {
            diagnostics.push(Diagnostic::warning(
                "exchange.correlation_deadline",
                "response correlation stopped at the bounded exchange deadline",
            ));
        }
        Ok(Evidence {
            observation_quality: Some(if self.unknown {
                packetcraftr_netio::capture::ObservationQuality::Unknown
            } else {
                packetcraftr_netio::capture::ObservationQuality::NoReportedLoss
            }),
            permit: grant.permit,
            sent,
            responses,
            unsolicited,
            undecoded,
            diagnostics,
            stats,
        })
    }

    fn cleanup(&mut self, evidence: &Evidence, _: &Stats) -> Result<Stats, BoundaryError> {
        let mut stats = Stats::default();
        for response in &evidence.responses {
            if let Some(reset) = packet::reset(
                &evidence.sent[response.request_index].built().packet,
                &response.response,
            ) {
                stats.bytes += build(reset).bytes.len() as u64;
                stats.packets_attempted += 1;
                stats.packets_completed += 1;
            }
        }
        Ok(stats)
    }
}
fn simulate(request: &Request, lab: &mut Lab) -> Aggregate {
    let policy = crate::policy::Policy::default();
    let resolver = NumericOnly;
    let mut admission = crate::client::admission::Admission::new(&policy, &resolver);
    let mut collector = Collector::default();
    let mut clock = TestClock::new();
    let mut deadline = clock.deadline();
    let report = engine::run(
        request,
        &mut admission,
        &builtin::registry(),
        lab,
        &mut clock,
        &mut deadline,
        8,
        |event, _| {
            crate::Sink::publish(&mut collector, event)
                .map_err(|source| crate::traceroute::Error::Output { source })
        },
    )
    .unwrap();
    collector.finish(report).unwrap()
}

#[test]
fn sweeps_preserve_flow_identity_and_independent_termination_with_branch_and_rejoin() {
    let mut lab = Lab::default();
    let result = simulate(&request(Transport::Udp, false), &mut lab);
    assert_eq!(result.report.summary.probes_sent, 14);
    assert_eq!(result.report.summary.sweeps_completed, 2);
    assert_eq!(result.report.summary.branch_points, 1);
    assert_eq!(result.report.summary.rejoin_points, 1);
    assert_eq!(result.report.completions.len(), 4);
    let mut completions = result
        .report
        .completions
        .iter()
        .map(|item| (item.flow_id, item.sweep, item.last_hop, item.completion))
        .collect::<Vec<_>>();
    completions.sort_by_key(|item| (item.0, item.1));
    assert_eq!(
        completions,
        [
            (1, 1, 3, crate::traceroute::Termination::DestinationReached),
            (1, 2, 3, crate::traceroute::Termination::DestinationReached),
            (2, 1, 4, crate::traceroute::Termination::DestinationReached),
            (2, 2, 4, crate::traceroute::Termination::DestinationReached),
        ]
    );
    assert_eq!(lab.batches[3], vec![(2, 1, 4)]);
    assert_eq!(lab.batches[4], vec![(1, 2, 1), (2, 2, 1)]);
    assert!(
        result
            .report
            .topology
            .edges
            .iter()
            .all(|edge| edge.from.hop_limit + 1 == edge.to.hop_limit)
    );
    assert!(!result.report.summary.incomplete);
}

#[test]
fn all_strategies_and_families_reach_destination_and_account_for_cleanup() {
    for v6 in [false, true] {
        for strategy in [Transport::Udp, Transport::Tcp, Transport::Icmp] {
            let result = simulate(&request(strategy, v6), &mut Lab::default());
            assert_eq!(result.report.summary.probes_sent, 14);
            assert_eq!(
                result.report.summary.cleanup_packets,
                if strategy == Transport::Tcp { 4 } else { 0 }
            );
            assert_eq!(
                result.report.stats.packets_attempted,
                14 + result.report.summary.cleanup_packets
            );
            assert!(
                result
                    .report
                    .completions
                    .iter()
                    .all(|completion| completion.completion
                        == crate::traceroute::Termination::DestinationReached)
            );
            let mut summaries = result
                .report
                .flow_summaries
                .iter()
                .map(|flow| {
                    (
                        flow.flow_id,
                        flow.probes_sent,
                        flow.sweeps_reached,
                        flow.destination_rtt.clone(),
                    )
                })
                .collect::<Vec<_>>();
            summaries.sort_by_key(|item| item.0);
            let rtt = Some(Rtt {
                samples: 2,
                minimum: Duration::from_millis(2),
                median: Duration::from_millis(2),
                maximum: Duration::from_millis(2),
            });
            assert_eq!(summaries, [(1, 6, 2, rtt.clone()), (2, 8, 2, rtt)]);
            assert!(
                result
                    .report
                    .flow_summaries
                    .iter()
                    .all(|flow| flow.sweeps_reached == 2
                        && flow.destination_rtt.as_ref().unwrap().samples == 2)
            );
        }
    }
}

#[test]
fn gaps_ambiguity_and_retention_never_manufacture_edges() {
    for mut lab in [
        Lab {
            missing: true,
            ..Default::default()
        },
        Lab {
            ambiguous: true,
            ..Default::default()
        },
    ] {
        let result = simulate(&request(Transport::Udp, false), &mut lab);
        assert_eq!(
            result
                .report
                .topology
                .edges
                .iter()
                .map(|edge| (
                    edge.from.hop_limit,
                    edge.from.responder,
                    edge.to.hop_limit,
                    edge.to.responder
                ))
                .collect::<Vec<_>>(),
            [(3, destination(false), 4, destination(false))]
        );
        assert!(
            result
                .report
                .topology
                .edges
                .iter()
                .all(|edge| edge.from.hop_limit != 2 && edge.to.hop_limit != 2)
        );
        if lab.ambiguous {
            assert!(result.report.summary.ambiguous_probes > 0);
        }
    }
    let mut request = request(Transport::Udp, false);
    request.trace.limits.evidence.max_bytes = 4096;
    request.trace.collection.capture.max_bytes = 4096;
    request.trace.collection.capture.snap_length = 4096;
    let result = simulate(&request, &mut Lab::default());
    assert!(result.report.summary.incomplete);
    assert!(result.report.summary.omitted_frames > 0);
    assert!(result.report.summary.retained_evidence_bytes <= 4096);
    request.trace.limits.evidence.max_bytes = crate::evidence::Limits::default().max_bytes;
    request.trace.collection = crate::exchange::Collection::default();
    let result = simulate(
        &request,
        &mut Lab {
            unknown: true,
            ..Default::default()
        },
    );
    assert!(result.report.summary.incomplete);
    assert!(result.probes.iter().all(|probe| probe.incomplete));
    assert_eq!(result.report.summary.omitted_frames, 0);
}

#[test]
fn unfinished_correlation_marks_the_batch_incomplete_before_building_topology() {
    for expiry in [
        CorrelationExpiry::RetainedReply,
        CorrelationExpiry::UndecodedFrame,
    ] {
        let result = simulate(
            &request(Transport::Udp, false),
            &mut Lab {
                correlation_expiry: Some(expiry),
                ..Default::default()
            },
        );
        assert!(result.report.summary.incomplete);
        assert_eq!(result.report.summary.omitted_frames, 0);
        assert_eq!(result.report.summary.ambiguous_probes, 0);
        assert_eq!(result.unmatched.len(), 4);
        assert!(
            result
                .probes
                .iter()
                .all(|probe| probe.incomplete == (probe.hop_limit == 2))
        );
        assert!(
            result
                .report
                .topology
                .nodes
                .iter()
                .any(|node| node.key.hop_limit == 2)
        );
        assert!(!result.report.topology.edges.is_empty());
        assert!(
            result
                .report
                .topology
                .edges
                .iter()
                .all(|edge| edge.from.hop_limit != 2 && edge.to.hop_limit != 2)
        );
        assert!(
            result
                .diagnostics
                .iter()
                .any(|diagnostic| { diagnostic.code == "exchange.correlation_deadline" })
        );
    }
}

#[test]
fn invalid_flow_ranges_and_excess_probe_counts_are_rejected() {
    let mut request = request(Transport::Udp, false);
    request.validate().unwrap();
    request.trace.source_port = Some(u16::MAX);
    assert!(request.validate().is_err());
    request.trace.source_port = None;
    request.flows = 65;
    assert!(request.validate().is_err());
    request.flows = 0;
    assert!(request.validate().is_err());
    request.flows = 2;
    request.trace.limits.max_probes = 1;
    assert!(request.validate().is_err());
}

#[test]
fn authoritative_exchange_matching_blocks_a_stale_same_tuple_response() {
    let request = request(Transport::Udp, false);
    let flow = packet::flows(&request, destination(false), 8)[0].clone();
    let old = build(packet::Probe::new(&request, flow.clone(), destination(false), 8, 1, 1).packet);
    let current = build(packet::Probe::new(&request, flow, destination(false), 8, 1, 2).packet);
    let tx = packetcraftr_netio::transmit::Submission::start()
        .complete(current.bytes.len(), current.bytes.clone());
    let sent = vec![std::sync::Arc::new(
        SentPacket::try_new(current, materialized(false), tx).unwrap(),
    )];
    let delayed = quote(&old, destination(false), false, usize::MAX - 40);
    let registry = builtin::registry();
    let dissector = Dissector::new(registry.clone());
    let clock = TestClock::new();
    let window = crate::exchange::Window::open(&clock, Duration::from_secs(10), None).unwrap();
    let collection = crate::exchange::Collection::default();
    for strict in [false, true] {
        let mut captured = crate::exchange::Accumulator::new(1);
        captured.authoritative_matcher = strict;
        let mut matcher = |_: usize, request: &Packet, reply: &DecodedPacket| {
            packet::classify(&registry, Transport::Udp, request, reply).is_some()
        };
        captured
            .process(
                packetcraftr_netio::capture::Captured::new(
                    delayed.frame.clone(),
                    std::time::Instant::now(),
                ),
                crate::exchange::ProcessContext {
                    registry: &registry,
                    dissector: &dissector,
                    request_count: 1,
                    sent: &sent,
                    window: &window,
                    collection: &collection,
                },
                Some(&mut matcher),
            )
            .unwrap();
        captured.finalize_unsolicited();
        let events = captured.drain_events().collect::<Vec<_>>();
        if strict {
            assert!(
                matches!(events.as_slice(), [crate::exchange::Event::Unsolicited { frame }] if frame.frame.bytes() == delayed.frame.bytes())
            );
        } else {
            assert!(
                matches!(events.as_slice(), [crate::exchange::Event::Response(response)] if response.request_index == 0 && response.response.frame.bytes() == delayed.frame.bytes())
            );
        }
    }
}

#[test]
fn cancellation_and_output_failure_stop_before_another_batch() {
    for cancel in [false, true] {
        let mut lab = Lab::default();
        let policy = crate::policy::Policy::default();
        let resolver = NumericOnly;
        let mut admission = crate::client::admission::Admission::new(&policy, &resolver);
        let cancellation = packetcraftr_core::budget::Cancellation::default();
        let mut clock = TestClock::new();
        let mut deadline = clock
            .deadline()
            .with_cancellation(Some(cancellation.clone()));
        let result = engine::run(
            &request(Transport::Udp, false),
            &mut admission,
            &builtin::registry(),
            &mut lab,
            &mut clock,
            &mut deadline,
            8,
            |event, _| {
                if matches!(event, Event::Probe(_)) {
                    if cancel {
                        cancellation.cancel();
                    } else {
                        return Err(crate::traceroute::Error::Output {
                            source: BoundaryError::internal_execution(
                                "test output closed",
                                "io.test_output",
                                "test",
                            ),
                        });
                    }
                }
                Ok(())
            },
        );
        let error = result.unwrap_err();
        if cancel {
            assert!(matches!(error, crate::traceroute::Error::Cancelled(_)));
        } else {
            let crate::traceroute::Error::Output { source } = error else {
                panic!("expected the supplied output failure");
            };
            assert_eq!(
                packetcraftr_core::error::Classified::classification(&source).code,
                "io.test_output"
            );
            assert_eq!(source.to_string(), "test output closed");
        }
        assert_eq!(lab.batches, [vec![(1, 1, 1), (2, 1, 1)]]);
    }
}

#[test]
fn topology_changes_require_two_observed_adjacent_sweeps() {
    let request = request(Transport::Udp, false);
    let mut result = simulate(&request, &mut Lab::default());
    let first = result.probes.remove(0);
    let mut second = first.clone();
    second.sweep = 2;
    second.sequence += 8;
    second.replies[0].responder = "10.0.1.9".parse().unwrap();
    let mut topology = topology::Topology::default();
    topology.observe(&first);
    let update = topology.observe(&second);
    assert_eq!(update.changes.len(), 1);
    assert_eq!(update.changes[0].flow_id, first.flow_id);
    assert_eq!(update.changes[0].hop_limit, first.hop_limit);
    assert_eq!(
        (update.changes[0].previous_sweep, update.changes[0].sweep),
        (1, 2)
    );
    assert_eq!(update.changes[0].before, first.replies[0].responder);
    assert_eq!(
        update.changes[0].after,
        "10.0.1.9".parse::<IpAddr>().unwrap()
    );
    assert_eq!(
        update.changes[0].evidence,
        [first.sequence, second.sequence]
    );
    let mut missing = second.clone();
    missing.sweep = 3;
    missing.replies.clear();
    missing.replies_seen = 0;
    topology.observe(&missing);
    second.sweep = 4;
    assert!(topology.observe(&second).changes.is_empty());
}

#[test]
fn non_echoing_udp_reply_is_not_attributed() {
    for v6 in [false, true] {
        let request = request(Transport::Udp, v6);
        let probe = packet::Probe::new(
            &request,
            packet::flows(&request, destination(v6), 8)[0].clone(),
            destination(v6),
            8,
            1,
            1,
        );
        let sent = build(probe.packet);
        let mut reply = Packet::new();
        if let Some(ip) = sent.packet.get::<Ipv4>() {
            reply.push(Ipv4 {
                source: ip.destination,
                destination: ip.source,
                ..Default::default()
            });
        } else {
            let ip = sent.packet.get::<Ipv6>().unwrap();
            reply.push(Ipv6 {
                source: ip.destination,
                destination: ip.source,
                ..Default::default()
            });
        }
        let udp = sent.packet.get::<Udp>().unwrap();
        reply.push(Udp {
            source_port: udp.destination_port,
            destination_port: udp.source_port,
            ..Default::default()
        });
        reply.push(packetcraftr_core::layer::Raw::new(vec![0; 16]));
        assert!(
            packet::classify(
                &builtin::registry(),
                Transport::Udp,
                &sent.packet,
                &decode(reply)
            )
            .is_none()
        );
    }
}
