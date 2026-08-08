// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::VecDeque;
use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, UNIX_EPOCH};

use bytes::Bytes;
use packetcraftr_capture::{Frame, LinkType};
use packetcraftr_client::policy::Policy as TrafficPolicy;
use packetcraftr_client::target::{Error as TargetResolutionError, Resolver as HostnameResolver};
use packetcraftr_core::error::{Classification, Classified, Kind};
use packetcraftr_packet::{
    Packet, decode::DecodedPacket, diagnostic::Diagnostic, layout::PacketLayout,
};
use packetcraftr_protocol::{
    builtin::registry as default_registry,
    icmp::{Icmpv4, Icmpv6},
    network::{Ipv4, Ipv6},
    transport::Udp,
};

use super::DEFAULT_TRACEROUTE_UDP_PORT;
use super::classification::classify_traceroute_response;
use super::engine::traceroute;
use super::error::TracerouteError;
use super::model::{
    TracerouteBatch, TracerouteBatchExecution, TracerouteCompletion, TracerouteExecutor,
    TracerouteLimits, TracerouteProbe, TracerouteProbeStatus, TracerouteRequest,
    TracerouteResponseKind, TracerouteStrategy,
};
use super::probe::probe_packet;
use crate::clock::Clock;
use crate::target::{Authorized, Authorizer, PolicyAuthorizer, Target};
use crate::{AddressFamily, BoundaryError, Stats};

fn udp_traceroute_request(target: Target) -> TracerouteRequest {
    TracerouteRequest {
        target,
        strategy: TracerouteStrategy::Udp,
        address_family: AddressFamily::Any,
        destination_port: Some(DEFAULT_TRACEROUTE_UDP_PORT),
        first_hop: 1,
        max_hops: 2,
        probes_per_hop: 2,
        timeout: Duration::from_millis(10),
        probes_per_second: None,
        limits: TracerouteLimits::default(),
    }
}

#[derive(Default)]
struct NoopClock;

impl Clock for NoopClock {
    type Error = Infallible;

    fn sleep(&mut self, _delay: Duration) -> Result<(), Self::Error> {
        Ok(())
    }
}

struct FixedAuthorizer {
    address: IpAddr,
    operations: Vec<(u64, u64)>,
}

impl Authorizer for FixedAuthorizer {
    fn resolve_and_authorize(&mut self, target: &Target) -> Result<Authorized, BoundaryError> {
        Ok(Authorized {
            declared: target.to_string(),
            addresses: vec![self.address],
        })
    }

    fn authorize_operation(
        &mut self,
        packets: u64,
        maximum_wire_bytes: u64,
    ) -> Result<(), BoundaryError> {
        self.operations.push((packets, maximum_wire_bytes));
        Ok(())
    }
}

struct AddressListAuthorizer {
    addresses: Vec<IpAddr>,
}

impl Authorizer for AddressListAuthorizer {
    fn resolve_and_authorize(&mut self, target: &Target) -> Result<Authorized, BoundaryError> {
        Ok(Authorized {
            declared: target.to_string(),
            addresses: self.addresses.clone(),
        })
    }

    fn authorize_operation(
        &mut self,
        _packets: u64,
        _maximum_wire_bytes: u64,
    ) -> Result<(), BoundaryError> {
        Ok(())
    }
}

struct ScriptedResolver {
    calls: Arc<AtomicUsize>,
    answers: Mutex<VecDeque<Vec<IpAddr>>>,
}

impl ScriptedResolver {
    fn new(answers: impl IntoIterator<Item = Vec<IpAddr>>) -> Self {
        Self {
            calls: Arc::new(AtomicUsize::new(0)),
            answers: Mutex::new(answers.into_iter().collect()),
        }
    }
}

impl HostnameResolver for ScriptedResolver {
    fn resolve(
        &self,
        _hostname: &packetcraftr_client::target::Hostname,
        _limit: usize,
    ) -> Result<Vec<IpAddr>, TargetResolutionError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(self
            .answers
            .lock()
            .expect("resolver lock")
            .pop_front()
            .expect("scripted resolver answer"))
    }
}

struct CountingRejectExecutor(Arc<AtomicUsize>);

impl TracerouteExecutor for CountingRejectExecutor {
    fn execute(
        &mut self,
        _batch: &TracerouteBatch,
    ) -> Result<TracerouteBatchExecution, BoundaryError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(BoundaryError::new(
            "stop after authorization",
            Classification::new("io.test", Kind::Io, None),
            Vec::new(),
        ))
    }
}

struct NoResponseExecutor;

impl TracerouteExecutor for NoResponseExecutor {
    fn execute(
        &mut self,
        batch: &TracerouteBatch,
    ) -> Result<TracerouteBatchExecution, BoundaryError> {
        let mut sent = Vec::new();
        let mut sent_evidence = Vec::new();
        for probe in &batch.probes {
            let mut packet = probe_packet(probe);
            if let Some(ipv4) = packet.get_mut::<Ipv4>() {
                ipv4.source = Ipv4Addr::new(10, 0, 0, 1);
            }
            sent.push(packet);
            sent_evidence.push(frame_at(probe.sequence + 1));
        }
        let count = u64::try_from(batch.probes.len()).expect("test batch fits u64");
        Ok(TracerouteBatchExecution {
            sent,
            sent_evidence,
            responses: Vec::new(),
            unsolicited: Vec::new(),
            undecoded: Vec::new(),
            diagnostics: Vec::new(),
            stats: Stats {
                packets_attempted: count,
                packets_completed: count,
                bytes: count,
                elapsed: Duration::from_millis(1),
                capture: packetcraftr_net::capture::Statistics::default(),
            },
        })
    }
}

struct MixedHopExecutor;

impl TracerouteExecutor for MixedHopExecutor {
    fn execute(
        &mut self,
        batch: &TracerouteBatch,
    ) -> Result<TracerouteBatchExecution, BoundaryError> {
        let local = Ipv4Addr::new(10, 0, 0, 1);
        let remote = Ipv4Addr::new(10, 0, 0, 9);
        let router = Ipv4Addr::new(10, 0, 0, 254);
        let mut sent = Vec::new();
        let mut sent_evidence = Vec::new();
        for probe in &batch.probes {
            let mut packet = probe_packet(probe);
            packet.get_mut::<Ipv4>().expect("IPv4 probe").source = local;
            sent.push(packet);
            sent_evidence.push(frame_at(probe.sequence + 1));
        }
        let responder = if batch.probes[0].hop_limit == 1 {
            icmpv4_error(
                router,
                local,
                11,
                0,
                ipv4_udp_quote(&sent[0]),
                batch.probes[0].sequence + 1,
                Vec::new(),
            )
        } else {
            icmpv4_error(
                remote,
                local,
                3,
                3,
                ipv4_udp_quote(&sent[0]),
                batch.probes[0].sequence + 1,
                Vec::new(),
            )
        };
        let count = u64::try_from(batch.probes.len()).expect("test batch fits u64");
        Ok(TracerouteBatchExecution {
            sent,
            sent_evidence,
            responses: Vec::new(),
            unsolicited: vec![responder],
            undecoded: Vec::new(),
            diagnostics: Vec::new(),
            stats: Stats {
                packets_attempted: count,
                packets_completed: count,
                bytes: count,
                elapsed: Duration::from_millis(1),
                capture: packetcraftr_net::capture::Statistics::default(),
            },
        })
    }
}

fn private_traceroute_policy() -> TrafficPolicy {
    TrafficPolicy {
        max_packets_per_operation: 1_000,
        max_bytes_per_operation: 1_000_000,
        ..TrafficPolicy::default()
    }
}

fn frame_at(seconds: u64) -> Frame {
    Frame::new(
        UNIX_EPOCH + Duration::from_secs(seconds),
        LinkType::RAW,
        Bytes::from_static(&[0x45]),
    )
    .expect("traceroute evidence frame")
}

fn decoded_at(packet: Packet, seconds: u64, diagnostics: Vec<Diagnostic>) -> DecodedPacket {
    let frame = frame_at(seconds);
    DecodedPacket {
        packet,
        original: frame.bytes().clone(),
        frame,
        layout: PacketLayout::default(),
        diagnostics,
    }
}

fn ipv4_udp_quote(packet: &Packet) -> Vec<u8> {
    let ip = packet.get::<Ipv4>().expect("IPv4 packet");
    let udp = packet.get::<Udp>().expect("UDP packet");
    let mut quote = vec![0_u8; 28];
    quote[0] = 0x45;
    quote[2..4].copy_from_slice(&28_u16.to_be_bytes());
    quote[8] = ip.ttl;
    quote[9] = 17;
    quote[12..16].copy_from_slice(&ip.source.octets());
    quote[16..20].copy_from_slice(&ip.destination.octets());
    quote[20..22].copy_from_slice(&udp.source_port.to_be_bytes());
    quote[22..24].copy_from_slice(&udp.destination_port.to_be_bytes());
    quote[24..26].copy_from_slice(&8_u16.to_be_bytes());
    quote
}

fn icmpv4_error(
    source: Ipv4Addr,
    destination: Ipv4Addr,
    icmp_type: u8,
    code: u8,
    quote: Vec<u8>,
    seconds: u64,
    diagnostics: Vec<Diagnostic>,
) -> DecodedPacket {
    let mut body = vec![0_u8; 4];
    body.extend(quote);
    let mut packet = Packet::new();
    packet
        .push(Ipv4 {
            source,
            destination,
            ..Ipv4::default()
        })
        .push(Icmpv4 {
            icmp_type,
            code,
            body: Bytes::from(body),
            ..Icmpv4::default()
        });
    decoded_at(packet, seconds, diagnostics)
}

fn ipv6_udp_quote(packet: &Packet) -> Vec<u8> {
    let ip = packet.get::<Ipv6>().expect("IPv6 packet");
    let udp = packet.get::<Udp>().expect("UDP packet");
    let mut quote = vec![0_u8; 48];
    quote[0] = 0x60;
    quote[4..6].copy_from_slice(&8_u16.to_be_bytes());
    quote[6] = 17;
    quote[7] = ip.hop_limit;
    quote[8..24].copy_from_slice(&ip.source.octets());
    quote[24..40].copy_from_slice(&ip.destination.octets());
    quote[40..42].copy_from_slice(&udp.source_port.to_be_bytes());
    quote[42..44].copy_from_slice(&udp.destination_port.to_be_bytes());
    quote[44..46].copy_from_slice(&8_u16.to_be_bytes());
    quote
}

fn icmpv6_error(
    source: Ipv6Addr,
    destination: Ipv6Addr,
    icmp_type: u8,
    code: u8,
    quote: Vec<u8>,
) -> DecodedPacket {
    let mut body = vec![0_u8; 4];
    body.extend(quote);
    let mut packet = Packet::new();
    packet
        .push(Ipv6 {
            source,
            destination,
            ..Ipv6::default()
        })
        .push(Icmpv6 {
            icmp_type,
            code,
            body: Bytes::from(body),
            ..Icmpv6::default()
        });
    decoded_at(packet, 2, Vec::new())
}

#[test]
fn traceroute_address_ordering_deduplicates_after_family_filtering() {
    let first = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9));
    let second = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 10));
    let mut request = udp_traceroute_request(Target::Hostname("ordered.example".to_owned()));
    request.address_family = AddressFamily::Ipv4;
    request.max_hops = 1;
    request.probes_per_hop = 1;
    let result = traceroute(
        &request,
        &mut AddressListAuthorizer {
            addresses: vec![Ipv6Addr::LOCALHOST.into(), first, first, second, first],
        },
        &default_registry().unwrap(),
        &mut NoResponseExecutor,
        &mut NoopClock,
    )
    .unwrap();

    assert_eq!(result.resolved_addresses, vec![first, second]);
    assert_eq!(result.destination, first);
}

#[test]
fn traceroute_hostname_policy_precedes_resolution_and_probe_execution() {
    let private = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9));
    let resolver = ScriptedResolver::new([vec![private]]);
    let calls = Arc::new(AtomicUsize::new(0));
    let mut executor = CountingRejectExecutor(Arc::clone(&calls));
    let policy = private_traceroute_policy();
    let mut authorizer = PolicyAuthorizer::new(&policy, &resolver);
    let error = traceroute(
        &udp_traceroute_request(Target::Hostname("lab.example".to_owned())),
        &mut authorizer,
        &default_registry().unwrap(),
        &mut executor,
        &mut NoopClock,
    )
    .unwrap_err();
    assert_eq!(error.classification().code, "policy.hostname_resolution");
    assert_eq!(resolver.calls.load(Ordering::SeqCst), 0);
    assert_eq!(calls.load(Ordering::SeqCst), 0);

    let resolver = ScriptedResolver::new([vec![private, "8.8.8.8".parse().unwrap()]]);
    let mut policy = private_traceroute_policy();
    policy.allow_hostname_resolution = true;
    let mut request = udp_traceroute_request(Target::Hostname("mixed.example".to_owned()));
    request.address_family = AddressFamily::Ipv6;
    let mut authorizer = PolicyAuthorizer::new(&policy, &resolver);
    let error = traceroute(
        &request,
        &mut authorizer,
        &default_registry().unwrap(),
        &mut executor,
        &mut NoopClock,
    )
    .unwrap_err();
    assert_eq!(error.classification().code, "policy.public_destination");
    assert_eq!(resolver.calls.load(Ordering::SeqCst), 1);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn traceroute_udp_port_overflow_is_rejected_before_authorization_or_execution() {
    let destination = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9));
    let mut request = udp_traceroute_request(Target::Address(destination));
    request.destination_port = Some(u16::MAX);
    let mut authorizer = FixedAuthorizer {
        address: destination,
        operations: Vec::new(),
    };
    let calls = Arc::new(AtomicUsize::new(0));
    let error = traceroute(
        &request,
        &mut authorizer,
        &default_registry().unwrap(),
        &mut CountingRejectExecutor(Arc::clone(&calls)),
        &mut NoopClock,
    )
    .unwrap_err();

    assert!(matches!(error, TracerouteError::InvalidPort { .. }));
    assert!(authorizer.operations.is_empty());
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn traceroute_ipv4_classification_distinguishes_intermediate_terminal_and_unreachable() {
    let registry = default_registry().unwrap();
    let local = Ipv4Addr::new(10, 0, 0, 1);
    let remote = Ipv4Addr::new(10, 0, 0, 9);
    let router = Ipv4Addr::new(10, 0, 0, 254);
    let mut probe = TracerouteProbe {
        sequence: 0,
        address: IpAddr::V4(remote),
        strategy: TracerouteStrategy::Udp,
        destination_port: Some(DEFAULT_TRACEROUTE_UDP_PORT),
        hop_limit: 1,
        attempt: 1,
    }
    .packet();
    probe.get_mut::<Ipv4>().unwrap().source = local;
    let quote = ipv4_udp_quote(&probe);

    assert_eq!(
        classify_traceroute_response(
            &registry,
            TracerouteStrategy::Udp,
            &probe,
            &icmpv4_error(router, local, 11, 0, quote.clone(), 2, Vec::new()),
        )
        .unwrap()
        .kind,
        TracerouteResponseKind::Intermediate
    );
    assert_eq!(
        classify_traceroute_response(
            &registry,
            TracerouteStrategy::Udp,
            &probe,
            &icmpv4_error(remote, local, 3, 3, quote.clone(), 2, Vec::new()),
        )
        .unwrap()
        .kind,
        TracerouteResponseKind::DestinationReached
    );
    assert_eq!(
        classify_traceroute_response(
            &registry,
            TracerouteStrategy::Udp,
            &probe,
            &icmpv4_error(router, local, 3, 1, quote, 2, Vec::new()),
        )
        .unwrap()
        .kind,
        TracerouteResponseKind::Unreachable
    );
}

#[test]
fn traceroute_ipv6_classification_correlates_intermediate_quote() {
    let registry = default_registry().unwrap();
    let local: Ipv6Addr = "fd00::1".parse().unwrap();
    let remote: Ipv6Addr = "fd00::9".parse().unwrap();
    let router: Ipv6Addr = "fd00::fe".parse().unwrap();
    let mut probe = TracerouteProbe {
        sequence: 9,
        address: IpAddr::V6(remote),
        strategy: TracerouteStrategy::Udp,
        destination_port: Some(DEFAULT_TRACEROUTE_UDP_PORT + 9),
        hop_limit: 4,
        attempt: 1,
    }
    .packet();
    probe.get_mut::<Ipv6>().unwrap().source = local;
    let response = icmpv6_error(router, local, 3, 0, ipv6_udp_quote(&probe));

    assert_eq!(
        classify_traceroute_response(&registry, TracerouteStrategy::Udp, &probe, &response,)
            .unwrap()
            .kind,
        TracerouteResponseKind::Intermediate
    );
}

#[test]
fn traceroute_stops_after_the_first_terminal_hop() {
    let destination = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9));
    let mut request = udp_traceroute_request(Target::Address(destination));
    request.probes_per_second = Some(2);
    request.max_hops = 8;
    let mut authorizer = FixedAuthorizer {
        address: destination,
        operations: Vec::new(),
    };
    let result = traceroute(
        &request,
        &mut authorizer,
        &default_registry().unwrap(),
        &mut MixedHopExecutor,
        &mut NoopClock,
    )
    .unwrap();

    assert_eq!(result.completion, TracerouteCompletion::DestinationReached);
    assert_eq!(result.hops.len(), 2);
    assert_eq!(result.hops[0].probes.len(), 2);
    assert_eq!(result.hops[1].probes.len(), 2);
    assert_eq!(
        result.hops[0].probes[0].response_kind,
        Some(TracerouteResponseKind::Intermediate)
    );
    assert_eq!(
        result.hops[0].probes[1].status,
        TracerouteProbeStatus::Timeout
    );
    assert_eq!(
        result.hops[1].probes[0].response_kind,
        Some(TracerouteResponseKind::DestinationReached)
    );
    assert_eq!(
        result.hops[1].probes[1].status,
        TracerouteProbeStatus::Timeout
    );
    assert_eq!(result.stats.packets_completed, 4);
    assert_eq!(authorizer.operations, vec![(16, 16 * 74)]);
}
