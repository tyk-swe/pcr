// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
#![allow(dead_code)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, UNIX_EPOCH};

use super::Error;
use crate::runtime::Runtime;
use crate::test_support::decoded_packet;
use bytes::Bytes;
use packetcraftr_core::protocol::{
    network::{Icmpv4, Icmpv6, Ipv4, Ipv6},
    transport::Udp,
};
use packetcraftr_core::{decode::DecodedPacket, diagnostic::Diagnostic, packet::Packet};

use super::DEFAULT_UDP_PORT;
use super::engine;
use super::error::Probes;
use super::plan::packet::probe_packet;
use super::{Aggregate, Collector, Event, Limits, Probe, Report, Request};
use crate::Sink;
use crate::clock::Clock;
use crate::execution::{Errors as _, Executor, publisher};
use crate::policy::Authorizer;
use crate::policy::Operation;
use crate::probe::Batch;
use crate::probe::{Evidence, ProbeEndpoint, Transport};
use crate::target::Authorized;
use crate::target::ResolveTarget;
use crate::target::Target;
use crate::test_support::{NoopClock, RejectingExecutor};
use crate::{Stats, target::Family};
use packetcraftr_core::budget::Deadline;
use packetcraftr_core::error::BoundaryError;
use packetcraftr_core::registry::Registry;

fn run<A, E, C>(
    request: &Request,
    authorizer: &mut A,
    registry: &Registry,
    executor: &mut E,
    clock: &mut C,
) -> Result<Aggregate, Error>
where
    A: Authorizer + ResolveTarget,
    E: Executor<Batch<Probe>>,
    C: Clock,
{
    let collector = Collector::default();
    let mut sink = collector.clone();
    let report = engine::run(
        request,
        authorizer,
        registry,
        executor,
        clock,
        &mut Deadline::new(request.limits.max_duration),
        |event, _| {
            sink.publish(event)
                .map_err(|source| Error::Output { source })
        },
    )?;
    collector.finish(report)
}

fn run_with_events<A, E, C, S>(
    request: &Request,
    authorizer: &mut A,
    registry: &Registry,
    executor: &mut E,
    clock: &mut C,
    runtime: &Runtime,
    sink: S,
) -> Result<Report, Error>
where
    A: Authorizer + ResolveTarget,
    E: Executor<Batch<Probe>>,
    C: Clock,
    S: Sink<Event, Ack = ()>,
{
    let publish = publisher(
        runtime,
        sink,
        |error| Probes.duration_limit(0, error),
        |source| Error::Output { source },
    )?;
    engine::run(
        request,
        authorizer,
        registry,
        executor,
        clock,
        &mut Deadline::new(request.limits.max_duration),
        publish,
    )
}

fn udp_traceroute_request(target: Target) -> Request {
    Request {
        target,
        strategy: Transport::Udp,
        address_family: Family::Any,
        destination_port: Some(DEFAULT_UDP_PORT),
        source_port: None,
        payload_size: 0,
        dont_fragment: false,
        dscp: 0,
        first_hop: 1,
        max_hops: 2,
        probes_per_hop: 2,
        timeout: Duration::from_millis(10),
        probes_per_second: None,
        limits: Limits::default(),
        route: crate::route::Options::default(),
        collection: crate::exchange::Collection::default(),
    }
}

struct FixedAuthorizer {
    address: IpAddr,
    operations: Vec<(u64, u64)>,
}

impl crate::target::ResolveTarget for FixedAuthorizer {
    fn resolve_and_authorize(&mut self, target: &Target) -> Result<Authorized, BoundaryError> {
        Ok(Authorized {
            declared: target.clone(),
            addresses: vec![self.address],
        })
    }
}

impl Authorizer for FixedAuthorizer {
    fn authorize_operation(&mut self, operation: Operation<'_>) -> Result<(), BoundaryError> {
        assert!(
            matches!(operation, Operation::Wire(_)),
            "target workflows submit limits-only requests, got {operation:?}"
        );
        let limits = operation.limits();
        self.operations
            .push((limits.packets(), limits.wire_bytes()));
        Ok(())
    }
}

#[derive(Default)]
struct NoResponseExecutor {
    invalid_sent_index: Option<usize>,
}

impl Executor<Batch<Probe>> for NoResponseExecutor {
    fn execute(&mut self, batch: &Batch<Probe>) -> Result<Evidence, BoundaryError> {
        let mut sent = Vec::new();
        let mut bytes = 0_u64;
        for probe in &batch.probes {
            let mut packet = probe_packet(probe);
            if let Some(ipv4) = packet.get_mut::<Ipv4>() {
                ipv4.source = Ipv4Addr::new(10, 0, 0, 1);
            }
            let receipt = crate::test_support::sent_packet(packet);
            bytes += u64::try_from(receipt.bytes_sent()).unwrap();
            sent.push(receipt);
        }
        if let Some(index) = self.invalid_sent_index {
            sent[index] = sent[0].clone();
        }
        let count = u64::try_from(batch.probes.len()).expect("test batch fits u64");
        Ok(Evidence {
            permit: batch.permit,
            sent,
            responses: Vec::new(),
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

struct MixedHopExecutor;

impl Executor<Batch<Probe>> for MixedHopExecutor {
    fn execute(&mut self, batch: &Batch<Probe>) -> Result<Evidence, BoundaryError> {
        let local = Ipv4Addr::new(10, 0, 0, 1);
        let remote = Ipv4Addr::new(10, 0, 0, 9);
        let router = Ipv4Addr::new(10, 0, 0, 254);
        let mut sent = Vec::new();
        let mut bytes = 0_u64;
        for probe in &batch.probes {
            let mut packet = probe_packet(probe);
            packet.get_mut::<Ipv4>().expect("IPv4 probe").source = local;
            let receipt = crate::test_support::sent_packet(packet);
            bytes += u64::try_from(receipt.bytes_sent()).unwrap();
            sent.push(receipt);
        }
        let responder = if batch.probes[0].hop_limit == 1 {
            icmpv4_error(
                router,
                local,
                11,
                0,
                ipv4_udp_quote(&sent[0].built().packet),
                batch.probes[0].sequence + 1,
                Vec::new(),
            )
        } else {
            icmpv4_error(
                remote,
                local,
                3,
                3,
                ipv4_udp_quote(&sent[0].built().packet),
                batch.probes[0].sequence + 1,
                Vec::new(),
            )
        };
        let count = u64::try_from(batch.probes.len()).expect("test batch fits u64");
        Ok(Evidence {
            permit: batch.permit,
            sent,
            responses: vec![crate::exchange::Response {
                request_index: 0,
                response: responder,
                latency: Duration::from_millis(1),
            }],
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

fn decoded_at(packet: Packet, seconds: u64, diagnostics: Vec<Diagnostic>) -> DecodedPacket {
    decoded_packet(
        packet,
        UNIX_EPOCH + Duration::from_secs(seconds),
        &[0x45],
        diagnostics,
    )
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
fn traceroute_udp_port_overflow_precedes_duration_limit() {
    let destination = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9));
    let mut request = udp_traceroute_request(Target::Address(destination));
    request.destination_port = Some(u16::MAX);
    request.limits.max_duration = Duration::from_millis(1);
    let mut authorizer = FixedAuthorizer {
        address: destination,
        operations: Vec::new(),
    };
    let calls = Arc::new(AtomicUsize::new(0));
    let error = run(
        &request,
        &mut authorizer,
        &packetcraftr_core::protocol::builtin::registry(),
        &mut RejectingExecutor {
            calls: Arc::clone(&calls),
        },
        &mut NoopClock,
    )
    .unwrap_err();

    assert!(matches!(error, Error::InvalidPort { .. }));
    assert!(authorizer.operations.is_empty());
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn traceroute_rejects_zero_source_port() {
    let destination = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9));
    let mut request = udp_traceroute_request(Target::Address(destination));
    request.source_port = Some(0);
    let mut authorizer = FixedAuthorizer {
        address: destination,
        operations: Vec::new(),
    };
    let calls = Arc::new(AtomicUsize::new(0));
    let error = run(
        &request,
        &mut authorizer,
        &packetcraftr_core::protocol::builtin::registry(),
        &mut RejectingExecutor {
            calls: Arc::clone(&calls),
        },
        &mut NoopClock,
    )
    .unwrap_err();

    assert!(matches!(error, Error::InvalidSourcePort));
    assert!(authorizer.operations.is_empty());
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

fn shaped_probe(address: IpAddr, target: ProbeEndpoint) -> Probe {
    Probe {
        sequence: 3,
        address,
        target,
        hop_limit: 5,
        attempt: 1,
        source_port: super::SOURCE_PORT,
        payload_size: 0,
        dont_fragment: false,
        dscp: 0,
    }
}
