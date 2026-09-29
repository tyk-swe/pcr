// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, UNIX_EPOCH};

use super::Error;
use crate::probe::test_support::{ProgressiveExecutor, private_policy};
use crate::runtime::Runtime;
use crate::test_support::decoded_packet;
use bytes::Bytes;
use packetcraftr_core::error::{Classification, Classified, Kind};
use packetcraftr_core::protocol::{
    network::{Icmpv4, Icmpv6, Ipv4, Ipv6},
    transport::Udp,
};
use packetcraftr_core::{decode::DecodedPacket, diagnostic::Diagnostic, packet::Packet};

use super::DEFAULT_UDP_PORT;
use super::engine;
use super::error::Probes;
use super::evidence::classify_response;
use super::plan::packet::probe_packet;
use super::{
    Aggregate, Collector, Event, Limits, Probe, Report, Request, ResponseKind, Termination,
};
use crate::Sink;
use crate::clock::Clock;
use crate::execution::Admission;
use crate::execution::{Errors as _, Executor, publisher};
use crate::policy::Authorizer;
use crate::policy::Operation;
use crate::probe::Batch;
use crate::probe::{Evidence, ProbeEndpoint, ProbeStatus, Transport};
use crate::target::Authorized;
use crate::target::ResolveTarget;
use crate::target::Target;
use crate::test_support::{AddressListAuthorizer, NoopClock, RejectingExecutor, ScriptedResolver};
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
        udp_port_mode: Default::default(),
        cycles: 1,
        cycle_interval: Duration::from_millis(1000),
        target,
        strategy: Transport::Udp,
        address_family: Family::Any,
        destination_port: Some(DEFAULT_UDP_PORT),
        source_port: None,
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
fn traceroute_address_ordering_deduplicates_after_family_filtering() {
    let first = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9));
    let second = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 10));
    let mut request = udp_traceroute_request(Target::Hostname("ordered.example".parse().unwrap()));
    request.address_family = Family::Ipv4;
    request.max_hops = 1;
    request.probes_per_hop = 1;
    let result = run(
        &request,
        &mut AddressListAuthorizer {
            addresses: vec![Ipv6Addr::LOCALHOST.into(), first, first, second, first],
        },
        &packetcraftr_core::protocol::builtin::registry(),
        &mut NoResponseExecutor::default(),
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
    let mut executor = RejectingExecutor {
        calls: Arc::clone(&calls),
    };
    let policy = private_policy();
    let mut authorizer = Admission::new(&policy, &resolver);
    let error = run(
        &udp_traceroute_request(Target::Hostname("lab.example".parse().unwrap())),
        &mut authorizer,
        &packetcraftr_core::protocol::builtin::registry(),
        &mut executor,
        &mut NoopClock,
    )
    .unwrap_err();
    assert_eq!(error.classification().code, "policy.hostname_resolution");
    assert_eq!(resolver.calls.load(Ordering::SeqCst), 0);
    assert_eq!(calls.load(Ordering::SeqCst), 0);

    let resolver = ScriptedResolver::new([vec![private, "8.8.8.8".parse().unwrap()]]);
    let mut policy = private_policy();
    policy.allow_hostname_resolution = true;
    let mut request = udp_traceroute_request(Target::Hostname("mixed.example".parse().unwrap()));
    request.address_family = Family::Ipv6;
    let mut authorizer = Admission::new(&policy, &resolver);
    let error = run(
        &request,
        &mut authorizer,
        &packetcraftr_core::protocol::builtin::registry(),
        &mut executor,
        &mut NoopClock,
    )
    .unwrap_err();
    assert_eq!(error.classification().code, "policy.public_destination");
    assert_eq!(resolver.calls.load(Ordering::SeqCst), 1);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn traceroute_request_bounds_the_timeout_and_the_probe_rate() {
    let request = udp_traceroute_request(Target::Address(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9))));

    let error = Request {
        timeout: Duration::ZERO,
        ..request.clone()
    }
    .validate()
    .unwrap_err();
    assert!(
        matches!(error, Error::InvalidTimeout { maximum, .. } if maximum == packetcraftr_netio::deadline::MAX_WAIT),
        "{error:?}"
    );

    let error = Request {
        probes_per_second: Some(0),
        ..request
    }
    .validate()
    .unwrap_err();
    assert!(
        matches!(
            error,
            Error::InvalidLimit {
                field: "probes_per_second",
                ..
            }
        ),
        "{error:?}"
    );
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
fn traceroute_zero_source_port_is_rejected_before_authorization_or_execution() {
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

#[test]
fn traceroute_icmp_source_port_is_rejected_before_authorization_or_execution() {
    let destination = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9));
    let mut request = udp_traceroute_request(Target::Address(destination));
    request.strategy = Transport::Icmp;
    request.destination_port = None;
    request.source_port = Some(53_333);
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

#[test]
fn traceroute_configured_source_port_threads_into_planned_probes() {
    let destination = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9));
    let mut request = udp_traceroute_request(Target::Address(destination));
    request.source_port = Some(53_333);
    let batches =
        super::plan::build_batches(&request, destination).expect("custom source port is valid");
    assert!(!batches.is_empty());
    for probe in batches.iter().flat_map(|batch| batch.probes.iter()) {
        assert_eq!(probe.source_port, 53_333);
        let packet = probe.packet();
        assert_eq!(packet.get::<Udp>().expect("UDP probe").source_port, 53_333);
        assert!(super::plan::packet::sent_probe_matches(probe, &packet));
    }

    request.source_port = None;
    let batches =
        super::plan::build_batches(&request, destination).expect("default source port is valid");
    assert!(!batches.is_empty());
    for probe in batches.iter().flat_map(|batch| batch.probes.iter()) {
        assert_eq!(probe.source_port, super::SOURCE_PORT);
    }
}

#[test]
fn traceroute_ipv4_classification_distinguishes_intermediate_terminal_and_unreachable() {
    let registry = packetcraftr_core::protocol::builtin::registry();
    let local = Ipv4Addr::new(10, 0, 0, 1);
    let remote = Ipv4Addr::new(10, 0, 0, 9);
    let router = Ipv4Addr::new(10, 0, 0, 254);
    let mut probe = Probe {
        udp_port_mode: Default::default(),
        cycle: 1,
        sequence: 0,
        address: IpAddr::V4(remote),
        target: ProbeEndpoint::Udp {
            port: DEFAULT_UDP_PORT,
        },
        hop_limit: 1,
        attempt: 1,
        source_port: super::SOURCE_PORT,
    }
    .packet();
    probe.get_mut::<Ipv4>().unwrap().source = local;
    let quote = ipv4_udp_quote(&probe);

    assert_eq!(
        classify_response(
            &registry,
            Transport::Udp,
            &probe,
            &icmpv4_error(router, local, 11, 0, quote.clone(), 2, Vec::new()),
        )
        .unwrap()
        .kind,
        ResponseKind::Intermediate
    );
    assert_eq!(
        classify_response(
            &registry,
            Transport::Udp,
            &probe,
            &icmpv4_error(remote, local, 3, 3, quote.clone(), 2, Vec::new()),
        )
        .unwrap()
        .kind,
        ResponseKind::DestinationReached
    );
    assert_eq!(
        classify_response(
            &registry,
            Transport::Udp,
            &probe,
            &icmpv4_error(router, local, 3, 1, quote, 2, Vec::new()),
        )
        .unwrap()
        .kind,
        ResponseKind::Unreachable
    );
}

#[test]
fn traceroute_ipv6_classification_correlates_intermediate_quote() {
    let registry = packetcraftr_core::protocol::builtin::registry();
    let local: Ipv6Addr = "fd00::1".parse().unwrap();
    let remote: Ipv6Addr = "fd00::9".parse().unwrap();
    let router: Ipv6Addr = "fd00::fe".parse().unwrap();
    let mut probe = Probe {
        udp_port_mode: Default::default(),
        cycle: 1,
        sequence: 9,
        address: IpAddr::V6(remote),
        target: ProbeEndpoint::Udp {
            port: DEFAULT_UDP_PORT + 9,
        },
        hop_limit: 4,
        attempt: 1,
        source_port: super::SOURCE_PORT,
    }
    .packet();
    probe.get_mut::<Ipv6>().unwrap().source = local;
    let response = icmpv6_error(router, local, 3, 0, ipv6_udp_quote(&probe));

    assert_eq!(
        classify_response(&registry, Transport::Udp, &probe, &response,)
            .unwrap()
            .kind,
        ResponseKind::Intermediate
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
    let result = run(
        &request,
        &mut authorizer,
        &packetcraftr_core::protocol::builtin::registry(),
        &mut MixedHopExecutor,
        &mut NoopClock,
    )
    .unwrap();

    assert_eq!(result.termination, Termination::DestinationReached);
    assert_eq!(result.hops.len(), 2);
    assert_eq!(result.hops[0].probes.len(), 2);
    assert_eq!(result.hops[1].probes.len(), 2);
    assert_eq!(
        result.hops[0].probes[0].response_kind,
        Some(ResponseKind::Intermediate)
    );
    assert_eq!(result.hops[0].probes[1].status, ProbeStatus::Timeout);
    assert_eq!(
        result.hops[1].probes[0].response_kind,
        Some(ResponseKind::DestinationReached)
    );
    assert_eq!(result.hops[1].probes[1].status, ProbeStatus::Timeout);
    assert_eq!(result.stats.packets_completed, 4);
    assert_eq!(authorizer.operations, vec![(16, 16 * 74)]);
}

#[test]
fn traceroute_invalid_sent_evidence_reports_the_exact_probe_sequence() {
    let address = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9));
    let request = udp_traceroute_request(Target::Address(address));
    let error = run(
        &request,
        &mut AddressListAuthorizer {
            addresses: vec![address],
        },
        &packetcraftr_core::protocol::builtin::registry(),
        &mut NoResponseExecutor {
            invalid_sent_index: Some(1),
        },
        &mut NoopClock,
    )
    .unwrap_err();

    assert!(matches!(
        error,
        Error::InvalidEvidence { sequence: 1, message }
            if message
                == "sent packet does not preserve the traceroute destination and probe identity"
    ));
}

#[test]
fn traceroute_events_precede_later_hops_and_survive_a_later_failure() {
    let address = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9));
    let mut request = udp_traceroute_request(Target::Address(address));
    request.probes_per_hop = 1;
    request.max_hops = 3;
    let calls = Arc::new(AtomicUsize::new(0));
    let shutdowns = Arc::new(AtomicUsize::new(0));
    let mut executor = ProgressiveExecutor {
        inner: NoResponseExecutor::default(),
        calls: Arc::clone(&calls),
        shutdowns: Arc::clone(&shutdowns),
        fail_at: Some(2),
        failure_message: "induced traceroute execution failure",
        failure_code: "io.test_traceroute",
    };
    let events = Arc::new(std::sync::Mutex::new(Vec::new()));
    let observed_events = Arc::clone(&events);
    let callback_calls = Arc::clone(&calls);

    let error = run_with_events(
        &request,
        &mut AddressListAuthorizer {
            addresses: vec![address],
        },
        &packetcraftr_core::protocol::builtin::registry(),
        &mut executor,
        &mut NoopClock,
        &Runtime::default(),
        move |event| {
            assert_eq!(callback_calls.load(Ordering::SeqCst), 1);
            observed_events.lock().unwrap().push(event);
            Ok(())
        },
    )
    .expect_err("the second hop must fail");

    assert!(matches!(error, Error::Execution { sequence: 1, .. }));
    let events = events.lock().unwrap();
    assert_eq!(events.len(), 1);
    assert!(matches!(
        &events[0],
        Event::Probe { probe, .. } if probe.sequence == 0 && probe.hop_limit == 1
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(shutdowns.load(Ordering::SeqCst), 1);
}

#[test]
fn traceroute_sink_failure_stops_later_hops_after_session_shutdown() {
    let address = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9));
    let mut request = udp_traceroute_request(Target::Address(address));
    request.probes_per_hop = 1;
    request.max_hops = 3;
    let calls = Arc::new(AtomicUsize::new(0));
    let shutdowns = Arc::new(AtomicUsize::new(0));
    let mut executor = ProgressiveExecutor {
        inner: NoResponseExecutor::default(),
        calls: Arc::clone(&calls),
        shutdowns: Arc::clone(&shutdowns),
        fail_at: None,
        failure_message: "induced traceroute execution failure",
        failure_code: "io.test_traceroute",
    };

    let error = run_with_events(
        &request,
        &mut AddressListAuthorizer {
            addresses: vec![address],
        },
        &packetcraftr_core::protocol::builtin::registry(),
        &mut executor,
        &mut NoopClock,
        &Runtime::default(),
        |_| {
            Err(BoundaryError::new(
                "induced output failure",
                Classification::new("io.test_output", Kind::Io, None),
                Vec::new(),
            ))
        },
    )
    .expect_err("the progressive sink must fail");

    assert!(matches!(&error, Error::Output { .. }));
    assert_eq!(error.classification().code, "io.test_output");
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(shutdowns.load(Ordering::SeqCst), 1);
}

#[test]
fn a_family_miss_is_reported_as_a_traceroute_error() {
    use packetcraftr_core::error::Classified as _;

    let error = crate::target::FamilyGate::new(Family::Ipv4, Error::family)
        .require(&[])
        .expect_err("an empty resolution fails the family gate");
    assert!(matches!(error, Error::Family { family: "IPv4" }));
    assert_eq!(
        error.to_string(),
        "resolved target has no IPv4 address selected for this traceroute"
    );
    assert_eq!(error.classification().code, "packet.target_address_family");
}

#[test]
fn a_collector_refuses_a_report_counting_probes_it_never_saw() {
    let destination = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2));
    let report = Report {
        target: "192.0.2.2".to_owned(),
        resolved_addresses: vec![destination],
        destination,
        strategy: Transport::Udp,
        destination_port: Some(DEFAULT_UDP_PORT),
        termination: Termination::Timeout,
        stats: Stats {
            packets_attempted: 1,
            packets_completed: 1,
            ..Stats::default()
        },
    };

    let error = Collector::default()
        .finish(report)
        .expect_err("one attempted probe but no collected outcome");

    assert!(matches!(error, Error::IncoherentEvents { .. }), "{error}");
    assert_eq!(
        error.classification().code,
        "internal.traceroute_event_coherence"
    );
}

#[test]
fn fixed_udp_keeps_tuple_and_flow_label_with_distinct_quoted_tokens() {
    use packetcraftr_core::{
        build::{Builder, Options},
        codec::Context,
        field::WireValue,
        protocol::builtin,
    };
    let mut request = udp_traceroute_request(Target::Address("2001:db8::2".parse().unwrap()));
    request.udp_port_mode = super::UdpPortMode::Fixed;
    let batches = super::plan::build_batches(&request, "2001:db8::2".parse().unwrap()).unwrap();
    let mut checksums = std::collections::HashSet::new();
    for probe in batches.iter().flat_map(|batch| &batch.probes) {
        let mut packet = probe.packet();
        packet.get_mut::<Ipv6>().unwrap().source = "2001:db8::1".parse().unwrap();
        let built = Builder::new(builtin::registry())
            .build(packet, Context::default(), Options::default())
            .unwrap();
        let udp = built.packet.get::<Udp>().unwrap();
        assert_eq!(udp.source_port, super::SOURCE_PORT);
        assert_eq!(udp.destination_port, DEFAULT_UDP_PORT);
        assert_eq!(built.packet.get::<Ipv6>().unwrap().flow_label, 0);
        let WireValue::Exact(checksum) = udp.checksum else {
            panic!("built checksum")
        };
        assert!(checksums.insert(checksum));
        assert!(super::plan::packet::sent_probe_matches(
            probe,
            &built.packet
        ));
    }
}

#[test]
fn repeated_cycles_share_plan_budget_and_keep_cycle_numbers() {
    let mut request = udp_traceroute_request(Target::Address("192.0.2.2".parse().unwrap()));
    request.cycles = 3;
    request.udp_port_mode = super::UdpPortMode::Fixed;
    assert_eq!(request.total_probe_count().unwrap(), 12);
    let batches = super::plan::build_batches(&request, "192.0.2.2".parse().unwrap()).unwrap();
    assert_eq!(
        batches
            .iter()
            .flat_map(|batch| &batch.probes)
            .map(|probe| probe.cycle)
            .collect::<Vec<_>>(),
        [1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3]
    );
    let mut authorizer = AddressListAuthorizer {
        addresses: vec!["192.0.2.2".parse().unwrap()],
    };
    let mut executor = RejectingExecutor {
        calls: Arc::new(AtomicUsize::new(0)),
    };
    request.limits.max_probes = 11;
    assert!(
        run(
            &request,
            &mut authorizer,
            &packetcraftr_core::protocol::builtin::registry(),
            &mut executor,
            &mut NoopClock
        )
        .is_err()
    );
    assert_eq!(executor.calls.load(Ordering::SeqCst), 0);
    request.limits.max_probes = 12;
    let mut authorized = FixedAuthorizer {
        address: "192.0.2.2".parse().unwrap(),
        operations: Vec::new(),
    };
    let aggregate = run(
        &request,
        &mut authorized,
        &packetcraftr_core::protocol::builtin::registry(),
        &mut NoResponseExecutor::default(),
        &mut NoopClock,
    )
    .unwrap();
    assert_eq!(authorized.operations.len(), 1);
    assert_eq!(aggregate.stats.packets_attempted, 12);
    assert_eq!(
        aggregate.stats.elapsed,
        Duration::from_secs(2) + Duration::from_millis(6)
    );
    for hop in aggregate.hops {
        assert_eq!(hop.probes.len(), 6);
        assert_eq!(hop.rtt.sent, 6);
        assert_eq!(hop.rtt.lost, 6);
        assert_eq!(hop.rtt.received, 0);
        assert!(hop.responders.is_empty());
    }
}

#[test]
fn advertised_mtu_is_retained_only_for_correlated_quotes() {
    let registry = packetcraftr_core::protocol::builtin::registry();
    let mut request = Packet::new();
    request
        .push(Ipv4 {
            source: "192.0.2.1".parse().unwrap(),
            destination: "192.0.2.2".parse().unwrap(),
            ..Default::default()
        })
        .push(Udp {
            source_port: 49152,
            destination_port: 33434,
            ..Default::default()
        });
    let mut response = icmpv4_error(
        "192.0.2.254".parse().unwrap(),
        "192.0.2.1".parse().unwrap(),
        3,
        4,
        ipv4_udp_quote(&request),
        1,
        Vec::new(),
    );
    let icmp = response.packet.get_mut::<Icmpv4>().unwrap();
    let mut body = icmp.body.to_vec();
    body[2..4].copy_from_slice(&1400u16.to_be_bytes());
    icmp.body = Bytes::from(body);
    assert_eq!(
        classify_response(&registry, Transport::Udp, &request, &response)
            .unwrap()
            .advertised_mtu,
        Some(1400)
    );
    let icmp = response.packet.get_mut::<Icmpv4>().unwrap();
    let mut body = icmp.body.to_vec();
    body[2..4].fill(0);
    icmp.body = Bytes::from(body);
    assert_eq!(
        classify_response(&registry, Transport::Udp, &request, &response)
            .unwrap()
            .advertised_mtu,
        Some(0)
    );
    request.get_mut::<Udp>().unwrap().destination_port += 1;
    assert!(classify_response(&registry, Transport::Udp, &request, &response).is_none());
    let mut request = Packet::new();
    request
        .push(Ipv6 {
            source: "2001:db8::1".parse().unwrap(),
            destination: "2001:db8::2".parse().unwrap(),
            ..Default::default()
        })
        .push(Udp {
            source_port: 49152,
            destination_port: 33434,
            ..Default::default()
        });
    let mut response = icmpv6_error(
        "2001:db8::ff".parse().unwrap(),
        "2001:db8::1".parse().unwrap(),
        2,
        0,
        ipv6_udp_quote(&request),
    );
    let icmp = response.packet.get_mut::<Icmpv6>().unwrap();
    let mut body = icmp.body.to_vec();
    body[..4].copy_from_slice(&1280u32.to_be_bytes());
    icmp.body = Bytes::from(body);
    assert_eq!(
        classify_response(&registry, Transport::Udp, &request, &response)
            .unwrap()
            .advertised_mtu,
        Some(1280)
    );
}

#[test]
fn fixed_udp_accepts_only_the_exact_quoted_checksum_token() {
    use crate::probe::runner::Classifier;
    use packetcraftr_core::field::WireValue;
    let registry = packetcraftr_core::protocol::builtin::registry();
    let probe = Probe {
        sequence: 0,
        cycle: 1,
        udp_port_mode: super::UdpPortMode::Fixed,
        address: "192.0.2.2".parse().unwrap(),
        target: ProbeEndpoint::Udp {
            port: DEFAULT_UDP_PORT,
        },
        hop_limit: 1,
        attempt: 1,
        source_port: super::SOURCE_PORT,
    };
    let mut packet = probe.packet();
    packet.get_mut::<Ipv4>().unwrap().source = "192.0.2.1".parse().unwrap();
    let sent = crate::test_support::sent_packet(packet);
    let udp = sent.built().packet.get::<Udp>().unwrap();
    let WireValue::Exact(token) = udp.checksum else {
        panic!("built token")
    };
    let mut quote = ipv4_udp_quote(&sent.built().packet);
    quote[26..28].copy_from_slice(&token.to_be_bytes());
    let response = icmpv4_error(
        "192.0.2.254".parse().unwrap(),
        "192.0.2.1".parse().unwrap(),
        11,
        0,
        quote.clone(),
        1,
        Vec::new(),
    );
    let classifier = super::evidence::ProbeClassifier {
        registry: &registry,
        target: Arc::from("192.0.2.2"),
        termination: Termination::Timeout,
    };
    assert!(classifier.classify(&probe, &sent, &response).is_some());
    quote[27] ^= 1;
    let response = icmpv4_error(
        "192.0.2.254".parse().unwrap(),
        "192.0.2.1".parse().unwrap(),
        11,
        0,
        quote,
        1,
        Vec::new(),
    );
    assert!(classifier.classify(&probe, &sent, &response).is_none());
}
