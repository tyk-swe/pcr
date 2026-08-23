// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::VecDeque;
use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, UNIX_EPOCH};

use crate::target::{Error as TargetError, Resolver};
use bytes::Bytes;
use packetcraftr_core::error::{Classification, Classified, Context};
use packetcraftr_core::frame::{Frame, LinkType};
use packetcraftr_core::protocol::{
    icmp::{Icmpv4, Icmpv6},
    network::{Ipv4, Ipv6},
    transport::Udp,
};
use packetcraftr_core::{
    Packet, decode::DecodedPacket, diagnostic::Diagnostic, layout::PacketLayout,
};

use super::DEFAULT_TRACEROUTE_UDP_PORT;
use super::classification::classify_response;
use super::engine::{run, run_with_events};
use super::model::{
    Batch, Completion, Event, Execution, Executor, Limits, Probe, ProbeStatus, Request,
    ResponseKind, Strategy,
};
use super::probe::probe_packet;
use crate::Error;
use crate::clock::Clock;
use crate::target::Target;
use crate::{BoundaryError, Stats, target::Family};

fn udp_traceroute_request(target: Target) -> Request {
    Request {
        target,
        strategy: Strategy::Udp,
        address_family: Family::Any,
        destination_port: Some(DEFAULT_TRACEROUTE_UDP_PORT),
        first_hop: 1,
        max_hops: 2,
        probes_per_hop: 2,
        timeout: Duration::from_millis(10),
        probes_per_second: None,
        limits: Limits::default(),
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

impl Resolver for ScriptedResolver {
    fn resolve(
        &self,
        _hostname: &crate::target::Hostname,
        _limit: usize,
    ) -> Result<Vec<IpAddr>, TargetError> {
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

impl Executor for CountingRejectExecutor {
    fn execute(&mut self, _batch: &Batch) -> Result<Execution, BoundaryError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(BoundaryError::new(
            "stop after authorization",
            Classification::new("io.test", None),
            Vec::new(),
        ))
    }
}

#[derive(Default)]
struct NoResponseExecutor {
    invalid_sent_index: Option<usize>,
}

impl Executor for NoResponseExecutor {
    fn execute(&mut self, batch: &Batch) -> Result<Execution, BoundaryError> {
        let mut sent = Vec::new();
        let mut bytes = 0_u64;
        for probe in &batch.probes {
            let mut packet = probe_packet(probe);
            if let Some(ipv4) = packet.get_mut::<Ipv4>() {
                ipv4.source = Ipv4Addr::new(10, 0, 0, 1);
            }
            let receipt = crate::evidence::test_sent_packet(packet);
            bytes += u64::try_from(receipt.bytes_sent()).unwrap();
            sent.push(receipt);
        }
        if let Some(index) = self.invalid_sent_index {
            sent[index] = sent[0].clone();
        }
        let count = u64::try_from(batch.probes.len()).expect("test batch fits u64");
        Ok(Execution {
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
                capture: packetcraftr_netio::capture::Statistics::default(),
            },
        })
    }
}

struct MixedHopExecutor;

impl Executor for MixedHopExecutor {
    fn execute(&mut self, batch: &Batch) -> Result<Execution, BoundaryError> {
        let local = Ipv4Addr::new(10, 0, 0, 1);
        let remote = Ipv4Addr::new(10, 0, 0, 9);
        let router = Ipv4Addr::new(10, 0, 0, 254);
        let mut sent = Vec::new();
        let mut bytes = 0_u64;
        for probe in &batch.probes {
            let mut packet = probe_packet(probe);
            packet.get_mut::<Ipv4>().expect("IPv4 probe").source = local;
            let receipt = crate::evidence::test_sent_packet(packet);
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
        Ok(Execution {
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
                capture: packetcraftr_netio::capture::Statistics::default(),
            },
        })
    }
}

struct ProgressiveExecutor {
    inner: NoResponseExecutor,
    calls: Arc<AtomicUsize>,
    shutdowns: Arc<AtomicUsize>,
    fail_at: Option<usize>,
}

struct RetainedEvidenceExecutor(NoResponseExecutor);

impl Executor for RetainedEvidenceExecutor {
    fn execute(&mut self, batch: &Batch) -> Result<Execution, BoundaryError> {
        let mut execution = self.0.execute(batch)?;
        execution.undecoded.extend([frame_at(3), frame_at(4)]);
        execution
            .diagnostics
            .push(Diagnostic::info("traceroute.fixture", "fixture diagnostic"));
        Ok(execution)
    }
}

impl Executor for ProgressiveExecutor {
    fn execute(&mut self, batch: &Batch) -> Result<Execution, BoundaryError> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
        if self.fail_at == Some(call) {
            return Err(BoundaryError::new(
                "induced traceroute execution failure",
                Classification::new("io.test_traceroute", None),
                Vec::new(),
            ));
        }
        let execution = self.inner.execute(batch);
        self.shutdowns.fetch_add(1, Ordering::SeqCst);
        execution
    }
}

fn private_traceroute_policy() -> crate::policy::Policy {
    crate::policy::Policy {
        max_packets_per_operation: 1_000,
        max_bytes_per_operation: 1_000_000,
        ..crate::policy::Policy::default()
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
    let mut request = udp_traceroute_request(Target::Hostname("ordered.example".parse().unwrap()));
    request.address_family = Family::Ipv4;
    request.max_hops = 1;
    request.probes_per_hop = 1;
    let resolver = ScriptedResolver::new([vec![
        Ipv6Addr::LOCALHOST.into(),
        first,
        first,
        second,
        first,
    ]]);
    let policy = crate::policy::Policy {
        allow_hostname_resolution: true,
        ..private_traceroute_policy()
    };
    let result = run(
        &request,
        &policy,
        &resolver,
        &packetcraftr_core::protocol::builtin::registry().unwrap(),
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
    let mut executor = CountingRejectExecutor(Arc::clone(&calls));
    let policy = private_traceroute_policy();
    let error = run(
        &udp_traceroute_request(Target::Hostname("lab.example".parse().unwrap())),
        &policy,
        &resolver,
        &packetcraftr_core::protocol::builtin::registry().unwrap(),
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
    let mut request = udp_traceroute_request(Target::Hostname("mixed.example".parse().unwrap()));
    request.address_family = Family::Ipv6;
    let error = run(
        &request,
        &policy,
        &resolver,
        &packetcraftr_core::protocol::builtin::registry().unwrap(),
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
    let policy = crate::policy::Policy {
        max_packets_per_operation: 0,
        ..private_traceroute_policy()
    };
    let calls = Arc::new(AtomicUsize::new(0));
    let error = run(
        &request,
        &policy,
        &ScriptedResolver::new([]),
        &packetcraftr_core::protocol::builtin::registry().unwrap(),
        &mut CountingRejectExecutor(Arc::clone(&calls)),
        &mut NoopClock,
    )
    .unwrap_err();

    assert!(matches!(error, Error::InvalidRequest { .. }));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn traceroute_ipv4_classification_distinguishes_intermediate_terminal_and_unreachable() {
    let registry = packetcraftr_core::protocol::builtin::registry().unwrap();
    let local = Ipv4Addr::new(10, 0, 0, 1);
    let remote = Ipv4Addr::new(10, 0, 0, 9);
    let router = Ipv4Addr::new(10, 0, 0, 254);
    let mut probe = Probe {
        sequence: 0,
        address: IpAddr::V4(remote),
        strategy: Strategy::Udp,
        destination_port: Some(DEFAULT_TRACEROUTE_UDP_PORT),
        hop_limit: 1,
        attempt: 1,
    }
    .packet();
    probe.get_mut::<Ipv4>().unwrap().source = local;
    let quote = ipv4_udp_quote(&probe);

    assert_eq!(
        classify_response(
            &registry,
            Strategy::Udp,
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
            Strategy::Udp,
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
            Strategy::Udp,
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
    let registry = packetcraftr_core::protocol::builtin::registry().unwrap();
    let local: Ipv6Addr = "fd00::1".parse().unwrap();
    let remote: Ipv6Addr = "fd00::9".parse().unwrap();
    let router: Ipv6Addr = "fd00::fe".parse().unwrap();
    let mut probe = Probe {
        sequence: 9,
        address: IpAddr::V6(remote),
        strategy: Strategy::Udp,
        destination_port: Some(DEFAULT_TRACEROUTE_UDP_PORT + 9),
        hop_limit: 4,
        attempt: 1,
    }
    .packet();
    probe.get_mut::<Ipv6>().unwrap().source = local;
    let response = icmpv6_error(router, local, 3, 0, ipv6_udp_quote(&probe));

    assert_eq!(
        classify_response(&registry, Strategy::Udp, &probe, &response,)
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
    let result = run(
        &request,
        &private_traceroute_policy(),
        &ScriptedResolver::new([]),
        &packetcraftr_core::protocol::builtin::registry().unwrap(),
        &mut MixedHopExecutor,
        &mut NoopClock,
    )
    .unwrap();

    assert_eq!(result.completion, Completion::DestinationReached);
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
    let restricted_policy = crate::policy::Policy {
        max_bytes_per_operation: 16 * 74 - 1,
        ..private_traceroute_policy()
    };
    let error = run(
        &request,
        &restricted_policy,
        &ScriptedResolver::new([]),
        &packetcraftr_core::protocol::builtin::registry().unwrap(),
        &mut NoResponseExecutor::default(),
        &mut NoopClock,
    )
    .unwrap_err();
    assert!(matches!(
        error,
        Error::Policy(crate::policy::Error::ByteLimit { actual: 1184, .. })
    ));
}

#[test]
fn traceroute_invalid_sent_evidence_reports_the_exact_probe_sequence() {
    let address = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9));
    let request = udp_traceroute_request(Target::Address(address));
    let error = run(
        &request,
        &private_traceroute_policy(),
        &ScriptedResolver::new([]),
        &packetcraftr_core::protocol::builtin::registry().unwrap(),
        &mut NoResponseExecutor {
            invalid_sent_index: Some(1),
        },
        &mut NoopClock,
    )
    .unwrap_err();

    assert!(matches!(
        error,
        Error::InvalidEvidence { context, message }
            if context == Context::probe_sequence(1) && message
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
    };
    let events = Arc::new(std::sync::Mutex::new(Vec::new()));
    let observed_events = Arc::clone(&events);
    let callback_calls = Arc::clone(&calls);

    let error = run_with_events(
        &request,
        &private_traceroute_policy(),
        &ScriptedResolver::new([]),
        &packetcraftr_core::protocol::builtin::registry().unwrap(),
        &mut executor,
        &mut NoopClock,
        move |event| {
            assert_eq!(callback_calls.load(Ordering::SeqCst), 1);
            observed_events.lock().unwrap().push(event);
            Ok(())
        },
    )
    .expect_err("the second hop must fail");

    assert!(matches!(
        error,
        Error::Execution { context, .. } if context == Context::probe_sequence(1)
    ));
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
    };

    let error = run_with_events(
        &request,
        &private_traceroute_policy(),
        &ScriptedResolver::new([]),
        &packetcraftr_core::protocol::builtin::registry().unwrap(),
        &mut executor,
        &mut NoopClock,
        |_| {
            Err(BoundaryError::new(
                "induced output failure",
                Classification::new("io.test_output", None),
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
fn traceroute_event_collection_preserves_stats_diagnostics_and_evidence_limits() {
    let address = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9));
    let mut request = udp_traceroute_request(Target::Address(address));
    request.max_hops = 1;
    request.probes_per_hop = 1;
    request.limits.max_undecoded = 1;
    let result = run(
        &request,
        &private_traceroute_policy(),
        &ScriptedResolver::new([]),
        &packetcraftr_core::protocol::builtin::registry().unwrap(),
        &mut RetainedEvidenceExecutor(NoResponseExecutor::default()),
        &mut NoopClock,
    )
    .expect("bounded undecoded evidence must complete");

    assert_eq!(result.hops.len(), 1);
    assert_eq!(result.hops[0].probes.len(), 1);
    assert_eq!(result.undecoded.len(), 1);
    assert_eq!(result.stats.packets_completed, 1);
    assert!(
        result
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "traceroute.fixture")
    );
    assert!(
        result
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "traceroute.undecoded_limit")
    );
}
