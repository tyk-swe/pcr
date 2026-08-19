// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::VecDeque;
use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, UNIX_EPOCH};

use crate::target::{Error as TargetError, Resolver};
use bytes::Bytes;
use packetcraftr_core::error::{Classification as ErrorClassification, Kind};
use packetcraftr_core::frame::{Frame, LinkType};
use packetcraftr_core::protocol::{
    network::{Ipv4, Ipv6},
    transport::Tcp,
};
use packetcraftr_core::{
    Packet, decode::DecodedPacket, diagnostic::Diagnostic, layout::PacketLayout,
};

use super::classification::classify_response;
use super::engine::{run, run_with_events};
use super::error::Error;
use super::model::{
    Batch, Classification, Event, Execution, Executor, Limits, ProbeStatus, Request, Transport,
};
use super::probe::probe_packet;
use crate::clock::Clock;
use crate::target::{Authorized, Authorizer, PolicyAuthorizer, Target};
use crate::{BoundaryError, Stats, target::Family};

fn private_scan_policy() -> crate::policy::Policy {
    crate::policy::Policy {
        max_packets_per_operation: 1_000,
        max_bytes_per_operation: 1_000_000,
        ..crate::policy::Policy::default()
    }
}

fn tcp_scan_request(target: Target) -> Request {
    Request {
        target,
        transport: Transport::Tcp,
        address_family: Family::Any,
        ports: vec![80],
        attempts: 1,
        timeout: Duration::from_millis(1),
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

#[derive(Default)]
struct RecordingClock(Vec<Duration>);

impl Clock for RecordingClock {
    type Error = Infallible;

    fn sleep(&mut self, delay: Duration) -> Result<(), Self::Error> {
        self.0.push(delay);
        Ok(())
    }
}

struct AddressListAuthorizer {
    addresses: Vec<IpAddr>,
}

impl Authorizer for AddressListAuthorizer {
    fn resolve_and_authorize(&mut self, target: &Target) -> Result<Authorized, BoundaryError> {
        Ok(Authorized {
            declared: target.clone(),
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

struct CountingRejectExecutor {
    calls: Arc<AtomicUsize>,
}

impl Executor for CountingRejectExecutor {
    fn execute(&mut self, _batch: &Batch) -> Result<Execution, BoundaryError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Err(BoundaryError::new(
            "stop after authorization",
            ErrorClassification::new("io.test", Kind::Io, None),
            Vec::new(),
        ))
    }
}

#[derive(Default)]
struct TimeoutExecutor {
    batches: Vec<(u32, Vec<Option<u16>>)>,
    invalid_sent_index: Option<usize>,
}

impl Executor for TimeoutExecutor {
    fn execute(&mut self, batch: &Batch) -> Result<Execution, BoundaryError> {
        self.batches.push((
            batch.probes[0].attempt,
            batch.probes.iter().map(|probe| probe.port).collect(),
        ));
        let mut sent = Vec::new();
        let mut bytes = 0_u64;
        for probe in &batch.probes {
            let mut packet = probe_packet(probe);
            match probe.address {
                IpAddr::V4(_) => {
                    packet.get_mut::<Ipv4>().expect("IPv4 probe").source =
                        Ipv4Addr::new(10, 0, 0, 1);
                }
                IpAddr::V6(_) => {
                    packet.get_mut::<Ipv6>().expect("IPv6 probe").source =
                        "fd00::1".parse().unwrap();
                }
            }
            let receipt = crate::evidence::test_sent_packet(packet);
            bytes += u64::try_from(receipt.bytes_sent()).unwrap();
            sent.push(receipt);
        }
        if let Some(index) = self.invalid_sent_index {
            sent[index] = sent[0].clone();
        }
        Ok(Execution {
            permit: batch.permit,
            sent,
            responses: Vec::new(),
            unsolicited: Vec::new(),
            undecoded: Vec::new(),
            diagnostics: Vec::new(),
            stats: Stats {
                packets_attempted: u64::try_from(batch.probes.len()).unwrap(),
                packets_completed: u64::try_from(batch.probes.len()).unwrap(),
                bytes,
                elapsed: Duration::from_millis(1),
                capture: packetcraftr_netio::capture::Statistics::default(),
            },
        })
    }
}

struct LateResponseExecutor(TimeoutExecutor);

impl Executor for LateResponseExecutor {
    fn execute(&mut self, batch: &Batch) -> Result<Execution, BoundaryError> {
        let mut execution = self.0.execute(batch)?;
        execution.unsolicited.push(decoded(
            tcp_packet(
                Ipv4Addr::new(10, 0, 0, 2),
                Ipv4Addr::new(10, 0, 0, 1),
                80,
                50_000,
                Tcp::SYN | Tcp::ACK,
            ),
            Vec::new(),
        ));
        Ok(execution)
    }
}

struct ProgressiveExecutor {
    inner: TimeoutExecutor,
    calls: Arc<AtomicUsize>,
    shutdowns: Arc<AtomicUsize>,
    fail_at: Option<usize>,
}

struct RetainedEvidenceExecutor(TimeoutExecutor);

impl Executor for RetainedEvidenceExecutor {
    fn execute(&mut self, batch: &Batch) -> Result<Execution, BoundaryError> {
        let mut execution = self.0.execute(batch)?;
        execution.undecoded.extend([
            Frame::new(UNIX_EPOCH, LinkType::RAW, Bytes::from_static(&[0xff])).unwrap(),
            Frame::new(UNIX_EPOCH, LinkType::RAW, Bytes::from_static(&[0xfe])).unwrap(),
        ]);
        execution
            .diagnostics
            .push(Diagnostic::info("scan.fixture", "fixture diagnostic"));
        Ok(execution)
    }
}

impl Executor for ProgressiveExecutor {
    fn execute(&mut self, batch: &Batch) -> Result<Execution, BoundaryError> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
        if self.fail_at == Some(call) {
            return Err(BoundaryError::new(
                "induced scan execution failure",
                ErrorClassification::new("io.test_scan", Kind::Io, None),
                Vec::new(),
            ));
        }
        let execution = self.inner.execute(batch);
        self.shutdowns.fetch_add(1, Ordering::SeqCst);
        execution
    }
}

fn tcp_packet(
    source: Ipv4Addr,
    destination: Ipv4Addr,
    source_port: u16,
    destination_port: u16,
    flags: u16,
) -> Packet {
    let mut packet = Packet::new();
    packet
        .push(Ipv4 {
            source,
            destination,
            ..Ipv4::default()
        })
        .push(Tcp {
            source_port,
            destination_port,
            flags,
            acknowledgment: if flags & Tcp::ACK != 0 { 1 } else { 0 },
            ..Tcp::default()
        });
    packet
}

fn decoded(packet: Packet, diagnostics: Vec<Diagnostic>) -> DecodedPacket {
    let frame = Frame::new(
        UNIX_EPOCH + Duration::from_secs(2),
        LinkType::RAW,
        Bytes::from_static(&[0x45]),
    )
    .expect("decoded evidence frame");
    DecodedPacket {
        packet,
        original: frame.bytes().clone(),
        frame,
        layout: PacketLayout::default(),
        diagnostics,
    }
}

#[test]
fn scan_batching_attempts_rate_and_timeout_evidence_are_deterministic() {
    let registry = packetcraftr_core::protocol::builtin::registry().unwrap();
    let address = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let mut request = tcp_scan_request(Target::Address(address));
    request.ports = vec![80, 81, 82, 83];
    request.attempts = 2;
    request.probes_per_second = Some(2);
    request.limits.batch_size = 2;
    let mut executor = TimeoutExecutor::default();
    let mut clock = RecordingClock::default();

    let result = run(
        &request,
        &mut AddressListAuthorizer {
            addresses: vec![address],
        },
        &registry,
        &mut executor,
        &mut clock,
    )
    .unwrap();

    assert_eq!(
        executor.batches,
        vec![
            (1, vec![Some(80), Some(81)]),
            (1, vec![Some(82), Some(83)]),
            (2, vec![Some(80), Some(81)]),
            (2, vec![Some(82), Some(83)]),
        ]
    );
    assert_eq!(clock.0, vec![Duration::from_secs(1); 3]);
    assert_eq!(result.endpoints.len(), 4);
    assert!(result.endpoints.iter().all(|endpoint| {
        endpoint.classification == Classification::Timeout
            && endpoint.evidence.len() == 2
            && endpoint
                .evidence
                .iter()
                .all(|evidence| evidence.status == ProbeStatus::Timeout)
    }));
    assert_eq!(result.stats.packets_attempted, 8);
    assert_eq!(result.stats.packets_completed, 8);
    assert_eq!(result.stats.elapsed, Duration::from_millis(3_004));
}

#[test]
fn scan_hostname_policy_denial_precedes_resolution_and_execution() {
    let resolver = ScriptedResolver::new([vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))]]);
    let executor_calls = Arc::new(AtomicUsize::new(0));
    let mut executor = CountingRejectExecutor {
        calls: Arc::clone(&executor_calls),
    };
    let policy = private_scan_policy();
    let mut authorizer = PolicyAuthorizer::new(&policy, &resolver);
    let error = run(
        &tcp_scan_request(Target::Hostname("lab.example".parse().unwrap())),
        &mut authorizer,
        &packetcraftr_core::protocol::builtin::registry().unwrap(),
        &mut executor,
        &mut NoopClock,
    )
    .unwrap_err();

    assert_eq!(
        packetcraftr_core::error::Classified::classification(&error).code,
        "policy.hostname_resolution"
    );
    assert_eq!(resolver.calls.load(Ordering::SeqCst), 0);
    assert_eq!(executor_calls.load(Ordering::SeqCst), 0);
}

#[test]
fn scan_authorizes_mixed_resolution_answers_before_family_filtering() {
    let resolver = ScriptedResolver::new([vec![
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
    ]]);
    let executor_calls = Arc::new(AtomicUsize::new(0));
    let mut executor = CountingRejectExecutor {
        calls: Arc::clone(&executor_calls),
    };
    let mut policy = private_scan_policy();
    policy.allow_hostname_resolution = true;
    let mut request = tcp_scan_request(Target::Hostname("mixed.example".parse().unwrap()));
    request.address_family = Family::Ipv6;
    let mut authorizer = PolicyAuthorizer::new(&policy, &resolver);

    let error = run(
        &request,
        &mut authorizer,
        &packetcraftr_core::protocol::builtin::registry().unwrap(),
        &mut executor,
        &mut NoopClock,
    )
    .unwrap_err();

    assert_eq!(
        packetcraftr_core::error::Classified::classification(&error).code,
        "policy.public_destination"
    );
    assert!(error.to_string().contains("8.8.8.8"));
    assert_eq!(resolver.calls.load(Ordering::SeqCst), 1);
    assert_eq!(executor_calls.load(Ordering::SeqCst), 0);
}

#[test]
fn scan_tcp_correlation_requires_integrity_and_classifies_valid_replies() {
    let registry = packetcraftr_core::protocol::builtin::registry().unwrap();
    let local = Ipv4Addr::new(10, 0, 0, 1);
    let remote = Ipv4Addr::new(10, 0, 0, 2);
    let request = tcp_packet(local, remote, 50_000, 443, Tcp::SYN);
    let syn_ack = decoded(
        tcp_packet(remote, local, 443, 50_000, Tcp::SYN | Tcp::ACK),
        Vec::new(),
    );
    assert_eq!(
        classify_response(&registry, Transport::Tcp, &request, &syn_ack)
            .unwrap()
            .classification,
        Classification::Open
    );

    let mut bad_ack = tcp_packet(remote, local, 443, 50_000, Tcp::SYN | Tcp::ACK);
    bad_ack.get_mut::<Tcp>().unwrap().acknowledgment = 99;
    assert!(
        classify_response(
            &registry,
            Transport::Tcp,
            &request,
            &decoded(bad_ack, Vec::new()),
        )
        .is_none()
    );
    assert!(
        classify_response(
            &registry,
            Transport::Tcp,
            &request,
            &decoded(
                tcp_packet(remote, local, 443, 50_000, Tcp::SYN | Tcp::ACK),
                vec![Diagnostic::warning("tcp.checksum", "invalid checksum")],
            ),
        )
        .is_none()
    );
}

#[test]
fn scan_late_unsolicited_response_remains_a_timeout() {
    let address = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let request = tcp_scan_request(Target::Address(address));
    let result = run(
        &request,
        &mut AddressListAuthorizer {
            addresses: vec![address],
        },
        &packetcraftr_core::protocol::builtin::registry().unwrap(),
        &mut LateResponseExecutor(TimeoutExecutor::default()),
        &mut NoopClock,
    )
    .unwrap();

    assert_eq!(result.endpoints[0].classification, Classification::Timeout);
    assert_eq!(result.endpoints[0].evidence[0].status, ProbeStatus::Timeout);
}

#[test]
fn scan_invalid_sent_evidence_reports_the_exact_probe_sequence() {
    let address = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let mut request = tcp_scan_request(Target::Address(address));
    request.ports = vec![80, 81];
    let error = run(
        &request,
        &mut AddressListAuthorizer {
            addresses: vec![address],
        },
        &packetcraftr_core::protocol::builtin::registry().unwrap(),
        &mut TimeoutExecutor {
            invalid_sent_index: Some(1),
            ..TimeoutExecutor::default()
        },
        &mut NoopClock,
    )
    .unwrap_err();

    assert!(matches!(
        error,
        Error::InvalidEvidence { sequence: 1, message }
            if message == "sent packet does not preserve the scan destination and probe identity"
    ));
}

#[test]
fn scan_events_precede_later_work_and_survive_a_later_failure() {
    let address = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let mut request = tcp_scan_request(Target::Address(address));
    request.ports = vec![80, 81];
    request.limits.batch_size = 1;
    let calls = Arc::new(AtomicUsize::new(0));
    let shutdowns = Arc::new(AtomicUsize::new(0));
    let mut executor = ProgressiveExecutor {
        inner: TimeoutExecutor::default(),
        calls: Arc::clone(&calls),
        shutdowns: Arc::clone(&shutdowns),
        fail_at: Some(2),
    };
    let mut events = Vec::new();

    let error = run_with_events(
        &request,
        &mut AddressListAuthorizer {
            addresses: vec![address],
        },
        &packetcraftr_core::protocol::builtin::registry().unwrap(),
        &mut executor,
        &mut NoopClock,
        |event| {
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            events.push(event);
            Ok(())
        },
    )
    .expect_err("the second batch must fail");

    assert!(matches!(error, Error::Execution { sequence: 1, .. }));
    assert_eq!(events.len(), 1);
    assert!(matches!(
        &events[0],
        Event::Probe { evidence, port: Some(80), .. } if evidence.sequence == 0
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(shutdowns.load(Ordering::SeqCst), 1);
}

#[test]
fn scan_sink_failure_stops_batches_after_cleaning_up_the_current_session() {
    let address = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let mut request = tcp_scan_request(Target::Address(address));
    request.ports = vec![80, 81, 82];
    request.limits.batch_size = 1;
    let calls = Arc::new(AtomicUsize::new(0));
    let shutdowns = Arc::new(AtomicUsize::new(0));
    let mut executor = ProgressiveExecutor {
        inner: TimeoutExecutor::default(),
        calls: Arc::clone(&calls),
        shutdowns: Arc::clone(&shutdowns),
        fail_at: None,
    };

    let error = run_with_events(
        &request,
        &mut AddressListAuthorizer {
            addresses: vec![address],
        },
        &packetcraftr_core::protocol::builtin::registry().unwrap(),
        &mut executor,
        &mut NoopClock,
        |_| {
            Err(BoundaryError::new(
                "induced output failure",
                ErrorClassification::new("io.test_output", Kind::Io, None),
                Vec::new(),
            ))
        },
    )
    .expect_err("the progressive sink must fail");

    assert!(matches!(&error, Error::Output { .. }));
    assert_eq!(
        packetcraftr_core::error::Classified::classification(&error).code,
        "io.scan_output"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(shutdowns.load(Ordering::SeqCst), 1);
}

#[test]
fn scan_event_collection_preserves_stats_diagnostics_and_evidence_limits() {
    let address = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let mut request = tcp_scan_request(Target::Address(address));
    request.limits.max_undecoded = 1;
    let result = run(
        &request,
        &mut AddressListAuthorizer {
            addresses: vec![address],
        },
        &packetcraftr_core::protocol::builtin::registry().unwrap(),
        &mut RetainedEvidenceExecutor(TimeoutExecutor::default()),
        &mut NoopClock,
    )
    .expect("bounded undecoded evidence must complete");

    assert_eq!(result.endpoints.len(), 1);
    assert_eq!(result.endpoints[0].evidence.len(), 1);
    assert_eq!(result.undecoded.len(), 1);
    assert_eq!(result.stats.packets_completed, 1);
    assert!(
        result
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "scan.fixture")
    );
    assert!(
        result
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "scan.undecoded_limit")
    );
}
