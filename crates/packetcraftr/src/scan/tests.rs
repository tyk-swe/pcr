// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::VecDeque;
use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, UNIX_EPOCH};

use crate::policy::Policy as TrafficPolicy;
use crate::target::{Error, Resolver};
use bytes::Bytes;
use packetcraftr_core::error::{Classification as ErrorClassification, Kind};
use packetcraftr_core::frame::{Frame, LinkType};
use packetcraftr_core::protocol::{
    builtin::registry as default_registry,
    network::{Ipv4, Ipv6},
    transport::Tcp,
};
use packetcraftr_core::{
    Packet, decode::DecodedPacket, diagnostic::Diagnostic, layout::PacketLayout,
};

use super::classification::classify_scan_response;
use super::engine::scan;
use super::error::ScanError;
use super::model::{
    ScanBatch, ScanBatchExecution, ScanClassification, ScanExecutor, ScanLimits, ScanProbeStatus,
    ScanRequest, ScanTransport,
};
use super::probe::probe_packet;
use crate::clock::Clock;
use crate::target::{Authorized, Authorizer, PolicyAuthorizer, Target};
use crate::{BoundaryError, Stats, target::Family};

fn private_scan_policy() -> TrafficPolicy {
    TrafficPolicy {
        max_packets_per_operation: 1_000,
        max_bytes_per_operation: 1_000_000,
        ..TrafficPolicy::default()
    }
}

fn tcp_scan_request(target: Target) -> ScanRequest {
    ScanRequest {
        target,
        transport: ScanTransport::Tcp,
        address_family: Family::Any,
        ports: vec![80],
        attempts: 1,
        timeout: Duration::from_millis(1),
        probes_per_second: None,
        limits: ScanLimits::default(),
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
    ) -> Result<Vec<IpAddr>, Error> {
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

impl ScanExecutor for CountingRejectExecutor {
    fn execute(&mut self, _batch: &ScanBatch) -> Result<ScanBatchExecution, BoundaryError> {
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

impl ScanExecutor for TimeoutExecutor {
    fn execute(&mut self, batch: &ScanBatch) -> Result<ScanBatchExecution, BoundaryError> {
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
        Ok(ScanBatchExecution {
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

impl ScanExecutor for LateResponseExecutor {
    fn execute(&mut self, batch: &ScanBatch) -> Result<ScanBatchExecution, BoundaryError> {
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
    let registry = default_registry().unwrap();
    let address = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let mut request = tcp_scan_request(Target::Address(address));
    request.ports = vec![80, 81, 82, 83];
    request.attempts = 2;
    request.probes_per_second = Some(2);
    request.limits.batch_size = 2;
    let mut executor = TimeoutExecutor::default();
    let mut clock = RecordingClock::default();

    let result = scan(
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
        endpoint.classification == ScanClassification::Timeout
            && endpoint.evidence.len() == 2
            && endpoint
                .evidence
                .iter()
                .all(|evidence| evidence.status == ScanProbeStatus::Timeout)
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
    let error = scan(
        &tcp_scan_request(Target::Hostname("lab.example".parse().unwrap())),
        &mut authorizer,
        &default_registry().unwrap(),
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

    let error = scan(
        &request,
        &mut authorizer,
        &default_registry().unwrap(),
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
    let registry = default_registry().unwrap();
    let local = Ipv4Addr::new(10, 0, 0, 1);
    let remote = Ipv4Addr::new(10, 0, 0, 2);
    let request = tcp_packet(local, remote, 50_000, 443, Tcp::SYN);
    let syn_ack = decoded(
        tcp_packet(remote, local, 443, 50_000, Tcp::SYN | Tcp::ACK),
        Vec::new(),
    );
    assert_eq!(
        classify_scan_response(&registry, ScanTransport::Tcp, &request, &syn_ack)
            .unwrap()
            .classification,
        ScanClassification::Open
    );

    let mut bad_ack = tcp_packet(remote, local, 443, 50_000, Tcp::SYN | Tcp::ACK);
    bad_ack.get_mut::<Tcp>().unwrap().acknowledgment = 99;
    assert!(
        classify_scan_response(
            &registry,
            ScanTransport::Tcp,
            &request,
            &decoded(bad_ack, Vec::new()),
        )
        .is_none()
    );
    assert!(
        classify_scan_response(
            &registry,
            ScanTransport::Tcp,
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
    let result = scan(
        &request,
        &mut AddressListAuthorizer {
            addresses: vec![address],
        },
        &default_registry().unwrap(),
        &mut LateResponseExecutor(TimeoutExecutor::default()),
        &mut NoopClock,
    )
    .unwrap();

    assert_eq!(
        result.endpoints[0].classification,
        ScanClassification::Timeout
    );
    assert_eq!(
        result.endpoints[0].evidence[0].status,
        ScanProbeStatus::Timeout
    );
}

#[test]
fn scan_invalid_sent_evidence_reports_the_exact_probe_sequence() {
    let address = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let mut request = tcp_scan_request(Target::Address(address));
    request.ports = vec![80, 81];
    let error = scan(
        &request,
        &mut AddressListAuthorizer {
            addresses: vec![address],
        },
        &default_registry().unwrap(),
        &mut TimeoutExecutor {
            invalid_sent_index: Some(1),
            ..TimeoutExecutor::default()
        },
        &mut NoopClock,
    )
    .unwrap_err();

    assert!(matches!(
        error,
        ScanError::InvalidEvidence { sequence: 1, message }
            if message == "sent packet does not preserve the scan destination and probe identity"
    ));
}
