// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
// Test code indexes fixtures and counts by hand; the fail-closed lints are
// for library paths.
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, UNIX_EPOCH};

use crate::probe::ErrorKind;
use crate::probe::test_fixtures::{
    ProgressiveExecutor, RetainedEvidenceExecutor, decoded_packet, evidence_frame, private_policy,
};
use crate::progress::Runtime;
use packetcraftr_core::error::{Classification as ErrorClassification, Kind};
use packetcraftr_core::protocol::{
    network::{Ipv4, Ipv6},
    transport::Tcp,
};
use packetcraftr_core::{Packet, decode::DecodedPacket, diagnostic::Diagnostic};

use super::classification::classify_response;
use super::engine::{run, run_with_events};
use super::model::{
    Batch, Classification, Event, Execution, Executor, Limits, PortSpec, ProbeStatus, Request,
    Transport, select_ports,
};
use super::probe::probe_packet;
use crate::target::{PolicyAuthorizer, Target};
use crate::test_fixtures::{
    AddressListAuthorizer, NoopClock, RecordingClock, RejectingExecutor, ScriptedResolver,
};
use crate::{BoundaryError, Stats, target::Family};

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
struct TimeoutExecutor {
    batches: Vec<(u32, Vec<Option<u16>>)>,
    invalid_sent_sequence: Option<u64>,
}

impl Executor<Batch> for TimeoutExecutor {
    fn execute(&mut self, batch: &Batch) -> Result<Execution, BoundaryError> {
        self.batches.push((
            batch.probes[0].attempt,
            batch
                .probes
                .iter()
                .map(|probe| probe.endpoint.port())
                .collect(),
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
            if self.invalid_sent_sequence == Some(probe.sequence) {
                packet.get_mut::<Tcp>().unwrap().sequence ^= 1;
            }
            let receipt = crate::evidence::test_sent_packet(packet);
            bytes += u64::try_from(receipt.bytes_sent()).unwrap();
            sent.push(receipt);
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

impl Executor<Batch> for LateResponseExecutor {
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
    decoded_packet(
        packet,
        UNIX_EPOCH + Duration::from_secs(2),
        &[0x45],
        diagnostics,
    )
}

#[test]
fn scan_batching_attempts_rate_and_timeout_evidence_are_deterministic() {
    let registry = packetcraftr_core::protocol::builtin::registry();
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
            (1, vec![Some(80)]),
            (1, vec![Some(81)]),
            (1, vec![Some(82)]),
            (1, vec![Some(83)]),
            (2, vec![Some(80)]),
            (2, vec![Some(81)]),
            (2, vec![Some(82)]),
            (2, vec![Some(83)]),
        ]
    );
    assert_eq!(clock.delays, vec![Duration::from_millis(500); 7]);
    assert_eq!(result.endpoints.len(), 4);
    assert!(result.endpoints.iter().all(|endpoint| {
        endpoint.classification == Classification::Timeout
            && endpoint.probes.len() == 2
            && endpoint
                .probes
                .iter()
                .all(|evidence| evidence.status == ProbeStatus::Timeout)
    }));
    assert_eq!(result.stats.packets_attempted, 8);
    assert_eq!(result.stats.packets_completed, 8);
    assert_eq!(result.stats.elapsed, Duration::from_millis(3_508));
}

#[test]
fn scan_hostname_policy_denial_precedes_resolution_and_execution() {
    let resolver = ScriptedResolver::new([vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))]]);
    let executor_calls = Arc::new(AtomicUsize::new(0));
    let mut executor = RejectingExecutor {
        calls: Arc::clone(&executor_calls),
    };
    let policy = private_policy();
    let mut authorizer = PolicyAuthorizer::new(&policy, &resolver);
    let error = run(
        &tcp_scan_request(Target::Hostname("lab.example".parse().unwrap())),
        &mut authorizer,
        &packetcraftr_core::protocol::builtin::registry(),
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
    let mut executor = RejectingExecutor {
        calls: Arc::clone(&executor_calls),
    };
    let mut policy = private_policy();
    policy.allow_hostname_resolution = true;
    let mut request = tcp_scan_request(Target::Hostname("mixed.example".parse().unwrap()));
    request.address_family = Family::Ipv6;
    let mut authorizer = PolicyAuthorizer::new(&policy, &resolver);

    let error = run(
        &request,
        &mut authorizer,
        &packetcraftr_core::protocol::builtin::registry(),
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
fn scan_probe_limit_precedes_duration_planning() {
    let first = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let second = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    let mut request = tcp_scan_request(Target::Address(first));
    request.ports = (1..=50_001).collect();
    request.limits.max_ports = request.ports.len();
    request.limits.max_probes = super::MAX_PROBES;
    request.limits.max_duration = Duration::from_secs(1);
    let calls = Arc::new(AtomicUsize::new(0));
    let error = run(
        &request,
        &mut AddressListAuthorizer {
            addresses: vec![first, second],
        },
        &packetcraftr_core::protocol::builtin::registry(),
        &mut RejectingExecutor {
            calls: Arc::clone(&calls),
        },
        &mut NoopClock,
    )
    .unwrap_err();

    assert!(
        matches!(
            error.kind,
            ErrorKind::InvalidLimit {
                field: "probes",
                ..
            }
        ),
        "{error:?}"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn scan_tcp_correlation_requires_integrity_and_classifies_valid_replies() {
    let registry = packetcraftr_core::protocol::builtin::registry();
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
                vec![Diagnostic::warning(
                    packetcraftr_core::diagnostic::TCP_CHECKSUM,
                    "invalid checksum",
                )],
            ),
        )
        .is_none()
    );
    assert_eq!(
        classify_response(
            &registry,
            Transport::Tcp,
            &request,
            &decoded(
                tcp_packet(remote, local, 443, 50_000, Tcp::SYN | Tcp::ACK),
                vec![Diagnostic::warning(
                    "vendor.checksum_mismatch",
                    "unrelated vendor diagnostic",
                )],
            ),
        )
        .unwrap()
        .classification,
        Classification::Open
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
        &packetcraftr_core::protocol::builtin::registry(),
        &mut LateResponseExecutor(TimeoutExecutor::default()),
        &mut NoopClock,
    )
    .unwrap();

    assert_eq!(result.endpoints[0].classification, Classification::Timeout);
    assert_eq!(result.endpoints[0].probes[0].status, ProbeStatus::Timeout);
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
        &packetcraftr_core::protocol::builtin::registry(),
        &mut TimeoutExecutor {
            invalid_sent_sequence: Some(1),
            ..TimeoutExecutor::default()
        },
        &mut NoopClock,
    )
    .unwrap_err();

    assert!(matches!(
        error.kind,
        ErrorKind::InvalidEvidence { sequence: 1, message }
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
        failure_message: "induced scan execution failure",
        failure_code: "io.test_scan",
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
    .expect_err("the second batch must fail");

    assert!(matches!(
        error.kind,
        ErrorKind::Execution { sequence: 1, .. }
    ));
    let events = events.lock().unwrap();
    assert_eq!(events.len(), 1);
    assert!(matches!(
        &events[0],
        Event::Probe { probe, .. } if probe.sequence == 0 && probe.port == Some(80)
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
        failure_message: "induced scan execution failure",
        failure_code: "io.test_scan",
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
                ErrorClassification::new("io.test_output", Kind::Io, None),
                Vec::new(),
            ))
        },
    )
    .expect_err("the progressive sink must fail");

    assert!(matches!(&error.kind, ErrorKind::Output { .. }));
    assert_eq!(
        packetcraftr_core::error::Classified::classification(&error).code,
        "io.test_output"
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
        &packetcraftr_core::protocol::builtin::registry(),
        &mut RetainedEvidenceExecutor {
            inner: TimeoutExecutor::default(),
            frames: vec![
                evidence_frame(UNIX_EPOCH, &[0xff]),
                evidence_frame(UNIX_EPOCH, &[0xfe]),
            ],
            diagnostic: Diagnostic::info("scan.fixture", "fixture diagnostic"),
        },
        &mut NoopClock,
    )
    .expect("bounded undecoded evidence must complete");

    assert_eq!(result.endpoints.len(), 1);
    assert_eq!(result.endpoints[0].probes.len(), 1);
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

#[test]
fn scan_summary_counts_endpoints_by_winning_classification() {
    let address = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let mut request = tcp_scan_request(Target::Address(address));
    request.ports = vec![80, 81];
    let summary = run_with_events(
        &request,
        &mut AddressListAuthorizer {
            addresses: vec![address],
        },
        &packetcraftr_core::protocol::builtin::registry(),
        &mut TimeoutExecutor::default(),
        &mut NoopClock,
        &Runtime::default(),
        |_| Ok(()),
    )
    .expect("all-timeout scan completes");

    assert_eq!(summary.target, "10.0.0.2");
    assert_eq!(summary.resolved_addresses, vec![address]);
    assert_eq!(summary.counts.timeout, 2);
    assert_eq!(summary.counts.open, 0);
    assert_eq!(summary.counts.closed, 0);
    assert_eq!(summary.counts.filtered, 0);
    assert_eq!(summary.counts.unreachable, 0);
    assert_eq!(summary.counts.unknown, 0);
}

#[test]
fn scan_classification_counts_cover_every_outcome_once() {
    let mut counts = super::ClassificationCounts::default();
    counts.increment(Classification::Open);
    counts.increment(Classification::Closed);
    counts.increment(Classification::Filtered);
    counts.increment(Classification::Unreachable);
    counts.increment(Classification::Unknown);
    counts.increment(Classification::Timeout);
    counts.increment(Classification::Timeout);

    assert_eq!(counts.open, 1);
    assert_eq!(counts.closed, 1);
    assert_eq!(counts.filtered, 1);
    assert_eq!(counts.unreachable, 1);
    assert_eq!(counts.unknown, 1);
    assert_eq!(counts.timeout, 2);
}

#[test]
fn port_selection_is_stable_deduplicated_and_limit_aware() {
    let specs = [
        PortSpec::Single(443),
        PortSpec::RangeInclusive { start: 80, end: 82 },
        PortSpec::Single(80),
        PortSpec::RangeInclusive {
            start: 81,
            end: 443,
        },
    ];

    let ports = select_ports(specs, 364).expect("364 distinct ports fit");
    assert_eq!(&ports[..4], &[443, 80, 81, 82]);
    assert_eq!(ports.len(), 364);
    assert_eq!(ports.last(), Some(&442));

    let repeated = [
        PortSpec::Single(7),
        PortSpec::Single(7),
        PortSpec::RangeInclusive { start: 7, end: 8 },
    ];
    assert_eq!(
        select_ports(repeated, 2).expect("duplicates do not consume the limit"),
        vec![7, 8],
    );
}

/// The bound is enforced while expanding, so a 65535-port range never
/// materializes before the limit rejects it.
#[test]
fn port_selection_stops_at_the_first_distinct_port_over_the_limit() {
    let error = select_ports(
        [PortSpec::RangeInclusive {
            start: 1,
            end: u16::MAX,
        }],
        2,
    )
    .expect_err("a third distinct port exceeds the bound");

    match error.kind {
        ErrorKind::InvalidLimit {
            field,
            value,
            reason,
        } => {
            assert_eq!(field, "ports");
            assert_eq!(value, 3);
            assert_eq!(reason, "exceeds max_ports=2");
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

/// A validated request selects the ports it declared, once each; the CLI and
/// the library agree because there is one expansion.
#[test]
fn a_validated_request_selects_its_declared_ports_once_each() {
    let target = Target::Address("192.0.2.1".parse().expect("documentation address"));
    let mut request = tcp_scan_request(target);
    request.ports = vec![80, 443, 80];
    assert_eq!(
        request.selected_ports().expect("validated request"),
        vec![80, 443]
    );

    request.limits.max_ports = 1;
    let error = request
        .selected_ports()
        .expect_err("two distinct ports exceed max_ports=1");
    assert!(matches!(
        error.kind,
        ErrorKind::InvalidLimit { field: "ports", .. }
    ));
}
