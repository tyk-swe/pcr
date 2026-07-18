use std::collections::VecDeque;
use std::convert::Infallible;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::UNIX_EPOCH;

use super::engine::{
    build_batches, sent_traceroute_probe_matches, traceroute_identity, validate_execution,
};
use super::*;
use crate::client::policy::Policy as TrafficPolicy;
use crate::client::target::{Error as TargetResolutionError, Resolver as HostnameResolver};
use crate::net::capture::CaptureStatistics;
use crate::packet::layout::PacketLayout;
use crate::protocol::builtin::registry as default_registry;
use crate::workflow::target::Authorized;
use crate::workflow::target_adapter::PolicyAuthorizer;
use std::result::Result;

fn private_traceroute_policy() -> TrafficPolicy {
    TrafficPolicy {
        max_packets_per_operation: 1_000,
        max_bytes_per_operation: 1_000_000,
        ..TrafficPolicy::default()
    }
}

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
struct NoopClock(Vec<Duration>);

impl Clock for NoopClock {
    type Error = Infallible;

    fn sleep(&mut self, delay: Duration) -> Result<(), Self::Error> {
        self.0.push(delay);
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
            let mut packet = probe.packet();
            packet.get_mut::<Ipv4>().unwrap().source = local;
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
        Ok(TracerouteBatchExecution {
            sent,
            sent_evidence,
            responses: Vec::new(),
            unsolicited: vec![responder],
            undecoded: Vec::new(),
            diagnostics: Vec::new(),
            stats: Stats {
                packets_attempted: batch.probes.len() as u64,
                packets_completed: batch.probes.len() as u64,
                bytes: batch.probes.len() as u64,
                elapsed: Duration::from_millis(1),
                capture: CaptureStatistics::default(),
            },
        })
    }
}

struct UndecodedExecutor;

impl TracerouteExecutor for UndecodedExecutor {
    fn execute(
        &mut self,
        batch: &TracerouteBatch,
    ) -> Result<TracerouteBatchExecution, BoundaryError> {
        let mut sent = Vec::new();
        let mut sent_evidence = Vec::new();
        for probe in &batch.probes {
            let mut packet = probe.packet();
            packet.get_mut::<Ipv4>().unwrap().source = Ipv4Addr::new(10, 0, 0, 1);
            sent.push(packet);
            sent_evidence.push(frame_at(probe.sequence + 1));
        }
        Ok(TracerouteBatchExecution {
            sent,
            sent_evidence,
            responses: Vec::new(),
            unsolicited: Vec::new(),
            undecoded: vec![frame_at(10), frame_at(11)],
            diagnostics: Vec::new(),
            stats: Stats {
                packets_attempted: batch.probes.len() as u64,
                packets_completed: batch.probes.len() as u64,
                bytes: batch.probes.len() as u64,
                elapsed: Duration::from_millis(1),
                capture: CaptureStatistics::default(),
            },
        })
    }
}

#[test]
fn workflow_preserves_mixed_attempts_and_stops_after_destination_evidence() {
    let destination = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9));
    let mut operation = udp_traceroute_request(Target::Address(destination));
    operation.probes_per_second = Some(2);
    operation.max_hops = 8;
    let mut authorizer = FixedAuthorizer {
        address: destination,
        operations: Vec::new(),
    };
    let registry = default_registry().unwrap();
    let mut clock = NoopClock::default();

    let result = traceroute(
        &operation,
        &mut authorizer,
        &registry,
        &mut MixedHopExecutor,
        &mut clock,
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
    assert!(result.hops[1].probes[0].response.is_some());
    assert_eq!(result.stats.packets_completed, 4);
    assert_eq!(result.stats.elapsed, Duration::from_millis(1_002));
    assert_eq!(clock.0, vec![Duration::from_secs(1)]);
    assert_eq!(authorizer.operations, vec![(16, 16 * 74)]);
}

#[test]
fn duplicate_resolved_addresses_preserve_first_seen_order_after_family_filtering() {
    let first = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9));
    let second = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 10));
    let excluded = IpAddr::V6(Ipv6Addr::LOCALHOST);
    let mut operation = udp_traceroute_request(Target::Hostname("ordered.example".to_owned()));
    operation.address_family = AddressFamily::Ipv4;
    operation.max_hops = 1;
    operation.probes_per_hop = 1;
    let result = traceroute(
        &operation,
        &mut AddressListAuthorizer {
            addresses: vec![excluded, first, first, second, first, excluded],
        },
        &default_registry().unwrap(),
        &mut UndecodedExecutor,
        &mut NoopClock::default(),
    )
    .unwrap();

    assert_eq!(result.resolved_addresses, vec![first, second]);
    assert_eq!(result.destination, first);
}

#[test]
fn unsorted_matched_groups_preserve_probe_and_fully_tied_evidence_order() {
    struct ReverseTiedResponses;

    impl TracerouteExecutor for ReverseTiedResponses {
        fn execute(
            &mut self,
            batch: &TracerouteBatch,
        ) -> Result<TracerouteBatchExecution, BoundaryError> {
            let local = Ipv4Addr::new(10, 0, 0, 1);
            let router = Ipv4Addr::new(10, 0, 0, 254);
            let mut sent = Vec::with_capacity(batch.probes.len());
            let mut sent_evidence = Vec::with_capacity(batch.probes.len());
            for probe in &batch.probes {
                let mut packet = probe.packet();
                packet.get_mut::<Ipv4>().unwrap().source = local;
                sent.push(packet);
                sent_evidence.push(frame_at(probe.sequence + 1));
            }
            let mut responses = Vec::with_capacity(batch.probes.len() * 2);
            for request_index in (0..batch.probes.len()).rev() {
                let probe = &batch.probes[request_index];
                let mut first = icmpv4_error(
                    router,
                    local,
                    11,
                    0,
                    ipv4_udp_quote(&sent[request_index]),
                    probe.sequence + 1,
                    Vec::new(),
                );
                first.frame.timestamp =
                    sent_evidence[request_index].timestamp + Duration::from_millis(1);
                first.frame.interface = Some(1);
                let mut second = first.clone();
                second.frame.interface = Some(2);
                responses.extend([
                    TracerouteMatchedResponse {
                        request_index,
                        response: first,
                        latency: Duration::from_millis(1),
                    },
                    TracerouteMatchedResponse {
                        request_index,
                        response: second,
                        latency: Duration::from_millis(1),
                    },
                ]);
            }
            Ok(TracerouteBatchExecution {
                sent,
                sent_evidence,
                responses,
                unsolicited: Vec::new(),
                undecoded: Vec::new(),
                diagnostics: Vec::new(),
                stats: Stats {
                    packets_attempted: batch.probes.len() as u64,
                    packets_completed: batch.probes.len() as u64,
                    bytes: batch.probes.len() as u64,
                    elapsed: Duration::from_millis(1),
                    capture: CaptureStatistics::default(),
                },
            })
        }
    }

    let destination = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9));
    let mut operation = udp_traceroute_request(Target::Address(destination));
    operation.max_hops = 1;
    operation.probes_per_hop = 3;
    let result = traceroute(
        &operation,
        &mut FixedAuthorizer {
            address: destination,
            operations: Vec::new(),
        },
        &default_registry().unwrap(),
        &mut ReverseTiedResponses,
        &mut NoopClock::default(),
    )
    .unwrap();

    assert_eq!(result.hops.len(), 1);
    assert_eq!(
        result.hops[0]
            .probes
            .iter()
            .map(|probe| (probe.sequence, probe.attempt))
            .collect::<Vec<_>>(),
        vec![(0, 1), (1, 2), (2, 3)]
    );
    assert!(result.hops[0].probes.iter().all(|probe| {
        probe.status == TracerouteProbeStatus::Response
            && probe.response_kind == Some(TracerouteResponseKind::Intermediate)
            && probe
                .response
                .as_ref()
                .is_some_and(|frame| frame.interface == Some(1))
    }));
}

#[test]
fn undecodable_evidence_remains_exact_hop_scoped_and_operation_bounded() {
    let destination = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9));
    let mut operation = udp_traceroute_request(Target::Address(destination));
    operation.probes_per_hop = 1;
    operation.limits.max_evidence_frames = 2;
    operation.limits.max_evidence_bytes = 2;
    operation.limits.max_undecoded = 1;
    let mut authorizer = FixedAuthorizer {
        address: destination,
        operations: Vec::new(),
    };

    let result = traceroute(
        &operation,
        &mut authorizer,
        &default_registry().unwrap(),
        &mut UndecodedExecutor,
        &mut NoopClock::default(),
    )
    .unwrap();

    assert_eq!(result.undecoded.len(), 1);
    assert_eq!(result.undecoded[0].hop_limit, 1);
    assert_eq!(result.undecoded[0].frame.bytes().as_ref(), &[0x45]);
    assert!(
        result
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "traceroute.undecoded_limit")
    );
}

#[test]
fn executor_cannot_replace_the_authorized_traceroute_probe() {
    let destination = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9));
    let operation = udp_traceroute_request(Target::Address(destination));
    let batch = build_batches(&operation, destination).unwrap().remove(0);
    let mut execution = UndecodedExecutor.execute(&batch).unwrap();
    let mut layer2 = execution.sent[0].clone();
    layer2
        .insert(0, crate::protocol::link::Ethernet::default())
        .unwrap();
    assert!(sent_traceroute_probe_matches(&batch.probes[0], &layer2));
    layer2.push(crate::protocol::link::Ethernet::default());
    assert!(!sent_traceroute_probe_matches(&batch.probes[0], &layer2));
    execution.stats.bytes = 0;
    let sent_bytes = execution
        .sent_evidence
        .iter()
        .map(|frame| frame.bytes().len() as u64)
        .sum::<u64>();
    let error = validate_execution(&batch, &execution, operation.limits).unwrap_err();
    assert!(matches!(
        error,
        TracerouteError::InvalidEvidence { sequence: 0, message }
            if message == format!(
                "successful exchange reported 0 sent bytes for {sent_bytes} exact frame bytes"
            )
    ));
    execution.stats.bytes = execution.sent_evidence[0].bytes().len() as u64;
    execution.sent[0].get_mut::<Ipv4>().unwrap().ttl += 1;

    let error = validate_execution(&batch, &execution, operation.limits).unwrap_err();

    assert!(matches!(
        error,
        TracerouteError::InvalidEvidence { sequence: 0, message }
            if message
                == "sent packet does not preserve the traceroute destination and probe identity"
    ));
}

#[test]
fn executor_capture_evidence_must_stay_within_declared_traceroute_limits() {
    let destination = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9));
    let operation = udp_traceroute_request(Target::Address(destination));
    let batch = build_batches(&operation, destination).unwrap().remove(0);
    let mut execution = UndecodedExecutor.execute(&batch).unwrap();
    execution.undecoded.push(frame_at(12));
    let limits = TracerouteLimits {
        max_evidence_frames: 2,
        ..operation.limits
    };
    assert!(matches!(
        validate_execution(&batch, &execution, limits),
        Err(TracerouteError::InvalidEvidence { sequence: 0, .. })
    ));

    execution.undecoded =
        vec![Frame::new(UNIX_EPOCH, crate::capture::LinkType::RAW, vec![0x45, 0]).unwrap()];
    let limits = TracerouteLimits {
        max_evidence_bytes: 1,
        ..operation.limits
    };
    assert!(matches!(
        validate_execution(&batch, &execution, limits),
        Err(TracerouteError::InvalidEvidence { sequence: 0, .. })
    ));
}

#[test]
fn unsolicited_hop_response_after_the_deadline_cannot_finish_the_trace() {
    struct LateHopExecutor;

    impl TracerouteExecutor for LateHopExecutor {
        fn execute(
            &mut self,
            batch: &TracerouteBatch,
        ) -> Result<TracerouteBatchExecution, BoundaryError> {
            let mut execution = MixedHopExecutor.execute(batch)?;
            for response in &mut execution.unsolicited {
                response.frame.timestamp += Duration::from_secs(1);
            }
            Ok(execution)
        }
    }

    let destination = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9));
    let operation = udp_traceroute_request(Target::Address(destination));
    let result = traceroute(
        &operation,
        &mut FixedAuthorizer {
            address: destination,
            operations: Vec::new(),
        },
        &default_registry().unwrap(),
        &mut LateHopExecutor,
        &mut NoopClock::default(),
    )
    .unwrap();

    assert_eq!(result.completion, TracerouteCompletion::Timeout);
    assert!(
        result
            .hops
            .iter()
            .flat_map(|hop| &hop.probes)
            .all(|probe| { probe.status == TracerouteProbeStatus::Timeout })
    );
}

#[test]
fn matched_response_deadline_uses_monotonic_latency_despite_wall_clock_skew() {
    struct PreSendMatchedExecutor;

    impl TracerouteExecutor for PreSendMatchedExecutor {
        fn execute(
            &mut self,
            batch: &TracerouteBatch,
        ) -> Result<TracerouteBatchExecution, BoundaryError> {
            let mut execution = MixedHopExecutor.execute(batch)?;
            let mut response = execution.unsolicited.remove(0);
            response.frame.timestamp = execution.sent_evidence[0]
                .timestamp
                .checked_sub(Duration::from_millis(1))
                .unwrap();
            execution.responses.push(TracerouteMatchedResponse {
                request_index: 0,
                response,
                latency: Duration::from_millis(1),
            });
            Ok(execution)
        }
    }

    let destination = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9));
    let result = traceroute(
        &udp_traceroute_request(Target::Address(destination)),
        &mut FixedAuthorizer {
            address: destination,
            operations: Vec::new(),
        },
        &default_registry().unwrap(),
        &mut PreSendMatchedExecutor,
        &mut NoopClock::default(),
    )
    .unwrap();

    let evidence = &result.hops[0].probes[0];
    assert_eq!(evidence.status, TracerouteProbeStatus::Response);
    assert!(evidence.received_at.unwrap() < evidence.sent_at);
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
        _hostname: &crate::client::target::Hostname,
        _limit: usize,
    ) -> Result<Vec<IpAddr>, TargetResolutionError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(self
            .answers
            .lock()
            .unwrap()
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

#[test]
fn hostname_policy_precedes_dns_and_every_answer_precedes_probe_execution() {
    let registry = default_registry().unwrap();
    let private = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9));

    let resolver = ScriptedResolver::new([vec![private]]);
    let calls = Arc::new(AtomicUsize::new(0));
    let mut executor = CountingRejectExecutor(Arc::clone(&calls));
    let policy = private_traceroute_policy();
    let mut authorizer = PolicyAuthorizer::new(&policy, &resolver);
    let error = traceroute(
        &udp_traceroute_request(Target::Hostname("lab.example".to_owned())),
        &mut authorizer,
        &registry,
        &mut executor,
        &mut NoopClock::default(),
    )
    .unwrap_err();
    assert_eq!(error.classification().code, "policy.hostname_resolution");
    assert_eq!(resolver.calls.load(Ordering::SeqCst), 0);
    assert_eq!(calls.load(Ordering::SeqCst), 0);

    let resolver = ScriptedResolver::new([vec![private, "8.8.8.8".parse().unwrap()]]);
    let mut policy = private_traceroute_policy();
    policy.allow_hostname_resolution = true;
    let mut operation = udp_traceroute_request(Target::Hostname("mixed.example".to_owned()));
    operation.address_family = AddressFamily::Ipv6;
    let mut authorizer = PolicyAuthorizer::new(&policy, &resolver);
    let error = traceroute(
        &operation,
        &mut authorizer,
        &registry,
        &mut executor,
        &mut NoopClock::default(),
    )
    .unwrap_err();
    assert_eq!(error.classification().code, "policy.public_destination");
    assert_eq!(resolver.calls.load(Ordering::SeqCst), 1);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn rerun_reauthorizes_rebound_hostname_before_another_probe() {
    let private = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9));
    let resolver =
        ScriptedResolver::new([vec![private], vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))]]);
    let mut policy = private_traceroute_policy();
    policy.allow_hostname_resolution = true;
    let registry = default_registry().unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let mut executor = CountingRejectExecutor(Arc::clone(&calls));
    let mut authorizer = PolicyAuthorizer::new(&policy, &resolver);
    let operation = udp_traceroute_request(Target::Hostname("changing.example".to_owned()));

    assert!(matches!(
        traceroute(
            &operation,
            &mut authorizer,
            &registry,
            &mut executor,
            &mut NoopClock::default(),
        ),
        Err(TracerouteError::Execution { .. })
    ));
    assert!(matches!(
        traceroute(
            &operation,
            &mut authorizer,
            &registry,
            &mut executor,
            &mut NoopClock::default(),
        ),
        Err(TracerouteError::Authorization(_))
    ));
    assert_eq!(resolver.calls.load(Ordering::SeqCst), 2);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn ipv4_classifier_accepts_intermediate_destination_and_unreachable_responses() {
    let registry = default_registry().unwrap();
    let local = Ipv4Addr::new(10, 0, 0, 1);
    let remote = Ipv4Addr::new(10, 0, 0, 9);
    let router = Ipv4Addr::new(10, 0, 0, 254);
    let mut udp_probe_packet = TracerouteProbe {
        sequence: 0,
        address: IpAddr::V4(remote),
        strategy: TracerouteStrategy::Udp,
        destination_port: Some(DEFAULT_TRACEROUTE_UDP_PORT),
        hop_limit: 1,
        attempt: 1,
    }
    .packet();
    udp_probe_packet.get_mut::<Ipv4>().unwrap().source = local;
    let quote = ipv4_udp_quote(&udp_probe_packet);

    let intermediate = icmpv4_error(router, local, 11, 0, quote.clone(), 2, Vec::new());
    assert_eq!(
        classify_traceroute_response(
            &registry,
            TracerouteStrategy::Udp,
            &udp_probe_packet,
            &intermediate,
        )
        .unwrap()
        .kind,
        TracerouteResponseKind::Intermediate
    );
    let reached = icmpv4_error(remote, local, 3, 3, quote.clone(), 2, Vec::new());
    assert_eq!(
        classify_traceroute_response(
            &registry,
            TracerouteStrategy::Udp,
            &udp_probe_packet,
            &reached,
        )
        .unwrap()
        .kind,
        TracerouteResponseKind::DestinationReached
    );
    let unreachable = icmpv4_error(router, local, 3, 1, quote.clone(), 2, Vec::new());
    assert_eq!(
        classify_traceroute_response(
            &registry,
            TracerouteStrategy::Udp,
            &udp_probe_packet,
            &unreachable,
        )
        .unwrap()
        .kind,
        TracerouteResponseKind::Unreachable
    );
}

#[test]
fn ipv4_classifier_rejects_corrupt_unrelated_and_malformed_evidence() {
    let registry = default_registry().unwrap();
    let local = Ipv4Addr::new(10, 0, 0, 1);
    let remote = Ipv4Addr::new(10, 0, 0, 9);
    let router = Ipv4Addr::new(10, 0, 0, 254);
    let mut udp_probe_packet = TracerouteProbe {
        sequence: 0,
        address: IpAddr::V4(remote),
        strategy: TracerouteStrategy::Udp,
        destination_port: Some(DEFAULT_TRACEROUTE_UDP_PORT),
        hop_limit: 1,
        attempt: 1,
    }
    .packet();
    udp_probe_packet.get_mut::<Ipv4>().unwrap().source = local;
    let quote = ipv4_udp_quote(&udp_probe_packet);

    let corrupt = icmpv4_error(
        router,
        local,
        11,
        0,
        quote,
        2,
        vec![Diagnostic::warning("icmpv4.checksum", "invalid checksum")],
    );
    assert!(
        classify_traceroute_response(
            &registry,
            TracerouteStrategy::Udp,
            &udp_probe_packet,
            &corrupt,
        )
        .is_none()
    );

    let mut unrelated_quote = ipv4_udp_quote(&udp_probe_packet);
    unrelated_quote[19] ^= 1;
    let unrelated = icmpv4_error(router, local, 11, 0, unrelated_quote, 2, Vec::new());
    assert!(
        classify_traceroute_response(
            &registry,
            TracerouteStrategy::Udp,
            &udp_probe_packet,
            &unrelated,
        )
        .is_none()
    );
    let malformed = icmpv4_error(router, local, 11, 0, vec![0_u8; 3], 2, Vec::new());
    assert!(
        classify_traceroute_response(
            &registry,
            TracerouteStrategy::Udp,
            &udp_probe_packet,
            &malformed,
        )
        .is_none()
    );
}

#[test]
fn ipv6_classifier_accepts_intermediate_response() {
    let registry = default_registry().unwrap();
    let local6: Ipv6Addr = "fd00::1".parse().unwrap();
    let remote6: Ipv6Addr = "fd00::9".parse().unwrap();
    let router6: Ipv6Addr = "fd00::fe".parse().unwrap();
    let mut udp_probe_packet = TracerouteProbe {
        sequence: 9,
        address: IpAddr::V6(remote6),
        strategy: TracerouteStrategy::Udp,
        destination_port: Some(DEFAULT_TRACEROUTE_UDP_PORT + 9),
        hop_limit: 4,
        attempt: 1,
    }
    .packet();
    udp_probe_packet.get_mut::<Ipv6>().unwrap().source = local6;
    let intermediate6 = icmpv6_error(router6, local6, 3, 0, ipv6_udp_quote(&udp_probe_packet), 11);
    assert_eq!(
        classify_traceroute_response(
            &registry,
            TracerouteStrategy::Udp,
            &udp_probe_packet,
            &intermediate6,
        )
        .unwrap()
        .kind,
        TracerouteResponseKind::Intermediate
    );
}

#[test]
fn tunneled_direct_reply_reaches_the_inner_destination() {
    let registry = default_registry().unwrap();
    let outer_source: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let outer_destination: Ipv6Addr = "2001:db8::2".parse().unwrap();
    let inner_source: Ipv6Addr = "2001:db8:1::1".parse().unwrap();
    let inner_destination: Ipv6Addr = "2001:db8:1::2".parse().unwrap();
    let mut request = Packet::new();
    request
        .push(Ipv6 {
            source: outer_source,
            destination: outer_destination,
            ..Ipv6::default()
        })
        .push(Ipv6 {
            source: inner_source,
            destination: inner_destination,
            ..Ipv6::default()
        })
        .push(Udp {
            source_port: TRACEROUTE_SOURCE_PORT,
            destination_port: DEFAULT_TRACEROUTE_UDP_PORT,
            ..Udp::default()
        });
    let mut reply = Packet::new();
    reply
        .push(Ipv6 {
            source: "2001:db8:ffff::1".parse().unwrap(),
            destination: "2001:db8:ffff::2".parse().unwrap(),
            ..Ipv6::default()
        })
        .push(Ipv6 {
            source: inner_destination,
            destination: inner_source,
            ..Ipv6::default()
        })
        .push(Udp {
            source_port: DEFAULT_TRACEROUTE_UDP_PORT,
            destination_port: TRACEROUTE_SOURCE_PORT,
            ..Udp::default()
        });

    let classification = classify_traceroute_response(
        &registry,
        TracerouteStrategy::Udp,
        &request,
        &decoded_at(reply, 2, Vec::new()),
    )
    .unwrap();

    assert_eq!(
        classification.kind,
        TracerouteResponseKind::DestinationReached
    );
    assert_eq!(classification.responder, IpAddr::V6(inner_destination));
}

#[test]
fn tcp_strategy_builds_hop_limit_and_accepts_direct_terminal_reply() {
    let registry = default_registry().unwrap();
    let local = Ipv4Addr::new(10, 0, 0, 1);
    let remote = Ipv4Addr::new(10, 0, 0, 9);
    let mut tcp_request = TracerouteProbe {
        sequence: 17,
        address: IpAddr::V4(remote),
        strategy: TracerouteStrategy::Tcp,
        destination_port: Some(443),
        hop_limit: 7,
        attempt: 1,
    }
    .packet();
    assert_eq!(tcp_request.get::<Ipv4>().unwrap().ttl, 7);
    tcp_request.get_mut::<Ipv4>().unwrap().source = local;
    let mut tcp_reply = Packet::new();
    tcp_reply
        .push(Ipv4 {
            source: remote,
            destination: local,
            ..Ipv4::default()
        })
        .push(Tcp {
            source_port: 443,
            destination_port: TRACEROUTE_SOURCE_PORT,
            flags: Tcp::SYN | Tcp::ACK,
            acknowledgment: 18,
            ..Tcp::default()
        });
    assert_eq!(
        classify_traceroute_response(
            &registry,
            TracerouteStrategy::Tcp,
            &tcp_request,
            &decoded_at(tcp_reply, 2, Vec::new()),
        )
        .unwrap()
        .kind,
        TracerouteResponseKind::DestinationReached
    );
}

#[test]
fn icmp_strategy_builds_hop_limit_and_accepts_direct_terminal_reply() {
    let registry = default_registry().unwrap();
    let local6: Ipv6Addr = "fd00::1".parse().unwrap();
    let remote6: Ipv6Addr = "fd00::9".parse().unwrap();
    let mut echo_request = TracerouteProbe {
        sequence: 23,
        address: IpAddr::V6(remote6),
        strategy: TracerouteStrategy::Icmp,
        destination_port: None,
        hop_limit: 9,
        attempt: 1,
    }
    .packet();
    assert_eq!(echo_request.get::<Ipv6>().unwrap().hop_limit, 9);
    echo_request.get_mut::<Ipv6>().unwrap().source = local6;
    let mut echo_reply = Packet::new();
    echo_reply
        .push(Ipv6 {
            source: remote6,
            destination: local6,
            ..Ipv6::default()
        })
        .push(Icmpv6 {
            icmp_type: 129,
            body: traceroute_identity(23),
            ..Icmpv6::default()
        });
    assert_eq!(
        classify_traceroute_response(
            &registry,
            TracerouteStrategy::Icmp,
            &echo_request,
            &decoded_at(echo_reply, 2, Vec::new()),
        )
        .unwrap()
        .kind,
        TracerouteResponseKind::DestinationReached
    );
}

#[test]
fn udp_destination_port_overflow_is_rejected_before_authorized_probe_construction() {
    let destination = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9));
    let mut operation = udp_traceroute_request(Target::Address(destination));
    operation.destination_port = Some(u16::MAX);
    let mut authorizer = FixedAuthorizer {
        address: destination,
        operations: Vec::new(),
    };
    let calls = Arc::new(AtomicUsize::new(0));
    let error = traceroute(
        &operation,
        &mut authorizer,
        &default_registry().unwrap(),
        &mut CountingRejectExecutor(Arc::clone(&calls)),
        &mut NoopClock::default(),
    )
    .unwrap_err();
    assert!(matches!(error, TracerouteError::InvalidPort { .. }));
    assert!(authorizer.operations.is_empty());
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn udp_and_tcp_traceroute_reject_zero_destination_ports() {
    let destination = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9));
    for strategy in [TracerouteStrategy::Udp, TracerouteStrategy::Tcp] {
        let mut request = udp_traceroute_request(Target::Address(destination));
        request.strategy = strategy;
        request.destination_port = Some(0);

        assert!(matches!(
            request.validate(),
            Err(TracerouteError::InvalidPort { message })
                if message == "UDP and TCP traceroute require a non-zero destination port"
        ));
    }
}

#[test]
fn generated_hop_batches_share_network_identity_and_preserve_every_attempt() {
    for destination in [
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9)),
        IpAddr::V6("fd00::9".parse().unwrap()),
    ] {
        let mut request = udp_traceroute_request(Target::Address(destination));
        request.probes_per_hop = 3;
        let batches = build_batches(&request, destination).unwrap();
        assert_eq!(batches.len(), 2);

        for batch in &batches {
            assert_eq!(batch.probes.len(), 3);
            assert!(
                batch
                    .probes
                    .iter()
                    .all(|probe| sent_traceroute_probe_matches(probe, &probe.packet()))
            );
        }

        match destination {
            IpAddr::V4(_) => {
                let first = batches[0].probes[0].packet();
                let second = batches[1].probes[0].packet();
                let first_id = first.get::<Ipv4>().unwrap().identification;
                assert!(
                    batches[0].probes.iter().all(|probe| probe
                        .packet()
                        .get::<Ipv4>()
                        .unwrap()
                        .identification
                        == first_id)
                );
                assert_ne!(second.get::<Ipv4>().unwrap().identification, first_id);
            }
            IpAddr::V6(_) => {
                let first = batches[0].probes[0].packet();
                let second = batches[1].probes[0].packet();
                let first_flow_label = first.get::<Ipv6>().unwrap().flow_label;
                assert!(
                    batches[0].probes.iter().all(|probe| probe
                        .packet()
                        .get::<Ipv6>()
                        .unwrap()
                        .flow_label
                        == first_flow_label)
                );
                assert_ne!(second.get::<Ipv6>().unwrap().flow_label, first_flow_label);
            }
        }
    }
}

fn frame_at(seconds: u64) -> Frame {
    Frame::new(
        UNIX_EPOCH + Duration::from_secs(seconds),
        crate::capture::LinkType::RAW,
        Bytes::from_static(&[0x45]),
    )
    .unwrap()
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
    let ip = packet.get::<Ipv4>().unwrap();
    let udp = packet.get::<Udp>().unwrap();
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

fn ipv6_udp_quote(packet: &Packet) -> Vec<u8> {
    let ip = packet.get::<Ipv6>().unwrap();
    let udp = packet.get::<Udp>().unwrap();
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

fn icmpv6_error(
    source: Ipv6Addr,
    destination: Ipv6Addr,
    icmp_type: u8,
    code: u8,
    quote: Vec<u8>,
    seconds: u64,
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
    decoded_at(packet, seconds, Vec::new())
}
