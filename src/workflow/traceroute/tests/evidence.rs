use std::net::Ipv4Addr;
use std::result::Result;
use std::time::UNIX_EPOCH;

use super::super::engine::{build_batches, sent_traceroute_probe_matches, validate_execution};
use super::super::*;
use super::support::{
    FixedAuthorizer, MixedHopExecutor, NoopClock, UndecodedExecutor, frame_at, icmpv4_error,
    ipv4_udp_quote, udp_traceroute_request,
};
use crate::net::capture::CaptureStatistics;
use crate::protocol::builtin::registry as default_registry;

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
