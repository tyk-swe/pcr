// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::*;

#[test]
fn batching_attempts_rate_and_timeout_evidence_are_deterministic() {
    let registry = default_registry().unwrap();
    let target = Target::Address(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
    let mut operation = tcp_scan_request(target);
    operation.ports = vec![80, 81, 82, 83];
    operation.attempts = 2;
    operation.probes_per_second = Some(2);
    operation.limits.batch_size = 2;
    let resolver = ScriptedResolver::new([]);
    let policy = private_scan_policy();
    let mut authorizer = PolicyAuthorizer::new(&policy, &resolver);
    let mut executor = TimeoutExecutor::new();
    let mut clock = RecordingClock::default();

    let result = scan(
        &operation,
        &mut authorizer,
        &registry,
        &mut executor,
        &mut clock,
    )
    .unwrap();

    assert_eq!(executor.batches.len(), 4);
    assert_eq!(executor.batches[0][0], (1, vec![Some(80), Some(81)]));
    assert_eq!(executor.batches[1][0], (1, vec![Some(82), Some(83)]));
    assert_eq!(executor.batches[2][0], (2, vec![Some(80), Some(81)]));
    assert_eq!(executor.batches[3][0], (2, vec![Some(82), Some(83)]));
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
fn duplicate_addresses_and_ports_preserve_first_seen_order_after_family_filtering() {
    let first = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let second = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    let excluded = IpAddr::V6(Ipv6Addr::LOCALHOST);
    let mut operation = tcp_scan_request(Target::Hostname("ordered.example".to_owned()));
    operation.address_family = AddressFamily::Ipv4;
    operation.ports = vec![443, 80, 443, 22, 80];
    operation.limits.batch_size = 3;
    let result = scan(
        &operation,
        &mut AddressListAuthorizer {
            addresses: vec![excluded, first, first, second, first, excluded],
        },
        &default_registry().unwrap(),
        &mut TimeoutExecutor::new(),
        &mut NoopClock,
    )
    .unwrap();

    assert_eq!(result.resolved_addresses, vec![first, second]);
    assert_eq!(
        result
            .endpoints
            .iter()
            .map(|endpoint| (endpoint.address, endpoint.port))
            .collect::<Vec<_>>(),
        vec![
            (first, Some(443)),
            (first, Some(80)),
            (first, Some(22)),
            (second, Some(443)),
            (second, Some(80)),
            (second, Some(22)),
        ]
    );
}

#[test]
fn unsorted_matched_groups_preserve_endpoint_attempt_and_fully_tied_evidence_order() {
    struct ReverseTiedResponses(TimeoutExecutor);

    impl ScanExecutor for ReverseTiedResponses {
        fn execute(&mut self, batch: &ScanBatch) -> Result<ScanBatchExecution, BoundaryError> {
            let mut execution = self.0.execute(batch)?;
            for request_index in (0..batch.probes.len()).rev() {
                let probe = &batch.probes[request_index];
                let IpAddr::V4(remote) = probe.address else {
                    unreachable!("regression uses IPv4 probes")
                };
                let mut first = decoded(
                    tcp_packet(
                        remote,
                        Ipv4Addr::new(10, 0, 0, 1),
                        probe.port.expect("TCP probe has a port"),
                        50_000,
                        Tcp::SYN | Tcp::ACK,
                    ),
                    Vec::new(),
                );
                first
                    .packet
                    .get_mut::<Tcp>()
                    .expect("response has TCP")
                    .acknowledgment = (probe.sequence as u32).wrapping_add(1);
                first.frame.timestamp =
                    execution.sent_evidence[request_index].timestamp + Duration::from_millis(1);
                first.frame.interface = Some(1);
                let mut second = first.clone();
                second.frame.interface = Some(2);
                execution.responses.extend([
                    ScanMatchedResponse {
                        request_index,
                        response: first,
                        latency: Duration::from_millis(1),
                    },
                    ScanMatchedResponse {
                        request_index,
                        response: second,
                        latency: Duration::from_millis(1),
                    },
                ]);
            }
            Ok(execution)
        }
    }

    let first = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let second = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    let mut operation = tcp_scan_request(Target::Hostname("grouped.example".to_owned()));
    operation.ports = vec![443, 80, 22];
    operation.attempts = 2;
    operation.timeout = Duration::from_millis(10);
    operation.limits.batch_size = 3;
    let result = scan(
        &operation,
        &mut AddressListAuthorizer {
            addresses: vec![first, second],
        },
        &default_registry().unwrap(),
        &mut ReverseTiedResponses(TimeoutExecutor::new()),
        &mut NoopClock,
    )
    .unwrap();

    assert_eq!(result.endpoints.len(), 6);
    for (endpoint_index, endpoint) in result.endpoints.iter().enumerate() {
        let expected_address = if endpoint_index < 3 { first } else { second };
        let expected_port = [443, 80, 22][endpoint_index % 3];
        assert_eq!(
            (endpoint.address, endpoint.port),
            (expected_address, Some(expected_port))
        );
        assert_eq!(endpoint.classification, ScanClassification::Open);
        assert_eq!(
            endpoint
                .evidence
                .iter()
                .map(|evidence| evidence.attempt)
                .collect::<Vec<_>>(),
            vec![1, 2]
        );
        assert!(endpoint.evidence.iter().all(|evidence| {
            evidence.status == ScanProbeStatus::Response
                && evidence
                    .response
                    .as_ref()
                    .is_some_and(|frame| frame.interface == Some(1))
        }));
    }
}

#[test]
fn undecodable_evidence_is_bounded_across_the_scan() {
    let registry = default_registry().unwrap();
    let mut operation = tcp_scan_request(Target::Address(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))));
    operation.limits.batch_size = 1;
    operation.limits.max_evidence_frames = 2;
    operation.limits.max_evidence_bytes = 2;
    operation.limits.max_undecoded = 1;
    let resolver = ScriptedResolver::new([]);
    let policy = private_scan_policy();
    let mut authorizer = PolicyAuthorizer::new(&policy, &resolver);
    let mut executor = UndecodedExecutor(TimeoutExecutor::new());

    let result = scan(
        &operation,
        &mut authorizer,
        &registry,
        &mut executor,
        &mut NoopClock,
    )
    .unwrap();

    assert_eq!(result.undecoded.len(), 1);
    assert!(
        result
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "scan.undecoded_limit")
    );
}

#[test]
fn correlated_response_becomes_exact_open_evidence() {
    let registry = default_registry().unwrap();
    let mut operation = tcp_scan_request(Target::Address(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))));
    operation.timeout = Duration::from_millis(10);
    let resolver = ScriptedResolver::new([]);
    let policy = private_scan_policy();
    let mut authorizer = PolicyAuthorizer::new(&policy, &resolver);
    let mut executor = OpenTcpExecutor(TimeoutExecutor::new());

    let result = scan(
        &operation,
        &mut authorizer,
        &registry,
        &mut executor,
        &mut NoopClock,
    )
    .unwrap();

    let endpoint = &result.endpoints[0];
    assert_eq!(endpoint.classification, ScanClassification::Open);
    assert_eq!(endpoint.evidence[0].status, ScanProbeStatus::Response);
    assert_eq!(
        endpoint.evidence[0].classification,
        ScanClassification::Open
    );
    assert_eq!(endpoint.evidence[0].latency, Some(Duration::from_millis(4)));
    assert!(endpoint.evidence[0].response.is_some());
}

#[test]
fn matched_response_deadline_uses_monotonic_latency_despite_wall_clock_skew() {
    struct PreSendMatchedExecutor;

    impl ScanExecutor for PreSendMatchedExecutor {
        fn execute(&mut self, batch: &ScanBatch) -> Result<ScanBatchExecution, BoundaryError> {
            let mut execution = OpenTcpExecutor(TimeoutExecutor::new()).execute(batch)?;
            execution.responses[0].response.frame.timestamp = execution.sent_evidence[0]
                .timestamp
                .checked_sub(Duration::from_millis(1))
                .unwrap();
            Ok(execution)
        }
    }

    let mut operation = tcp_scan_request(Target::Address(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))));
    operation.timeout = Duration::from_millis(10);
    let result = scan(
        &operation,
        &mut PolicyAuthorizer::new(&private_scan_policy(), &ScriptedResolver::new([])),
        &default_registry().unwrap(),
        &mut PreSendMatchedExecutor,
        &mut NoopClock,
    )
    .unwrap();

    let evidence = &result.endpoints[0].evidence[0];
    assert_eq!(evidence.status, ScanProbeStatus::Response);
    assert!(evidence.received_at.unwrap() < evidence.sent_at);
}

#[test]
fn executor_cannot_replace_the_authorized_scan_probe() {
    let operation = tcp_scan_request(Target::Address(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))));
    let batch = build_batches(
        &operation,
        &[IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))],
        &[Some(80)],
    )
    .unwrap()
    .remove(0);
    let mut execution = TimeoutExecutor::new().execute(&batch).unwrap();
    let mut layer2 = execution.sent[0].clone();
    layer2
        .insert(0, crate::protocol::link::Ethernet::default())
        .unwrap();
    assert!(sent_scan_probe_matches(&batch.probes[0], &layer2));
    layer2.push(crate::protocol::link::Ethernet::default());
    assert!(!sent_scan_probe_matches(&batch.probes[0], &layer2));
    execution.stats.bytes = 0;
    let sent_bytes = execution.sent_evidence[0].bytes().len() as u64;
    let error = validate_exchange_evidence(&batch, &execution, operation.limits).unwrap_err();
    assert!(matches!(
        error,
        ScanError::InvalidEvidence { sequence: 0, message }
            if message == format!(
                "successful exchange reported 0 sent bytes for {sent_bytes} exact frame bytes"
            )
    ));
    execution.stats.bytes = execution.sent_evidence[0].bytes().len() as u64;
    execution.sent[0].get_mut::<Ipv4>().unwrap().destination = Ipv4Addr::new(10, 0, 0, 99);

    let error = validate_exchange_evidence(&batch, &execution, operation.limits).unwrap_err();

    assert!(matches!(
        error,
        ScanError::InvalidEvidence { sequence: 0, message }
            if message
                == "sent packet does not preserve the scan destination and probe identity"
    ));
}

#[test]
fn executor_capture_evidence_must_stay_within_declared_scan_limits() {
    let operation = tcp_scan_request(Target::Address(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))));
    let batch = build_batches(
        &operation,
        &[IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))],
        &[Some(80)],
    )
    .unwrap()
    .remove(0);
    let mut execution = TimeoutExecutor::new().execute(&batch).unwrap();
    execution.undecoded = vec![
        Frame::new(UNIX_EPOCH, LinkType::RAW, vec![0xff]).unwrap(),
        Frame::new(UNIX_EPOCH, LinkType::RAW, vec![0xfe]).unwrap(),
    ];
    let limits = ScanLimits {
        max_evidence_frames: 1,
        ..operation.limits
    };
    assert!(matches!(
        validate_exchange_evidence(&batch, &execution, limits),
        Err(ScanError::InvalidEvidence { sequence: 0, .. })
    ));

    execution.undecoded = vec![Frame::new(UNIX_EPOCH, LinkType::RAW, vec![0xff, 0xfe]).unwrap()];
    let limits = ScanLimits {
        max_evidence_bytes: 1,
        ..operation.limits
    };
    assert!(matches!(
        validate_exchange_evidence(&batch, &execution, limits),
        Err(ScanError::InvalidEvidence { sequence: 0, .. })
    ));
}

#[test]
fn unsolicited_response_after_the_probe_deadline_remains_a_timeout() {
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

    let operation = tcp_scan_request(Target::Address(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))));
    let result = scan(
        &operation,
        &mut PolicyAuthorizer::new(&private_scan_policy(), &ScriptedResolver::new([])),
        &default_registry().unwrap(),
        &mut LateResponseExecutor(TimeoutExecutor::new()),
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
fn equal_rank_candidates_choose_earliest_evidence_independent_of_source_list() {
    struct ReorderedResponses(TimeoutExecutor);

    impl ScanExecutor for ReorderedResponses {
        fn execute(&mut self, batch: &ScanBatch) -> Result<ScanBatchExecution, BoundaryError> {
            let mut execution = self.0.execute(batch)?;
            let reply = || {
                decoded(
                    tcp_packet(
                        Ipv4Addr::new(10, 0, 0, 2),
                        Ipv4Addr::new(10, 0, 0, 1),
                        80,
                        50_000,
                        Tcp::SYN | Tcp::ACK,
                    ),
                    Vec::new(),
                )
            };
            let mut later = reply();
            later.frame.timestamp = execution.sent_evidence[0].timestamp + Duration::from_millis(5);
            let mut earlier = reply();
            earlier.frame.timestamp =
                execution.sent_evidence[0].timestamp + Duration::from_millis(2);
            execution.responses.push(ScanMatchedResponse {
                request_index: 0,
                response: later,
                latency: Duration::from_millis(5),
            });
            execution.unsolicited.push(earlier);
            Ok(execution)
        }
    }

    let mut operation = tcp_scan_request(Target::Address(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))));
    operation.timeout = Duration::from_millis(10);
    let result = scan(
        &operation,
        &mut PolicyAuthorizer::new(&private_scan_policy(), &ScriptedResolver::new([])),
        &default_registry().unwrap(),
        &mut ReorderedResponses(TimeoutExecutor::new()),
        &mut NoopClock,
    )
    .unwrap();

    assert_eq!(
        result.endpoints[0].evidence[0].latency,
        Some(Duration::from_millis(2))
    );
}
