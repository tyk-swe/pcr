// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::*;

#[test]
fn hostname_policy_denial_precedes_resolution_and_probe_construction() {
    let resolver = ScriptedResolver::new([vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))]]);
    let executor_calls = Arc::new(AtomicUsize::new(0));
    let mut executor = CountingRejectExecutor {
        calls: Arc::clone(&executor_calls),
    };
    let registry = default_registry().unwrap();
    let target = Target::Hostname("lab.example".to_owned());
    let policy = private_scan_policy();
    let mut authorizer = PolicyAuthorizer::new(&policy, &resolver);

    let error = scan(
        &tcp_scan_request(target),
        &mut authorizer,
        &registry,
        &mut executor,
        &mut NoopClock,
    )
    .unwrap_err();

    assert_eq!(error.classification().code, "policy.hostname_resolution");
    assert_eq!(resolver.calls.load(Ordering::SeqCst), 0);
    assert_eq!(executor_calls.load(Ordering::SeqCst), 0);
}

#[test]
fn every_mixed_resolution_answer_is_authorized_before_family_filter_or_probe() {
    let resolver = ScriptedResolver::new([vec![
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
    ]]);
    let executor_calls = Arc::new(AtomicUsize::new(0));
    let mut executor = CountingRejectExecutor {
        calls: Arc::clone(&executor_calls),
    };
    let registry = default_registry().unwrap();
    let mut policy = private_scan_policy();
    policy.allow_hostname_resolution = true;
    let mut operation = tcp_scan_request(Target::Hostname("mixed.example".to_owned()));
    operation.address_family = AddressFamily::Ipv6;
    let mut authorizer = PolicyAuthorizer::new(&policy, &resolver);

    let error = scan(
        &operation,
        &mut authorizer,
        &registry,
        &mut executor,
        &mut NoopClock,
    )
    .unwrap_err();

    assert_eq!(error.classification().code, "policy.public_destination");
    assert!(error.to_string().contains("8.8.8.8"));
    assert_eq!(resolver.calls.load(Ordering::SeqCst), 1);
    assert_eq!(executor_calls.load(Ordering::SeqCst), 0);
}

#[test]
fn rerunning_scan_reauthorizes_changed_addresses_before_another_probe() {
    let resolver = ScriptedResolver::new([
        vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))],
        vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))],
    ]);
    let executor_calls = Arc::new(AtomicUsize::new(0));
    let mut executor = CountingRejectExecutor {
        calls: Arc::clone(&executor_calls),
    };
    let registry = default_registry().unwrap();
    let mut policy = private_scan_policy();
    policy.allow_hostname_resolution = true;
    let operation = tcp_scan_request(Target::Hostname("changing.example".to_owned()));
    let mut authorizer = PolicyAuthorizer::new(&policy, &resolver);

    assert!(matches!(
        scan(
            &operation,
            &mut authorizer,
            &registry,
            &mut executor,
            &mut NoopClock,
        ),
        Err(ScanError::Execution { .. })
    ));
    assert_eq!(executor_calls.load(Ordering::SeqCst), 1);

    assert!(matches!(
        scan(
            &operation,
            &mut authorizer,
            &registry,
            &mut executor,
            &mut NoopClock,
        ),
        Err(ScanError::Authorization(_))
    ));
    assert_eq!(resolver.calls.load(Ordering::SeqCst), 2);
    assert_eq!(executor_calls.load(Ordering::SeqCst), 1);
}

#[test]
fn aggregate_packet_and_wire_byte_policy_precede_probe_execution() {
    for (packet_limit, byte_limit, expected_code) in [
        (0, 1_000_000, "policy.packet_limit"),
        (1_000, 1, "policy.byte_limit"),
    ] {
        let resolver = ScriptedResolver::new([]);
        let executor_calls = Arc::new(AtomicUsize::new(0));
        let mut executor = CountingRejectExecutor {
            calls: Arc::clone(&executor_calls),
        };
        let registry = default_registry().unwrap();
        let mut policy = private_scan_policy();
        policy.max_packets_per_operation = packet_limit;
        policy.max_bytes_per_operation = byte_limit;
        let mut authorizer = PolicyAuthorizer::new(&policy, &resolver);
        let operation = tcp_scan_request(Target::Address(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))));

        let error = scan(
            &operation,
            &mut authorizer,
            &registry,
            &mut executor,
            &mut NoopClock,
        )
        .unwrap_err();

        assert_eq!(error.classification().code, expected_code);
        assert_eq!(executor_calls.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn aggregate_duration_precedes_operation_authorization() {
    struct CountingAuthorizer {
        operation_calls: usize,
    }

    impl Authorizer for CountingAuthorizer {
        fn resolve_and_authorize(
            &mut self,
            target: &Target,
        ) -> Result<crate::workflow::target::Authorized, BoundaryError> {
            Ok(crate::workflow::target::Authorized {
                declared: target.to_string(),
                addresses: vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))],
            })
        }

        fn authorize_operation(
            &mut self,
            _packets: u64,
            _maximum_wire_bytes: u64,
        ) -> Result<(), BoundaryError> {
            self.operation_calls += 1;
            Ok(())
        }
    }

    let mut operation = tcp_scan_request(Target::Address(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))));
    operation.limits.max_duration = Duration::from_micros(1);
    let mut authorizer = CountingAuthorizer { operation_calls: 0 };
    let error = scan(
        &operation,
        &mut authorizer,
        &default_registry().unwrap(),
        &mut CountingRejectExecutor {
            calls: Arc::new(AtomicUsize::new(0)),
        },
        &mut NoopClock,
    )
    .unwrap_err();

    assert!(matches!(error, ScanError::DurationLimit { .. }));
    assert_eq!(authorizer.operation_calls, 0);
}

#[test]
fn slow_executor_expires_before_the_next_scan_batch() {
    struct SlowExecutor {
        calls: usize,
        inner: TimeoutExecutor,
    }

    impl ScanExecutor for SlowExecutor {
        fn execute(&mut self, batch: &ScanBatch) -> Result<ScanBatchExecution, BoundaryError> {
            self.calls += 1;
            std::thread::sleep(Duration::from_millis(20));
            self.inner.execute(batch)
        }
    }

    let address = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let mut request = tcp_scan_request(Target::Address(address));
    request.ports = vec![80, 81];
    request.timeout = Duration::from_millis(1);
    request.limits.batch_size = 1;
    request.limits.max_duration = Duration::from_millis(5);
    let mut executor = SlowExecutor {
        calls: 0,
        inner: TimeoutExecutor::new(),
    };

    let error = scan(
        &request,
        &mut AddressListAuthorizer {
            addresses: vec![address],
        },
        &default_registry().unwrap(),
        &mut executor,
        &mut NoopClock,
    )
    .unwrap_err();

    assert!(matches!(error, ScanError::DurationLimit { .. }));
    assert_eq!(executor.calls, 1);
}

#[test]
fn candidate_heavy_batch_expires_before_the_next_scan_execution() {
    struct CandidateHeavyExecutor {
        calls: usize,
    }

    impl ScanExecutor for CandidateHeavyExecutor {
        fn execute(&mut self, batch: &ScanBatch) -> Result<ScanBatchExecution, BoundaryError> {
            self.calls += 1;
            let mut execution = OpenTcpExecutor(TimeoutExecutor::new()).execute(batch)?;
            let sent_at = execution.sent_evidence[0].timestamp;
            let mut candidate = execution.responses.pop().unwrap();
            candidate.latency = Duration::ZERO;
            candidate.response.frame.timestamp = sent_at;
            execution.responses = vec![candidate; DEFAULT_CAPTURE_QUEUE_FRAMES];
            execution.stats.elapsed = Duration::ZERO;
            Ok(execution)
        }
    }

    let address = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let mut request = tcp_scan_request(Target::Address(address));
    request.ports = vec![80, 81];
    request.timeout = Duration::from_nanos(1);
    request.limits.batch_size = 1;
    request.limits.max_duration = Duration::from_millis(5);
    let mut executor = CandidateHeavyExecutor { calls: 0 };

    let error = scan(
        &request,
        &mut AddressListAuthorizer {
            addresses: vec![address],
        },
        &default_registry().unwrap(),
        &mut executor,
        &mut NoopClock,
    )
    .unwrap_err();

    assert!(matches!(error, ScanError::DurationLimit { .. }));
    assert_eq!(executor.calls, 1);
}
