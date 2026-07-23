// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::*;

fn private_policy() -> TrafficPolicy {
    TrafficPolicy {
        allow_public_destinations: false,
        allow_hostname_resolution: false,
        max_packets_per_operation: 32,
        max_bytes_per_operation: 1_000_000,
        ..TrafficPolicy::default()
    }
}

fn retry_request() -> DnsRequest {
    DnsRequest {
        server: Target::Hostname("resolver.example".to_owned()),
        address_family: AddressFamily::Any,
        server_port: 53,
        source_port: 50_000,
        query_name: "www.example.test".to_owned(),
        query_type: DnsQueryType::A,
        transaction_id: 0x5043,
        recursion_desired: true,
        attempts: 2,
        timeout: Duration::from_millis(10),
        queries_per_second: None,
        limits: DnsLimits::default(),
    }
}

#[test]
fn hostname_intent_is_denied_before_resolver_or_executor_side_effects() {
    let resolver = ScriptedResolver::new([vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 53))]]);
    let policy = private_policy();
    let mut authorizer = PolicyAuthorizer::new(&policy, &resolver);
    let mut executor = TimeoutExecutor::default();
    let error = dns(
        &retry_request(),
        &mut authorizer,
        &default_registry().unwrap(),
        &mut executor,
        &mut NoopClock,
    )
    .unwrap_err();
    assert_eq!(error.classification().code, "policy.hostname_resolution");
    assert_eq!(resolver.calls.load(Ordering::SeqCst), 0);
    assert_eq!(executor.calls, 0);
}

#[test]
fn every_mixed_answer_is_authorized_before_family_selection() {
    let resolver = ScriptedResolver::new([vec![
        IpAddr::V6(Ipv6Addr::LOCALHOST),
        IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
    ]]);
    let mut policy = private_policy();
    policy.allow_hostname_resolution = true;
    let mut authorizer = PolicyAuthorizer::new(&policy, &resolver);
    let mut executor = TimeoutExecutor::default();
    let mut request = retry_request();
    request.address_family = AddressFamily::Ipv6;
    request.attempts = 1;
    let error = dns(
        &request,
        &mut authorizer,
        &default_registry().unwrap(),
        &mut executor,
        &mut NoopClock,
    )
    .unwrap_err();
    assert_eq!(error.classification().code, "policy.public_destination");
    assert!(error.to_string().contains("8.8.8.8"));
    assert_eq!(executor.calls, 0);
}

#[test]
fn every_retry_reresolves_and_reauthorizes_rebinding_before_probe_construction() {
    let resolver = ScriptedResolver::new([
        vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 53))],
        vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))],
    ]);
    let mut policy = private_policy();
    policy.allow_hostname_resolution = true;
    let mut authorizer = PolicyAuthorizer::new(&policy, &resolver);
    let mut executor = TimeoutExecutor::default();
    let error = dns(
        &retry_request(),
        &mut authorizer,
        &default_registry().unwrap(),
        &mut executor,
        &mut NoopClock,
    )
    .unwrap_err();
    assert_eq!(error.classification().code, "policy.public_destination");
    assert_eq!(resolver.calls.load(Ordering::SeqCst), 2);
    assert_eq!(executor.calls, 1);
    assert_eq!(
        executor.addresses,
        [IpAddr::V4(Ipv4Addr::new(10, 0, 0, 53))]
    );
}

#[test]
fn complete_operation_budget_precedes_resolution_and_queries() {
    let resolver = ScriptedResolver::new([vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 53))]]);
    let mut policy = private_policy();
    policy.allow_hostname_resolution = true;
    policy.max_packets_per_operation = 1;
    let mut authorizer = PolicyAuthorizer::new(&policy, &resolver);
    let mut executor = TimeoutExecutor::default();
    let error = dns(
        &retry_request(),
        &mut authorizer,
        &default_registry().unwrap(),
        &mut executor,
        &mut NoopClock,
    )
    .unwrap_err();
    assert_eq!(error.classification().code, "policy.packet_limit");
    assert_eq!(resolver.calls.load(Ordering::SeqCst), 0);
    assert_eq!(executor.calls, 0);
}

#[test]
fn aggregate_duration_is_rejected_before_operation_authorization() {
    struct CountingAuthorizer {
        operation_calls: usize,
    }

    impl Authorizer for CountingAuthorizer {
        fn resolve_and_authorize(&mut self, _target: &Target) -> Result<Authorized, BoundaryError> {
            panic!("duration validation must precede resolution")
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

    let mut request = single_attempt_request();
    request.attempts = 2;
    request.timeout = Duration::from_millis(10);
    request.limits.max_duration = Duration::from_millis(1);
    let mut authorizer = CountingAuthorizer { operation_calls: 0 };
    let error = dns(
        &request,
        &mut authorizer,
        &default_registry().unwrap(),
        &mut TimeoutExecutor::default(),
        &mut NoopClock,
    )
    .unwrap_err();

    assert!(matches!(error, DnsError::DurationLimit { .. }));
    assert_eq!(authorizer.operation_calls, 0);
}

#[test]
fn slow_resolver_expires_before_executor_side_effects() {
    struct SlowResolver {
        calls: AtomicUsize,
    }

    impl HostnameResolver for SlowResolver {
        fn resolve(
            &self,
            _hostname: &Hostname,
            _limit: usize,
        ) -> Result<Vec<IpAddr>, TargetResolutionError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            std::thread::sleep(Duration::from_millis(20));
            Ok(vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 53))])
        }
    }

    let resolver = SlowResolver {
        calls: AtomicUsize::new(0),
    };
    let mut policy = private_policy();
    policy.allow_hostname_resolution = true;
    let mut authorizer = PolicyAuthorizer::new(&policy, &resolver);
    let mut executor = TimeoutExecutor::default();
    let mut request = single_attempt_request();
    request.server = Target::Hostname("slow-resolver.example".to_owned());
    request.timeout = Duration::from_millis(1);
    request.limits.max_duration = Duration::from_millis(5);

    let error = dns(
        &request,
        &mut authorizer,
        &default_registry().unwrap(),
        &mut executor,
        &mut NoopClock,
    )
    .unwrap_err();

    assert!(matches!(error, DnsError::DurationLimit { .. }));
    assert_eq!(resolver.calls.load(Ordering::SeqCst), 1);
    assert_eq!(executor.calls, 0);
}

#[test]
fn candidate_heavy_result_expires_before_a_second_dns_attempt() {
    struct CountingAuthorizer {
        resolutions: usize,
    }

    impl Authorizer for CountingAuthorizer {
        fn resolve_and_authorize(&mut self, target: &Target) -> Result<Authorized, BoundaryError> {
            self.resolutions += 1;
            Ok(Authorized {
                declared: target.to_string(),
                addresses: vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 53))],
            })
        }

        fn authorize_operation(
            &mut self,
            packets: u64,
            _maximum_wire_bytes: u64,
        ) -> Result<(), BoundaryError> {
            assert_eq!(packets, 2);
            Ok(())
        }
    }

    struct CandidateHeavyExecutor {
        calls: usize,
    }

    impl DnsExecutor for CandidateHeavyExecutor {
        fn execute(
            &mut self,
            exchange: &DnsExchange,
        ) -> Result<DnsExchangeExecution, BoundaryError> {
            self.calls += 1;
            let mut execution = PayloadExecutor {
                payload: Bytes::from_static(b"malformed"),
            }
            .execute(exchange)?;
            let sent_at = execution.sent_evidence.timestamp;
            let mut candidate = execution.responses.pop().unwrap();
            candidate.latency = Duration::ZERO;
            candidate.response.frame.timestamp = sent_at;
            execution.responses = vec![candidate; exchange.max_responses];
            execution.stats.elapsed = Duration::ZERO;
            Ok(execution)
        }
    }

    let mut request = single_attempt_request();
    request.attempts = 2;
    request.timeout = Duration::from_nanos(1);
    request.limits.max_duration = Duration::from_millis(5);
    request.limits.max_evidence_frames = DEFAULT_CAPTURE_QUEUE_FRAMES;
    let mut authorizer = CountingAuthorizer { resolutions: 0 };
    let mut executor = CandidateHeavyExecutor { calls: 0 };

    let error = dns(
        &request,
        &mut authorizer,
        &default_registry().unwrap(),
        &mut executor,
        &mut NoopClock,
    )
    .unwrap_err();

    assert!(matches!(error, DnsError::DurationLimit { .. }));
    assert_eq!(authorizer.resolutions, 1);
    assert_eq!(executor.calls, 1);
}
