// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::VecDeque;
use std::net::Ipv4Addr;
use std::time::Duration;

use packetcraftr::clock::SystemClock;
use packetcraftr::dns::{self, tcp};
use packetcraftr::policy::{Authorizer, DnsOperation, Operation, Policy, PolicyAuthorizer};
use packetcraftr::probe::Executor;
use packetcraftr::progress::Runtime;
use packetcraftr::target::{Authorized, Family, Target};
use packetcraftr_core::error::{BoundaryError, Classification, Classified, Kind};

#[derive(Default)]
struct PolicyGate {
    policy: Policy,
    operations: Vec<DnsOperation>,
    resolutions: usize,
}

impl packetcraftr::target::ResolveTarget for PolicyGate {
    fn resolve_and_authorize(&mut self, target: &Target) -> Result<Authorized, BoundaryError> {
        self.resolutions += 1;
        PolicyAuthorizer::for_packets(&self.policy).resolve_and_authorize(target)
    }
}

impl Authorizer for PolicyGate {
    fn authorize_operation(&mut self, operation: Operation<'_>) -> Result<(), BoundaryError> {
        let Operation::Dns(dns) = operation else {
            panic!("DNS must declare UDP and TCP costs");
        };
        self.operations.push(dns);
        PolicyAuthorizer::for_packets(&self.policy).authorize_operation(operation)
    }
}

/// Scripted failures report confirmed writes through the public TCP error
/// contract without manufacturing opaque successful execution receipts.
#[derive(Default)]
struct TcpFailures {
    errors: VecDeque<tcp::Error>,
    calls: usize,
}

impl Executor<dns::Exchange> for TcpFailures {
    fn execute(&mut self, _: &dns::Exchange) -> Result<dns::Execution, BoundaryError> {
        panic!("no UDP traffic is expected");
    }
}

impl dns::TcpExecutor for TcpFailures {
    fn execute_tcp(&mut self, _: &dns::TcpExchange) -> Result<dns::TcpExecution, tcp::Error> {
        self.calls += 1;
        Err(self
            .errors
            .pop_front()
            .expect("no additional TCP queries authorized by fixture"))
    }
}

fn request(name: &str) -> dns::Request {
    dns::Request {
        server: Target::Address(Ipv4Addr::LOCALHOST.into()),
        address_family: Family::Any,
        server_port: 53,
        source_port: 40000,
        query_name: name.to_owned(),
        query_type: dns::QueryType::A,
        transaction_id: 0x1234,
        recursion_desired: true,
        edns: None,
        transport: dns::TransportMode::Tcp,
        attempts: 1,
        timeout: Duration::from_secs(1),
        queries_per_second: None,
        limits: dns::Limits::default(),
    }
}

fn timeout_after_query() -> tcp::Error {
    tcp::Error::Timeout {
        phase: tcp::Phase::ReadPrefix,
        transferred: 0,
    }
}

fn framed_query_bytes(request: &dns::Request) -> u64 {
    dns::encode_query(
        &request.query_name,
        request.query_type,
        request.transaction_id,
        request.recursion_desired,
        request.edns,
    )
    .unwrap()
    .len() as u64
        + 2
}

#[test]
fn batches_authorize_combined_retry_and_transport_units_before_discovery() {
    for (transport, per_question_units) in [
        (dns::TransportMode::Udp, 2),
        (dns::TransportMode::Tcp, 4),
        (dns::TransportMode::UdpThenTcp, 6),
    ] {
        let mut question = request("a");
        question.transport = transport;
        question.attempts = 2;
        question.edns = Some(dns::EdnsRequest {
            udp_payload_size: 1232,
            dnssec_ok: true,
        });
        let mut gate = PolicyGate {
            policy: Policy {
                max_packets_per_operation: per_question_units,
                ..Policy::default()
            },
            ..PolicyGate::default()
        };
        let mut executor = TcpFailures::default();
        let error = dns::run_batch(
            &[question.clone(), question.clone(), question],
            &mut gate,
            &packetcraftr_core::protocol::builtin::registry(),
            &mut executor,
            &mut SystemClock,
        )
        .unwrap_err();
        assert_eq!(error.classification().code, "policy.traffic_unit_limit");
        assert_eq!(gate.operations.len(), 1);
        assert_eq!(
            gate.operations[0].limits().packets(),
            3 * per_question_units
        );
        assert_eq!(gate.resolutions, 0);
        assert_eq!(executor.calls, 0);
    }
}

#[test]
fn batches_authorize_combined_query_bytes_before_discovery() {
    let questions = [request("a"), request("longer.example.test"), request("z")];
    let total = questions.iter().map(framed_query_bytes).sum::<u64>();
    let mut gate = PolicyGate {
        policy: Policy {
            max_bytes_per_operation: total - 1,
            ..Policy::default()
        },
        ..PolicyGate::default()
    };
    assert!(
        questions
            .iter()
            .all(|question| framed_query_bytes(question) <= gate.policy.max_bytes_per_operation)
    );
    let mut executor = TcpFailures::default();
    let error = dns::run_batch(
        &questions,
        &mut gate,
        &packetcraftr_core::protocol::builtin::registry(),
        &mut executor,
        &mut SystemClock,
    )
    .unwrap_err();
    assert_eq!(error.classification().code, "policy.traffic_byte_limit");
    assert_eq!(gate.operations.len(), 1);
    assert_eq!(gate.operations[0].tcp().application_bytes(), total);
    assert_eq!(gate.resolutions, 0);
    assert_eq!(executor.calls, 0);
}

#[test]
fn batch_output_failure_prevents_later_retries_and_questions() {
    let mut first = request("first.test");
    first.attempts = 2;
    let mut executor = TcpFailures {
        errors: [timeout_after_query()].into(),
        calls: 0,
    };
    let mut gate = PolicyGate::default();
    let error = dns::run_batch_with_events(
        &[first, request("second.test"), request("third.test")],
        &mut gate,
        &packetcraftr_core::protocol::builtin::registry(),
        &mut executor,
        &mut SystemClock,
        &Runtime::default(),
        |_| {
            Err(BoundaryError::new(
                "output failed",
                Classification::new("io.test_output", Kind::Io, None),
                Vec::new(),
            ))
        },
    )
    .unwrap_err();
    assert!(matches!(error, dns::Error::Output { .. }));
    assert_eq!(error.classification().code, "io.test_output");
    assert_eq!(executor.calls, 1);
    assert_eq!(
        gate.resolutions, 2,
        "only the first TCP endpoint is authorized"
    );
}

#[test]
fn batch_totals_include_traffic_from_questions_that_later_fail() {
    let mut first = request("first.test");
    first.attempts = 2;
    let second = request("second.test");
    let expected_bytes = framed_query_bytes(&first) + framed_query_bytes(&second);
    let mut executor = TcpFailures {
        errors: [
            timeout_after_query(),
            tcp::Error::Unsupported {
                message: "fixture failure on retry".to_owned(),
            },
            timeout_after_query(),
        ]
        .into(),
        calls: 0,
    };
    let mut gate = PolicyGate::default();
    let report = dns::run_batch(
        &[first, second],
        &mut gate,
        &packetcraftr_core::protocol::builtin::registry(),
        &mut executor,
        &mut SystemClock,
    )
    .unwrap();
    assert_eq!(report.status_counts(), (1, 1, 0));
    assert!(matches!(
        report.questions[0].error,
        Some(dns::Error::TcpExecution { attempt: 2, .. })
    ));
    assert_eq!(executor.calls, 3);
    assert_eq!(report.stats.bytes, expected_bytes);
    assert_eq!(gate.operations.len(), 1);
    assert_eq!(
        gate.resolutions, 6,
        "every attempted TCP endpoint is still authorized"
    );
}

#[test]
fn batch_cancellation_during_retry_wait_retains_confirmed_traffic() {
    #[derive(Clone)]
    struct CancellingClock(packetcraftr_core::budget::Cancellation);
    impl packetcraftr::clock::Clock for CancellingClock {
        type Error = std::io::Error;

        fn sleep(
            &self,
            _: Duration,
            _: &packetcraftr_core::budget::Deadline,
        ) -> Result<(), Self::Error> {
            self.0.cancel();
            Err(std::io::Error::other("interrupted clock"))
        }

        fn cancellation(&self) -> Option<packetcraftr_core::budget::Cancellation> {
            Some(self.0.clone())
        }
    }

    let mut first = request("first.test");
    first.attempts = 2;
    let expected_bytes = framed_query_bytes(&first);
    let mut executor = TcpFailures {
        errors: [timeout_after_query()].into(),
        calls: 0,
    };
    let report = dns::run_batch(
        &[first, request("never.test")],
        &mut PolicyGate::default(),
        &packetcraftr_core::protocol::builtin::registry(),
        &mut executor,
        &mut CancellingClock(Default::default()),
    )
    .unwrap();
    assert_eq!(report.status_counts(), (0, 1, 1));
    assert!(matches!(
        report.questions[0].error,
        Some(dns::Error::Cancelled(_))
    ));
    assert_eq!(report.stats.bytes, expected_bytes);
    assert_eq!(executor.calls, 1);
}

#[test]
fn a_pre_cancelled_batch_leaves_every_question_unattempted() {
    let signal = packetcraftr_core::budget::Cancellation::default();
    signal.cancel();
    let mut gate = PolicyGate::default();
    let report = dns::run_batch(
        &[request("first.test"), request("never.test")],
        &mut gate,
        &packetcraftr_core::protocol::builtin::registry(),
        &mut TcpFailures::default(),
        &mut packetcraftr::clock::CancellableClock(signal),
    )
    .unwrap();
    assert_eq!(report.status_counts(), (0, 0, 2));
    assert_eq!(report.stats, packetcraftr::Stats::default());
    assert!(gate.operations.is_empty());
    assert_eq!(gate.resolutions, 0);
}

#[test]
fn batch_rejects_mixed_server_identity_before_authorization() {
    for change_port in [false, true] {
        let mut second = request("second.test");
        if change_port {
            second.server_port = 5353;
        } else {
            second.server = Target::Address(Ipv4Addr::new(127, 0, 0, 2).into());
        }
        let mut gate = PolicyGate::default();
        let mut executor = TcpFailures::default();
        let error = dns::run_batch(
            &[request("first.test"), second],
            &mut gate,
            &packetcraftr_core::protocol::builtin::registry(),
            &mut executor,
            &mut SystemClock,
        )
        .unwrap_err();
        assert_eq!(error.classification().code, "cli.dns_limit");
        assert!(gate.operations.is_empty());
        assert_eq!(gate.resolutions, 0);
        assert_eq!(executor.calls, 0);
    }
}

#[derive(Clone, Default)]
struct RecordingClock(std::sync::Arc<std::sync::Mutex<Vec<Duration>>>);

impl RecordingClock {
    fn delays(&self) -> Vec<Duration> {
        self.0.lock().unwrap().clone()
    }
}

impl packetcraftr::clock::Clock for RecordingClock {
    type Error = std::convert::Infallible;

    fn sleep(
        &self,
        delay: Duration,
        _: &packetcraftr_core::budget::Deadline,
    ) -> Result<(), Self::Error> {
        self.0.lock().unwrap().push(delay);
        Ok(())
    }
}

#[test]
fn rate_intervals_are_shared_across_single_attempt_questions() {
    let mut questions = [request("a"), request("b"), request("c")];
    for question in &mut questions {
        question.queries_per_second = Some(2);
    }
    let mut executor = TcpFailures {
        errors: [
            timeout_after_query(),
            timeout_after_query(),
            timeout_after_query(),
        ]
        .into(),
        calls: 0,
    };
    let mut clock = RecordingClock::default();
    let report = dns::run_batch(
        &questions,
        &mut PolicyGate::default(),
        &packetcraftr_core::protocol::builtin::registry(),
        &mut executor,
        &mut clock,
    )
    .unwrap();
    assert_eq!(report.status_counts(), (3, 0, 0));
    assert_eq!(clock.delays(), [Duration::from_millis(500); 2]);
    assert!(report.stats.elapsed >= Duration::from_secs(1));
}

#[test]
fn the_shared_deadline_can_prevent_an_interquestion_wait() {
    let mut questions = [request("a"), request("b")];
    for question in &mut questions {
        question.queries_per_second = Some(1);
        question.timeout = Duration::from_millis(50);
        question.limits.max_duration = Duration::from_millis(500);
    }
    let expected_bytes = framed_query_bytes(&questions[0]);
    let mut executor = TcpFailures {
        errors: [timeout_after_query()].into(),
        calls: 0,
    };
    let mut clock = RecordingClock::default();
    let report = dns::run_batch(
        &questions,
        &mut PolicyGate::default(),
        &packetcraftr_core::protocol::builtin::registry(),
        &mut executor,
        &mut clock,
    )
    .unwrap();
    assert_eq!(report.status_counts(), (1, 0, 1));
    assert_eq!(report.stats.bytes, expected_bytes);
    assert_eq!(executor.calls, 1);
    assert!(clock.delays().is_empty());
}
