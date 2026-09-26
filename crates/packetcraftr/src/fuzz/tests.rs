// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

use crate::progress::Runtime;
use bytes::Bytes;
use packetcraftr_core::error::Classified;
use packetcraftr_core::fuzz as packet_fuzz;
use packetcraftr_core::protocol::{network::Ipv4, transport::Udp};
use packetcraftr_core::{layer::Raw, packet::Packet};

use crate::test_support::NoopClock;
use crate::{BoundaryError, Stats as ExecutionStats};

use crate::policy::{Authorizer, Operation};

use super::{CaseOutcome, Execution, ExecutionCase, RunInput, run, run_with_events};
use super::{LiveLimits, LiveOptions, Stats};
use crate::probe::Executor;

#[test]
fn live_evidence_limits_are_validated_outside_the_offline_campaign() {
    LiveOptions::default()
        .validate()
        .expect("default live limits");

    for limits in [
        LiveLimits {
            max_evidence_frames: 0,
            ..LiveLimits::default()
        },
        LiveLimits {
            max_evidence_bytes: 0,
            ..LiveLimits::default()
        },
    ] {
        let error = LiveOptions {
            limits,
            ..LiveOptions::default()
        }
        .validate()
        .expect_err("zero live evidence limit must fail");
        assert!(matches!(error, super::Error::InvalidLimit { .. }));
    }
}

#[test]
fn aggregate_live_fuzz_validates_case_count_before_collecting() {
    let registry = packetcraftr_core::protocol::builtin::registry();
    let request = packet_fuzz::Request {
        cases: usize::MAX,
        ..packet_fuzz::Request::default()
    };
    let mut authorizer = AllowAll;
    let mut executor = CountingExecutor::default();

    let error = run(
        RunInput {
            request: &request,
            live: LiveOptions::default(),
            packet: packet(),
            registry,
        },
        &mut authorizer,
        &mut executor,
        &mut NoopClock,
    )
    .expect_err("an oversized live aggregate campaign must fail validation");

    assert!(matches!(
        error,
        super::Error::Campaign(packet_fuzz::Error::InvalidLimit { field: "cases", .. })
    ));
    assert_eq!(executor.executions, 0);
}

struct AllowAll;

impl Authorizer for AllowAll {
    fn authorize_operation(&mut self, operation: Operation<'_>) -> Result<(), BoundaryError> {
        // The fuzz workflow always states its packets, its chosen destination,
        // and its permissive-live position; a budget-only request would skip
        // the destination gate.
        assert!(
            matches!(operation, Operation::Declared(_)),
            "fuzz submits a declared-packet request, got {operation:?}"
        );
        Ok(())
    }
}

struct RebuildingExecutor;

impl Executor<ExecutionCase> for RebuildingExecutor {
    fn execute(&mut self, case: &ExecutionCase) -> Result<Execution, BoundaryError> {
        let sent = crate::test_support::sent_packet(case.packet.clone());
        Ok(Execution {
            permit: case.permit,
            stats: ExecutionStats {
                packets_attempted: 1,
                packets_completed: 1,
                bytes: u64::try_from(sent.bytes_sent()).unwrap(),
                ..ExecutionStats::default()
            },
            sent,
            responses: Vec::new(),
            unmatched: Vec::new(),
            undecoded: Vec::new(),
            diagnostics: Vec::new(),
        })
    }
}

#[derive(Default)]
struct CountingExecutor {
    executions: usize,
}

impl Executor<ExecutionCase> for CountingExecutor {
    fn execute(&mut self, case: &ExecutionCase) -> Result<Execution, BoundaryError> {
        self.executions += 1;
        let mut executor = RebuildingExecutor;
        executor.execute(case)
    }
}

struct InterruptedPacingClock {
    signal: packetcraftr_core::budget::Cancellation,
    cancel: bool,
    fail: bool,
}

impl crate::clock::Clock for InterruptedPacingClock {
    type Error = std::io::Error;

    fn sleep(&mut self, delay: Duration) -> Result<(), Self::Error> {
        assert!(!delay.is_zero());
        if self.cancel {
            self.signal.cancel();
        }
        if self.fail {
            Err(std::io::Error::other("pacing stopped"))
        } else {
            Ok(())
        }
    }

    fn cancellation(&self) -> Option<packetcraftr_core::budget::Cancellation> {
        Some(self.signal.clone())
    }
}

#[test]
fn live_pacing_distinguishes_cancellation_from_clock_failure() {
    for progressive in [false, true] {
        for (cancel, fail) in [(true, true), (true, false), (false, true)] {
            let request = packet_fuzz::Request {
                cases: 2,
                first_case: 7,
                strategies: vec![packet_fuzz::Strategy::BitFlip],
                targets: vec!["2.bytes".parse().unwrap()],
                ..packet_fuzz::Request::default()
            };
            let input = RunInput {
                request: &request,
                live: LiveOptions {
                    cases_per_second: Some(10),
                    ..LiveOptions::default()
                },
                packet: packet(),
                registry: packetcraftr_core::protocol::builtin::registry(),
            };
            let mut clock = InterruptedPacingClock {
                signal: Default::default(),
                cancel,
                fail,
            };
            let mut executor = CountingExecutor::default();
            let published = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let error = if progressive {
                let published = Arc::clone(&published);
                run_with_events(
                    input,
                    &mut AllowAll,
                    &mut executor,
                    &mut clock,
                    &Runtime::default(),
                    move |_| {
                        published.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        Ok(())
                    },
                )
                .unwrap_err()
            } else {
                run(input, &mut AllowAll, &mut executor, &mut clock).unwrap_err()
            };
            assert_eq!(executor.executions, 1);
            assert_eq!(
                published.load(std::sync::atomic::Ordering::SeqCst),
                usize::from(progressive)
            );
            if cancel {
                assert!(matches!(error, super::Error::Cancelled(_)));
                assert_eq!(error.classification().code, "io.cancelled");
            } else {
                assert!(matches!(error, super::Error::Clock { case_index: 8, .. }));
                assert_eq!(error.classification().code, "io.fuzz_clock");
                assert_eq!(error.causes(), ["pacing stopped"]);
            }
        }
    }
}

/// Reports the first case as having spent most of the campaign budget, then
/// answers the next case after `latency`.
struct BudgetSpendingExecutor {
    latency: Duration,
    executions: usize,
}

impl Executor<ExecutionCase> for BudgetSpendingExecutor {
    fn execute(&mut self, case: &ExecutionCase) -> Result<Execution, BoundaryError> {
        let first = self.executions == 0;
        self.executions += 1;
        let sent = crate::test_support::sent_packet(case.packet.clone());
        let responses = if first {
            Vec::new()
        } else {
            vec![crate::exchange::Response {
                request_index: 0,
                response: crate::probe::test_support::decoded_packet(
                    case.packet.clone(),
                    std::time::UNIX_EPOCH,
                    sent.wire_bytes(),
                    Vec::new(),
                ),
                latency: self.latency,
            }]
        };
        Ok(Execution {
            permit: case.permit,
            stats: ExecutionStats {
                packets_attempted: 1,
                packets_completed: 1,
                bytes: u64::try_from(sent.bytes_sent()).unwrap(),
                elapsed: Duration::from_millis(if first { 4300 } else { 300 }),
                ..ExecutionStats::default()
            },
            sent,
            responses,
            unmatched: Vec::new(),
            undecoded: Vec::new(),
            diagnostics: Vec::new(),
        })
    }
}

/// A 5 s campaign whose first case reports 4.3 s and whose pacing adds
/// 200 ms leaves at most 500 ms for the second case's 1 s timeout.
fn budget_spending_input(request: &packet_fuzz::Request) -> RunInput<'_> {
    RunInput {
        request,
        live: LiveOptions {
            timeout: Duration::from_secs(1),
            cases_per_second: Some(5),
            ..LiveOptions::default()
        },
        packet: packet(),
        registry: packetcraftr_core::protocol::builtin::registry(),
    }
}

fn budget_spending_request() -> packet_fuzz::Request {
    packet_fuzz::Request {
        cases: 2,
        strategies: vec![packet_fuzz::Strategy::BitFlip],
        targets: vec!["2.bytes".parse().unwrap()],
        limits: packet_fuzz::Limits {
            max_duration: Duration::from_secs(5),
            ..packet_fuzz::Limits::default()
        },
        ..packet_fuzz::Request::default()
    }
}

#[test]
fn live_cases_are_classified_and_their_statistics_summarized() {
    let request = budget_spending_request();
    let mut executor = BudgetSpendingExecutor {
        latency: Duration::from_millis(300),
        executions: 0,
    };

    let report = run(
        budget_spending_input(&request),
        &mut AllowAll,
        &mut executor,
        &mut NoopClock,
    )
    .expect("a response within the remaining budget is valid");

    assert_eq!(
        report
            .cases
            .iter()
            .map(|case| case.outcome)
            .collect::<Vec<_>>(),
        [CaseOutcome::Timeout, CaseOutcome::Response]
    );
    assert_eq!(report.cases[1].responses.len(), 1);
    let bytes = report
        .cases
        .iter()
        .map(|case| u64::try_from(case.sent.as_ref().unwrap().bytes().len()).unwrap())
        .sum();
    // Both executions plus the scheduled pacing delay.
    assert_eq!(
        report.stats,
        Stats {
            cases_generated: 2,
            cases_built: 2,
            packets_attempted: 2,
            packets_completed: 2,
            bytes,
            elapsed: Duration::from_millis(4300 + 200 + 300),
            ..Stats::default()
        }
    );
}

#[test]
fn live_case_evidence_beyond_the_remaining_budget_is_rejected_before_publication() {
    let request = budget_spending_request();
    let mut executor = BudgetSpendingExecutor {
        latency: Duration::from_millis(700),
        executions: 0,
    };
    let published = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let observed = Arc::clone(&published);

    let error = run_with_events(
        budget_spending_input(&request),
        &mut AllowAll,
        &mut executor,
        &mut NoopClock,
        &Runtime::default(),
        move |_| {
            observed.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        },
    )
    .expect_err("700 ms latency fits the requested timeout but not the remaining budget");

    assert!(matches!(
        error,
        super::Error::InvalidEvidence { case_index: 1, .. }
    ));
    assert_eq!(published.load(std::sync::atomic::Ordering::SeqCst), 1);
}

/// Answers every case with one response, one unmatched and one undecodable
/// frame.
struct ThreeFrameExecutor;

impl Executor<ExecutionCase> for ThreeFrameExecutor {
    fn execute(&mut self, case: &ExecutionCase) -> Result<Execution, BoundaryError> {
        let mut execution = RebuildingExecutor.execute(case)?;
        let frame = |bytes: &'static [u8]| {
            packetcraftr_core::frame::Frame::new(
                std::time::UNIX_EPOCH,
                packetcraftr_core::frame::LinkType::RAW,
                bytes,
            )
            .unwrap()
        };
        execution.responses.push(crate::exchange::Response {
            request_index: 0,
            response: crate::probe::test_support::decoded_packet(
                case.packet.clone(),
                std::time::UNIX_EPOCH,
                &[1],
                Vec::new(),
            ),
            latency: Duration::from_millis(1),
        });
        execution.unmatched.push(frame(&[2]));
        execution.undecoded.push(frame(&[3]));
        Ok(execution)
    }
}

#[test]
fn live_evidence_is_retained_under_one_campaign_budget_that_warns_once() {
    let request = packet_fuzz::Request {
        cases: 3,
        strategies: vec![packet_fuzz::Strategy::BitFlip],
        targets: vec!["2.bytes".parse().unwrap()],
        ..packet_fuzz::Request::default()
    };

    let report = run(
        RunInput {
            request: &request,
            live: LiveOptions {
                limits: LiveLimits {
                    max_evidence_frames: 4,
                    ..LiveLimits::default()
                },
                ..LiveOptions::default()
            },
            packet: packet(),
            registry: packetcraftr_core::protocol::builtin::registry(),
        },
        &mut AllowAll,
        &mut ThreeFrameExecutor,
        &mut NoopClock,
    )
    .expect("omitted evidence is not a failure");

    let retained = |case: &super::Case| {
        [&case.responses, &case.unmatched, &case.undecoded].map(|frames| {
            frames
                .iter()
                .map(|frame| frame.bytes().to_vec())
                .collect::<Vec<_>>()
        })
    };
    let warnings = |case: &super::Case| {
        case.prepared
            .diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.code == "fuzz.evidence_limit")
            .map(|diagnostic| diagnostic.message.to_string())
            .collect::<Vec<_>>()
    };
    let none: Vec<Vec<u8>> = Vec::new();
    assert_eq!(
        report.cases.iter().map(retained).collect::<Vec<_>>(),
        [
            [vec![vec![1]], vec![vec![2]], vec![vec![3]]],
            [vec![vec![1]], none.clone(), none.clone()],
            [none.clone(), none.clone(), none],
        ]
    );
    assert!(
        report
            .cases
            .iter()
            .all(|case| case.outcome == CaseOutcome::Response)
    );
    assert_eq!(
        report.cases.iter().map(warnings).collect::<Vec<_>>(),
        [
            Vec::new(),
            vec![format!(
                "fuzz response evidence exceeded 4 frame(s) or {} byte(s); later exact frames were omitted",
                LiveLimits::default().max_evidence_bytes
            )],
            Vec::new(),
        ]
    );
}

struct SubstitutingFuzzExecutor;

impl Executor<ExecutionCase> for SubstitutingFuzzExecutor {
    fn execute(&mut self, _case: &ExecutionCase) -> Result<Execution, BoundaryError> {
        let sent = crate::test_support::sent_packet(packet());
        Ok(Execution {
            permit: _case.permit,
            stats: ExecutionStats {
                packets_attempted: 1,
                packets_completed: 1,
                bytes: u64::try_from(sent.bytes_sent()).unwrap(),
                ..ExecutionStats::default()
            },
            sent,
            responses: Vec::new(),
            unmatched: Vec::new(),
            undecoded: Vec::new(),
            diagnostics: Vec::new(),
        })
    }
}

pub(super) fn packet() -> Packet {
    let mut packet = Packet::new();
    packet
        .push(Ipv4 {
            source: Ipv4Addr::new(192, 0, 2, 1),
            destination: Ipv4Addr::new(198, 51, 100, 1),
            ..Ipv4::default()
        })
        .push(Udp {
            destination_port: 9,
            ..Udp::default()
        })
        .push(Raw::new(Bytes::from_static(b"campaign")));
    packet
}

#[test]
fn live_execution_uses_the_identical_packet_campaign() {
    let registry = packetcraftr_core::protocol::builtin::registry();
    let request = packet_fuzz::Request {
        seed: 0x5eed,
        cases: 8,
        strategies: vec![packet_fuzz::Strategy::BitFlip],
        targets: vec!["2.bytes".parse().expect("raw field target")],
        ..packet_fuzz::Request::default()
    };
    let offline =
        packet_fuzz::run(&request, packet(), Arc::clone(&registry)).expect("offline campaign");
    let mut authorizer = AllowAll;
    let mut executor = RebuildingExecutor;
    let live = run(
        RunInput {
            request: &request,
            live: LiveOptions {
                timeout: Duration::from_millis(1),
                ..LiveOptions::default()
            },
            packet: packet(),
            registry,
        },
        &mut authorizer,
        &mut executor,
        &mut NoopClock,
    )
    .expect("live campaign");

    assert_eq!(offline.cases.len(), live.cases.len());
    for (offline, live) in offline.cases.iter().zip(&live.cases) {
        assert_eq!(offline.index, live.prepared.index);
        assert_eq!(offline.seed, live.prepared.seed);
        assert_eq!(offline.mutation, live.prepared.mutation);
        assert_eq!(offline.shrink_values, live.prepared.shrink_values);
        assert_eq!(
            offline.built.as_ref().map(|built| built.bytes.as_ref()),
            live.prepared
                .built
                .as_ref()
                .map(|built| built.bytes.as_ref())
        );
    }
}

#[test]
fn live_fuzz_sink_failure_prevents_later_case_execution() {
    let registry = packetcraftr_core::protocol::builtin::registry();
    let request = packet_fuzz::Request {
        cases: 3,
        strategies: vec![packet_fuzz::Strategy::BitFlip],
        targets: vec!["2.bytes".parse().expect("raw field target")],
        ..packet_fuzz::Request::default()
    };
    let mut authorizer = AllowAll;
    let mut executor = CountingExecutor::default();
    let emitted = Arc::new(std::sync::Mutex::new(Vec::new()));
    let observed = Arc::clone(&emitted);

    let error = run_with_events(
        RunInput {
            request: &request,
            live: LiveOptions {
                timeout: Duration::from_millis(1),
                ..LiveOptions::default()
            },
            packet: packet(),
            registry,
        },
        &mut authorizer,
        &mut executor,
        &mut NoopClock,
        &Runtime::default(),
        move |case| {
            observed.lock().unwrap().push(case.prepared.index);
            Err(BoundaryError::new(
                "induced live fuzz sink failure",
                packetcraftr_core::error::Classification::new(
                    "io.test_output",
                    packetcraftr_core::error::Kind::Io,
                    None,
                ),
                Vec::new(),
            ))
        },
    )
    .expect_err("the first case event must stop the campaign");

    assert!(matches!(error, super::Error::Output { .. }));
    assert_eq!(executor.executions, 1);
    assert_eq!(*emitted.lock().unwrap(), [0]);
}

#[test]
fn live_fuzz_rejects_substituted_authorized_case() {
    let registry = packetcraftr_core::protocol::builtin::registry();
    let request = packet_fuzz::Request {
        cases: 1,
        strategies: vec![packet_fuzz::Strategy::BitFlip],
        targets: vec!["2.bytes".parse().expect("raw field target")],
        ..packet_fuzz::Request::default()
    };
    let mut authorizer = AllowAll;
    let mut executor = SubstitutingFuzzExecutor;
    let error = run(
        RunInput {
            request: &request,
            live: LiveOptions {
                timeout: Duration::from_millis(1),
                ..LiveOptions::default()
            },
            packet: packet(),
            registry,
        },
        &mut authorizer,
        &mut executor,
        &mut NoopClock,
    )
    .expect_err("substituted sent evidence must be rejected");

    assert_eq!(error.classification().code, "internal.fuzz_evidence");
    assert!(error.to_string().contains("substituted bytes"));
}

#[test]
fn live_fuzz_keeps_the_preparation_error_for_a_case_its_route_cannot_verify() {
    let registry = packetcraftr_core::protocol::builtin::registry();
    let request = packet_fuzz::Request {
        cases: 1,
        strategies: vec![packet_fuzz::Strategy::BitFlip],
        targets: vec!["2.bytes".parse().expect("raw field target")],
        ..packet_fuzz::Request::default()
    };
    // The reported route has no packet source to fill the unspecified one.
    let mut unsourced = packet();
    unsourced
        .layer_mut(0)
        .expect("IPv4 layer")
        .set_field(
            "source",
            packetcraftr_core::field::FieldValue::Ipv4(Ipv4Addr::UNSPECIFIED),
        )
        .expect("IPv4 source field");
    let error = run(
        RunInput {
            request: &request,
            live: LiveOptions {
                timeout: Duration::from_millis(1),
                ..LiveOptions::default()
            },
            packet: unsourced,
            registry,
        },
        &mut AllowAll,
        &mut RebuildingExecutor,
        &mut NoopClock,
    )
    .expect_err("a case its reported route cannot prepare must be rejected");

    assert_eq!(error.classification().code, "internal.fuzz_evidence");
    let super::Error::UnverifiableRoute { case_index, source } = &error else {
        panic!("expected the preparation error as the source, got {error:?}");
    };
    assert_eq!(*case_index, 0);
    assert!(
        matches!(
            source,
            crate::Error::PacketMaterialization {
                field: "source",
                ..
            }
        ),
        "{source:?}"
    );
}

struct DenyingAuthorizer {
    invocations: usize,
}

impl Authorizer for DenyingAuthorizer {
    fn authorize_operation(&mut self, _operation: Operation<'_>) -> Result<(), BoundaryError> {
        self.invocations += 1;
        Err(BoundaryError::from_error(
            crate::policy::Error::PublicDestination {
                destination: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)),
            },
        ))
    }
}

#[test]
fn live_fuzz_consults_the_authorizer_exactly_once_before_any_execution() {
    let registry = packetcraftr_core::protocol::builtin::registry();
    let request = packet_fuzz::Request {
        seed: 0x5eed,
        cases: 4,
        strategies: vec![packet_fuzz::Strategy::BitFlip],
        targets: vec!["2.bytes".parse().expect("raw field target")],
        ..packet_fuzz::Request::default()
    };
    let mut authorizer = DenyingAuthorizer { invocations: 0 };
    let mut executor = CountingExecutor::default();

    let error = run(
        RunInput {
            request: &request,
            live: LiveOptions {
                destination: Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9))),
                ..LiveOptions::default()
            },
            packet: packet(),
            registry,
        },
        &mut authorizer,
        &mut executor,
        &mut NoopClock,
    )
    .expect_err("a denied campaign must not run");

    assert_eq!(authorizer.invocations, 1);
    assert_eq!(executor.executions, 0);
    assert_eq!(error.classification().code, "policy.public_destination");
}

#[test]
fn live_fuzz_authorizes_a_campaign_where_no_case_built() {
    let registry = packetcraftr_core::protocol::builtin::registry();
    let request = packet_fuzz::Request {
        seed: 0x5eed,
        cases: 4,
        strategies: vec![packet_fuzz::Strategy::Malformed],
        targets: vec!["1.length".parse().expect("derived length target")],
        ..packet_fuzz::Request::default()
    };
    let offline =
        packet_fuzz::run(&request, packet(), Arc::clone(&registry)).expect("offline campaign");
    assert!(
        offline.cases.iter().all(|case| case.built.is_none()),
        "the fixture must reject every case so the campaign declares no packets"
    );
    let mut authorizer = DenyingAuthorizer { invocations: 0 };
    let mut executor = CountingExecutor::default();

    let error = run(
        RunInput {
            request: &request,
            live: LiveOptions {
                destination: Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9))),
                ..LiveOptions::default()
            },
            packet: packet(),
            registry,
        },
        &mut authorizer,
        &mut executor,
        &mut NoopClock,
    )
    .expect_err("a campaign with nothing to send is still authorized");

    assert_eq!(authorizer.invocations, 1);
    assert_eq!(executor.executions, 0);
    assert_eq!(error.classification().code, "policy.public_destination");
}

/// Permissive live traffic requires both the operation opt-in and policy
/// allowance to pass authorization before transmission.
#[test]
fn a_permissive_live_campaign_is_denied_by_the_authorizer_before_any_transmission() {
    let registry = packetcraftr_core::protocol::builtin::registry();
    let permissive_build = packetcraftr_core::build::Options {
        mode: packetcraftr_core::codec::Mode::Permissive,
        ..packetcraftr_core::build::Options::default()
    };
    let malformed = packet_fuzz::Request {
        seed: 0x5eed,
        cases: 4,
        strategies: vec![packet_fuzz::Strategy::Malformed],
        targets: vec!["1.length".parse().expect("derived length target")],
        build: permissive_build.clone(),
        ..packet_fuzz::Request::default()
    };
    let offline = packet_fuzz::run(&malformed, packet(), Arc::clone(&registry))
        .expect("permissive offline campaign");
    assert!(
        offline.cases.iter().any(|case| {
            case.built
                .as_ref()
                .is_some_and(crate::policy::requires_live_opt_in)
        }),
        "the fixture must build at least one case that needs the live opt-in"
    );

    let permissive_policy = crate::policy::Policy {
        allow_permissive_packets: true,
        ..crate::policy::Policy::default()
    };
    let strict_policy = crate::policy::Policy::default();
    for (policy, allow_malformed_live, expected_code) in [
        (&permissive_policy, false, "policy.permissive_live_opt_in"),
        (&strict_policy, true, "policy.permissive_packet"),
        (&strict_policy, false, "policy.permissive_live_opt_in"),
    ] {
        let mut authorizer = crate::policy::PolicyAuthorizer::for_packets(policy);
        let mut executor = CountingExecutor::default();

        let error = run(
            RunInput {
                request: &malformed,
                live: LiveOptions {
                    destination: Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9))),
                    allow_malformed_live,
                    ..LiveOptions::default()
                },
                packet: packet(),
                registry: Arc::clone(&registry),
            },
            &mut authorizer,
            &mut executor,
            &mut NoopClock,
        )
        .expect_err("a permissive live campaign without both approvals must be refused");

        assert_eq!(error.classification().code, expected_code);
        assert_eq!(
            executor.executions, 0,
            "nothing may be transmitted before both approvals pass"
        );
    }

    // The same gate approves when both are present: a permissively built
    // campaign whose cases still encode exactly runs to completion.
    let encodable = packet_fuzz::Request {
        seed: 0x5eed,
        cases: 4,
        strategies: vec![packet_fuzz::Strategy::BitFlip],
        targets: vec!["2.bytes".parse().expect("raw field target")],
        build: permissive_build,
        ..packet_fuzz::Request::default()
    };
    let mut authorizer = crate::policy::PolicyAuthorizer::for_packets(&permissive_policy);
    let mut executor = CountingExecutor::default();
    let report = run(
        RunInput {
            request: &encodable,
            live: LiveOptions {
                destination: Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9))),
                allow_malformed_live: true,
                ..LiveOptions::default()
            },
            packet: packet(),
            registry,
        },
        &mut authorizer,
        &mut executor,
        &mut NoopClock,
    )
    .expect("both approvals present");
    assert_eq!(executor.executions, 4);
    assert_eq!(report.cases.len(), 4);
}

fn offline_report(cases: usize) -> packet_fuzz::Report {
    let request = packet_fuzz::Request {
        cases,
        ..packet_fuzz::Request::default()
    };
    packet_fuzz::run(
        &request,
        packet(),
        packetcraftr_core::protocol::builtin::registry(),
    )
    .expect("offline fixture campaign runs")
}

#[test]
fn a_coherent_campaign_reports_its_totals() {
    let report = offline_report(2);
    let totals = super::Totals::try_from(&report).expect("a generated campaign is coherent");
    assert_eq!(totals.generated, 2);
    assert_eq!(totals.built + totals.rejected, 2);
    let live = super::Report {
        seed: report.seed,
        first_case: report.first_case,
        stats: Stats {
            cases_generated: report.stats.cases_generated,
            cases_built: report.stats.cases_built,
            ..Stats::default()
        },
        cases: report.cases.into_iter().map(super::Case::from).collect(),
    };
    assert_eq!(super::Totals::try_from(&live), Ok(totals));
}

#[test]
fn campaign_totals_reject_more_built_than_generated_cases() {
    let offline = packet_fuzz::Stats {
        cases_generated: 0,
        cases_built: 1,
        ..packet_fuzz::Stats::default()
    };
    let live = Stats {
        cases_generated: 0,
        cases_built: 1,
        ..Stats::default()
    };
    for error in [
        super::Totals::try_from(&offline).expect_err("offline totals are incoherent"),
        super::Totals::try_from(&live).expect_err("live totals are incoherent"),
    ] {
        assert_eq!(
            error.to_string(),
            "built case count exceeds generated case count"
        );
    }
}

#[test]
fn campaign_cases_must_match_the_summary_and_publication_order() {
    let mut missing = offline_report(1);
    missing.cases.clear();
    let mut reordered = offline_report(2);
    reordered.cases.swap(0, 1);
    let mut foreign = offline_report(1);
    foreign.cases[0].operation_seed = foreign.seed.wrapping_add(1);
    let mut miscounted = offline_report(1);
    miscounted.stats.cases_built = 1 - miscounted.stats.cases_built;
    for (report, reason) in [
        (
            missing,
            "case cardinality does not match the campaign summary",
        ),
        (
            reordered,
            "case identity or publication order does not match the campaign",
        ),
        (
            foreign,
            "case identity or publication order does not match the campaign",
        ),
        (
            miscounted,
            "case outcomes do not match the campaign built count",
        ),
    ] {
        assert_eq!(
            super::Totals::try_from(&report)
                .expect_err("an incoherent campaign is refused")
                .to_string(),
            reason
        );
    }
}
