// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use packetcraftr_core::budget::{Cancellation, Deadline};
use packetcraftr_core::error::Classified;
use packetcraftr_core::fuzz as packet_fuzz;
use packetcraftr_core::protocol::{network::Ipv4, transport::Udp};
use packetcraftr_core::{layer::Raw, packet::Packet};
use packetcraftr_netio::capture::MAX_CAPTURE_QUEUE_BYTES;

use crate::clock::Clock;
use crate::execution::{Executor, publisher};
use crate::policy::{Authorizer, Operation, Policy};
use crate::progress::Runtime;
use crate::test_support::{Call, FakeProviders, NoopClock};
use crate::{BoundaryError, Client, Sink, Stats};

use super::engine::run;
use super::error::duration_limit;
use super::executor::{CaseEvidence, CaseStep};
use super::{Aggregate, Collector, Error, Event, Outcome, Report, Request, Trial};

/// A live run of `campaign` over the fixture packet.
fn request(campaign: packet_fuzz::Request) -> Request {
    Request::new(campaign, packet())
}

/// Runs the engine, publishing each case to `sink` on a worker.
fn publish<A, E, C, S>(
    request: &Request,
    authorizer: &mut A,
    executor: &mut E,
    clock: &mut C,
    sink: S,
) -> Result<Report, Error>
where
    A: Authorizer,
    E: Executor<CaseStep>,
    C: Clock,
    S: Sink<Event, Ack = ()>,
{
    publish_cancellable(request, authorizer, executor, clock, None, sink)
}

/// [`publish`] under a deadline carrying `cancellation`, as the client
/// builds one from its own.
fn publish_cancellable<A, E, C, S>(
    request: &Request,
    authorizer: &mut A,
    executor: &mut E,
    clock: &mut C,
    cancellation: Option<Cancellation>,
    sink: S,
) -> Result<Report, Error>
where
    A: Authorizer,
    E: Executor<CaseStep>,
    C: Clock,
    S: Sink<Event, Ack = ()>,
{
    let mut deadline =
        Deadline::new(request.campaign.limits.max_duration).with_cancellation(cancellation);
    let runtime = Runtime::default();
    let emit = publisher(&runtime, sink, duration_limit, |source| Error::Output {
        source,
    })?;
    run(
        request,
        authorizer,
        packetcraftr_core::protocol::builtin::registry(),
        executor,
        clock,
        &mut deadline,
        emit,
    )
}

/// Runs the engine into its aggregate through a [`Collector`].
fn collect<A, E, C>(
    request: &Request,
    authorizer: &mut A,
    executor: &mut E,
    clock: &mut C,
) -> Result<Aggregate, Error>
where
    A: Authorizer,
    E: Executor<CaseStep>,
    C: Clock,
{
    collect_cancellable(request, authorizer, executor, clock, None)
}

/// [`collect`] under a deadline carrying `cancellation`.
fn collect_cancellable<A, E, C>(
    request: &Request,
    authorizer: &mut A,
    executor: &mut E,
    clock: &mut C,
    cancellation: Option<Cancellation>,
) -> Result<Aggregate, Error>
where
    A: Authorizer,
    E: Executor<CaseStep>,
    C: Clock,
{
    let collector = Collector::default();
    let report = publish_cancellable(
        request,
        authorizer,
        executor,
        clock,
        cancellation,
        collector.clone(),
    )?;
    Ok(collector.finish(report))
}

fn outcome(trial: &Trial) -> Option<Outcome> {
    trial.evidence.as_ref().map(|evidence| evidence.outcome)
}

#[test]
fn live_evidence_limits_are_validated_outside_the_offline_campaign() {
    let valid = request(packet_fuzz::Request::default());
    valid.validate().expect("default live limits");

    for invalid in [
        Request {
            max_evidence_frames: 0,
            ..valid.clone()
        },
        Request {
            max_evidence_bytes: 0,
            ..valid.clone()
        },
    ] {
        let error = invalid
            .validate()
            .expect_err("zero live evidence limit must fail");
        assert!(matches!(error, Error::InvalidLimit { .. }));
    }
}

#[test]
fn aggregate_live_fuzz_validates_case_count_before_collecting() {
    let request = request(packet_fuzz::Request {
        cases: usize::MAX,
        ..packet_fuzz::Request::default()
    });
    let mut authorizer = AllowAll;
    let mut executor = CountingExecutor::default();

    let error = collect(&request, &mut authorizer, &mut executor, &mut NoopClock)
        .expect_err("an oversized live aggregate campaign must fail validation");

    assert!(matches!(
        error,
        Error::Campaign(packet_fuzz::Error::InvalidLimit { field: "cases", .. })
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

impl Executor<CaseStep> for RebuildingExecutor {
    fn execute(&mut self, case: &CaseStep) -> Result<CaseEvidence, BoundaryError> {
        let sent = crate::test_support::sent_packet(case.packet.clone());
        Ok(CaseEvidence {
            permit: case.permit,
            stats: Stats {
                packets_attempted: 1,
                packets_completed: 1,
                bytes: u64::try_from(sent.bytes_sent()).unwrap(),
                ..Stats::default()
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

impl Executor<CaseStep> for CountingExecutor {
    fn execute(&mut self, case: &CaseStep) -> Result<CaseEvidence, BoundaryError> {
        self.executions += 1;
        let mut executor = RebuildingExecutor;
        executor.execute(case)
    }
}

#[derive(Clone)]
struct InterruptedPacingClock {
    signal: Cancellation,
    cancel: bool,
    fail: bool,
}

impl Clock for InterruptedPacingClock {
    type Error = std::io::Error;

    fn sleep(&self, delay: Duration, _deadline: &Deadline) -> Result<(), Self::Error> {
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
}

#[test]
fn live_pacing_distinguishes_cancellation_from_clock_failure() {
    for progressive in [false, true] {
        for (cancel, fail) in [(true, true), (true, false), (false, true)] {
            let request = Request {
                cases_per_second: Some(10),
                ..request(packet_fuzz::Request {
                    cases: 2,
                    first_case: 7,
                    strategies: vec![packet_fuzz::Strategy::BitFlip],
                    targets: vec!["2.bytes".parse().unwrap()],
                    ..packet_fuzz::Request::default()
                })
            };
            let signal = Cancellation::default();
            let mut clock = InterruptedPacingClock {
                signal: signal.clone(),
                cancel,
                fail,
            };
            let mut executor = CountingExecutor::default();
            let published = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let error = if progressive {
                let published = Arc::clone(&published);
                publish_cancellable(
                    &request,
                    &mut AllowAll,
                    &mut executor,
                    &mut clock,
                    Some(signal.clone()),
                    move |_| {
                        published.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        Ok(())
                    },
                )
                .unwrap_err()
            } else {
                collect_cancellable(
                    &request,
                    &mut AllowAll,
                    &mut executor,
                    &mut clock,
                    Some(signal.clone()),
                )
                .unwrap_err()
            };
            assert_eq!(executor.executions, 1);
            assert_eq!(
                published.load(std::sync::atomic::Ordering::SeqCst),
                usize::from(progressive)
            );
            if cancel {
                assert!(matches!(error, Error::Cancelled(_)));
                assert_eq!(error.classification().code, "io.cancelled");
            } else {
                assert!(matches!(error, Error::Clock { case_index: 8, .. }));
                assert_eq!(error.classification().code, "io.fuzz_clock");
                assert_eq!(error.causes(), ["pacing stopped"]);
            }
        }
    }
}

/// Cancels the campaign while approving it.
struct CancellingAuthorizer {
    signal: Cancellation,
    calls: usize,
}

impl Authorizer for CancellingAuthorizer {
    fn authorize_operation(&mut self, operation: Operation<'_>) -> Result<(), BoundaryError> {
        assert!(matches!(operation, Operation::Declared(_)));
        self.calls += 1;
        self.signal.cancel();
        Ok(())
    }
}

#[test]
fn cancellation_during_authorization_prevents_the_first_live_case() {
    let signal = Cancellation::default();
    let request = request(packet_fuzz::Request {
        cases: 1,
        strategies: vec![packet_fuzz::Strategy::BitFlip],
        targets: vec!["2.bytes".parse().unwrap()],
        ..packet_fuzz::Request::default()
    });
    let mut authorizer = CancellingAuthorizer {
        signal: signal.clone(),
        calls: 0,
    };
    let mut executor = CountingExecutor::default();
    let mut deadline =
        Deadline::new(request.campaign.limits.max_duration).with_cancellation(Some(signal));

    let error = run(
        &request,
        &mut authorizer,
        packetcraftr_core::protocol::builtin::registry(),
        &mut executor,
        &mut NoopClock,
        &mut deadline,
        |_, _| panic!("a cancelled campaign must not publish a case"),
    )
    .expect_err("the campaign was cancelled while it was admitted");

    assert_eq!(authorizer.calls, 1);
    assert_eq!(executor.executions, 0);
    assert_eq!(error.classification().code, "io.cancelled");
}

/// Reports the first case as having spent most of the campaign budget, then
/// answers the next case after `latency`.
struct BudgetSpendingExecutor {
    latency: Duration,
    executions: usize,
}

impl Executor<CaseStep> for BudgetSpendingExecutor {
    fn execute(&mut self, case: &CaseStep) -> Result<CaseEvidence, BoundaryError> {
        let first = self.executions == 0;
        self.executions += 1;
        let sent = crate::test_support::sent_packet(case.packet.clone());
        let responses = if first {
            Vec::new()
        } else {
            vec![crate::exchange::Response {
                request_index: 0,
                response: crate::test_support::decoded_packet(
                    case.packet.clone(),
                    std::time::UNIX_EPOCH,
                    sent.wire_bytes(),
                    Vec::new(),
                ),
                latency: self.latency,
            }]
        };
        Ok(CaseEvidence {
            permit: case.permit,
            stats: Stats {
                packets_attempted: 1,
                packets_completed: 1,
                bytes: u64::try_from(sent.bytes_sent()).unwrap(),
                elapsed: Duration::from_millis(if first { 4300 } else { 300 }),
                ..Stats::default()
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
fn budget_spending_request() -> Request {
    Request {
        timeout: Duration::from_secs(1),
        cases_per_second: Some(5),
        ..request(packet_fuzz::Request {
            cases: 2,
            strategies: vec![packet_fuzz::Strategy::BitFlip],
            targets: vec!["2.bytes".parse().unwrap()],
            limits: packet_fuzz::Limits {
                max_duration: Duration::from_secs(5),
                ..packet_fuzz::Limits::default()
            },
            ..packet_fuzz::Request::default()
        })
    }
}

#[test]
fn live_cases_are_classified_and_their_statistics_summarized() {
    let request = budget_spending_request();
    let mut executor = BudgetSpendingExecutor {
        latency: Duration::from_millis(300),
        executions: 0,
    };

    let aggregate = collect(&request, &mut AllowAll, &mut executor, &mut NoopClock)
        .expect("a response within the remaining budget is valid");

    assert_eq!(
        aggregate.trials.iter().map(outcome).collect::<Vec<_>>(),
        [Some(Outcome::Timeout), Some(Outcome::Response)]
    );
    let evidence = |index: usize| aggregate.trials[index].evidence.as_ref().unwrap();
    assert_eq!(evidence(1).responses.len(), 1);
    let bytes = (0..2)
        .map(|index| u64::try_from(evidence(index).sent.bytes().len()).unwrap())
        .sum();
    assert_eq!(
        (
            aggregate.campaign.cases_generated,
            aggregate.campaign.cases_built
        ),
        (2, 2)
    );
    // Both executions plus the scheduled pacing delay.
    assert_eq!(
        aggregate.stats,
        Stats {
            packets_attempted: 2,
            packets_completed: 2,
            bytes,
            elapsed: Duration::from_millis(4300 + 200 + 300),
            ..Stats::default()
        }
    );
    assert_eq!(
        packet_fuzz::Totals::try_from(&aggregate).map(|totals| totals.built),
        Ok(2)
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

    let error = publish(
        &request,
        &mut AllowAll,
        &mut executor,
        &mut NoopClock,
        move |_| {
            observed.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        },
    )
    .expect_err("700 ms latency fits the requested timeout but not the remaining budget");

    assert!(matches!(
        error,
        Error::InvalidEvidence { case_index: 1, .. }
    ));
    assert_eq!(published.load(std::sync::atomic::Ordering::SeqCst), 1);
}

/// Answers every case with one response, one unmatched and one undecodable
/// frame.
struct ThreeFrameExecutor;

impl Executor<CaseStep> for ThreeFrameExecutor {
    fn execute(&mut self, case: &CaseStep) -> Result<CaseEvidence, BoundaryError> {
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
            response: crate::test_support::decoded_packet(
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
    let request = Request {
        max_evidence_frames: 4,
        ..request(packet_fuzz::Request {
            cases: 3,
            strategies: vec![packet_fuzz::Strategy::BitFlip],
            targets: vec!["2.bytes".parse().unwrap()],
            ..packet_fuzz::Request::default()
        })
    };

    let aggregate = collect(
        &request,
        &mut AllowAll,
        &mut ThreeFrameExecutor,
        &mut NoopClock,
    )
    .expect("omitted evidence is not a failure");

    let retained = |trial: &Trial| {
        let evidence = trial.evidence.as_ref().expect("every case was sent");
        [
            &evidence.responses,
            &evidence.unmatched,
            &evidence.undecoded,
        ]
        .map(|frames| {
            frames
                .iter()
                .map(|frame| frame.bytes().to_vec())
                .collect::<Vec<_>>()
        })
    };
    let warnings = |trial: &Trial| {
        trial
            .case
            .diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.code == "fuzz.evidence_limit")
            .map(|diagnostic| diagnostic.message.to_string())
            .collect::<Vec<_>>()
    };
    let none: Vec<Vec<u8>> = Vec::new();
    assert_eq!(
        aggregate.trials.iter().map(retained).collect::<Vec<_>>(),
        [
            [vec![vec![1]], vec![vec![2]], vec![vec![3]]],
            [vec![vec![1]], none.clone(), none.clone()],
            [none.clone(), none.clone(), none],
        ]
    );
    assert!(
        aggregate
            .trials
            .iter()
            .all(|trial| outcome(trial) == Some(Outcome::Response))
    );
    assert_eq!(
        aggregate.trials.iter().map(warnings).collect::<Vec<_>>(),
        [
            Vec::new(),
            vec![format!(
                "fuzz response evidence exceeded 4 frame(s) or {MAX_CAPTURE_QUEUE_BYTES} byte(s); later exact frames were omitted"
            )],
            Vec::new(),
        ]
    );
}

struct SubstitutingFuzzExecutor;

impl Executor<CaseStep> for SubstitutingFuzzExecutor {
    fn execute(&mut self, case: &CaseStep) -> Result<CaseEvidence, BoundaryError> {
        let sent = crate::test_support::sent_packet(packet());
        Ok(CaseEvidence {
            permit: case.permit,
            stats: Stats {
                packets_attempted: 1,
                packets_completed: 1,
                bytes: u64::try_from(sent.bytes_sent()).unwrap(),
                ..Stats::default()
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

/// A bit-flip campaign of `cases` cases over the fixture's raw payload.
fn bit_flip(cases: usize) -> packet_fuzz::Request {
    packet_fuzz::Request {
        seed: 0x5eed,
        cases,
        strategies: vec![packet_fuzz::Strategy::BitFlip],
        targets: vec!["2.bytes".parse().expect("raw field target")],
        ..packet_fuzz::Request::default()
    }
}

/// Short collection windows, so fixture exchanges finish quickly, yet long
/// enough that preparing each exchange fits inside its window under load.
fn quick(campaign: packet_fuzz::Request) -> Request {
    Request {
        timeout: Duration::from_millis(50),
        ..request(campaign)
    }
}

#[test]
fn live_execution_uses_the_identical_packet_campaign() {
    let request = quick(bit_flip(8));
    let offline = packet_fuzz::run(
        &request.campaign,
        packet(),
        packetcraftr_core::protocol::builtin::registry(),
    )
    .expect("offline campaign");
    let live = collect(
        &request,
        &mut AllowAll,
        &mut RebuildingExecutor,
        &mut NoopClock,
    )
    .expect("live campaign");

    assert_eq!(offline.cases.len(), live.trials.len());
    for (offline, Trial { case: live, .. }) in offline.cases.iter().zip(&live.trials) {
        assert_eq!(offline.index, live.index);
        assert_eq!(offline.seed, live.seed);
        assert_eq!(offline.mutation, live.mutation);
        assert_eq!(offline.shrink_values, live.shrink_values);
        assert_eq!(
            offline.built.as_ref().map(|built| built.bytes.as_ref()),
            live.built.as_ref().map(|built| built.bytes.as_ref())
        );
    }
}

#[test]
fn live_fuzz_sink_failure_prevents_later_case_execution() {
    let request = quick(bit_flip(3));
    let mut executor = CountingExecutor::default();
    let emitted = Arc::new(std::sync::Mutex::new(Vec::new()));
    let observed = Arc::clone(&emitted);

    let error = publish(
        &request,
        &mut AllowAll,
        &mut executor,
        &mut NoopClock,
        move |Event::Case(trial)| {
            observed.lock().unwrap().push(trial.case.index);
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

    assert!(matches!(error, Error::Output { .. }));
    assert_eq!(executor.executions, 1);
    assert_eq!(*emitted.lock().unwrap(), [0]);
}

#[test]
fn live_fuzz_rejects_substituted_authorized_case() {
    let request = quick(bit_flip(1));
    let error = collect(
        &request,
        &mut AllowAll,
        &mut SubstitutingFuzzExecutor,
        &mut NoopClock,
    )
    .expect_err("substituted sent evidence must be rejected");

    assert_eq!(error.classification().code, "internal.fuzz_evidence");
    assert!(error.to_string().contains("substituted bytes"));
}

#[test]
fn live_fuzz_keeps_the_preparation_error_for_a_case_its_route_cannot_verify() {
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
    let request = Request {
        packet: unsourced,
        ..quick(bit_flip(1))
    };
    let error = collect(
        &request,
        &mut AllowAll,
        &mut RebuildingExecutor,
        &mut NoopClock,
    )
    .expect_err("a case its reported route cannot prepare must be rejected");

    assert_eq!(error.classification().code, "internal.fuzz_evidence");
    let Error::UnverifiableRoute { case_index, source } = &error else {
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
    let request = Request {
        destination: Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9))),
        ..request(bit_flip(4))
    };
    let mut authorizer = DenyingAuthorizer { invocations: 0 };
    let mut executor = CountingExecutor::default();

    let error = collect(&request, &mut authorizer, &mut executor, &mut NoopClock)
        .expect_err("a denied campaign must not run");

    assert_eq!(authorizer.invocations, 1);
    assert_eq!(executor.executions, 0);
    assert_eq!(error.classification().code, "policy.public_destination");
}

#[test]
fn live_fuzz_authorizes_a_campaign_where_no_case_built() {
    let request = Request {
        destination: Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9))),
        ..request(packet_fuzz::Request {
            seed: 0x5eed,
            cases: 4,
            strategies: vec![packet_fuzz::Strategy::Malformed],
            targets: vec!["1.length".parse().expect("derived length target")],
            ..packet_fuzz::Request::default()
        })
    };
    let offline = packet_fuzz::run(
        &request.campaign,
        packet(),
        packetcraftr_core::protocol::builtin::registry(),
    )
    .expect("offline campaign");
    assert!(
        offline.cases.iter().all(|case| case.built.is_none()),
        "the fixture must reject every case so the campaign declares no packets"
    );
    let mut authorizer = DenyingAuthorizer { invocations: 0 };
    let mut executor = CountingExecutor::default();

    let error = collect(&request, &mut authorizer, &mut executor, &mut NoopClock)
        .expect_err("a campaign with nothing to send is still authorized");

    assert_eq!(authorizer.invocations, 1);
    assert_eq!(executor.executions, 0);
    assert_eq!(error.classification().code, "policy.public_destination");
}

fn transmissions(providers: &FakeProviders) -> usize {
    providers
        .calls()
        .iter()
        .filter(|call| matches!(call, Call::Transmit(_)))
        .count()
}

/// Permissive live traffic requires both the request opt-in and the client
/// policy's allowance to pass admission before any provider is consulted.
#[test]
fn a_permissive_live_campaign_is_refused_by_client_admission_before_any_provider_call() {
    let permissive_build = packetcraftr_core::build::Options {
        mode: packetcraftr_core::codec::Mode::Permissive,
        ..packetcraftr_core::build::Options::default()
    };
    let malformed = packet_fuzz::Request {
        strategies: vec![packet_fuzz::Strategy::Malformed],
        targets: vec!["1.length".parse().expect("derived length target")],
        build: permissive_build.clone(),
        ..bit_flip(4)
    };
    let offline = packet_fuzz::run(
        &malformed,
        packet(),
        packetcraftr_core::protocol::builtin::registry(),
    )
    .expect("permissive offline campaign");
    assert!(
        offline.cases.iter().any(|case| {
            case.built
                .as_ref()
                .is_some_and(crate::policy::requires_live_opt_in)
        }),
        "the fixture must build at least one case that needs the live opt-in"
    );

    let permissive_policy = Policy {
        allow_permissive_packets: true,
        ..Policy::default()
    };
    let client = |policy: &Policy| {
        let providers = FakeProviders::default();
        let client = Client::new(
            packetcraftr_core::protocol::builtin::registry(),
            policy.clone(),
            providers.clone(),
        );
        (client, providers)
    };
    let documentation = Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9)));
    for (policy, allow_permissive_live, expected_code) in [
        (&permissive_policy, false, "policy.permissive_live_opt_in"),
        (&Policy::default(), true, "policy.permissive_packet"),
        (&Policy::default(), false, "policy.permissive_live_opt_in"),
    ] {
        let (client, providers) = client(policy);
        let error = client
            .fuzz(
                Request {
                    destination: documentation,
                    allow_permissive_live,
                    ..quick(malformed.clone())
                },
                Collector::default(),
            )
            .expect_err("a permissive live campaign without both approvals must be refused");

        assert_eq!(error.classification().code, expected_code);
        assert_eq!(
            providers.calls(),
            [],
            "no provider may be consulted before both approvals pass"
        );
    }

    // The same gate approves when both are present: a permissively built
    // campaign whose cases still encode exactly runs to completion.
    let (client, providers) = client(&permissive_policy);
    let collector = Collector::default();
    let report = client
        .fuzz(
            Request {
                destination: documentation,
                allow_permissive_live: true,
                ..quick(packet_fuzz::Request {
                    build: permissive_build,
                    ..bit_flip(4)
                })
            },
            collector.clone(),
        )
        .expect("both approvals present");
    assert_eq!(transmissions(&providers), 4);
    assert_eq!(collector.finish(report).trials.len(), 4);
}

#[test]
fn client_fuzz_publishes_every_case_with_the_evidence_its_exchange_produced() {
    let (client, providers) = crate::test_support::fake_client();
    let collector = Collector::default();

    let report = client
        .fuzz(quick(bit_flip(3)), collector.clone())
        .expect("the fixture campaign runs");
    let aggregate = collector.finish(report);

    assert_eq!(transmissions(&providers), 3);
    let totals = packet_fuzz::Totals::try_from(&aggregate).expect("a coherent campaign");
    assert_eq!((totals.generated, totals.built), (3, 3));
    assert_eq!(aggregate.stats.packets_completed, 3);
    let sent = providers
        .calls()
        .into_iter()
        .filter_map(|call| match call {
            Call::Transmit(bytes) => Some(bytes),
            _ => None,
        })
        .collect::<Vec<_>>();
    for (trial, sent) in aggregate.trials.iter().zip(sent) {
        let evidence = trial.evidence.as_ref().expect("every built case is sent");
        assert_eq!(evidence.outcome, Outcome::Timeout);
        assert_eq!(evidence.sent.bytes(), sent.as_slice());
    }
}

#[test]
fn a_live_aggregate_must_publish_its_cases_in_campaign_order() {
    let request = quick(bit_flip(2));
    let mut aggregate = collect(
        &request,
        &mut AllowAll,
        &mut RebuildingExecutor,
        &mut NoopClock,
    )
    .expect("live campaign");
    packet_fuzz::Totals::try_from(&aggregate).expect("the collected campaign is coherent");

    aggregate.trials.swap(0, 1);
    assert_eq!(
        packet_fuzz::Totals::try_from(&aggregate)
            .expect_err("reordered cases are refused")
            .to_string(),
        "case identity or publication order does not match the campaign"
    );
}
