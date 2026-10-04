// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
#![allow(dead_code)]

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use packetcraftr_core::budget::{Cancellation, Deadline};
use packetcraftr_core::error::Classified;
use packetcraftr_core::fuzz as packet_fuzz;
use packetcraftr_core::protocol::{network::Ipv4, transport::Udp};
use packetcraftr_core::{layer::Raw, packet::Packet};

use crate::clock::Clock;
use crate::execution::{Executor, publisher};
use crate::policy::{Authorizer, Operation};
use crate::runtime::Runtime;
use crate::test_support::{Call, FakeProviders, NoopClock};
use crate::{Sink, Stats};
use packetcraftr_core::error::BoundaryError;

use super::engine::run;
use super::error::duration_limit;
use super::executor::{CaseEvidence, CaseStep};
use super::{Aggregate, Collector, Error, Event, Outcome, Report, Request, Trial};

fn request(campaign: packet_fuzz::Request) -> Request {
    Request::new(campaign, packet())
}

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
fn live_ev_offline_campaign() {
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

struct AllowAll;

impl Authorizer for AllowAll {
    fn authorize_operation(&mut self, operation: Operation<'_>) -> Result<(), BoundaryError> {
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
fn live_pacing_clock_fail() {
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

#[derive(Clone, Copy)]
enum ResponseFault {
    None,
    MissingTimestamp,
    AfterTimeout,
}

/// Executes the case, then spends the campaign budget and/or cancels it while
/// answering with a response carrying `fault`.
struct InterruptingExecutor {
    fault: ResponseFault,
    now: Arc<std::sync::Mutex<std::time::Instant>>,
    expire: bool,
    signal: Option<Cancellation>,
}

impl Executor<CaseStep> for InterruptingExecutor {
    fn execute(&mut self, case: &CaseStep) -> Result<CaseEvidence, BoundaryError> {
        let mut execution = RebuildingExecutor.execute(case)?;
        let mut response = crate::test_support::decoded_packet(
            case.packet.clone(),
            std::time::UNIX_EPOCH,
            execution.sent.wire_bytes(),
            Vec::new(),
        );
        let mut latency = Duration::from_millis(1);
        match self.fault {
            ResponseFault::None => {}
            ResponseFault::MissingTimestamp => response.frame.timestamp = None,
            ResponseFault::AfterTimeout => latency = case.timeout + Duration::from_millis(1),
        }
        execution.responses.push(crate::exchange::Response {
            request_index: 0,
            response,
            latency,
        });
        if self.expire {
            *self.now.lock().unwrap() += Duration::from_secs(3600);
        }
        if let Some(signal) = &self.signal {
            signal.cancel();
        }
        Ok(execution)
    }
}

fn run_interrupted_case(
    fault: ResponseFault,
    expire: bool,
    cancel: bool,
) -> (Error, Arc<std::sync::atomic::AtomicUsize>) {
    let request = quick(bit_flip(2));
    let baseline = std::time::Instant::now();
    let now = Arc::new(std::sync::Mutex::new(baseline));
    let clock = Arc::clone(&now);
    let signal = Cancellation::default();
    let mut deadline =
        Deadline::with_time_source(request.campaign.limits.max_duration, move || {
            *clock.lock().unwrap()
        })
        .with_cancellation(Some(signal.clone()));
    let mut executor = InterruptingExecutor {
        fault,
        now,
        expire,
        signal: cancel.then_some(signal),
    };
    let published = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let observed = Arc::clone(&published);

    let error = run(
        &request,
        &mut AllowAll,
        packetcraftr_core::protocol::builtin::registry(),
        &mut executor,
        &mut NoopClock,
        &mut deadline,
        move |_, _| {
            observed.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        },
    )
    .expect_err("the interrupted case must stop the campaign");
    (error, published)
}

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

struct TamperingExecutor(fn(&mut CaseEvidence));

impl Executor<CaseStep> for TamperingExecutor {
    fn execute(&mut self, case: &CaseStep) -> Result<CaseEvidence, BoundaryError> {
        let mut execution = RebuildingExecutor.execute(case)?;
        (self.0)(&mut execution);
        Ok(execution)
    }
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

fn transmissions(providers: &FakeProviders) -> usize {
    providers
        .calls()
        .iter()
        .filter(|call| matches!(call, Call::Transmit(_)))
        .count()
}
