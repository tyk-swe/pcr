// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::cell::Cell;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, UNIX_EPOCH};

use packetcraftr_core::budget::{Cancellation, Deadline};
use packetcraftr_core::error::{BoundaryError, Classification, Classified, Coordinate, Kind};

use super::*;
use crate::probe::runner::ProbeStepErrors;
use crate::probe::test_fixtures::{decoded_packet, raw_frame};
use crate::probe::{ErrorKind, Workflow};
use crate::test_fixtures::RecordingClock;

struct TestRequest {
    timeout: Duration,
    permit: ExecutionPermit,
}
impl Request for TestRequest {
    type Execution = TestReceipt;
}
impl LiveRequest for TestRequest {
    fn timeout_mut(&mut self) -> &mut Duration {
        &mut self.timeout
    }
    fn permit(&self) -> ExecutionPermit {
        self.permit
    }
}

struct TestReceipt {
    permit: ExecutionPermit,
    stats: Stats,
    matched: Vec<crate::exchange::Response>,
    unmatched: Vec<Frame>,
}
impl Receipt for TestReceipt {
    fn permit(&self) -> ExecutionPermit {
        self.permit
    }
    fn stats(&self) -> &Stats {
        &self.stats
    }
    fn diagnostics(&self) -> &[Diagnostic] {
        &[]
    }
    fn matched(&self) -> &[crate::exchange::Response] {
        &self.matched
    }
    fn unmatched(&self) -> &[Frame] {
        &self.unmatched
    }
    fn undecoded(&self) -> &[Frame] {
        &[]
    }
}

struct TestExecutor {
    calls: Vec<Duration>,
    fail: bool,
    wrong_permit: bool,
    cancelled: Option<Cancellation>,
    advance_time: Option<(Arc<Mutex<Instant>>, Duration)>,
    elapsed: Duration,
    bytes: u64,
    matched_latency: Option<Duration>,
    unmatched: Vec<Frame>,
}
impl Default for TestExecutor {
    fn default() -> Self {
        Self {
            calls: Vec::new(),
            fail: false,
            wrong_permit: false,
            cancelled: None,
            advance_time: None,
            elapsed: Duration::ZERO,
            bytes: 1,
            matched_latency: None,
            unmatched: Vec::new(),
        }
    }
}
impl Executor<TestRequest> for TestExecutor {
    fn execute(&mut self, request: &TestRequest) -> Result<TestReceipt, BoundaryError> {
        self.calls.push(request.timeout);
        if let Some((now, elapsed)) = &self.advance_time {
            *now.lock().unwrap() += *elapsed;
        }
        if let Some(signal) = &self.cancelled {
            signal.cancel();
        }
        if self.fail {
            return Err(BoundaryError::new(
                "executor failure",
                Classification::new("io.fixture", Kind::Io, None),
                Vec::new(),
            ));
        }
        Ok(TestReceipt {
            permit: if self.wrong_permit {
                ExecutionPermit::new()
            } else {
                request.permit
            },
            stats: Stats {
                packets_attempted: 1,
                packets_completed: 1,
                bytes: self.bytes,
                elapsed: self.elapsed,
                ..Stats::default()
            },
            matched: self
                .matched_latency
                .map(|latency| crate::exchange::Response {
                    request_index: 0,
                    response: decoded_packet(
                        packetcraftr_core::packet::Packet::new(),
                        UNIX_EPOCH,
                        &[0x45],
                        Vec::new(),
                    ),
                    latency,
                })
                .into_iter()
                .collect(),
            unmatched: self.unmatched.clone(),
        })
    }
}

fn errors(sequence: u64) -> ProbeStepErrors {
    ProbeStepErrors {
        workflow: Workflow::Scan,
        sequence,
    }
}
fn request() -> TestRequest {
    TestRequest {
        timeout: Duration::from_millis(800),
        permit: ExecutionPermit::new(),
    }
}
fn bounds() -> EvidenceBounds {
    EvidenceBounds {
        frames: 4,
        bytes: 4,
    }
}
fn deadline(spent: Duration) -> Deadline {
    let now = Instant::now();
    let mut deadline = Deadline::with_time_source(Duration::from_secs(1), move || now);
    let _ = deadline.account(spent);
    deadline
}
fn run(
    deadline: &mut Deadline,
    executor: &mut TestExecutor,
    request: &mut TestRequest,
    stats: &mut Stats,
    sequence: u64,
    validate: impl FnOnce(&TestRequest, &TestReceipt) -> Result<(), crate::probe::Error>,
) -> Result<TestReceipt, crate::probe::Error> {
    execute(
        deadline,
        executor,
        request,
        bounds(),
        stats,
        &errors(sequence),
        validate,
    )
}

#[test]
fn interruption_outranks_simultaneous_executor_failure() {
    let signal = Cancellation::default();
    let mut executor = TestExecutor {
        fail: true,
        cancelled: Some(signal.clone()),
        ..Default::default()
    };
    let error = run(
        &mut deadline(Duration::ZERO).with_cancellation(Some(signal)),
        &mut executor,
        &mut request(),
        &mut Stats::default(),
        42,
        |_, _| Ok(()),
    )
    .err()
    .expect("interrupted");
    assert!(matches!(error.kind, ErrorKind::Cancelled(_)));
    assert_eq!(executor.calls.len(), 1);
}

#[test]
fn wall_deadline_outweighs_executor_error_and_counts_a_returned_receipt() {
    for fail in [true, false] {
        let now = Arc::new(Mutex::new(Instant::now()));
        let source = Arc::clone(&now);
        let mut deadline =
            Deadline::with_time_source(Duration::from_secs(1), move || *source.lock().unwrap());
        let mut executor = TestExecutor {
            fail,
            advance_time: Some((now, Duration::from_secs(2))),
            ..Default::default()
        };
        let mut stats = Stats::default();
        let validated = Cell::new(false);
        let error = run(
            &mut deadline,
            &mut executor,
            &mut request(),
            &mut stats,
            50,
            |_, _| {
                validated.set(true);
                Ok(())
            },
        )
        .err()
        .unwrap();
        assert!(matches!(error.kind, ErrorKind::DurationLimit { .. }));
        assert_eq!(validated.get(), !fail);
        assert_eq!(stats.packets_completed, u64::from(!fail));
    }
}

#[test]
fn returned_receipt_is_validated_and_counted_before_interruption() {
    let signal = Cancellation::default();
    let mut executor = TestExecutor {
        cancelled: Some(signal.clone()),
        bytes: 9,
        ..Default::default()
    };
    let validated = Cell::new(false);
    let mut stats = Stats::default();
    let error = run(
        &mut deadline(Duration::ZERO).with_cancellation(Some(signal)),
        &mut executor,
        &mut request(),
        &mut stats,
        7,
        |_, receipt| {
            validated.set(receipt.stats.bytes == 9);
            Ok(())
        },
    )
    .err()
    .expect("interrupted");
    assert!(validated.get());
    assert!(matches!(error.kind, ErrorKind::Cancelled(_)));
    assert_eq!(stats.bytes, 9);
    assert_eq!(stats.packets_completed, 1);
}

#[test]
fn zero_and_exhausted_budgets_do_not_call_executor() {
    for spent in [
        Duration::ZERO,
        Duration::from_secs(1),
        Duration::from_millis(1001),
    ] {
        let mut deadline = if spent.is_zero() {
            Deadline::new(Duration::ZERO)
        } else {
            deadline(spent)
        };
        let mut executor = TestExecutor::default();
        let error = run(
            &mut deadline,
            &mut executor,
            &mut request(),
            &mut Stats::default(),
            3,
            |_, _| Ok(()),
        )
        .err()
        .unwrap();
        assert!(matches!(error.kind, ErrorKind::DurationLimit { .. }));
        assert!(executor.calls.is_empty());
    }
}

#[test]
fn clipped_timeout_rejects_late_evidence_before_accounting() {
    let mut executor = TestExecutor {
        matched_latency: Some(Duration::from_millis(300)),
        ..Default::default()
    };
    let mut request = request();
    let mut stats = Stats::default();
    let error = run(
        &mut deadline(Duration::from_millis(800)),
        &mut executor,
        &mut request,
        &mut stats,
        19,
        |request, receipt| {
            crate::probe::evidence::validate_response_frames_and_deadlines(
                &receipt.matched,
                &[],
                request.timeout,
            )
            .map_err(|error| errors(19).evidence(format!("{error:?}")))
        },
    )
    .err()
    .unwrap();
    assert!(matches!(
        error.kind,
        ErrorKind::InvalidEvidence { sequence: 19, .. }
    ));
    assert_eq!(executor.calls, [Duration::from_millis(200)]);
    assert_eq!(stats, Stats::default());
}

#[test]
fn preceding_pacing_tightens_timeout_and_charges_stats() {
    let mut deadline = deadline(Duration::from_millis(500));
    let mut clock = RecordingClock::default();
    let mut stats = Stats::default();
    let errors = errors(21);
    Pacer::wait(
        &mut deadline,
        &mut clock,
        Duration::from_millis(200),
        |error| errors.interrupted(error),
        |error| errors.duration(error),
        |source| errors.clock(Box::new(source)),
    )
    .unwrap();
    account_pacing(&mut stats, Duration::from_millis(200), &errors).unwrap();
    let mut executor = TestExecutor::default();
    let mut request = request();
    run(
        &mut deadline,
        &mut executor,
        &mut request,
        &mut stats,
        21,
        |_, _| Ok(()),
    )
    .unwrap();
    assert_eq!(executor.calls, [Duration::from_millis(300)]);
    assert_eq!(stats.elapsed, Duration::from_millis(200));
    assert_eq!(clock.delays, [Duration::from_millis(200)]);
}

#[test]
fn permit_mismatch_is_rejected_before_validation_even_if_cancelled() {
    let signal = Cancellation::default();
    let mut executor = TestExecutor {
        wrong_permit: true,
        cancelled: Some(signal.clone()),
        ..Default::default()
    };
    let called = Cell::new(false);
    let error = run(
        &mut deadline(Duration::ZERO).with_cancellation(Some(signal)),
        &mut executor,
        &mut request(),
        &mut Stats::default(),
        8,
        |_, _| {
            called.set(true);
            Ok(())
        },
    )
    .err()
    .unwrap();
    assert!(!called.get());
    assert!(matches!(
        error.kind,
        ErrorKind::InvalidEvidence { sequence: 8, .. }
    ));
}

#[test]
fn aggregate_frame_and_byte_caps_include_unmatched_raw_evidence() {
    for unmatched in [
        vec![
            raw_frame(0),
            raw_frame(1),
            raw_frame(2),
            raw_frame(3),
            raw_frame(4),
        ],
        vec![
            packetcraftr_core::frame::Frame::new(
                UNIX_EPOCH,
                packetcraftr_core::frame::LinkType::RAW,
                bytes::Bytes::from_static(&[1, 2, 3, 4, 5]),
            )
            .unwrap(),
        ],
    ] {
        let mut executor = TestExecutor {
            unmatched,
            ..Default::default()
        };
        let error = run(
            &mut deadline(Duration::ZERO),
            &mut executor,
            &mut request(),
            &mut Stats::default(),
            11,
            |_, _| Ok(()),
        )
        .err()
        .unwrap();
        assert!(matches!(
            error.kind,
            ErrorKind::InvalidEvidence { sequence: 11, .. }
        ));
    }
}

#[test]
fn statistics_overflow_has_workflow_coordinate_without_mutating_totals() {
    let mut stats = Stats {
        bytes: u64::MAX,
        ..Stats::default()
    };
    let error = run(
        &mut deadline(Duration::ZERO),
        &mut TestExecutor::default(),
        &mut request(),
        &mut stats,
        99,
        |_, _| Ok(()),
    )
    .err()
    .unwrap();
    assert!(matches!(
        error.kind,
        ErrorKind::StatisticsOverflow { sequence: 99 }
    ));
    assert_eq!(error.context(), Some(Coordinate::ProbeSequence(99)));
    assert_eq!(stats.packets_completed, 0);
    assert_eq!(stats.bytes, u64::MAX);
}

#[test]
fn fuzz_campaign_totals_use_checked_receipt_addition_without_changing_case_counts() {
    let mut stats = crate::fuzz::Stats {
        cases_generated: 7,
        cases_built: 5,
        ..Default::default()
    };
    execute(
        &mut deadline(Duration::ZERO),
        &mut TestExecutor::default(),
        &mut request(),
        bounds(),
        &mut stats,
        &errors(20),
        |_, _| Ok(()),
    )
    .unwrap();
    assert_eq!(stats.cases_generated, 7);
    assert_eq!(stats.cases_built, 5);
    assert_eq!(stats.packets_completed, 1);
    stats.bytes = u64::MAX;
    let before = stats.clone();
    let error = execute(
        &mut deadline(Duration::ZERO),
        &mut TestExecutor::default(),
        &mut request(),
        bounds(),
        &mut stats,
        &errors(22),
        |_, _| Ok(()),
    )
    .err()
    .unwrap();
    assert!(matches!(
        error.kind,
        ErrorKind::StatisticsOverflow { sequence: 22 }
    ));
    assert_eq!(stats, before);
}

#[test]
fn pacing_enforces_the_full_wall_deadline_after_sleep() {
    struct AdvancingClock(Arc<Mutex<Instant>>);
    impl Clock for AdvancingClock {
        type Error = std::convert::Infallible;
        fn sleep(&mut self, _: Duration) -> Result<(), Self::Error> {
            *self.0.lock().unwrap() += Duration::from_secs(2);
            Ok(())
        }
    }
    let now = Arc::new(Mutex::new(Instant::now()));
    let source = Arc::clone(&now);
    let mut deadline =
        Deadline::with_time_source(Duration::from_secs(1), move || *source.lock().unwrap());
    let errors = errors(15);
    let error = Pacer::wait(
        &mut deadline,
        &mut AdvancingClock(now),
        Duration::from_millis(100),
        |error| errors.interrupted(error),
        |error| errors.duration(error),
        |source| errors.clock(Box::new(source)),
    )
    .err()
    .unwrap();
    assert!(matches!(error.kind, ErrorKind::DurationLimit { .. }));
}
