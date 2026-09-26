// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::{Arc, Mutex};
use std::time::Instant;

use packetcraftr_core::budget::{Cancellation, Cancelled};
use packetcraftr_core::error::{Classification, Classified, Kind};

use super::*;
use crate::StatsOverflow;
use crate::test_support::{Failure, RecordingClock, TestErrors};

#[derive(Debug, thiserror::Error)]
#[error("pacing timer failed")]
struct TimerFault;

/// Monotonic test time: deadlines read it and [`ScriptedClock`] advances it.
#[derive(Clone)]
struct Time(Arc<Mutex<Instant>>);

impl Time {
    fn new() -> Self {
        Self(Arc::new(Mutex::new(Instant::now())))
    }

    fn deadline(&self, limit: Duration) -> Deadline {
        let time = self.0.clone();
        Deadline::with_time_source(limit, move || *time.lock().unwrap())
    }

    fn advance(&self, by: Duration) {
        let mut now = self.0.lock().unwrap();
        *now += by;
    }
}

/// Records every sleep, advances [`Time`] by the delay plus `overrun`, and can
/// raise a stop request or fail while sleeping.
#[derive(Clone)]
struct ScriptedClock {
    recording: RecordingClock,
    time: Time,
    overrun: Duration,
    cancel: Option<Cancellation>,
    fail: bool,
}

impl ScriptedClock {
    fn new(time: &Time) -> Self {
        Self {
            recording: RecordingClock::default(),
            time: time.clone(),
            overrun: Duration::ZERO,
            cancel: None,
            fail: false,
        }
    }
}

impl Clock for ScriptedClock {
    type Error = TimerFault;

    fn sleep(&self, delay: Duration, deadline: &Deadline) -> Result<(), TimerFault> {
        let Ok(()) = self.recording.sleep(delay, deadline);
        self.time.advance(delay + self.overrun);
        if let Some(signal) = &self.cancel {
            signal.cancel();
        }
        if self.fail { Err(TimerFault) } else { Ok(()) }
    }
}

#[derive(Debug)]
struct Evidence {
    permit: ExecutionPermit,
    stats: Stats,
}

impl Receipt for Evidence {
    fn permit(&self) -> ExecutionPermit {
        self.permit
    }
    fn stats(&self) -> &Stats {
        &self.stats
    }
}

fn sent(packets: u64, elapsed: Duration) -> Stats {
    Stats {
        packets_attempted: packets,
        packets_completed: packets,
        bytes: packets * 60,
        elapsed,
        ..Stats::default()
    }
}

fn executor_failure() -> BoundaryError {
    BoundaryError::new(
        "executor failed",
        Classification::new("io.test_executor", Kind::Io, None),
        Vec::new(),
    )
}

/// Runs a step whose work returns `stats` under the granted permit, after
/// calling `during` to simulate what happens while the executor is blocked.
fn run_step(
    context: &mut Context<'_, impl Clock, TestErrors>,
    timeout: Duration,
    stats: Stats,
    during: impl FnOnce(),
) -> Result<(Evidence, Grant), Failure> {
    context.step(
        3,
        timeout,
        &mut (),
        |(), grant| {
            during();
            Ok(Evidence {
                permit: grant.permit,
                stats,
            })
        },
        |(), _, _, _| Ok(()),
    )
}

#[test]
fn after_a_sleep_interruption_outranks_a_clock_failure() {
    let signal = Cancellation::default();
    for (cancel, overrun) in [
        (true, Duration::ZERO),
        (false, Duration::from_secs(2)),
        (true, Duration::from_secs(2)),
        (false, Duration::ZERO),
    ] {
        let time = Time::new();
        let mut deadline = time
            .deadline(Duration::from_secs(1))
            .with_cancellation(cancel.then(|| signal.clone()));
        let mut clock = ScriptedClock {
            overrun,
            cancel: cancel.then(|| signal.clone()),
            fail: true,
            ..ScriptedClock::new(&time)
        };
        let mut context = Context::new(&mut deadline, &mut clock, TestErrors);

        let error = context
            .pace(7, Duration::from_millis(100))
            .expect_err("the clock failed");

        let case = format!("cancel={cancel}, overrun={overrun:?}");
        match error {
            Failure::Interrupted(7, Interrupted::Cancelled(_)) => assert!(cancel, "{case}"),
            Failure::Interrupted(7, Interrupted::Exceeded(exceeded)) => {
                assert!(!cancel && !overrun.is_zero(), "{case}");
                assert_eq!(exceeded.limit, Duration::from_secs(1));
            }
            Failure::Clock(7, source) => {
                assert!(!cancel && overrun.is_zero(), "{case}");
                assert!(source.downcast_ref::<TimerFault>().is_some());
            }
            error => panic!("{case}: unexpected {error:?}"),
        }
        assert_eq!(context.into_stats().elapsed, Duration::ZERO, "{case}");
    }
}

#[test]
fn cancellation_during_a_sleep_stops_before_the_delay_is_charged_or_work_runs() {
    let signal = Cancellation::default();
    let time = Time::new();
    let mut deadline = time
        .deadline(Duration::from_secs(10))
        .with_cancellation(Some(signal.clone()));
    let mut clock = ScriptedClock {
        cancel: Some(signal),
        ..ScriptedClock::new(&time)
    };
    let mut context = Context::new(&mut deadline, &mut clock, TestErrors);

    let error = context
        .pace(1, Duration::from_millis(250))
        .expect_err("stop requested while sleeping");
    assert!(matches!(
        error,
        Failure::Interrupted(1, Interrupted::Cancelled(Cancelled))
    ));
    let mut executed = false;
    let error = run_step(
        &mut context,
        Duration::from_secs(1),
        Stats::default(),
        || executed = true,
    )
    .expect_err("a cancelled operation starts no step");
    assert!(matches!(error, Failure::Interrupted(3, _)));
    assert!(!executed);
    assert_eq!(context.into_stats().elapsed, Duration::ZERO);
    assert_eq!(clock.recording.delays(), [Duration::from_millis(250)]);
}

#[test]
fn scheduled_delay_is_added_to_elapsed_stats() {
    let time = Time::new();
    let mut deadline = time.deadline(Duration::from_secs(10));
    let mut clock = RecordingClock::default();
    let mut context = Context::new(&mut deadline, &mut clock, TestErrors);

    context
        .pace(1, Duration::from_millis(200))
        .expect("delay fits the budget");
    run_step(
        &mut context,
        Duration::from_secs(1),
        sent(1, Duration::from_millis(500)),
        || {},
    )
    .expect("step fits the budget");
    context
        .pace(2, Duration::from_millis(300))
        .expect("delay fits the budget");

    assert_eq!(context.into_stats(), sent(1, Duration::from_secs(1)));
    assert_eq!(
        clock.delays(),
        [Duration::from_millis(200), Duration::from_millis(300)]
    );
}

#[test]
fn a_delay_past_the_remaining_budget_is_refused_before_sleeping() {
    let time = Time::new();
    let mut deadline = time.deadline(Duration::from_secs(1));
    let mut clock = RecordingClock::default();
    let mut context = Context::new(&mut deadline, &mut clock, TestErrors);
    context
        .pace(1, Duration::from_millis(600))
        .expect("delay fits the budget");

    let error = context
        .pace(2, Duration::from_millis(600))
        .expect_err("the delay would pass the budget");

    assert!(matches!(
        error,
        Failure::DurationLimit(2, DeadlineExceeded { limit, .. }) if limit == Duration::from_secs(1)
    ));
    assert_eq!(context.into_stats().elapsed, Duration::from_millis(600));
    assert_eq!(clock.delays(), [Duration::from_millis(600)]);
}

#[test]
fn step_timeouts_are_clipped_to_the_remaining_budget() {
    let time = Time::new();
    let mut deadline = time.deadline(Duration::from_secs(1));
    let mut clock = RecordingClock::default();
    let mut context = Context::new(&mut deadline, &mut clock, TestErrors);
    run_step(
        &mut context,
        Duration::from_secs(1),
        sent(1, Duration::from_millis(500)),
        || {},
    )
    .expect("first step fits");
    context
        .pace(2, Duration::from_millis(200))
        .expect("delay fits");

    let mut granted = Vec::new();
    let (_, grant) = context
        .step(
            3,
            Duration::from_millis(800),
            &mut granted,
            |granted, grant| {
                granted.push(grant);
                Ok(Evidence {
                    permit: grant.permit,
                    stats: Stats::default(),
                })
            },
            |granted, _, grant, _| {
                granted.push(grant);
                Ok(())
            },
        )
        .expect("clipped step runs");

    assert_eq!(grant.timeout, Duration::from_millis(300));
    assert_eq!(granted, [grant, grant]);
}

#[test]
fn a_spent_budget_never_executes_a_step() {
    for spent in [Duration::from_secs(1), Duration::from_millis(1001)] {
        let time = Time::new();
        let mut deadline = time.deadline(Duration::from_secs(1));
        let _ = deadline.account(spent);
        let mut clock = RecordingClock::default();
        let mut context = Context::new(&mut deadline, &mut clock, TestErrors);
        let mut executed = false;

        let error = run_step(
            &mut context,
            Duration::from_millis(800),
            Stats::default(),
            || executed = true,
        )
        .expect_err("no budget remains for the step");

        match error {
            // Exactly spent: the gate passes, but no timeout is left to grant.
            Failure::DurationLimit(3, exceeded) => {
                assert_eq!(spent, Duration::from_secs(1));
                assert_eq!(exceeded.limit, Duration::from_secs(1));
            }
            Failure::Interrupted(3, Interrupted::Exceeded(_)) => {
                assert_eq!(spent, Duration::from_millis(1001));
            }
            error => panic!("spent={spent:?}: unexpected {error:?}"),
        }
        assert!(!executed, "spent={spent:?}");
    }
}

#[test]
fn a_permit_mismatch_fails_before_validation_or_accounting() {
    let time = Time::new();
    let mut deadline = time.deadline(Duration::from_secs(10));
    let mut clock = RecordingClock::default();
    let mut context = Context::new(&mut deadline, &mut clock, TestErrors);
    let mut validated = false;

    let error = context
        .step(
            3,
            Duration::from_secs(1),
            &mut validated,
            |_, _| {
                Ok(Evidence {
                    permit: ExecutionPermit::new(),
                    stats: sent(1, Duration::from_millis(5)),
                })
            },
            |validated, _, _, _| {
                *validated = true;
                Ok(())
            },
        )
        .expect_err("evidence from another permit is rejected");

    assert!(matches!(
        error,
        Failure::InvalidEvidence(3, crate::evidence::Error::PermitMismatch)
    ));
    assert!(!validated);
    assert_eq!(context.into_stats(), Stats::default());
}

#[test]
fn stats_are_merged_before_a_post_execution_interruption_surfaces() {
    let signal = Cancellation::default();
    let time = Time::new();
    let mut deadline = time
        .deadline(Duration::from_secs(10))
        .with_cancellation(Some(signal.clone()));
    let mut clock = RecordingClock::default();
    let mut context = Context::new(&mut deadline, &mut clock, TestErrors);

    let error = run_step(
        &mut context,
        Duration::from_secs(1),
        sent(2, Duration::from_millis(40)),
        || signal.cancel(),
    )
    .expect_err("stop requested during execution");

    assert!(matches!(
        error,
        Failure::Interrupted(3, Interrupted::Cancelled(_))
    ));
    assert_eq!(context.into_stats(), sent(2, Duration::from_millis(40)));
}

#[test]
fn an_interruption_outranks_a_failed_execution() {
    for cancel in [true, false] {
        let signal = Cancellation::default();
        let time = Time::new();
        let mut deadline = time
            .deadline(Duration::from_secs(10))
            .with_cancellation(Some(signal.clone()));
        let mut clock = RecordingClock::default();
        let mut context = Context::new(&mut deadline, &mut clock, TestErrors);

        let error = context
            .step(
                3,
                Duration::from_secs(1),
                &mut (),
                |(), _| -> Result<Evidence, _> {
                    if cancel {
                        signal.cancel();
                    }
                    Err(executor_failure())
                },
                |(), _, _, _| Ok(()),
            )
            .expect_err("the executor failed");

        match error {
            Failure::Interrupted(3, Interrupted::Cancelled(_)) => assert!(cancel),
            Failure::Execution(3, source) => {
                assert!(!cancel);
                assert_eq!(source.classification().code, "io.test_executor");
            }
            error => panic!("cancel={cancel}: unexpected {error:?}"),
        }
    }
}

#[test]
fn stats_overflow_is_mapped_through_the_adapter_and_leaves_stats_untouched() {
    let time = Time::new();
    let mut deadline = time.deadline(Duration::from_secs(10));
    let mut clock = RecordingClock::default();
    let mut context = Context::new(&mut deadline, &mut clock, TestErrors);
    let saturated = Stats {
        packets_attempted: u64::MAX,
        ..Stats::default()
    };
    context.merge(1, &saturated).expect("first merge fits");

    let error = run_step(
        &mut context,
        Duration::from_secs(1),
        sent(1, Duration::ZERO),
        || {},
    )
    .expect_err("the attempted-packet counter overflows");

    assert!(matches!(error, Failure::StatsOverflow(3, StatsOverflow)));
    assert_eq!(context.into_stats(), saturated);
}

#[test]
fn a_rate_delay_names_an_invalid_rate_through_the_adapter() {
    assert_eq!(
        rate_delay(&TestErrors, "probes_per_second", 3, Some(3)).unwrap(),
        Duration::from_secs(1)
    );
    assert!(matches!(
        rate_delay(&TestErrors, "probes_per_second", 1, Some(0)),
        Err(Failure::InvalidLimit("probes_per_second"))
    ));
}
