// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::{Arc, Mutex};
use std::time::Instant;

use packetcraftr_core::budget::{Cancellation, Cancelled};

use super::*;
use crate::test_support::{Failure, RecordingClock, TestErrors};

#[derive(Debug, thiserror::Error)]
#[error("pacing timer failed")]
struct TimerFault;

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
