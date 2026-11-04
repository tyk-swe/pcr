// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::convert::Infallible;
use std::error::Error;
use std::time::{Duration, Instant, SystemTime};

use crate::budget::{Deadline, POLL_INTERVAL};

/// The client's source of monotonic time and pacing delays.
/// A fake clock must share the real monotonic base with capture timestamps.
pub trait Clock: Clone + Send + Sync + 'static {
    type Error: Error + Send + Sync + 'static;

    /// Deterministic clocks must advance this value when sleeping or simulating work.
    fn now(&self) -> Instant;

    /// Wall-clock time for evidence stamps, on the same base as `now`.
    fn wall_now(&self) -> SystemTime;

    /// Waits `delay`, returning early once `deadline` expires or is cancelled.
    fn sleep(&self, delay: Duration, deadline: &Deadline) -> Result<(), Self::Error>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    type Error = Infallible;

    fn now(&self) -> Instant {
        Instant::now()
    }

    fn wall_now(&self) -> SystemTime {
        SystemTime::now()
    }

    fn sleep(&self, delay: Duration, deadline: &Deadline) -> Result<(), Self::Error> {
        interruptible_sleep(delay, || deadline.live_remaining().is_err());
        Ok(())
    }
}

fn interruptible_sleep(delay: Duration, stop: impl Fn() -> bool) {
    let start = Instant::now();
    loop {
        if stop() {
            return;
        }
        let remaining = delay.saturating_sub(start.elapsed());
        if remaining.is_zero() {
            return;
        }
        std::thread::sleep(remaining.min(POLL_INTERVAL));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn live_deadline_allows_requested_sleep() {
        let start = SystemClock.now();
        SystemClock
            .sleep(
                Duration::from_millis(50),
                &Deadline::new(Duration::from_secs(60)),
            )
            .unwrap();
        assert!(start.elapsed() >= Duration::from_millis(40));
    }

    #[test]
    fn clock_stops_at_spent_deadline() {
        let start = SystemClock.now();
        SystemClock
            .sleep(Duration::from_secs(10), &Deadline::immediate(None))
            .unwrap();
        assert!(start.elapsed() < Duration::from_secs(1));
    }
}
