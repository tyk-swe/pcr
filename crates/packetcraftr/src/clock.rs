// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::convert::Infallible;
use std::error::Error;
use std::time::{Duration, Instant};

use packetcraftr_core::budget::Deadline;
use packetcraftr_netio::deadline::POLL_INTERVAL;

/// The client's source of monotonic time and pacing delays.
///
/// A client anchors every workflow deadline and send schedule on its clock, so
/// a deterministic clock drives a whole run. Capture waits stay on the capture
/// session: a fake clock must share the real monotonic base with capture
/// timestamps, starting from [`Instant::now`] and advancing only forward.
pub trait Clock: Clone + Send + Sync + 'static {
    type Error: Error + Send + Sync + 'static;

    /// Current monotonic time. Deterministic clocks must advance this value
    /// when sleeping or simulating work.
    fn now(&self) -> Instant {
        Instant::now()
    }

    /// Waits `delay`, returning early once `deadline`'s cancellation is
    /// signaled; the caller checks the deadline again afterwards.
    ///
    /// # Errors
    ///
    /// Returns the clock's own failure while the operation could still
    /// continue.
    fn sleep(&self, delay: Duration, deadline: &Deadline) -> Result<(), Self::Error>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    type Error = Infallible;

    fn sleep(&self, delay: Duration, deadline: &Deadline) -> Result<(), Self::Error> {
        interruptible_sleep(delay, || deadline.check_cancelled().is_err());
        Ok(())
    }
}

/// Sleeps `delay` in slices no longer than [`POLL_INTERVAL`], stopping early
/// once `stop` reports true.
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

pub(crate) fn rate_delay(items: usize, rate: Option<u32>) -> Option<Duration> {
    let Some(rate) = rate else {
        return Some(Duration::ZERO);
    };
    let rate = u128::from(rate);
    // `checked_sub(1)?` rejects a zero rate before division.
    let nanos = u128::try_from(items)
        .unwrap_or(u128::MAX)
        .checked_mul(1_000_000_000)?
        .checked_add(rate.checked_sub(1)?)?
        / rate;
    Some(Duration::from_nanos(u64::try_from(nanos).ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_system_clock_stops_sleeping_once_the_deadline_is_cancelled() {
        let signal = packetcraftr_core::budget::Cancellation::default();
        let deadline =
            Deadline::new(Duration::from_secs(120)).with_cancellation(Some(signal.clone()));
        signal.cancel();
        let started = Instant::now();
        let Ok(()) = SystemClock.sleep(Duration::from_secs(60), &deadline);
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn rate_delay_uses_ceiling_division_and_rejects_invalid_rates() {
        for (items, rate, expected) in [
            (99, None, Some(Duration::ZERO)),
            (0, Some(10), Some(Duration::ZERO)),
            (1, Some(1), Some(Duration::from_secs(1))),
            (1, Some(3), Some(Duration::from_nanos(333_333_334))),
            (3, Some(3), Some(Duration::from_secs(1))),
            (1, Some(u32::MAX), Some(Duration::from_nanos(1))),
            (1, Some(0), None),
        ] {
            assert_eq!(
                rate_delay(items, rate),
                expected,
                "items={items}, rate={rate:?}"
            );
        }

        #[cfg(target_pointer_width = "64")]
        assert_eq!(rate_delay(usize::MAX, Some(1)), None);
    }
}
