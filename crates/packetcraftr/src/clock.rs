// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::convert::Infallible;
use std::error::Error;
use std::time::{Duration, Instant};

use packetcraftr_core::budget::Deadline;
use packetcraftr_netio::deadline::POLL_INTERVAL;

/// The client's source of monotonic time and pacing delays.
/// A fake clock must share the real monotonic base with capture timestamps.
pub trait Clock: Clone + Send + Sync + 'static {
    type Error: Error + Send + Sync + 'static;

    /// Deterministic clocks must advance this value when sleeping or simulating work.
    fn now(&self) -> Instant {
        Instant::now()
    }

    /// Waits `delay`, returning early once `deadline` expires or is cancelled.
    fn sleep(&self, delay: Duration, deadline: &Deadline) -> Result<(), Self::Error>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    type Error = Infallible;

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
