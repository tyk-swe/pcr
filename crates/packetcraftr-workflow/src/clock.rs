// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::convert::Infallible;
use std::error::Error;
use std::time::Duration;

use packetcraftr_core::budget::Deadline;

/// Injectable delay seam shared by rate-limited and replay workflows.
pub trait Clock {
    type Error: Error + Send + Sync + 'static;

    fn sleep(&mut self, delay: Duration) -> Result<(), Self::Error>;
}

/// Production wall-clock implementation.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    type Error = Infallible;

    fn sleep(&mut self, delay: Duration) -> Result<(), Self::Error> {
        std::thread::sleep(delay);
        Ok(())
    }
}

pub(crate) fn rate_delay(items: usize, rate: Option<u32>) -> Option<Duration> {
    let Some(rate) = rate else {
        return Some(Duration::ZERO);
    };
    let rate = u128::from(rate);
    let nanos = (items as u128)
        .checked_mul(1_000_000_000)?
        .checked_add(rate.checked_sub(1)?)?
        / rate;
    Some(Duration::from_nanos(u64::try_from(nanos).ok()?))
}

pub(crate) fn check_deadline<E>(
    deadline: &Deadline,
    mut duration_error: impl FnMut(Duration, Duration) -> E,
) -> Result<(), E> {
    deadline
        .check()
        .map_err(|error| duration_error(error.actual, error.limit))
}
