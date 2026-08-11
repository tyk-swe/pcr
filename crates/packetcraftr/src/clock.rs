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

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn check_deadline_maps_the_budget_error_without_losing_durations() {
        check_deadline(&Deadline::new(Duration::MAX), |_, _| ())
            .expect("fresh deadline remains open");

        let mut deadline = Deadline::new(Duration::from_secs(1));
        deadline
            .account(Duration::from_secs(2))
            .expect_err("fixture must spend the deadline");

        let (actual, limit) = check_deadline(&deadline, |actual, limit| (actual, limit))
            .expect_err("spent deadline must be mapped");

        assert!(actual >= Duration::from_secs(2));
        assert_eq!(limit, Duration::from_secs(1));
    }
}
