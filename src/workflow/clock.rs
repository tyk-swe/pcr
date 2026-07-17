// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::convert::Infallible;
use std::error::Error;
use std::time::Duration;

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

pub(super) fn rate_delay(items: usize, rate: Option<u32>) -> Option<Duration> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_delay_uses_ceiling_division() {
        assert_eq!(rate_delay(3, Some(2)), Some(Duration::from_millis(1_500)));
        assert_eq!(rate_delay(1, Some(u32::MAX)), Some(Duration::from_nanos(1)));
    }

    #[test]
    fn rate_delay_handles_disabled_and_invalid_rates() {
        assert_eq!(rate_delay(10, None), Some(Duration::ZERO));
        assert_eq!(rate_delay(1, Some(0)), None);
    }

    #[test]
    fn system_clock_implements_the_public_clock_trait() {
        let mut clock = crate::workflow::clock::SystemClock;
        assert_eq!(clock.sleep(Duration::ZERO), Ok(()));
    }
}
