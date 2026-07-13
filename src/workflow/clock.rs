// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::convert::Infallible;
use std::error::Error;
use std::time::Duration;

/// Injectable delay seam shared by rate-limited and replay workflows.
pub trait Clock {
    type Error: Error + Send + Sync + 'static;

    fn sleep(&mut self, delay: Duration) -> Result<(), Self::Error>;

    /// Cancellation-aware delay. Test clocks retain their deterministic sleep
    /// behavior through this default; the system clock wakes immediately.
    fn sleep_cancelled(
        &mut self,
        delay: Duration,
        cancellation: &crate::operation::Cancellation,
    ) -> Result<(), SleepError<Self::Error>> {
        cancellation.check().map_err(SleepError::Cancelled)?;
        self.sleep(delay).map_err(SleepError::Clock)?;
        cancellation.check().map_err(SleepError::Cancelled)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SleepError<E: Error + 'static> {
    #[error("{0}")]
    Clock(E),
    #[error("{0}")]
    Cancelled(crate::operation::Error),
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

    fn sleep_cancelled(
        &mut self,
        delay: Duration,
        cancellation: &crate::operation::Cancellation,
    ) -> Result<(), SleepError<Self::Error>> {
        cancellation.wait(delay).map_err(SleepError::Cancelled)
    }
}

/// Backward-compatible name for [`SystemClock`].
pub use SystemClock as System;

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
    fn preferred_public_clock_name_is_usable() {
        let mut clock = crate::workflow::clock::SystemClock;
        assert_eq!(clock.sleep(Duration::ZERO), Ok(()));

        let _legacy_name: crate::workflow::clock::System = clock;
    }
}
