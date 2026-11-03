// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

pub use packetcraftr_core::clock::{Clock, SystemClock};

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
    fn rate_delay_without_a_rate_never_waits() {
        assert_eq!(rate_delay(10, None), Some(Duration::ZERO));
    }

    #[test]
    fn rate_delay_spaces_items_evenly_and_rounds_up() {
        assert_eq!(rate_delay(1, Some(1_000)), Some(Duration::from_millis(1)));
        assert_eq!(rate_delay(2, Some(2)), Some(Duration::from_secs(1)));
        assert_eq!(
            rate_delay(1, Some(3)),
            Some(Duration::from_nanos(333_333_334))
        );
        assert_eq!(rate_delay(0, Some(5)), Some(Duration::ZERO));
    }

    #[test]
    fn rate_delay_rejects_a_zero_rate_and_unrepresentable_delays() {
        assert_eq!(rate_delay(1, Some(0)), None);
        assert_eq!(rate_delay(usize::MAX, Some(1)), None);
    }
}
