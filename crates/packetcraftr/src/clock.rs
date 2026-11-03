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
