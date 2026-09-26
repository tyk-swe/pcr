// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

use packetcraftr_netio::capture::MAX_TIMEOUT;

use super::LiveOptions;
use super::error::Error;

pub(super) fn worst_case_duration(live: LiveOptions, cases: usize) -> Result<Duration, Error> {
    let exchange = live
        .timeout
        .checked_mul(u32::try_from(cases).unwrap_or(u32::MAX))
        .ok_or(Error::DurationLimit {
            actual: Duration::MAX,
            limit: MAX_TIMEOUT,
        })?;
    let delay = rate_delay(live.cases_per_second)?
        .checked_mul(u32::try_from(cases.saturating_sub(1)).unwrap_or(u32::MAX))
        .ok_or(Error::DurationLimit {
            actual: Duration::MAX,
            limit: MAX_TIMEOUT,
        })?;
    exchange.checked_add(delay).ok_or(Error::DurationLimit {
        actual: Duration::MAX,
        limit: MAX_TIMEOUT,
    })
}

pub(super) fn rate_delay(rate: Option<u32>) -> Result<Duration, Error> {
    crate::clock::rate_delay(1, rate).ok_or(Error::InvalidLimit {
        field: "cases_per_second",
        value: u64::from(rate.unwrap_or_default()),
        reason: "rate-delay arithmetic overflowed".to_owned(),
    })
}
