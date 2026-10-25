// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

pub(crate) const MAX_RATE: u32 = 1_000_000;

pub(crate) fn check_rate<E>(
    errors: fn(u64, crate::error::Failure) -> E,
    field: &'static str,
    rate: Option<u32>,
) -> Result<(), E> {
    match rate {
        Some(rate) if rate == 0 || rate > MAX_RATE => Err((errors)(
            0_u64,
            crate::error::Failure::InvalidLimit {
                field,
                value: u64::from(rate),
                reason: format!("must be within 1..={MAX_RATE}"),
            },
        )),
        _ => Ok(()),
    }
}

pub(crate) fn duration_violation(value: Duration, maximum: Duration) -> bool {
    value.is_zero() || value > maximum
}
