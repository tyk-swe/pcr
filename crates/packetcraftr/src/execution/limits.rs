// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

pub(crate) const MAX_RATE: u32 = 1_000_000;

pub(crate) fn check_limits<E>(
    ranges: &[(&'static str, usize, usize)],
    bounded_by: &[(&'static str, usize, usize, &str)],
    invalid: impl Fn(&'static str, u64, String) -> E,
) -> Result<(), E> {
    for &(field, value, maximum) in ranges {
        if value == 0 || value > maximum {
            return Err(invalid(
                field,
                widen(value),
                format!("must be within 1..={maximum}"),
            ));
        }
    }
    for &(field, value, maximum, reason) in bounded_by {
        if value > maximum {
            return Err(invalid(field, widen(value), reason.to_owned()));
        }
    }
    Ok(())
}

pub(crate) use crate::evidence::Limits as EvidenceLimits;

pub(crate) fn check_rate<E>(
    errors: fn(u64, crate::execution::Failure) -> E,
    field: &'static str,
    rate: Option<u32>,
) -> Result<(), E> {
    match rate {
        Some(rate) if rate == 0 || rate > MAX_RATE => Err((errors)(
            0_u64,
            crate::execution::Failure::InvalidLimit {
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

fn widen(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}
