// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::{Error, capture::TimestampPrecision};

// the guard below rejects fractions outside 0..precision bound
pub(crate) fn system_time(
    seconds: i64,
    fraction: i64,
    precision: TimestampPrecision,
) -> Result<SystemTime, Error> {
    let bound = match precision {
        TimestampPrecision::Micro => 1_000_000,
        TimestampPrecision::Nano => 1_000_000_000,
    };
    if !(0..bound).contains(&fraction) {
        return Err(Error::Capture {
            message: format!(
                "native capture timestamp has invalid {} fraction {fraction}",
                precision
            ),
            source: None,
        });
    }
    let fractional = match precision {
        TimestampPrecision::Micro => Duration::from_micros(fraction as u64),
        TimestampPrecision::Nano => Duration::from_nanos(fraction as u64),
    };
    if seconds >= 0 {
        UNIX_EPOCH
            .checked_add(Duration::from_secs(seconds as u64))
            .and_then(|time| time.checked_add(fractional))
    } else {
        UNIX_EPOCH
            .checked_sub(Duration::from_secs(seconds.unsigned_abs()))
            .and_then(|time| time.checked_add(fractional))
    }
    .ok_or_else(|| Error::Capture {
        message: "native capture timestamp is outside SystemTime range".to_owned(),
        source: None,
    })
}

pub(crate) fn monotonic_packet_time(
    packet_timestamp: SystemTime,
    observed_wall: SystemTime,
    observed_at: Instant,
) -> Option<Instant> {
    let age = observed_wall.duration_since(packet_timestamp).ok()?;
    observed_at.checked_sub(age)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn representability_edges_are_exact_or_rejected_never_clamped() {
        for (seconds, fraction, precision, fractional) in [
            (
                i64::MAX,
                999_999_999,
                TimestampPrecision::Nano,
                Duration::from_nanos(999_999_999),
            ),
            (i64::MAX, 0, TimestampPrecision::Micro, Duration::ZERO),
            (
                i64::MIN,
                999_999_999,
                TimestampPrecision::Nano,
                Duration::from_nanos(999_999_999),
            ),
            (
                i64::MIN,
                1,
                TimestampPrecision::Micro,
                Duration::from_micros(1),
            ),
        ] {
            let expected = if seconds >= 0 {
                UNIX_EPOCH
                    .checked_add(Duration::from_secs(seconds as u64))
                    .and_then(|time| time.checked_add(fractional))
            } else {
                UNIX_EPOCH
                    .checked_sub(Duration::from_secs(seconds.unsigned_abs()))
                    .and_then(|time| time.checked_add(fractional))
            };
            match (system_time(seconds, fraction, precision), expected) {
                (Ok(actual), Some(expected)) => assert_eq!(actual, expected),
                (Err(Error::Capture { .. }), None) => {}
                (other, expected) => {
                    panic!("system_time({seconds}, {fraction}) = {other:?}, expected {expected:?}")
                }
            }
        }
    }
}
