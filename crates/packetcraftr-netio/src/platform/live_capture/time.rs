// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Checked wall-clock and monotonic capture-time conversion.

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::{Error, capture::TimestampPrecision};

// the guard below rejects fractions outside 0..precision bound and the branch
// below only converts seconds once it is known to be non-negative
pub(in crate::platform) fn system_time(
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

/// Projects a wall-clock timestamp to monotonic time; returns `None` for future
/// or unrepresentably old packets.
pub(in crate::platform) fn monotonic_packet_time(
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
    fn timestamp_conversion_is_checked_across_clock_domains() {
        let micro = TimestampPrecision::Micro;
        assert_eq!(system_time(0, 0, micro).expect("epoch"), UNIX_EPOCH);
        assert_eq!(
            system_time(-1, 500_000, micro).expect("pre-epoch timestamp"),
            UNIX_EPOCH - Duration::from_millis(500)
        );

        for invalid in [-1, 1_000_000] {
            assert!(matches!(
                system_time(0, invalid, micro),
                Err(Error::Capture { .. })
            ));
        }

        let observed_at = Instant::now();
        let observed_wall = UNIX_EPOCH + Duration::from_secs(10);
        let packet_wall = observed_wall - Duration::from_millis(25);
        assert_eq!(
            monotonic_packet_time(packet_wall, observed_wall, observed_at),
            observed_at.checked_sub(Duration::from_millis(25))
        );
        // Windows SystemTime has 100 ns precision, so a 1 ns offset rounds away.
        let future_wall = observed_wall + Duration::from_secs(1);
        assert!(future_wall > observed_wall);
        assert_eq!(
            monotonic_packet_time(future_wall, observed_wall, observed_at),
            None
        );
    }

    #[test]
    fn nanosecond_fractions_are_not_read_as_microseconds() {
        let nano = TimestampPrecision::Nano;
        // A nanosecond field over the microsecond bound is accepted and lands
        // at its own value, never divided or clamped into microseconds.
        assert_eq!(
            system_time(0, 999_999_999, nano).expect("upper bound"),
            UNIX_EPOCH + Duration::from_nanos(999_999_999)
        );
        assert_eq!(
            system_time(0, 1, nano).expect("one nanosecond"),
            UNIX_EPOCH + Duration::from_nanos(1)
        );
        // The same fraction value means different durations per precision.
        assert_eq!(
            system_time(0, 500_000, nano).expect("nano fraction"),
            UNIX_EPOCH + Duration::from_nanos(500_000)
        );
        // Pre-epoch seconds keep a positive sub-second fraction. Use a
        // fraction representable by Windows SystemTime's 100 ns ticks.
        assert_eq!(
            system_time(-1, 999_999_900, nano).expect("pre-epoch nano"),
            UNIX_EPOCH - Duration::from_nanos(100)
        );
        for invalid in [-1, 1_000_000_000, i64::MIN, i64::MAX] {
            assert!(
                matches!(system_time(0, invalid, nano), Err(Error::Capture { .. })),
                "fraction {invalid}"
            );
        }
    }

    #[test]
    fn representability_edges_are_exact_or_rejected_never_clamped() {
        // The conversion is checked, never clamped: a 64-bit-timespec host
        // represents every i64 second exactly, while a narrower SystemTime
        // (Windows FILETIME ticks) must reject instead of wrapping. Either
        // way the result agrees with the checked arithmetic itself.
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
