// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Checked wall-clock and monotonic capture-time conversion.

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::Error;

#[expect(
    clippy::cast_sign_loss,
    reason = "the guard below rejects microseconds outside 0..1_000_000 and the branch below \
              only converts seconds once it is known to be non-negative"
)]
pub(in crate::platform) fn system_time(
    seconds: i64,
    microseconds: i64,
) -> Result<SystemTime, Error> {
    if !(0..1_000_000).contains(&microseconds) {
        return Err(Error::Capture {
            message: format!("native capture timestamp has invalid microseconds {microseconds}"),
            source: None,
        });
    }
    let fractional = Duration::from_micros(microseconds as u64);
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
        assert_eq!(system_time(0, 0).expect("epoch"), UNIX_EPOCH);
        assert_eq!(
            system_time(-1, 500_000).expect("pre-epoch timestamp"),
            UNIX_EPOCH - Duration::from_millis(500)
        );

        for invalid in [-1, 1_000_000] {
            assert!(matches!(
                system_time(0, invalid),
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
        assert_eq!(
            monotonic_packet_time(
                observed_wall + Duration::from_nanos(1),
                observed_wall,
                observed_at
            ),
            None
        );
    }
}
