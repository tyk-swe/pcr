// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Checked wall-clock and monotonic capture-time conversion.

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::Error as LiveIoError;

#[expect(
    clippy::cast_sign_loss,
    reason = "the guard below rejects microseconds outside 0..1_000_000 and the branch below \
              only converts seconds once it is known to be non-negative"
)]
pub(in crate::platform) fn system_time(
    seconds: i64,
    microseconds: i64,
) -> Result<SystemTime, LiveIoError> {
    if !(0..1_000_000).contains(&microseconds) {
        return Err(LiveIoError::Capture {
            message: format!("native capture timestamp has invalid microseconds {microseconds}"),
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
    .ok_or_else(|| LiveIoError::Capture {
        message: "native capture timestamp is outside SystemTime range".to_owned(),
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
    monotonic_time_for_age(age, observed_at)
}

pub(super) fn monotonic_time_for_age(age: Duration, observed_at: Instant) -> Option<Instant> {
    observed_at.checked_sub(age)
}
