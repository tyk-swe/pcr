// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! The one deadline and cancellation convention for provider calls.

use packetcraftr_core::clock::{Clock, SystemClock};
use std::time::{Duration, Instant};

use packetcraftr_core::budget::{Deadline, Interrupted};

/// Longest slice an uninterruptible wait should take between checks of a cancellation signal.
pub use packetcraftr_core::budget::POLL_INTERVAL;

pub const MAX_WAIT: Duration = Duration::from_secs(60 * 60);

/// Treat `None` as expiry before calling providers that reject a zero timeout.
#[must_use]
pub fn remaining_before(deadline: Instant) -> Option<Duration> {
    deadline
        .checked_duration_since(SystemClock.now())
        .filter(|remaining| !remaining.is_zero())
}

pub fn expires_at(deadline: &Deadline) -> Result<Instant, Interrupted> {
    let remaining = deadline.live_remaining()?.min(MAX_WAIT);
    let now = SystemClock.now();
    Ok(now.checked_add(remaining).unwrap_or(now))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn past_instant_is_expired() {
        let past = SystemClock.now() - Duration::from_secs(1);
        assert_eq!(remaining_before(past), None);
        let future = SystemClock.now() + Duration::from_secs(5);
        let remaining = remaining_before(future).unwrap();
        assert!(!remaining.is_zero() && remaining <= Duration::from_secs(5));
    }

    #[test]
    fn expiry_caps_long_deadlines() {
        let before = SystemClock.now();
        let expiry = expires_at(&Deadline::new(Duration::from_secs(10 * 60 * 60))).unwrap();
        let capped = expiry.duration_since(before);
        assert!(capped <= MAX_WAIT + Duration::from_secs(5), "{capped:?}");
        assert!(capped >= MAX_WAIT - Duration::from_secs(5), "{capped:?}");
        let before = SystemClock.now();
        let expiry = expires_at(&Deadline::new(Duration::from_secs(2))).unwrap();
        let short = expiry.duration_since(before);
        assert!(short >= Duration::from_secs(1), "{short:?}");
        assert!(short <= Duration::from_secs(3), "{short:?}");
    }

    #[test]
    fn expired_deadline_rejects_expiry_lookup() {
        assert!(expires_at(&Deadline::new(Duration::ZERO)).is_err());
    }
}
