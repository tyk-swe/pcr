// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! The one deadline and cancellation convention for provider calls.

use std::time::{Duration, Instant};

use packetcraftr_core::budget::{Deadline, Interrupted};

/// Longest slice an uninterruptible wait should take between checks of a cancellation signal.
pub const POLL_INTERVAL: Duration = Duration::from_millis(25);

pub const MAX_WAIT: Duration = Duration::from_secs(60 * 60);

/// Treat `None` as expiry before calling providers that reject a zero timeout.
#[must_use]
pub fn remaining_before(deadline: Instant) -> Option<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
}

pub fn expires_at(deadline: &Deadline) -> Result<Instant, Interrupted> {
    let remaining = deadline.live_remaining()?.min(MAX_WAIT);
    let now = Instant::now();
    Ok(now.checked_add(remaining).unwrap_or(now))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remaining_before_treats_past_and_present_as_expired() {
        let past = Instant::now() - Duration::from_secs(1);
        assert_eq!(remaining_before(past), None);
        let future = Instant::now() + Duration::from_secs(5);
        let remaining = remaining_before(future).unwrap();
        assert!(!remaining.is_zero() && remaining <= Duration::from_secs(5));
    }

    #[test]
    fn expires_at_never_exceeds_the_max_wait_cap() {
        let before = Instant::now();
        let expiry = expires_at(&Deadline::new(Duration::from_secs(10 * 60 * 60))).unwrap();
        assert!(expiry.duration_since(before) <= MAX_WAIT + Duration::from_secs(5));
        assert!(expiry > before);
    }

    #[test]
    fn expires_at_rejects_an_already_expired_deadline() {
        assert!(expires_at(&Deadline::new(Duration::ZERO)).is_err());
    }
}
