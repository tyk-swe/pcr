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
    use packetcraftr_core::budget::Cancellation;

    use super::*;

    #[test]
    fn remaining_before_treats_the_boundary_as_arrived() {
        let now = Instant::now();
        assert!(remaining_before(now - Duration::from_secs(1)).is_none());
        assert!(remaining_before(now).is_none());
        let remaining = remaining_before(now + Duration::from_secs(3600)).expect("future deadline");
        assert!(remaining > Duration::from_secs(3599));
    }

    #[test]
    fn expires_at_refuses_a_spent_or_cancelled_deadline() {
        let frozen = Instant::now();
        let spent = Deadline::with_time_source(Duration::ZERO, move || frozen);
        assert!(matches!(expires_at(&spent), Err(Interrupted::Exceeded(_))));

        let signal = Cancellation::default();
        let live = Deadline::new(Duration::from_secs(60)).with_cancellation(Some(signal.clone()));
        assert!(expires_at(&live).is_ok());
        signal.cancel();
        assert!(matches!(expires_at(&live), Err(Interrupted::Cancelled(_))));
    }
}
