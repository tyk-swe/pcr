// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Wall-clock helpers for provider waits bounded by a deadline or a
//! cooperative [`Cancellation`](packetcraftr_core::budget::Cancellation).

use std::time::{Duration, Instant};

/// Longest slice an uninterruptible wait should take between checks of a
/// cancellation signal, so a stop request is honored promptly without
/// spinning.
pub const POLL_INTERVAL: Duration = Duration::from_millis(25);

/// Wall-clock time remaining, or `None` at or after `deadline`. Treat `None` as
/// expiry before calling providers that reject a zero timeout.
#[must_use]
pub fn remaining_before(deadline: Instant) -> Option<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remaining_before_treats_the_boundary_as_arrived() {
        let now = Instant::now();
        assert!(remaining_before(now - Duration::from_secs(1)).is_none());
        assert!(remaining_before(now).is_none());
        let remaining = remaining_before(now + Duration::from_secs(3600)).expect("future deadline");
        assert!(remaining > Duration::from_secs(3599));
    }
}
