// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::{Duration, Instant};

pub(crate) fn remaining_probe_time(start: Instant, timeout: Duration) -> Option<Duration> {
    remaining_probe_time_at(start, Instant::now(), timeout)
}

pub(crate) fn remaining_probe_time_at(
    start: Instant,
    now: Instant,
    timeout: Duration,
) -> Option<Duration> {
    now.checked_duration_since(start)
        .and_then(|elapsed| timeout.checked_sub(elapsed))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remaining_probe_time_at_returns_remaining_duration_before_timeout() {
        let start = Instant::now();
        let now = start + Duration::from_millis(40);

        assert_eq!(
            remaining_probe_time_at(start, now, Duration::from_millis(100)),
            Some(Duration::from_millis(60))
        );
    }

    #[test]
    fn remaining_probe_time_at_returns_zero_at_timeout_boundary() {
        let start = Instant::now();
        let timeout = Duration::from_millis(100);

        assert_eq!(
            remaining_probe_time_at(start, start + timeout, timeout),
            Some(Duration::ZERO)
        );
    }

    #[test]
    fn remaining_probe_time_at_returns_none_after_timeout() {
        let start = Instant::now();

        assert_eq!(
            remaining_probe_time_at(
                start,
                start + Duration::from_millis(101),
                Duration::from_millis(100)
            ),
            None
        );
    }
}
