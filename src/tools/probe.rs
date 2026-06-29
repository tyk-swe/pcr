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
