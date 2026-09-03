// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Wall-clock deadline arithmetic shared by the blocking I/O paths.

use std::time::{Duration, Instant};

/// Time left before `deadline`, or `None` once it has arrived. A socket
/// timeout of exactly zero is rejected as `InvalidInput`, so an exact hit must
/// classify as the deadline expiring rather than as an I/O failure.
pub(crate) fn remaining_before(deadline: Instant) -> Option<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
}
