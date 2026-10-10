// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::{Duration, Instant};

use packetcraftr_core::budget::{Cancellation, Deadline};

/// Allowance for a passive route or interface lookup whose operation has no deadline.
pub const PASSIVE_LOOKUP_TIMEOUT: Duration = Duration::from_secs(3);

pub(crate) fn until(deadline: Instant, cancellation: Option<Cancellation>) -> Deadline {
    Deadline::new(deadline.saturating_duration_since(Instant::now()))
        .with_cancellation(cancellation)
}

/// A spent deadline: a capture read given it takes only what is already queued.
pub(crate) fn immediate(cancellation: Option<Cancellation>) -> Deadline {
    Deadline::new(Duration::ZERO).with_cancellation(cancellation)
}
