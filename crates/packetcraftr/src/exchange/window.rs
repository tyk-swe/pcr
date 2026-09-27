// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;
use std::time::{Duration, Instant};

use packetcraftr_core::budget::{Cancellation, Deadline};

use crate::clock::Clock;

type TimeSource = Arc<dyn Fn() -> Instant + Send + Sync>;

pub(crate) struct Window {
    deadline: Deadline,
    started: Instant,
    ends_at: Instant,
    now: TimeSource,
}

impl Window {
    pub(crate) fn open<K: Clock>(
        clock: &K,
        limit: Duration,
        cancellation: Option<Cancellation>,
    ) -> Option<Self> {
        let source = clock.clone();
        let now: TimeSource = Arc::new(move || source.now());
        let started = now();
        let ends_at = started.checked_add(limit)?;
        let deadline = Deadline::with_time_source(limit, {
            let now = Arc::clone(&now);
            move || now()
        })
        .with_cancellation(cancellation);
        Some(Self {
            deadline,
            started,
            ends_at,
            now,
        })
    }

    pub(crate) fn deadline(&self) -> &Deadline {
        &self.deadline
    }

    /// Whether the window has closed. Its end itself is closed.
    pub(crate) fn expired(&self) -> bool {
        crate::planning::expired(&self.deadline)
    }

    pub(crate) fn ends_at(&self) -> Instant {
        self.ends_at
    }

    pub(crate) fn elapsed(&self) -> Duration {
        (self.now)().saturating_duration_since(self.started)
    }
}
