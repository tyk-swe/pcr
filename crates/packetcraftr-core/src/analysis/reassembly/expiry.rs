// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use crate::analysis::Constraint;

/// An idle expiry the monotonic clock cannot add to the present, with the value to report.
pub(super) fn violation(expiry: Duration) -> Option<(u64, Constraint)> {
    Instant::now().checked_add(expiry).is_none().then(|| {
        (
            u64::try_from(expiry.as_millis()).unwrap_or(u64::MAX),
            Constraint::WithinClockRange,
        )
    })
}

/// Keys ordered by deadline, then key. Each entry is a single set node, so
/// moving a key to a new deadline allocates nothing beyond the set's nodes.
#[derive(Debug)]
pub(super) struct ExpiryIndex<K> {
    entries: BTreeSet<(Instant, K)>,
}

impl<K> Default for ExpiryIndex<K> {
    fn default() -> Self {
        Self {
            entries: BTreeSet::new(),
        }
    }
}

impl<K: Ord + Clone> ExpiryIndex<K> {
    pub(super) fn insert(&mut self, deadline: Option<Instant>, key: K) {
        if let Some(deadline) = deadline {
            self.entries.insert((deadline, key));
        }
    }

    pub(super) fn remove(&mut self, deadline: Option<Instant>, key: &K) {
        if let Some(deadline) = deadline {
            self.entries.remove(&(deadline, key.clone()));
        }
    }

    pub(super) fn take_expired(&mut self, now: Instant) -> Vec<K> {
        let mut keys = Vec::new();
        self.drain_expired(now, |key| keys.push(key));
        keys
    }

    pub(super) fn drain_expired<F>(&mut self, now: Instant, mut visit: F)
    where
        F: FnMut(K),
    {
        while self
            .entries
            .first()
            .is_some_and(|(deadline, _)| *deadline <= now)
        {
            if let Some((_, key)) = self.entries.pop_first() {
                visit(key);
            }
        }
    }
}
