// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

use crate::analysis::Constraint;

/// An idle expiry the monotonic clock cannot add to the present, which could
/// never be scheduled, with the value to report.
pub(super) fn violation(expiry: Duration) -> Option<(u64, Constraint)> {
    Instant::now().checked_add(expiry).is_none().then(|| {
        (
            u64::try_from(expiry.as_millis()).unwrap_or(u64::MAX),
            Constraint::WithinClockRange,
        )
    })
}

/// Deadlines paired one-for-one with retained reassembly states.
#[derive(Debug)]
pub(super) struct ExpiryIndex<K> {
    entries: BTreeMap<Instant, BTreeSet<K>>,
}

impl<K> Default for ExpiryIndex<K> {
    fn default() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }
}

impl<K: Ord> ExpiryIndex<K> {
    pub(super) fn insert(&mut self, deadline: Option<Instant>, key: K) {
        if let Some(deadline) = deadline {
            self.entries.entry(deadline).or_default().insert(key);
        }
    }

    pub(super) fn remove(&mut self, deadline: Option<Instant>, key: &K) {
        let Some(deadline) = deadline else {
            return;
        };
        let remove_deadline = self.entries.get_mut(&deadline).is_some_and(|keys| {
            keys.remove(key);
            keys.is_empty()
        });
        if remove_deadline {
            self.entries.remove(&deadline);
        }
    }

    /// Removes deadlines through `now` and returns their keys in index order
    /// (deadline, then key). Eviction order is the caller's to choose: the
    /// TCP engine re-sorts them by key alone.
    pub(super) fn take_expired(&mut self, now: Instant) -> Vec<K> {
        let mut keys = Vec::new();
        self.drain_expired(now, |key| keys.push(key));
        keys
    }

    /// Removes deadlines through `now`, visiting each key in deadline and
    /// then stable-key order without first collecting an unbounded key list.
    pub(super) fn drain_expired<F>(&mut self, now: Instant, mut visit: F)
    where
        F: FnMut(K),
    {
        for (_, keys) in self.entries.extract_if(..=now, |_, _| true) {
            for key in keys {
                visit(key);
            }
        }
    }

    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.entries.values().map(BTreeSet::len).sum()
    }
}
