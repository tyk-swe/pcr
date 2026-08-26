// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::{BTreeMap, BTreeSet};
use std::time::Instant;

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

    /// Removes deadlines through `now`, ordered by deadline and then stable key.
    pub(super) fn take_expired(&mut self, now: Instant) -> Vec<K> {
        let Some((&first_deadline, _)) = self.entries.first_key_value() else {
            return Vec::new();
        };
        if first_deadline > now {
            return Vec::new();
        }

        let mut future = self.entries.split_off(&now);
        let at_now = future.remove(&now);
        let expired = std::mem::replace(&mut self.entries, future);
        let mut keys = expired
            .into_values()
            .flat_map(BTreeSet::into_iter)
            .collect::<Vec<_>>();
        if let Some(at_now) = at_now {
            keys.extend(at_now);
        }
        keys
    }

    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.entries.values().map(BTreeSet::len).sum()
    }
}
