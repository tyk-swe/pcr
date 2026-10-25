// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::{BTreeMap, BTreeSet};

use packetcraftr_core::{
    error::BoundaryError,
    packet::Packet,
    protocol::response_identity::{self, Identity},
    registry::Registry,
};

#[derive(Default)]
struct Scope {
    buckets: BTreeMap<Identity, BTreeSet<usize>>,
    fallback: BTreeSet<usize>,
    all: BTreeSet<usize>,
}

struct Entry {
    source: usize,
    keys: Option<[Identity; 2]>,
}

/// The source index belongs to one armed capture group's validated interface
/// identities. Every retained attempt has its own stable index; collisions
/// retain every member and never manufacture a uniquely attributed response.
pub(in crate::scan::executor::pipeline) struct CandidateIndex {
    scopes: Vec<Scope>,
    entries: BTreeMap<usize, Entry>,
    capacity: usize,
}

impl CandidateIndex {
    pub(in crate::scan::executor::pipeline) fn new(sources: usize, capacity: usize) -> Self {
        Self {
            scopes: (0..sources).map(|_| Scope::default()).collect(),
            entries: BTreeMap::new(),
            capacity,
        }
    }

    pub(in crate::scan::executor::pipeline) fn insert(
        &mut self,
        index: usize,
        source: usize,
        packet: &Packet,
        registry: &Registry,
    ) -> Result<(), BoundaryError> {
        if self.entries.len() >= self.capacity {
            return Err(super::super::limit(
                "candidate index entries",
                self.capacity,
            ));
        }
        if source >= self.scopes.len() || self.entries.contains_key(&index) {
            return Err(BoundaryError::internal_execution(
                "scan candidate index received an invalid source or repeated attempt",
                "internal.scan_candidate_index",
                "retain unique attempt identity within the armed capture group",
            ));
        }
        let keys = packet
            .iter()
            .filter_map(|layer| registry.matcher(layer.protocol_id().as_str()))
            .all(|matcher| matcher.uses_builtin_response_identity())
            .then(|| response_identity::request(packet))
            .flatten();
        let scope = &mut self.scopes[source];
        scope.all.insert(index);
        match keys {
            Some(keys) => {
                scope.buckets.entry(keys[0]).or_default().insert(index);
                if keys[1] != keys[0] {
                    scope.buckets.entry(keys[1]).or_default().insert(index);
                }
            }
            None => {
                scope.fallback.insert(index);
            }
        }
        self.entries.insert(index, Entry { source, keys });
        Ok(())
    }

    /// Pending-to-recent transfer keeps membership. Actual eviction removes
    /// the entry and empty buckets, so historical keys cannot grow this index.
    pub(in crate::scan::executor::pipeline) fn remove(&mut self, index: usize) {
        let Some(entry) = self.entries.remove(&index) else {
            return;
        };
        let scope = &mut self.scopes[entry.source];
        scope.all.remove(&index);
        match entry.keys {
            Some(keys) => {
                for key in keys {
                    if let Some(bucket) = scope.buckets.get_mut(&key) {
                        bucket.remove(&index);
                        if bucket.is_empty() {
                            scope.buckets.remove(&key);
                        }
                    }
                }
            }
            None => {
                scope.fallback.remove(&index);
            }
        }
    }

    pub(in crate::scan::executor::pipeline) fn lookup(
        &self,
        source: usize,
        response: &Packet,
    ) -> Vec<usize> {
        let Some(scope) = self.scopes.get(source) else {
            return Vec::new();
        };
        let Some(keys) = response_identity::response(response) else {
            return scope.all.iter().copied().collect();
        };
        // Missing outer IP paths cannot produce an Observation, even with a
        // custom matcher: that gate precedes matcher dispatch.
        if keys.is_empty() {
            return Vec::new();
        }
        let mut possible = scope.fallback.clone();
        for key in keys {
            if let Some(bucket) = scope.buckets.get(&key) {
                possible.extend(bucket.iter().copied());
            }
        }
        possible.into_iter().collect()
    }
}

/// Conservative reservation for two keys/entry, B-tree node slack, collision and
/// scope membership nodes, temporary key extraction and deduplicated query
/// overlap. Numeric source indices borrow the already charged interface table.
/// All structures grow only to their live-entry high-water bound.
pub(in crate::scan::executor::pipeline) fn charge(capacity: usize, sources: usize) -> usize {
    capacity
        .saturating_add(1)
        .saturating_mul(2048)
        // New epoch scopes are allocated before the emptied old table drops.
        .saturating_add(
            sources
                .saturating_mul(std::mem::size_of::<Scope>())
                .saturating_mul(2),
        )
        .saturating_add(
            response_identity::MAX_RESPONSE_IDENTITIES
                .saturating_mul(std::mem::size_of::<Identity>())
                .saturating_mul(2),
        )
}

#[cfg(test)]
mod tests;
