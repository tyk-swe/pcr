// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use std::time::{Duration, Instant, SystemTime};

use super::report::ReusedHop;

#[derive(Clone, Debug)]
pub(super) struct Intermediate {
    pub(super) sequence: u64,
    pub(super) responder: IpAddr,
    pub(super) received_at: Option<SystemTime>,
}

#[derive(Debug)]
pub(super) struct Entry {
    slot: usize,
    source: IpAddr,
    hop_limit: u8,
    intermediates: Vec<Intermediate>,
    planned_at: Instant,
}

/// Hops hosts of one operation observed, for one address family. Entries are
/// inserted as hosts finish, so each per-hop list is ordered by `planned_at`
/// and its fresh entries form a suffix.
#[derive(Debug)]
pub(super) struct Cache {
    max_age: Duration,
    entries: Vec<Entry>,
    by_hop: BTreeMap<u8, Vec<usize>>,
    by_responder: HashMap<(u8, IpAddr), Vec<usize>>,
    by_slot: HashMap<(usize, u8), usize>,
}

impl Cache {
    pub(super) fn new(max_age: Duration) -> Self {
        Self {
            max_age,
            entries: Vec::new(),
            by_hop: BTreeMap::new(),
            by_responder: HashMap::new(),
            by_slot: HashMap::new(),
        }
    }

    pub(super) fn insert(
        &mut self,
        slot: usize,
        source: IpAddr,
        hop_limit: u8,
        intermediates: Vec<Intermediate>,
        planned_at: Instant,
    ) {
        let index = self.entries.len();
        self.by_hop.entry(hop_limit).or_default().push(index);
        for intermediate in &intermediates {
            let indices = self
                .by_responder
                .entry((hop_limit, intermediate.responder))
                .or_default();
            if indices.last() != Some(&index) {
                indices.push(index);
            }
        }
        self.by_slot.insert((slot, hop_limit), index);
        self.entries.push(Entry {
            slot,
            source,
            hop_limit,
            intermediates,
            planned_at,
        });
    }

    fn is_fresh(&self, index: usize, now: Instant) -> bool {
        now.saturating_duration_since(self.entries[index].planned_at) <= self.max_age
    }

    fn first_fresh(&self, indices: &[usize], now: Instant) -> Option<usize> {
        let first = indices.partition_point(|&index| !self.is_fresh(index, now));
        indices.get(first).copied()
    }

    /// The highest hop limit holding a fresh entry.
    pub(super) fn anchor(&self, now: Instant) -> Option<u8> {
        self.by_hop.iter().rev().find_map(|(hop_limit, indices)| {
            indices
                .last()
                .is_some_and(|&index| self.is_fresh(index, now))
                .then_some(*hop_limit)
        })
    }

    /// The earliest traced host with a fresh entry at `hop_limit` that shares
    /// one of `responders`.
    pub(super) fn matching(
        &self,
        hop_limit: u8,
        responders: &[IpAddr],
        now: Instant,
    ) -> Option<usize> {
        responders
            .iter()
            .filter_map(|responder| {
                let indices = self.by_responder.get(&(hop_limit, *responder))?;
                self.first_fresh(indices, now)
            })
            .map(|index| self.entries[index].slot)
            .min()
    }

    pub(super) fn reuse(&self, slot: usize, hop_limit: u8, now: Instant) -> Option<ReusedHop> {
        let index = *self.by_slot.get(&(slot, hop_limit))?;
        if !self.is_fresh(index, now) {
            return None;
        }
        let entry = &self.entries[index];
        let mut responders = Vec::new();
        for intermediate in &entry.intermediates {
            if !responders.contains(&intermediate.responder) {
                responders.push(intermediate.responder);
            }
        }
        Some(ReusedHop {
            hop_limit: entry.hop_limit,
            source: entry.source,
            probes: entry
                .intermediates
                .iter()
                .map(|intermediate| intermediate.sequence)
                .collect(),
            responders,
            observed_at: entry
                .intermediates
                .iter()
                .filter_map(|intermediate| intermediate.received_at)
                .max(),
            age: now.saturating_duration_since(entry.planned_at),
        })
    }
}
