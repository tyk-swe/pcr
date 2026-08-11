// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::{BTreeMap, HashMap};
use std::time::Instant;

use bytes::Bytes;

use super::Limits;

use plan::{FragmentPlan, datagram_memory_charge_parts};

mod commit;
mod contract;
pub use contract::*;
mod plan;

#[derive(Debug)]
struct DatagramState {
    segments: BTreeMap<u32, Bytes>,
    final_length: Option<u32>,
    fragment_count: usize,
    stored_bytes: usize,
    last_update: Instant,
    had_conflicting_overlap: bool,
}

#[derive(Debug)]
pub struct Reassembler {
    limits: Limits,
    overlap_policy: OverlapPolicy,
    flows: HashMap<DatagramKey, DatagramState>,
    aggregate_bytes: usize,
    aggregate_memory_charge: usize,
}

impl Reassembler {
    pub fn new(limits: Limits, overlap_policy: OverlapPolicy) -> Self {
        Self {
            limits,
            overlap_policy,
            flows: HashMap::new(),
            aggregate_bytes: 0,
            aggregate_memory_charge: 0,
        }
    }

    pub fn flow_count(&self) -> usize {
        self.flows.len()
    }

    pub fn aggregate_bytes(&self) -> usize {
        self.aggregate_bytes
    }

    pub fn aggregate_memory_charge(&self) -> usize {
        self.aggregate_memory_charge
    }

    /// Admits one fragment, returning an event once a datagram completes.
    ///
    /// # Panics
    ///
    /// Panics only if reassembly loses a validated flow or planned segment;
    /// input errors return [`enum@Error`].
    pub fn push(&mut self, fragment: Fragment, now: Instant) -> Result<Option<Event>, Error> {
        match self.plan_fragment(&fragment)? {
            FragmentPlan::Complete => Ok(Some(Event::Complete(Datagram {
                key: fragment.key,
                bytes: fragment.bytes,
                fragment_count: 1,
                had_conflicting_overlap: false,
            }))),
            FragmentPlan::Retain(plan) => self.commit_fragment(fragment, now, plan),
        }
    }

    fn remove_flows(&mut self, mut keys: Vec<DatagramKey>) -> Vec<Event> {
        keys.sort_by_key(|key| {
            (
                key.source,
                key.destination,
                key.identification,
                key.next_header,
            )
        });
        keys.into_iter()
            .filter_map(|key| {
                let state = self.flows.remove(&key)?;
                self.aggregate_bytes = self.aggregate_bytes.saturating_sub(state.stored_bytes);
                let charge = datagram_memory_charge(&state).unwrap_or(0);
                self.aggregate_memory_charge = self.aggregate_memory_charge.saturating_sub(charge);
                Some(Event::Expired {
                    key,
                    received_bytes: state.stored_bytes,
                    fragment_count: state.fragment_count,
                })
            })
            .collect()
    }

    pub fn expire(&mut self, now: Instant) -> Vec<Event> {
        let expired = self
            .flows
            .iter()
            .filter_map(|(key, state)| {
                now.checked_duration_since(state.last_update)
                    .filter(|idle| *idle >= self.limits.fragment_expiry)
                    .map(|_| key.clone())
            })
            .collect::<Vec<_>>();
        self.remove_flows(expired)
    }

    pub fn flush(&mut self) -> Vec<Event> {
        let keys = self.flows.keys().cloned().collect();
        self.remove_flows(keys)
    }
}

fn datagram_memory_charge(state: &DatagramState) -> Option<usize> {
    datagram_memory_charge_parts(state.stored_bytes, state.segments.len())
}

fn is_complete(segments: &BTreeMap<u32, Bytes>, final_length: u32) -> bool {
    let mut cursor = 0u32;
    for (offset, bytes) in segments {
        if *offset != cursor {
            return false;
        }
        let Ok(length) = u32::try_from(bytes.len()) else {
            return false;
        };
        let Some(end) = cursor.checked_add(length) else {
            return false;
        };
        cursor = end;
    }
    cursor == final_length
}
