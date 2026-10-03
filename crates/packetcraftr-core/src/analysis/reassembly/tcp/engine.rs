// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::HashMap;
use std::time::Instant;

use super::pending::{commit::commit_push, plan_push};
use super::state::{TcpFlowState, flow_memory_charge, retained_bytes};
use super::{Error, Event, Limits, Reassembler, Resource, ScopedFlowKey, Segment};

impl Reassembler {
    pub fn new(limits: Limits) -> Result<Self, crate::analysis::Error> {
        limits.validate()?;
        Ok(Self {
            limits,
            flows: HashMap::new(),
            expiry: Default::default(),
            aggregate_bytes: 0,
            aggregate_memory_charge: 0,
        })
    }

    /// Input errors return [`enum@Error`] without mutating the flow table.
    pub fn push(&mut self, segment: Segment, now: Instant) -> Result<Vec<Event>, Error> {
        if segment.payload.is_empty()
            && !segment.syn
            && !segment.fin
            && !segment.rst
            && !self.flows.contains_key(&segment.flow)
        {
            return Ok(Vec::new());
        }
        let first_payload_sequence = segment.sequence.wrapping_add(u32::from(segment.syn));
        let existing = self.flows.get(&segment.flow);
        let changes_generation = (segment.syn || existing.is_none())
            && existing.is_none_or(|state| state.base_sequence != first_payload_sequence);
        if changes_generation
            && self
                .flows
                .len()
                .saturating_sub(usize::from(existing.is_some()))
                >= self.limits.max_flows
        {
            return Err(Resource::FlowLimit {
                limit: self.limits.max_flows,
            }
            .into());
        }

        let (aggregate_bytes, aggregate_memory_charge) = self.aggregates_without(existing)?;
        let empty = TcpFlowState::new(
            first_payload_sequence,
            now,
            now.checked_add(self.limits.idle_expiry),
        );
        let state = if changes_generation {
            &empty
        } else {
            existing.expect("an unchanged generation has an established flow")
        };
        // `existing` stays allocated while the plan is built, so the transient peak starts from the
        // full aggregate charge.
        let plan = plan_push(
            &self.limits,
            state,
            aggregate_bytes,
            aggregate_memory_charge,
            self.aggregate_memory_charge,
            &segment,
        )?;

        Ok(commit_push(self, segment, now, changes_generation, plan))
    }

    pub fn expire(&mut self, now: Instant) -> Vec<Event> {
        let keys = self.expiry.take_expired(now);
        self.remove_flows(keys)
    }

    pub fn flush(&mut self) -> Vec<Event> {
        let keys = self.flows.keys().cloned().collect::<Vec<_>>();
        self.remove_flows(keys)
    }

    pub fn evict_flow(&mut self, flow: &ScopedFlowKey) -> Vec<Event> {
        self.remove_flows(vec![flow.clone()])
    }

    pub fn flow_count(&self) -> usize {
        self.flows.len()
    }

    pub fn flow_base_sequence(&self, flow: &ScopedFlowKey) -> Option<u32> {
        self.flows.get(flow).map(|state| state.base_sequence)
    }

    // The `as u32` deliberately keeps next_offset modulo 2^32, as wire sequence arithmetic needs.
    pub fn flow_next_sequence(&self, flow: &ScopedFlowKey) -> Option<u32> {
        self.flows
            .get(flow)
            .map(|state| state.base_sequence.wrapping_add(state.next_offset as u32))
    }

    pub fn flow_observed_payload(&self, flow: &ScopedFlowKey) -> bool {
        self.flows.get(flow).is_some_and(|state| {
            state.next_offset > 0 || !state.pending.is_empty() || state.fin_offset.is_some()
        })
    }

    pub fn aggregate_bytes(&self) -> usize {
        self.aggregate_bytes
    }

    pub fn aggregate_memory_charge(&self) -> usize {
        self.aggregate_memory_charge
    }

    fn aggregates_without(&self, existing: Option<&TcpFlowState>) -> Result<(usize, usize), Error> {
        let error = || self.limits.aggregate_byte_error();
        let old_retained_bytes = existing.map_or(Some(0), retained_bytes).ok_or_else(error)?;
        let old_memory_charge = existing
            .map_or(Some(0), flow_memory_charge)
            .ok_or_else(error)?;
        let aggregate_bytes = self
            .aggregate_bytes
            .checked_sub(old_retained_bytes)
            .ok_or_else(error)?;
        let aggregate_memory_charge = self
            .aggregate_memory_charge
            .checked_sub(old_memory_charge)
            .ok_or_else(error)?;
        Ok((aggregate_bytes, aggregate_memory_charge))
    }

    // Offsets are cumulative; the `as u32` casts deliberately wrap them modulo 2^32.
    fn remove_flows(&mut self, mut keys: Vec<ScopedFlowKey>) -> Vec<Event> {
        keys.sort();
        let mut events = Vec::new();
        for key in keys {
            let Some(state) = self.flows.remove(&key) else {
                continue;
            };
            self.expiry.remove(state.deadline, &key);
            if let Some((&next, _)) = state.pending.first_key_value()
                && next > state.next_offset
            {
                events.push(Event::Gap {
                    flow: key.clone(),
                    expected_sequence: state.base_sequence.wrapping_add(state.next_offset as u32),
                    next_sequence: state.base_sequence.wrapping_add(next as u32),
                });
            }
            let retained_bytes = retained_bytes(&state).unwrap_or(0);
            self.aggregate_bytes = self.aggregate_bytes.saturating_sub(retained_bytes);
            let memory_charge = flow_memory_charge(&state).unwrap_or(0);
            self.aggregate_memory_charge =
                self.aggregate_memory_charge.saturating_sub(memory_charge);
            events.push(Event::Evicted {
                flow: key,
                pending_bytes: state.pending_bytes,
            });
        }
        events
    }
}
