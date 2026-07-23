// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::HashMap;
use std::time::Instant;

use super::pending::{commit_push, plan_push};
use super::state::{TcpFlowState, flow_memory_charge, retained_bytes};
use super::{Error, Event, FlowKey, Reassembler, ReassemblyLimits, Segment, TCP_SERIAL_HALF_SPACE};

impl Reassembler {
    pub fn new(limits: ReassemblyLimits) -> Self {
        Self {
            limits,
            flows: HashMap::new(),
            aggregate_bytes: 0,
            aggregate_memory_charge: 0,
        }
    }

    pub fn open_flow(
        &mut self,
        flow: FlowKey,
        first_payload_sequence: u32,
        now: Instant,
    ) -> Result<(), Error> {
        self.validate_limits()?;
        if let Some(existing) = self.flows.get(&flow)
            && existing.base_sequence == first_payload_sequence
        {
            return Ok(());
        }
        let last_update = self
            .flows
            .get(&flow)
            .map_or(now, |state| state.last_update.max(now));
        if let Some(stale) = self.flows.remove(&flow) {
            self.aggregate_bytes = self
                .aggregate_bytes
                .saturating_sub(retained_bytes(&stale).unwrap_or(0));
            self.aggregate_memory_charge = self
                .aggregate_memory_charge
                .saturating_sub(flow_memory_charge(&stale).unwrap_or(0));
        }
        if self.flows.len() >= self.limits.max_flows {
            return Err(Error::FlowLimit {
                limit: self.limits.max_flows,
            });
        }
        self.flows
            .insert(flow, TcpFlowState::new(first_payload_sequence, last_update));
        Ok(())
    }

    pub fn push(&mut self, segment: Segment, now: Instant) -> Result<Vec<Event>, Error> {
        self.validate_limits()?;
        let first_payload_sequence = segment.sequence.wrapping_add(u32::from(segment.syn));
        let (changes_generation, aggregate_bytes, aggregate_memory_charge) = {
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
                return Err(Error::FlowLimit {
                    limit: self.limits.max_flows,
                });
            }

            let (aggregate_bytes, aggregate_memory_charge) = if changes_generation {
                match existing {
                    Some(stale) => (
                        self.aggregate_bytes
                            .saturating_sub(retained_bytes(stale).unwrap_or(0)),
                        self.aggregate_memory_charge
                            .saturating_sub(flow_memory_charge(stale).unwrap_or(0)),
                    ),
                    None => (self.aggregate_bytes, self.aggregate_memory_charge),
                }
            } else {
                (self.aggregate_bytes, self.aggregate_memory_charge)
            };
            (changes_generation, aggregate_bytes, aggregate_memory_charge)
        };

        let plan = {
            // A replacement generation is planned against an empty state. The
            // established entry remains untouched until that plan succeeds.
            let empty = TcpFlowState::new(first_payload_sequence, now);
            let state = if changes_generation {
                &empty
            } else {
                self.flows
                    .get(&segment.flow)
                    .expect("an unchanged generation has an established flow")
            };
            plan_push(
                &self.limits,
                state,
                aggregate_bytes,
                aggregate_memory_charge,
                &segment,
            )?
        };

        Ok(commit_push(self, segment, now, changes_generation, plan))
    }

    pub fn expire(&mut self, now: Instant) -> Vec<Event> {
        let keys = self
            .flows
            .iter()
            .filter_map(|(key, state)| {
                now.checked_duration_since(state.last_update)
                    .filter(|idle| *idle >= self.limits.tcp_idle_expiry)
                    .map(|_| key.clone())
            })
            .collect::<Vec<_>>();
        self.remove_flows(keys)
    }

    pub fn flush(&mut self) -> Vec<Event> {
        let keys = self.flows.keys().cloned().collect::<Vec<_>>();
        self.remove_flows(keys)
    }

    pub fn aggregate_bytes(&self) -> usize {
        // Includes both out-of-order bytes and the bounded emitted-byte
        // history retained for contradictory retransmission detection.
        self.aggregate_bytes
    }

    pub fn aggregate_memory_charge(&self) -> usize {
        self.aggregate_memory_charge
    }

    fn validate_limits(&self) -> Result<(), Error> {
        if self.limits.max_bytes_per_flow >= TCP_SERIAL_HALF_SPACE {
            return Err(Error::InvalidWindowLimit {
                limit: self.limits.max_bytes_per_flow,
            });
        }
        Ok(())
    }

    fn remove_flows(&mut self, mut keys: Vec<FlowKey>) -> Vec<Event> {
        keys.sort_by_key(|key| {
            (
                key.source.to_string(),
                key.source_port,
                key.destination.to_string(),
                key.destination_port,
            )
        });
        let mut events = Vec::new();
        for key in keys {
            let Some(state) = self.flows.remove(&key) else {
                continue;
            };
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
