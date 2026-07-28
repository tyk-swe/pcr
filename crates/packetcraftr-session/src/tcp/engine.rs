// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::HashMap;
use std::time::Instant;

use super::pending::{commit::commit_push, plan_push};
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

    /// Admits one segment, returning the events its arrival resolved.
    ///
    /// # Panics
    ///
    /// Panics if a flow whose generation is unchanged is not established,
    /// which would mean the plan and commit halves of this reassembler had
    /// disagreed. Every input-driven rejection, including exhausted budgets,
    /// is reported through [`enum@Error`], and a rejected segment leaves the flow
    /// table untouched.
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

    /// Removes one flow immediately, returning its eviction evidence.
    ///
    /// This is how a caller that knows a connection is over — for example
    /// because a new SYN reuses the four-tuple — retires state that would
    /// otherwise misinterpret the next generation's segments against the old
    /// sequence base. Evicting an unknown flow is a no-op.
    pub fn evict_flow(&mut self, flow: &FlowKey) -> Vec<Event> {
        if !self.flows.contains_key(flow) {
            return Vec::new();
        }
        self.remove_flows(vec![flow.clone()])
    }

    pub fn limits(&self) -> &ReassemblyLimits {
        &self.limits
    }

    pub fn flow_count(&self) -> usize {
        self.flows.len()
    }

    /// The sequence anchoring a tracked flow's current generation, when the
    /// flow is tracked at all. A caller compares this against a SYN's
    /// implied base to tell a retransmitted handshake from four-tuple reuse.
    pub fn flow_base_sequence(&self, flow: &FlowKey) -> Option<u32> {
        self.flows.get(flow).map(|state| state.base_sequence)
    }

    /// The sequence one past a tracked flow's contiguously delivered bytes,
    /// when the flow is tracked at all. Together with the base this brackets
    /// the acknowledgment a current-generation SYN-ACK may carry — a Fast
    /// Open SYN's payload moves it past the base.
    #[expect(
        clippy::cast_possible_truncation,
        reason = "validate_limits rejects max_bytes_per_flow >= TCP_SERIAL_HALF_SPACE (2^31), \
                  so next_offset never reaches 2^32 and the narrowing is lossless"
    )]
    pub fn flow_next_sequence(&self, flow: &FlowKey) -> Option<u32> {
        self.flows
            .get(flow)
            .map(|state| state.base_sequence.wrapping_add(state.next_offset as u32))
    }

    /// Whether a tracked flow has carried any payload or a FIN — as opposed
    /// to a bare opening SYN. A caller uses this to tell an in-progress
    /// handshake's half-open state from a previous connection's remains.
    pub fn flow_observed_payload(&self, flow: &FlowKey) -> bool {
        self.flows.get(flow).is_some_and(|state| {
            state.next_offset > 0 || !state.pending.is_empty() || state.fin_offset.is_some()
        })
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

    #[expect(
        clippy::cast_possible_truncation,
        reason = "validate_limits rejects max_bytes_per_flow >= TCP_SERIAL_HALF_SPACE (2^31), so \
                  neither next_offset nor a pending offset reaches 2^32"
    )]
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
