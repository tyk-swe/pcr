// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::HashMap;
use std::time::Instant;

use super::pending::{commit::commit_push, plan_push};
use super::state::{TcpFlowState, flow_memory_charge, retained_bytes};
use super::{
    Error, Event, Limits, Reassembler, ScopedFlowKey, Segment, TCP_FLOW_STATE_METADATA_CHARGE,
    TCP_SERIAL_HALF_SPACE,
};

impl Reassembler {
    pub fn new(limits: Limits) -> Self {
        Self {
            limits,
            flows: HashMap::new(),
            expiry: Default::default(),
            aggregate_bytes: 0,
            aggregate_memory_charge: 0,
        }
    }

    pub fn open_flow(
        &mut self,
        flow: ScopedFlowKey,
        first_payload_sequence: u32,
        now: Instant,
    ) -> Result<(), Error> {
        self.validate_limits()?;
        if let Some(existing) = self.flows.get_mut(&flow)
            && existing.base_sequence == first_payload_sequence
        {
            let previous_deadline = existing.deadline;
            existing.last_update = existing.last_update.max(now);
            existing.deadline = existing
                .last_update
                .checked_add(self.limits.tcp_idle_expiry);
            let deadline = existing.deadline;
            self.expiry.remove(previous_deadline, &flow);
            self.expiry.insert(deadline, flow);
            return Ok(());
        }
        let existing = self.flows.get(&flow);
        if self
            .flows
            .len()
            .saturating_sub(usize::from(existing.is_some()))
            >= self.limits.max_flows
        {
            return Err(Error::FlowLimit {
                limit: self.limits.max_flows,
            });
        }
        let (aggregate_bytes, aggregate_memory_charge) =
            self.plan_replacement_accounting(existing, TCP_FLOW_STATE_METADATA_CHARGE)?;

        let last_update = existing.map_or(now, |state| state.last_update.max(now));
        let previous_deadline = existing.and_then(|state| state.deadline);
        let deadline = last_update.checked_add(self.limits.tcp_idle_expiry);
        self.expiry.remove(previous_deadline, &flow);
        self.flows.insert(
            flow.clone(),
            TcpFlowState::new(first_payload_sequence, last_update, deadline),
        );
        self.expiry.insert(deadline, flow);
        self.aggregate_bytes = aggregate_bytes;
        self.aggregate_memory_charge = aggregate_memory_charge;
        Ok(())
    }

    /// Admits one segment, returning the events its arrival resolved.
    ///
    /// # Panics
    ///
    /// Panics only if planning and commit disagree about an unchanged flow;
    /// input errors return [`enum@Error`] without mutating the flow table.
    pub fn push(&mut self, segment: Segment, now: Instant) -> Result<Vec<Event>, Error> {
        self.validate_limits()?;
        if segment.payload.is_empty()
            && !segment.syn
            && !segment.fin
            && !segment.rst
            && !self.flows.contains_key(&segment.flow)
        {
            return Ok(Vec::new());
        }
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
                self.plan_replacement_accounting(existing, 0)?
            } else {
                (self.aggregate_bytes, self.aggregate_memory_charge)
            };
            (changes_generation, aggregate_bytes, aggregate_memory_charge)
        };

        let plan = {
            // Plan replacements against empty state without mutating the established flow.
            let empty = TcpFlowState::new(
                first_payload_sequence,
                now,
                now.checked_add(self.limits.tcp_idle_expiry),
            );
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
                !changes_generation,
                aggregate_bytes,
                aggregate_memory_charge,
                &segment,
            )?
        };

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

    /// Removes one flow immediately, returning its eviction evidence.
    ///
    /// This is how a caller that knows a connection is over — for example
    /// because a new SYN reuses the four-tuple — retires state that would
    /// otherwise misinterpret the next generation's segments against the old
    /// sequence base. Evicting an unknown flow is a no-op.
    pub fn evict_flow(&mut self, flow: &ScopedFlowKey) -> Vec<Event> {
        self.remove_flows(vec![flow.clone()])
    }

    pub fn flow_count(&self) -> usize {
        self.flows.len()
    }

    /// The sequence anchoring a tracked flow's current generation, when the
    /// flow is tracked at all. A caller compares this against a SYN's
    /// implied base to tell a retransmitted handshake from four-tuple reuse.
    pub fn flow_base_sequence(&self, flow: &ScopedFlowKey) -> Option<u32> {
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
    pub fn flow_next_sequence(&self, flow: &ScopedFlowKey) -> Option<u32> {
        self.flows
            .get(flow)
            .map(|state| state.base_sequence.wrapping_add(state.next_offset as u32))
    }

    /// Whether a tracked flow has carried any payload or a FIN — as opposed
    /// to a bare opening SYN. A caller uses this to tell an in-progress
    /// handshake's half-open state from a previous connection's remains.
    pub fn flow_observed_payload(&self, flow: &ScopedFlowKey) -> bool {
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

    fn plan_replacement_accounting(
        &self,
        existing: Option<&TcpFlowState>,
        replacement_memory_charge: usize,
    ) -> Result<(usize, usize), Error> {
        let accounting_error = || Error::AggregateByteLimit {
            limit: self.limits.max_aggregate_bytes,
        };
        let old_retained_bytes = existing
            .map_or(Some(0), retained_bytes)
            .ok_or_else(accounting_error)?;
        let old_memory_charge = existing
            .map_or(Some(0), flow_memory_charge)
            .ok_or_else(accounting_error)?;
        let aggregate_bytes = self
            .aggregate_bytes
            .checked_sub(old_retained_bytes)
            .ok_or_else(accounting_error)?;
        let aggregate_memory_charge = self
            .aggregate_memory_charge
            .checked_sub(old_memory_charge)
            .and_then(|charge| charge.checked_add(replacement_memory_charge))
            .ok_or_else(accounting_error)?;
        if aggregate_bytes > self.limits.max_aggregate_bytes
            || aggregate_memory_charge > self.limits.max_aggregate_bytes
        {
            return Err(accounting_error());
        }
        Ok((aggregate_bytes, aggregate_memory_charge))
    }

    #[expect(
        clippy::cast_possible_truncation,
        reason = "validate_limits rejects max_bytes_per_flow >= TCP_SERIAL_HALF_SPACE (2^31), so \
                  neither next_offset nor a pending offset reaches 2^32"
    )]
    fn remove_flows(&mut self, mut keys: Vec<ScopedFlowKey>) -> Vec<Event> {
        keys.sort_by_key(|key| {
            (
                key.scope,
                key.flow.source,
                key.flow.source_port,
                key.flow.destination,
                key.flow.destination_port,
            )
        });
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

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    use bytes::Bytes;

    use super::*;
    use crate::analysis::reassembly::tcp::FlowKey;
    use crate::analysis::scope::ScopeInterner;

    const IDLE_FLOW_COUNT: usize = 8_000;
    const ACTIVE_SEGMENT_COUNT: u32 = 100_000;

    fn test_flow(source_port: u16) -> ScopedFlowKey {
        let scope = ScopeInterner::new()
            .intern(None, Vec::new())
            .expect("empty scope fits");
        ScopedFlowKey {
            scope,
            flow: FlowKey {
                source: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
                source_port,
                destination: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2)),
                destination_port: 443,
            },
        }
    }

    #[test]
    fn dense_flow_expiry_examinations_are_near_linear() {
        let start = Instant::now();
        let idle_expiry = Duration::from_secs(120);
        let mut reassembler = Reassembler::new(Limits {
            max_flows: IDLE_FLOW_COUNT + 1,
            tcp_idle_expiry: idle_expiry,
            ..Limits::default()
        });

        for index in 0..IDLE_FLOW_COUNT {
            let source_port = u16::try_from(10_000usize + index).expect("test port fits u16");
            reassembler
                .open_flow(test_flow(source_port), 0, start)
                .expect("idle flow opens");
        }
        let active = test_flow(60_000);
        reassembler
            .open_flow(active.clone(), 0, start)
            .expect("active flow opens");

        for sequence in 0..ACTIVE_SEGMENT_COUNT {
            let now = start + Duration::from_nanos(u64::from(sequence) + 1);
            assert!(reassembler.expire(now).is_empty());
            reassembler
                .push(
                    Segment {
                        flow: active.clone(),
                        sequence,
                        payload: Bytes::from_static(b"x"),
                        syn: false,
                        fin: false,
                        rst: false,
                    },
                    now,
                )
                .expect("active segment is accepted");
        }

        assert_eq!(reassembler.expiry.len(), reassembler.flow_count());
        assert_eq!(
            reassembler.expire(start + idle_expiry).len(),
            IDLE_FLOW_COUNT
        );
        assert_eq!(reassembler.flow_count(), 1);
        assert_eq!(reassembler.expiry.len(), 1);
        let examined = reassembler.expiry.examined_entries();
        let expected_upper_bound = usize::try_from(ACTIVE_SEGMENT_COUNT)
            .expect("segment count fits usize")
            + IDLE_FLOW_COUNT
            + 2;
        assert!(
            examined <= expected_upper_bound,
            "expiry examined {examined} entries, expected at most {expected_upper_bound}"
        );
    }
}
