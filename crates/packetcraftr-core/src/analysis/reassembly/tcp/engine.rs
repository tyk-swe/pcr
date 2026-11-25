// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::HashMap;
use std::time::Instant;

use super::pending::{commit::commit_push, plan_push};
use super::state::{TcpFlowState, flow_memory_charge, retained_bytes};
use super::{Error, Event, EvictionReason, Limits, Reassembler, Resource, ScopedFlowKey, Segment};

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
        self.remove_flows(keys, EvictionReason::Idle)
    }

    pub fn flush(&mut self) -> Vec<Event> {
        let keys = self.flows.keys().cloned().collect::<Vec<_>>();
        self.remove_flows(keys, EvictionReason::Flush)
    }

    pub fn evict_flow(&mut self, flow: &ScopedFlowKey, reason: EvictionReason) -> Vec<Event> {
        self.remove_flows(vec![flow.clone()], reason)
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

    pub fn flow_pending_source_spans(&self, flow: &ScopedFlowKey) -> Option<usize> {
        self.flows
            .get(flow)
            .map(|state| state.pending_sources.len())
    }

    pub fn flow_observed_payload(&self, flow: &ScopedFlowKey) -> bool {
        self.flows.get(flow).is_some_and(|state| {
            state.next_offset > 0 || !state.pending.is_empty() || state.fin_offset.is_some()
        })
    }

    pub(crate) fn flow_final_next_sequence(&self, flow: &ScopedFlowKey) -> Option<u32> {
        self.flows.get(flow).and_then(|state| {
            state.fin_offset.map(|offset| {
                state
                    .base_sequence
                    .wrapping_add(offset as u32)
                    .wrapping_add(1)
            })
        })
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
    fn remove_flows(&mut self, mut keys: Vec<ScopedFlowKey>, reason: EvictionReason) -> Vec<Event> {
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
                reason,
            });
        }
        events
    }
}

#[cfg(test)]
mod tests {
    use std::time::UNIX_EPOCH;

    use super::*;
    use crate::analysis::FlowKey;
    use crate::analysis::provenance::{SourceFrame, Tracker};
    use crate::analysis::reassembly::tcp::DataSources;
    use crate::analysis::scope::Interner;
    use bytes::Bytes;

    fn flow() -> ScopedFlowKey {
        ScopedFlowKey {
            scope: Interner::default().intern(None, Vec::new()).unwrap(),
            flow: FlowKey {
                source: "192.0.2.1".parse().unwrap(),
                source_port: 40000,
                destination: "192.0.2.2".parse().unwrap(),
                destination_port: 80,
            },
        }
    }

    fn source(tracker: &Tracker, number: u64) -> crate::analysis::provenance::SourceSet {
        tracker
            .single(SourceFrame {
                number,
                timestamp: UNIX_EPOCH,
            })
            .unwrap()
    }

    fn segment(
        flow: &ScopedFlowKey,
        sequence: u32,
        payload: &[u8],
        sources: Option<crate::analysis::provenance::SourceSet>,
    ) -> Segment {
        Segment {
            flow: flow.clone(),
            sequence,
            payload: Bytes::copy_from_slice(payload),
            sources,
            syn: false,
            fin: false,
            rst: false,
        }
    }

    #[test]
    fn split_out_of_order_provenance_stays_accounted() {
        let tracker = Tracker::new(1 << 20, 32).unwrap();
        let flow = flow();
        let base = 1_000;
        let wire: Vec<u8> = (0..60).map(|offset| (offset % 251) as u8).collect();
        let mut reassembler = Reassembler::new(Limits::default()).unwrap();
        let now = Instant::now();
        let mut syn = segment(&flow, base - 1, &[], None);
        syn.syn = true;
        reassembler.push(syn, now).unwrap();
        for (offset, length, number) in [(10, 10, 1), (30, 10, 2), (5, 40, 3)] {
            reassembler
                .push(
                    segment(
                        &flow,
                        base + offset,
                        &wire[offset as usize..(offset + length) as usize],
                        Some(source(&tracker, number)),
                    ),
                    now,
                )
                .unwrap();
        }

        let events = reassembler
            .push(
                segment(&flow, base, &wire[..5], Some(source(&tracker, 4))),
                now,
            )
            .unwrap();
        let data = events.iter().find_map(|event| match event {
            Event::Data { bytes, sources, .. } => Some((bytes, sources)),
            _ => None,
        });
        let Some((bytes, sources)) = data else {
            panic!("gap fill did not emit reassembled data: {events:?}");
        };
        assert_eq!(bytes.as_ref(), &wire[..45]);
        let DataSources::Spans(spans) = sources else {
            panic!("merged data did not retain span provenance: {sources:?}");
        };
        let spans: Vec<(usize, Vec<u64>)> = spans
            .iter()
            .map(|(length, sources)| {
                (
                    *length,
                    sources.iter().map(|frame| frame.number).collect::<Vec<_>>(),
                )
            })
            .collect();
        assert_eq!(
            spans,
            vec![
                (5, vec![4]),
                (5, vec![3]),
                (10, vec![1]),
                (10, vec![3]),
                (10, vec![2]),
                (5, vec![3]),
            ]
        );
    }

    #[test]
    fn conflicting_retransmission_preserves_first_seen_provenance() {
        let tracker = Tracker::new(1 << 20, 32).unwrap();
        let flow = flow();
        let base = 1_000;
        let mut reassembler = Reassembler::new(Limits::default()).unwrap();
        let now = Instant::now();
        let mut syn = segment(&flow, base - 1, &[], None);
        syn.syn = true;
        reassembler.push(syn, now).unwrap();
        reassembler
            .push(
                segment(&flow, base + 5, b"fghij", Some(source(&tracker, 1))),
                now,
            )
            .unwrap();
        let retransmission = reassembler
            .push(
                segment(&flow, base + 5, b"xxxxx", Some(source(&tracker, 2))),
                now,
            )
            .unwrap();
        assert!(retransmission.iter().any(|event| matches!(
            event,
            Event::Retransmission {
                conflicting: true,
                ..
            }
        )));

        let events = reassembler
            .push(
                segment(&flow, base, b"abcde", Some(source(&tracker, 3))),
                now,
            )
            .unwrap();

        let Some((bytes, sources)) = events.iter().find_map(|event| match event {
            Event::Data { bytes, sources, .. } => Some((bytes, sources)),
            _ => None,
        }) else {
            panic!("gap fill did not emit reassembled data: {events:?}");
        };
        assert_eq!(bytes.as_ref(), b"abcdefghij");
        let DataSources::Spans(spans) = sources else {
            panic!("merged data did not retain span provenance: {sources:?}");
        };
        let spans: Vec<(usize, Vec<u64>)> = spans
            .iter()
            .map(|(length, sources)| {
                (
                    *length,
                    sources.iter().map(|frame| frame.number).collect::<Vec<_>>(),
                )
            })
            .collect();
        assert_eq!(spans, vec![(5, vec![3]), (5, vec![1])]);
    }

    #[test]
    fn reassembly_and_provenance_survive_sequence_wraps() {
        let tracker = Tracker::new(1 << 20, 32).unwrap();
        let flow = flow();
        let base = u32::MAX - 1;
        let mut reassembler = Reassembler::new(Limits::default()).unwrap();
        let now = Instant::now();
        let mut syn = segment(&flow, base.wrapping_sub(1), &[], None);
        syn.syn = true;
        reassembler.push(syn, now).unwrap();
        reassembler
            .push(segment(&flow, 1, b"de", Some(source(&tracker, 2))), now)
            .unwrap();

        let events = reassembler
            .push(segment(&flow, base, b"abc", Some(source(&tracker, 1))), now)
            .unwrap();

        let Some((bytes, sources)) = events.iter().find_map(|event| match event {
            Event::Data { bytes, sources, .. } => Some((bytes, sources)),
            _ => None,
        }) else {
            panic!("sequence wrap did not emit reassembled data: {events:?}");
        };
        assert_eq!(bytes.as_ref(), b"abcde");
        let DataSources::Spans(spans) = sources else {
            panic!("wrapped data did not retain span provenance: {sources:?}");
        };
        let spans: Vec<(usize, Vec<u64>)> = spans
            .iter()
            .map(|(length, sources)| {
                (
                    *length,
                    sources.iter().map(|frame| frame.number).collect::<Vec<_>>(),
                )
            })
            .collect();
        assert_eq!(spans, vec![(3, vec![1]), (2, vec![2])]);
    }
}
