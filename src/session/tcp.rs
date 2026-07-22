// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::net::IpAddr;
use std::ops::Range;
use std::time::Instant;

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::ReassemblyLimits;

// Conservative accounting for a BTree node, key, and Bytes handle. The
// allocator may use more, but never charging metadata allowed sparse one-byte
// segments to bypass the aggregate resource ceiling entirely.
const PENDING_SEGMENT_METADATA_CHARGE: usize = 64;
const TCP_SERIAL_HALF_SPACE: usize = 1usize << 31;

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FlowKey {
    pub source: IpAddr,
    pub source_port: u16,
    pub destination: IpAddr,
    pub destination_port: u16,
}

impl FlowKey {
    #[must_use]
    pub fn reverse(&self) -> Self {
        Self {
            source: self.destination,
            source_port: self.destination_port,
            destination: self.source,
            destination_port: self.source_port,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Segment {
    pub flow: FlowKey,
    pub sequence: u32,
    pub payload: Bytes,
    pub syn: bool,
    pub fin: bool,
    pub rst: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    Data {
        flow: FlowKey,
        sequence: u32,
        bytes: Bytes,
    },
    Retransmission {
        flow: FlowKey,
        sequence: u32,
        bytes: usize,
        conflicting: bool,
    },
    Gap {
        flow: FlowKey,
        expected_sequence: u32,
        next_sequence: u32,
    },
    Closed {
        flow: FlowKey,
        reset: bool,
    },
    Evicted {
        flow: FlowKey,
        pending_bytes: usize,
    },
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    #[error("TCP flow table reached flow limit {limit}")]
    FlowLimit { limit: usize },
    #[error("TCP flow reached pending segment limit {limit}")]
    SegmentLimit { limit: usize },
    #[error("TCP flow exceeds per-flow byte/window limit {limit}")]
    FlowByteLimit { limit: usize },
    #[error("TCP flow table would exceed aggregate byte limit {limit}")]
    AggregateByteLimit { limit: usize },
    #[error("TCP per-flow window {limit} reaches or exceeds the serial-number half-space")]
    InvalidWindowLimit { limit: usize },
    #[error(
        "TCP FIN sequence {new_offset} conflicts with established final offset {existing_offset}"
    )]
    ConflictingFinalSequence {
        existing_offset: u64,
        new_offset: u64,
    },
    #[error("TCP data extends beyond established final offset {final_offset}")]
    BeyondFinalSequence { final_offset: u64 },
}

#[derive(Debug)]
struct TcpFlowState {
    base_sequence: u32,
    next_offset: u64,
    // A contiguous tail ending at `next_offset`. It is deliberately bounded
    // by the same per-flow budget as pending data so retransmission checking
    // cannot turn a long-lived stream into an unbounded byte log.
    history_start_offset: u64,
    emitted_history: VecDeque<u8>,
    pending: BTreeMap<u64, Bytes>,
    pending_bytes: usize,
    fin_offset: Option<u64>,
    last_update: Instant,
}

impl TcpFlowState {
    fn new(base_sequence: u32, now: Instant) -> Self {
        Self {
            base_sequence,
            next_offset: 0,
            history_start_offset: 0,
            emitted_history: VecDeque::new(),
            pending: BTreeMap::new(),
            pending_bytes: 0,
            fin_offset: None,
            last_update: now,
        }
    }
}

#[derive(Debug)]
pub struct Reassembler {
    limits: ReassemblyLimits,
    flows: HashMap<FlowKey, TcpFlowState>,
    aggregate_bytes: usize,
    aggregate_memory_charge: usize,
}

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
            self.plan_push(state, aggregate_bytes, aggregate_memory_charge, &segment)?
        };

        Ok(self.commit_push(segment, now, changes_generation, plan))
    }

    fn plan_push(
        &self,
        state: &TcpFlowState,
        aggregate_base_bytes: usize,
        aggregate_base_memory_charge: usize,
        segment: &Segment,
    ) -> Result<PushPlan, Error> {
        let payload_sequence = segment.sequence.wrapping_add(u32::from(segment.syn));

        // Unwrap the 32-bit sequence number around the current receive
        // cursor. TCP windows are bounded well below the signed half-space,
        // so this remains unambiguous across the 4 GiB wrap boundary and
        // treats packets preceding the capture base as old data rather than a
        // multi-gigabyte forward gap.
        let expected_sequence = state.base_sequence.wrapping_add(state.next_offset as u32);
        let signed_delta = i64::from(payload_sequence.wrapping_sub(expected_sequence) as i32);
        let absolute = i128::from(state.next_offset) + i128::from(signed_delta);
        let original_payload_len = segment.payload.len() as i128;
        let incoming_fin_offset = if segment.fin {
            let absolute_fin =
                absolute
                    .checked_add(original_payload_len)
                    .ok_or(Error::FlowByteLimit {
                        limit: self.limits.max_bytes_per_flow,
                    })?;
            (absolute_fin >= 0)
                .then(|| u64::try_from(absolute_fin).ok())
                .flatten()
        } else {
            None
        };
        let mut payload = segment.payload.as_ref();
        let mut retransmitted = 0usize;
        let mut conflicting = false;
        let before_base = if absolute < 0 {
            usize::try_from((-absolute).min(payload.len() as i128)).unwrap_or(payload.len())
        } else {
            0
        };
        let mut payload_start = before_base;
        retransmitted += before_base;
        payload = &payload[before_base..];
        let mut offset = u64::try_from(absolute.max(0)).map_err(|_| Error::FlowByteLimit {
            limit: self.limits.max_bytes_per_flow,
        })?;
        if offset < state.next_offset {
            let consumed = usize::try_from((state.next_offset - offset).min(payload.len() as u64))
                .unwrap_or(payload.len());
            conflicting |= emitted_history_conflicts(state, offset, &payload[..consumed]);
            retransmitted += consumed;
            payload_start = payload_start
                .checked_add(consumed)
                .ok_or(Error::FlowByteLimit {
                    limit: self.limits.max_bytes_per_flow,
                })?;
            payload = &payload[consumed..];
            offset = state.next_offset;
        }

        let window_end = state
            .next_offset
            .checked_add(self.limits.max_bytes_per_flow as u64)
            .ok_or(Error::FlowByteLimit {
                limit: self.limits.max_bytes_per_flow,
            })?;
        let remaining_end =
            offset
                .checked_add(payload.len() as u64)
                .ok_or(Error::FlowByteLimit {
                    limit: self.limits.max_bytes_per_flow,
                })?;
        if let Some(final_offset) = state.fin_offset {
            if incoming_fin_offset.is_some_and(|fin_offset| fin_offset != final_offset) {
                return Err(Error::ConflictingFinalSequence {
                    existing_offset: final_offset,
                    new_offset: incoming_fin_offset.expect("checked as present"),
                });
            }
            if remaining_end > final_offset {
                return Err(Error::BeyondFinalSequence { final_offset });
            }
        }
        if let Some(fin_offset) = incoming_fin_offset
            && state.next_offset > fin_offset
        {
            return Err(Error::BeyondFinalSequence {
                final_offset: fin_offset,
            });
        }
        if offset > window_end || remaining_end > window_end {
            return Err(Error::FlowByteLimit {
                limit: self.limits.max_bytes_per_flow,
            });
        }

        let old_retained_bytes = retained_bytes(state).ok_or(Error::AggregateByteLimit {
            limit: self.limits.max_aggregate_bytes,
        })?;
        let old_memory_charge = flow_memory_charge(state).ok_or(Error::AggregateByteLimit {
            limit: self.limits.max_aggregate_bytes,
        })?;
        let mut merge = plan_pending_merge(&state.pending, offset, payload, state.next_offset)
            .ok_or(Error::FlowByteLimit {
                limit: self.limits.max_bytes_per_flow,
            })?;
        let pending_bytes =
            state
                .pending_bytes
                .checked_add(merge.added_bytes)
                .ok_or(Error::FlowByteLimit {
                    limit: self.limits.max_bytes_per_flow,
                })?;
        if pending_bytes > self.limits.max_bytes_per_flow {
            return Err(Error::FlowByteLimit {
                limit: self.limits.max_bytes_per_flow,
            });
        }
        if let Some(fin_offset) = incoming_fin_offset
            && (state
                .pending
                .last_key_value()
                .is_some_and(|(start, bytes)| {
                    start
                        .checked_add(bytes.len() as u64)
                        .is_none_or(|end| end > fin_offset)
                })
                || remaining_end > fin_offset)
        {
            return Err(Error::BeyondFinalSequence {
                final_offset: fin_offset,
            });
        }
        let initial_history_capacity = self.limits.max_bytes_per_flow.saturating_sub(pending_bytes);
        let final_pending_bytes = pending_bytes.saturating_sub(merge.emitted_segment_bytes);
        let final_pending_segments = merge
            .segment_count
            .saturating_sub(usize::from(merge.emitted_segment_bytes != 0));
        if final_pending_segments > self.limits.max_tcp_segments_per_flow {
            return Err(Error::SegmentLimit {
                limit: self.limits.max_tcp_segments_per_flow,
            });
        }
        let final_history_capacity = self
            .limits
            .max_bytes_per_flow
            .saturating_sub(final_pending_bytes);
        let prospective_history = state
            .emitted_history
            .len()
            .min(initial_history_capacity)
            .saturating_add(merge.emitted_segment_bytes)
            .min(final_history_capacity);
        let history_allocation = planned_history_allocation(
            state.emitted_history.capacity(),
            prospective_history,
            final_history_capacity,
        );
        let prospective_retained = final_pending_bytes.checked_add(prospective_history).ok_or(
            Error::AggregateByteLimit {
                limit: self.limits.max_aggregate_bytes,
            },
        )?;
        let prospective_memory = pending_memory_charge(final_pending_bytes, final_pending_segments)
            .and_then(|charge| charge.checked_add(history_allocation))
            .ok_or(Error::AggregateByteLimit {
                limit: self.limits.max_aggregate_bytes,
            })?;
        let prospective_aggregate_bytes = aggregate_base_bytes
            .checked_sub(old_retained_bytes)
            .and_then(|bytes| bytes.checked_add(prospective_retained))
            .ok_or(Error::AggregateByteLimit {
                limit: self.limits.max_aggregate_bytes,
            })?;
        let prospective_aggregate_memory = aggregate_base_memory_charge
            .checked_sub(old_memory_charge)
            .and_then(|charge| charge.checked_add(prospective_memory))
            .ok_or(Error::AggregateByteLimit {
                limit: self.limits.max_aggregate_bytes,
            })?;
        if prospective_aggregate_bytes > self.limits.max_aggregate_bytes
            || prospective_aggregate_memory > self.limits.max_aggregate_bytes
        {
            return Err(Error::AggregateByteLimit {
                limit: self.limits.max_aggregate_bytes,
            });
        }

        materialize_pending_merge(&state.pending, offset, payload, &mut merge).ok_or(
            Error::FlowByteLimit {
                limit: self.limits.max_bytes_per_flow,
            },
        )?;
        let direct_payload = if merge.direct_output {
            let end = payload_start
                .checked_add(payload.len())
                .ok_or(Error::FlowByteLimit {
                    limit: self.limits.max_bytes_per_flow,
                })?;
            Some(payload_start..end)
        } else {
            None
        };

        let final_next_offset = state
            .next_offset
            .checked_add(merge.emitted_segment_bytes as u64)
            .ok_or(Error::FlowByteLimit {
                limit: self.limits.max_bytes_per_flow,
            })?;
        let final_fin_offset = state.fin_offset.or(incoming_fin_offset);
        let closed = segment.rst
            || final_fin_offset.is_some_and(|fin_offset| final_next_offset >= fin_offset);
        let (aggregate_bytes, aggregate_memory_charge) = if closed {
            (
                aggregate_base_bytes.checked_sub(old_retained_bytes).ok_or(
                    Error::AggregateByteLimit {
                        limit: self.limits.max_aggregate_bytes,
                    },
                )?,
                aggregate_base_memory_charge
                    .checked_sub(old_memory_charge)
                    .ok_or(Error::AggregateByteLimit {
                        limit: self.limits.max_aggregate_bytes,
                    })?,
            )
        } else {
            (prospective_aggregate_bytes, prospective_aggregate_memory)
        };
        Ok(PushPlan {
            payload_sequence,
            incoming_fin_offset,
            retransmitted,
            conflicting,
            merge,
            direct_payload,
            pending_bytes,
            initial_history_capacity,
            history_allocation,
            closed,
            aggregate_bytes,
            aggregate_memory_charge,
        })
    }

    fn commit_push(
        &mut self,
        segment: Segment,
        now: Instant,
        changes_generation: bool,
        plan: PushPlan,
    ) -> Vec<Event> {
        let first_payload_sequence = segment.sequence.wrapping_add(u32::from(segment.syn));
        let closed = plan.closed;
        let aggregate_bytes = plan.aggregate_bytes;
        let aggregate_memory_charge = plan.aggregate_memory_charge;
        let max_bytes_per_flow = self.limits.max_bytes_per_flow;
        let last_update = self
            .flows
            .get(&segment.flow)
            .map_or(now, |state| state.last_update.max(now));
        let Segment {
            flow, rst, payload, ..
        } = segment;
        let direct_payload = plan
            .direct_payload
            .as_ref()
            .map(|range| payload.slice(range.clone()));

        let (replacement, mut events) = if changes_generation {
            let mut state = TcpFlowState::new(first_payload_sequence, last_update);
            let events = commit_flow_push(
                &mut state,
                &flow,
                now,
                max_bytes_per_flow,
                plan,
                direct_payload,
            );
            (Some(state), events)
        } else {
            let state = self
                .flows
                .get_mut(&flow)
                .expect("an unchanged generation has an established flow");
            (
                None,
                commit_flow_push(state, &flow, now, max_bytes_per_flow, plan, direct_payload),
            )
        };

        self.aggregate_bytes = aggregate_bytes;
        self.aggregate_memory_charge = aggregate_memory_charge;
        if closed {
            self.flows.remove(&flow);
            events.push(Event::Closed { flow, reset: rst });
        } else if let Some(state) = replacement {
            self.flows.insert(flow, state);
        }
        events
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

fn pending_memory_charge(pending_bytes: usize, segment_count: usize) -> Option<usize> {
    segment_count
        .checked_mul(PENDING_SEGMENT_METADATA_CHARGE)
        .and_then(|metadata| pending_bytes.checked_add(metadata))
}

fn retained_bytes(state: &TcpFlowState) -> Option<usize> {
    state.pending_bytes.checked_add(state.emitted_history.len())
}

fn flow_memory_charge(state: &TcpFlowState) -> Option<usize> {
    pending_memory_charge(state.pending_bytes, state.pending.len())?
        .checked_add(state.emitted_history.capacity())
}

fn planned_history_allocation(current: usize, required: usize, limit: usize) -> usize {
    let retained = current.min(limit);
    if required <= retained {
        return retained;
    }
    retained.saturating_mul(2).max(required).min(limit)
}

fn emitted_history_conflicts(state: &TcpFlowState, offset: u64, payload: &[u8]) -> bool {
    let Some(payload_end) = offset.checked_add(payload.len() as u64) else {
        return true;
    };
    let history_end = state
        .history_start_offset
        .saturating_add(state.emitted_history.len() as u64);
    let overlap_start = offset.max(state.history_start_offset);
    let overlap_end = payload_end.min(history_end);
    if overlap_start >= overlap_end {
        return false;
    }
    let payload_start = (overlap_start - offset) as usize;
    let history_start = (overlap_start - state.history_start_offset) as usize;
    let length = (overlap_end - overlap_start) as usize;
    !state
        .emitted_history
        .range(history_start..history_start + length)
        .eq(payload[payload_start..payload_start + length].iter())
}

fn trim_emitted_history(state: &mut TcpFlowState, capacity: usize) {
    if state.emitted_history.len() > capacity {
        let remove = state.emitted_history.len() - capacity;
        state.history_start_offset = state.history_start_offset.saturating_add(remove as u64);
        state.emitted_history.drain(..remove);
    }
}

fn resize_emitted_history(state: &mut TcpFlowState, capacity: usize) {
    if state.emitted_history.capacity() == capacity {
        return;
    }
    let mut resized = VecDeque::with_capacity(capacity);
    resized.extend(state.emitted_history.drain(..));
    state.emitted_history = resized;
}

fn append_emitted_history(
    state: &mut TcpFlowState,
    output_start: u64,
    output: &[u8],
    capacity: usize,
) {
    let output_end = output_start.saturating_add(output.len() as u64);
    if capacity == 0 {
        state.history_start_offset = output_end;
        state.emitted_history.clear();
        return;
    }

    let old_end = state
        .history_start_offset
        .saturating_add(state.emitted_history.len() as u64);
    debug_assert!(state.emitted_history.is_empty() || old_end == output_start);
    let keep = state
        .emitted_history
        .len()
        .saturating_add(output.len())
        .min(capacity);
    let history_start_offset = output_end.saturating_sub(keep as u64);
    if !state.emitted_history.is_empty() && history_start_offset < output_start {
        let old_start = (history_start_offset - state.history_start_offset) as usize;
        state.emitted_history.drain(..old_start);
    } else {
        state.emitted_history.clear();
    }
    let output_skip = history_start_offset.saturating_sub(output_start) as usize;
    state
        .emitted_history
        .extend(output[output_skip..].iter().copied());
    state.history_start_offset = history_start_offset;
}

#[derive(Debug)]
struct PushPlan {
    payload_sequence: u32,
    incoming_fin_offset: Option<u64>,
    retransmitted: usize,
    conflicting: bool,
    merge: PendingMergePlan,
    direct_payload: Option<Range<usize>>,
    pending_bytes: usize,
    initial_history_capacity: usize,
    history_allocation: usize,
    closed: bool,
    aggregate_bytes: usize,
    aggregate_memory_charge: usize,
}

#[derive(Debug)]
struct PendingReplacement {
    start: u64,
    bytes: Bytes,
}

#[derive(Debug)]
struct PendingMergePlan {
    added_bytes: usize,
    overlapping_bytes: usize,
    has_conflicting_overlap: bool,
    segment_count: usize,
    emitted_segment_bytes: usize,
    direct_output: bool,
    first_affected: Option<u64>,
    affected_segment_count: usize,
    union_start: u64,
    union_end: u64,
    replacement: Option<PendingReplacement>,
}

fn plan_pending_merge(
    existing: &BTreeMap<u64, Bytes>,
    offset: u64,
    payload: &[u8],
    next_offset: u64,
) -> Option<PendingMergePlan> {
    if payload.is_empty() {
        return Some(PendingMergePlan {
            added_bytes: 0,
            overlapping_bytes: 0,
            has_conflicting_overlap: false,
            segment_count: existing.len(),
            emitted_segment_bytes: 0,
            direct_output: false,
            first_affected: None,
            affected_segment_count: 0,
            union_start: offset,
            union_end: offset,
            replacement: None,
        });
    }
    let payload_end = offset.checked_add(payload.len() as u64)?;
    let mut overlapping_bytes = 0usize;
    let mut has_conflicting_overlap = false;
    let mut first_affected = None;
    let mut affected_segment_count = 0usize;
    let mut union_start = offset;
    let mut union_end = payload_end;
    {
        let mut record_affected = |start: u64, value: &Bytes| -> Option<()> {
            let end = start.checked_add(value.len() as u64)?;
            if end < offset || start > payload_end {
                return Some(());
            }

            if first_affected.is_none() {
                first_affected = Some(start);
            }
            affected_segment_count = affected_segment_count.checked_add(1)?;
            union_start = union_start.min(start);
            union_end = union_end.max(end);

            let overlap_start = start.max(offset);
            let overlap_end = end.min(payload_end);
            if overlap_start < overlap_end {
                let length = usize::try_from(overlap_end - overlap_start).ok()?;
                let existing_start = usize::try_from(overlap_start - start).ok()?;
                let payload_start = usize::try_from(overlap_start - offset).ok()?;
                let existing_end = existing_start.checked_add(length)?;
                let payload_end = payload_start.checked_add(length)?;
                overlapping_bytes = overlapping_bytes.checked_add(length)?;
                has_conflicting_overlap |= value.get(existing_start..existing_end)?
                    != payload.get(payload_start..payload_end)?;
            }
            Some(())
        };

        // Pending ranges are coalesced, so only the predecessor can reach the
        // incoming start before the bounded forward range begins.
        if let Some((start, value)) = existing.range(..offset).next_back() {
            record_affected(*start, value)?;
        }
        for (start, value) in existing.range(offset..=payload_end) {
            record_affected(*start, value)?;
        }
    }
    let added_bytes = payload.len().checked_sub(overlapping_bytes)?;
    let direct_output = offset == next_offset && first_affected.is_none();
    Some(PendingMergePlan {
        added_bytes,
        overlapping_bytes,
        has_conflicting_overlap,
        segment_count: existing
            .len()
            .checked_add(1)?
            .checked_sub(affected_segment_count)?,
        emitted_segment_bytes: (offset == next_offset)
            .then(|| usize::try_from(union_end.checked_sub(next_offset)?).ok())
            .flatten()
            .unwrap_or(0),
        direct_output,
        first_affected,
        affected_segment_count,
        union_start,
        union_end,
        replacement: None,
    })
}

fn materialize_pending_merge(
    existing: &BTreeMap<u64, Bytes>,
    offset: u64,
    payload: &[u8],
    plan: &mut PendingMergePlan,
) -> Option<()> {
    if plan.added_bytes == 0 || plan.direct_output {
        return Some(());
    }
    let union_len = usize::try_from(plan.union_end.checked_sub(plan.union_start)?).ok()?;
    let mut bytes = vec![0u8; union_len];
    let payload_start = usize::try_from(offset.checked_sub(plan.union_start)?).ok()?;
    let payload_end = payload_start.checked_add(payload.len())?;
    bytes
        .get_mut(payload_start..payload_end)?
        .copy_from_slice(payload);
    let mut current = plan.first_affected;
    for index in 0..plan.affected_segment_count {
        let start = current?;
        let value = existing.get(&start)?;
        let relative = usize::try_from(start.checked_sub(plan.union_start)?).ok()?;
        let end = relative.checked_add(value.len())?;
        // Retained bytes win overlaps, preserving the existing retransmission
        // semantics after conflict detection.
        bytes.get_mut(relative..end)?.copy_from_slice(value);
        if index + 1 < plan.affected_segment_count {
            current = existing
                .range((std::ops::Bound::Excluded(start), std::ops::Bound::Unbounded))
                .next()
                .map(|(start, _)| *start);
        }
    }
    plan.replacement = Some(PendingReplacement {
        start: plan.union_start,
        bytes: Bytes::from(bytes),
    });
    Some(())
}

fn commit_flow_push(
    state: &mut TcpFlowState,
    flow: &FlowKey,
    now: Instant,
    max_bytes_per_flow: usize,
    plan: PushPlan,
    direct_payload: Option<Bytes>,
) -> Vec<Event> {
    let PushPlan {
        payload_sequence,
        incoming_fin_offset,
        mut retransmitted,
        mut conflicting,
        merge,
        pending_bytes,
        initial_history_capacity,
        history_allocation,
        ..
    } = plan;
    retransmitted += merge.overlapping_bytes;
    conflicting |= merge.has_conflicting_overlap;

    state.last_update = state.last_update.max(now);
    trim_emitted_history(state, initial_history_capacity);
    resize_emitted_history(state, history_allocation);
    apply_pending_merge(state, merge);
    state.pending_bytes = pending_bytes;
    if state.fin_offset.is_none() {
        state.fin_offset = incoming_fin_offset;
    }

    let mut events = Vec::new();
    if retransmitted != 0 || conflicting {
        events.push(Event::Retransmission {
            flow: flow.clone(),
            sequence: payload_sequence,
            bytes: retransmitted,
            conflicting,
        });
    }

    if let Some(bytes) = direct_payload {
        state.pending_bytes = state.pending_bytes.saturating_sub(bytes.len());
        emit_data(state, flow, bytes, max_bytes_per_flow, &mut events);
    }

    loop {
        let next_start = state
            .pending
            .range(..=state.next_offset)
            .next_back()
            .map(|(start, _)| *start);
        let Some(start) = next_start else {
            break;
        };
        let (_, bytes) = state
            .pending
            .remove_entry(&start)
            .expect("pending entry selected for emission exists");
        let end = start
            .checked_add(bytes.len() as u64)
            .expect("pending entry end was validated while planning");
        if end <= state.next_offset {
            state.pending_bytes = state.pending_bytes.saturating_sub(bytes.len());
            continue;
        }
        let skip = usize::try_from(state.next_offset - start)
            .expect("pending entry skip fits its byte length");
        let output = bytes.slice(skip..);
        state.pending_bytes = state.pending_bytes.saturating_sub(bytes.len());
        emit_data(state, flow, output, max_bytes_per_flow, &mut events);
    }
    events
}

fn emit_data(
    state: &mut TcpFlowState,
    flow: &FlowKey,
    bytes: Bytes,
    max_bytes_per_flow: usize,
    events: &mut Vec<Event>,
) {
    let sequence = state.base_sequence.wrapping_add(state.next_offset as u32);
    let output_start = state.next_offset;
    state.next_offset = state
        .next_offset
        .checked_add(bytes.len() as u64)
        .expect("pending emission was validated while planning");
    let history_capacity = max_bytes_per_flow.saturating_sub(state.pending_bytes);
    append_emitted_history(state, output_start, bytes.as_ref(), history_capacity);
    events.push(Event::Data {
        flow: flow.clone(),
        sequence,
        bytes,
    });
}

fn apply_pending_merge(state: &mut TcpFlowState, merge: PendingMergePlan) {
    let PendingMergePlan {
        first_affected,
        affected_segment_count,
        replacement,
        segment_count,
        direct_output,
        ..
    } = merge;
    if let Some(replacement) = replacement {
        let mut current = first_affected;
        for index in 0..affected_segment_count {
            let start = current.expect("pending merge entry was validated while planning");
            state
                .pending
                .remove(&start)
                .expect("pending merge entry was validated while planning");
            if index + 1 < affected_segment_count {
                current = state
                    .pending
                    .range((std::ops::Bound::Excluded(start), std::ops::Bound::Unbounded))
                    .next()
                    .map(|(start, _)| *start);
            }
        }
        let replaced = state.pending.insert(replacement.start, replacement.bytes);
        debug_assert!(replaced.is_none());
    }
    if direct_output {
        debug_assert_eq!(state.pending.len().saturating_add(1), segment_count);
    } else {
        debug_assert_eq!(state.pending.len(), segment_count);
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    use super::*;

    fn flow() -> FlowKey {
        FlowKey {
            source: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            source_port: 12345,
            destination: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)),
            destination_port: 80,
        }
    }

    fn segment(sequence: u32, payload: &'static [u8]) -> Segment {
        Segment {
            flow: flow(),
            sequence,
            payload: Bytes::from_static(payload),
            syn: false,
            fin: false,
            rst: false,
        }
    }

    fn emitted_bytes(state: &TcpFlowState) -> Vec<u8> {
        state.emitted_history.iter().copied().collect()
    }

    #[test]
    fn emitted_history_wraparound_preserves_byte_order() {
        let mut state = TcpFlowState::new(100, Instant::now());
        state.emitted_history.reserve_exact(4);
        let capacity = state.emitted_history.capacity();
        let initial = (0..capacity).map(|value| value as u8).collect::<Vec<_>>();

        append_emitted_history(&mut state, 0, &initial, capacity);
        append_emitted_history(&mut state, capacity as u64, &[0xfe, 0xff], capacity);

        let mut expected = initial[2..].to_vec();
        expected.extend_from_slice(&[0xfe, 0xff]);
        assert_eq!(emitted_bytes(&state), expected);
        assert_eq!(state.history_start_offset, 2);
        assert!(!state.emitted_history.as_slices().1.is_empty());
    }

    #[test]
    fn emitted_history_trimming_discards_the_oldest_bytes() {
        let mut state = TcpFlowState::new(100, Instant::now());
        append_emitted_history(&mut state, 0, b"abcdef", 6);

        trim_emitted_history(&mut state, 3);

        assert_eq!(state.history_start_offset, 3);
        assert_eq!(emitted_bytes(&state), b"def");
    }

    #[test]
    fn emitted_history_conflict_detection_crosses_wraparound() {
        let mut state = TcpFlowState::new(100, Instant::now());
        state.emitted_history.reserve_exact(4);
        let capacity = state.emitted_history.capacity();
        let initial = vec![b'a'; capacity];
        append_emitted_history(&mut state, 0, &initial, capacity);
        append_emitted_history(&mut state, capacity as u64, b"bc", capacity);
        assert!(!state.emitted_history.as_slices().1.is_empty());
        let retained = emitted_bytes(&state);

        assert!(!emitted_history_conflicts(
            &state,
            state.history_start_offset,
            &retained
        ));
        let mut conflicting = retained;
        conflicting[capacity - 2] = b'x';
        assert!(emitted_history_conflicts(
            &state,
            state.history_start_offset,
            &conflicting
        ));
    }

    #[test]
    fn emitted_history_zero_capacity_retains_no_bytes() {
        let mut state = TcpFlowState::new(100, Instant::now());
        append_emitted_history(&mut state, 0, b"abc", 3);

        trim_emitted_history(&mut state, 0);
        assert!(state.emitted_history.is_empty());
        assert_eq!(state.history_start_offset, 3);

        append_emitted_history(&mut state, 3, b"de", 0);

        assert!(state.emitted_history.is_empty());
        assert_eq!(state.history_start_offset, 5);
        assert!(!emitted_history_conflicts(&state, 3, b"XX"));
    }

    #[test]
    fn out_of_order_segments_emit_in_sequence() {
        let now = Instant::now();
        let mut reassembler = Reassembler::new(ReassemblyLimits::default());
        reassembler.open_flow(flow(), 100, now).unwrap();
        assert!(
            reassembler
                .push(segment(103, b"def"), now)
                .unwrap()
                .is_empty()
        );
        let events = reassembler.push(segment(100, b"abc"), now).unwrap();
        let data = events
            .into_iter()
            .filter_map(|event| match event {
                Event::Data { bytes, .. } => Some(bytes),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(data, [Bytes::from_static(b"abcdef")]);
    }

    #[test]
    fn in_order_data_emits_the_input_bytes_without_pending_storage() {
        let now = Instant::now();
        let mut reassembler = Reassembler::new(ReassemblyLimits::default());
        reassembler.open_flow(flow(), 100, now).unwrap();
        let payload = Bytes::from_static(b"abc");
        let pointer = payload.as_ptr();

        let events = reassembler
            .push(
                Segment {
                    flow: flow(),
                    sequence: 100,
                    payload,
                    syn: false,
                    fin: false,
                    rst: false,
                },
                now,
            )
            .unwrap();

        let output = events
            .into_iter()
            .find_map(|event| match event {
                Event::Data { bytes, .. } => Some(bytes),
                _ => None,
            })
            .unwrap();
        assert_eq!(output.as_ref(), b"abc");
        assert_eq!(output.as_ptr(), pointer);
        assert!(reassembler.flows[&flow()].pending.is_empty());
    }

    #[test]
    fn ack_only_segment_leaves_pending_data_intact() {
        let now = Instant::now();
        let mut reassembler = Reassembler::new(ReassemblyLimits::default());
        reassembler.open_flow(flow(), 100, now).unwrap();
        reassembler.push(segment(103, b"def"), now).unwrap();

        assert!(reassembler.push(segment(100, b""), now).unwrap().is_empty());
        let events = reassembler.push(segment(100, b"abc"), now).unwrap();
        assert!(events.iter().any(
            |event| matches!(event, Event::Data { sequence: 100, bytes, .. } if bytes.as_ref() == b"abcdef")
        ));
    }

    #[test]
    fn retransmission_is_reported_without_duplicate_data() {
        let now = Instant::now();
        let mut reassembler = Reassembler::new(ReassemblyLimits::default());
        reassembler.open_flow(flow(), 100, now).unwrap();
        reassembler.push(segment(100, b"abc"), now).unwrap();
        let events = reassembler.push(segment(101, b"bc"), now).unwrap();
        assert!(events.iter().any(|event| matches!(
            event,
            Event::Retransmission {
                bytes: 2,
                conflicting: false,
                ..
            }
        )));
        assert!(
            !events
                .iter()
                .any(|event| matches!(event, Event::Data { .. }))
        );
    }

    #[test]
    fn fully_covered_pending_retransmission_keeps_the_retained_segment() {
        let now = Instant::now();
        let mut reassembler = Reassembler::new(ReassemblyLimits::default());
        reassembler.open_flow(flow(), 100, now).unwrap();
        reassembler.push(segment(102, b"abc"), now).unwrap();
        let pointer = reassembler.flows[&flow()].pending[&2].as_ptr();

        let events = reassembler.push(segment(102, b"abc"), now).unwrap();

        assert!(events.iter().any(|event| matches!(
            event,
            Event::Retransmission {
                bytes: 3,
                conflicting: false,
                ..
            }
        )));
        assert_eq!(reassembler.flows[&flow()].pending[&2].as_ptr(), pointer);
    }

    #[test]
    fn contradictory_retransmission_of_emitted_bytes_is_reported() {
        let now = Instant::now();
        let mut reassembler = Reassembler::new(ReassemblyLimits::default());
        reassembler.open_flow(flow(), 100, now).unwrap();
        reassembler.push(segment(100, b"abcdef"), now).unwrap();

        let events = reassembler.push(segment(102, b"cX"), now).unwrap();
        assert!(events.iter().any(|event| matches!(
            event,
            Event::Retransmission {
                sequence: 102,
                bytes: 2,
                conflicting: true,
                ..
            }
        )));
        assert!(
            !events
                .iter()
                .any(|event| matches!(event, Event::Data { .. }))
        );
    }

    #[test]
    fn sequence_numbers_unwrap_across_u32_boundary() {
        let now = Instant::now();
        let mut reassembler = Reassembler::new(ReassemblyLimits::default());
        reassembler.open_flow(flow(), u32::MAX - 1, now).unwrap();
        reassembler.push(segment(u32::MAX - 1, b"ab"), now).unwrap();
        let events = reassembler.push(segment(0, b"cd"), now).unwrap();
        assert!(events.iter().any(
            |event| matches!(event, Event::Data { sequence: 0, bytes, .. } if bytes.as_ref() == b"cd")
        ));

        let events = reassembler.push(segment(u32::MAX, b"bX"), now).unwrap();
        assert!(events.iter().any(|event| matches!(
            event,
            Event::Retransmission {
                sequence: u32::MAX,
                bytes: 2,
                conflicting: true,
                ..
            }
        )));
    }

    #[test]
    fn data_before_capture_base_is_old_not_a_four_gibibyte_gap() {
        let now = Instant::now();
        let mut reassembler = Reassembler::new(ReassemblyLimits::default());
        reassembler.open_flow(flow(), 100, now).unwrap();
        reassembler.push(segment(100, b"abc"), now).unwrap();
        let events = reassembler.push(segment(99, b"z"), now).unwrap();
        assert!(
            events
                .iter()
                .any(|event| matches!(event, Event::Retransmission { bytes: 1, .. }))
        );
    }

    #[test]
    fn byte_limit_bounds_buffered_window_not_flow_lifetime() {
        let now = Instant::now();
        let limits = ReassemblyLimits {
            max_bytes_per_flow: 4,
            ..ReassemblyLimits::default()
        };
        let mut reassembler = Reassembler::new(limits);
        reassembler.open_flow(flow(), 100, now).unwrap();

        for (sequence, payload) in [(100, b"abcd"), (104, b"efgh"), (108, b"ijkl")] {
            assert!(
                reassembler
                    .push(segment(sequence, payload), now)
                    .unwrap()
                    .iter()
                    .any(|event| matches!(event, Event::Data { .. }))
            );
        }
        assert_eq!(reassembler.aggregate_bytes(), 4);
        assert_eq!(reassembler.aggregate_memory_charge(), 4);
    }

    #[test]
    fn emitted_history_shares_per_flow_and_aggregate_limits_with_pending_data() {
        let now = Instant::now();
        let limits = ReassemblyLimits {
            max_bytes_per_flow: 4,
            ..ReassemblyLimits::default()
        };
        let mut reassembler = Reassembler::new(limits);
        reassembler.open_flow(flow(), 100, now).unwrap();
        reassembler.push(segment(100, b"abcd"), now).unwrap();
        assert_eq!(reassembler.aggregate_bytes(), 4);
        assert_eq!(reassembler.aggregate_memory_charge(), 4);

        reassembler.push(segment(106, b"x"), now).unwrap();
        assert_eq!(reassembler.aggregate_bytes(), 4);
        assert_eq!(reassembler.aggregate_memory_charge(), 68);

        let evicted = reassembler.push(segment(100, b"X"), now).unwrap();
        assert!(evicted.iter().any(|event| matches!(
            event,
            Event::Retransmission {
                conflicting: false,
                ..
            }
        )));
        let retained = reassembler.push(segment(101, b"X"), now).unwrap();
        assert!(retained.iter().any(|event| matches!(
            event,
            Event::Retransmission {
                conflicting: true,
                ..
            }
        )));
    }

    #[test]
    fn pending_data_releases_excess_history_allocation() {
        let now = Instant::now();
        let limits = ReassemblyLimits {
            max_bytes_per_flow: 8,
            max_aggregate_bytes: 72,
            ..ReassemblyLimits::default()
        };
        let mut reassembler = Reassembler::new(limits);
        reassembler.open_flow(flow(), 100, now).unwrap();
        reassembler.push(segment(100, b"abcdefgh"), now).unwrap();

        reassembler.push(segment(109, b"1234567"), now).unwrap();

        let state = reassembler.flows.get(&flow()).unwrap();
        assert_eq!(state.pending_bytes, 7);
        assert_eq!(state.emitted_history.len(), 1);
        assert!(state.emitted_history.capacity() <= 1);
        assert_eq!(reassembler.aggregate_memory_charge(), 72);
    }

    #[test]
    fn aggregate_limit_rejects_emitted_history_atomically() {
        let now = Instant::now();
        let limits = ReassemblyLimits {
            max_bytes_per_flow: 4,
            max_aggregate_bytes: 3,
            ..ReassemblyLimits::default()
        };
        let mut reassembler = Reassembler::new(limits);
        reassembler.open_flow(flow(), 100, now).unwrap();
        assert_eq!(
            reassembler.push(segment(100, b"abcd"), now).unwrap_err(),
            Error::AggregateByteLimit { limit: 3 }
        );
        assert_eq!(reassembler.aggregate_bytes(), 0);
        assert_eq!(reassembler.aggregate_memory_charge(), 0);

        let events = reassembler.push(segment(100, b"abc"), now).unwrap();
        assert!(
            events
                .iter()
                .any(|event| matches!(event, Event::Data { sequence: 100, .. }))
        );
        assert_eq!(reassembler.aggregate_bytes(), 3);
    }

    #[test]
    fn reset_still_must_pass_prospective_resource_check() {
        let now = Instant::now();
        let limits = ReassemblyLimits {
            max_bytes_per_flow: 4,
            max_aggregate_bytes: 3,
            ..ReassemblyLimits::default()
        };
        let mut reassembler = Reassembler::new(limits);
        reassembler.open_flow(flow(), 100, now).unwrap();
        let mut reset = segment(100, b"abcd");
        reset.rst = true;

        assert_eq!(
            reassembler.push(reset, now).unwrap_err(),
            Error::AggregateByteLimit { limit: 3 }
        );
        assert_eq!(reassembler.aggregate_bytes(), 0);
        assert!(matches!(
            reassembler.flush().as_slice(),
            [Event::Evicted {
                pending_bytes: 0,
                ..
            }]
        ));
    }

    #[test]
    fn rejected_first_segment_does_not_leave_an_empty_flow() {
        let now = Instant::now();
        let limits = ReassemblyLimits {
            max_bytes_per_flow: 4,
            max_aggregate_bytes: 3,
            ..ReassemblyLimits::default()
        };
        let mut reassembler = Reassembler::new(limits);

        assert_eq!(
            reassembler.push(segment(100, b"abcd"), now).unwrap_err(),
            Error::AggregateByteLimit { limit: 3 }
        );
        assert_eq!(reassembler.aggregate_bytes(), 0);
        assert_eq!(reassembler.aggregate_memory_charge(), 0);
        assert!(reassembler.flush().is_empty());
    }

    #[test]
    fn rejected_replacement_syn_restores_the_established_generation() {
        let now = Instant::now();
        let mut reassembler = Reassembler::new(ReassemblyLimits {
            max_bytes_per_flow: 4,
            ..ReassemblyLimits::default()
        });
        reassembler.open_flow(flow(), 100, now).unwrap();
        reassembler
            .push(segment(102, b"cd"), now + Duration::from_millis(1))
            .unwrap();
        let before = {
            let state = &reassembler.flows[&flow()];
            (
                state.base_sequence,
                state.next_offset,
                state.history_start_offset,
                state.emitted_history.clone(),
                state.pending.clone(),
                state.pending_bytes,
                state.fin_offset,
                state.last_update,
                reassembler.aggregate_bytes(),
                reassembler.aggregate_memory_charge(),
            )
        };

        let mut replacement = segment(199, b"abcde");
        replacement.syn = true;
        assert_eq!(
            reassembler
                .push(replacement, now + Duration::from_millis(2))
                .unwrap_err(),
            Error::FlowByteLimit { limit: 4 }
        );
        let after = {
            let state = &reassembler.flows[&flow()];
            (
                state.base_sequence,
                state.next_offset,
                state.history_start_offset,
                state.emitted_history.clone(),
                state.pending.clone(),
                state.pending_bytes,
                state.fin_offset,
                state.last_update,
                reassembler.aggregate_bytes(),
                reassembler.aggregate_memory_charge(),
            )
        };
        assert_eq!(after, before);

        let events = reassembler.push(segment(100, b"ab"), now).unwrap();
        assert!(events.iter().any(
            |event| matches!(event, Event::Data { sequence: 100, bytes, .. } if bytes.as_ref() == b"abcd")
        ));
    }

    #[test]
    fn older_accepted_timestamp_does_not_regress_expiry_state() {
        let start = Instant::now();
        let expiry = Duration::from_millis(10);
        let mut reassembler = Reassembler::new(ReassemblyLimits {
            tcp_idle_expiry: expiry,
            ..ReassemblyLimits::default()
        });
        reassembler.open_flow(flow(), 100, start).unwrap();
        let latest = start + Duration::from_millis(8);
        reassembler.push(segment(102, b"b"), latest).unwrap();

        reassembler
            .push(segment(104, b"d"), start + Duration::from_millis(2))
            .unwrap();

        assert_eq!(reassembler.flows[&flow()].last_update, latest);
        assert!(
            reassembler
                .expire(start + Duration::from_millis(12))
                .is_empty()
        );
        assert!(!reassembler.expire(latest + expiry).is_empty());
    }

    #[test]
    fn pending_segment_limit_is_typed_and_atomic() {
        let now = Instant::now();
        let limits = ReassemblyLimits {
            max_tcp_segments_per_flow: 2,
            ..ReassemblyLimits::default()
        };
        let mut reassembler = Reassembler::new(limits);
        reassembler.open_flow(flow(), 100, now).unwrap();

        reassembler.push(segment(101, b"a"), now).unwrap();
        reassembler.push(segment(103, b"b"), now).unwrap();
        assert_eq!(reassembler.aggregate_bytes(), 2);

        assert_eq!(
            reassembler.push(segment(105, b"c"), now).unwrap_err(),
            Error::SegmentLimit { limit: 2 }
        );
        assert_eq!(reassembler.aggregate_bytes(), 2);

        let flushed = reassembler.flush();
        assert!(matches!(
            flushed.as_slice(),
            [
                Event::Gap { .. },
                Event::Evicted {
                    pending_bytes: 2,
                    ..
                }
            ]
        ));
    }

    #[test]
    fn in_order_data_at_pending_segment_limit_uses_final_retained_count() {
        let now = Instant::now();
        let limits = ReassemblyLimits {
            max_tcp_segments_per_flow: 2,
            ..ReassemblyLimits::default()
        };
        let mut reassembler = Reassembler::new(limits);
        reassembler.open_flow(flow(), 100, now).unwrap();
        reassembler.push(segment(102, b"b"), now).unwrap();
        reassembler.push(segment(104, b"d"), now).unwrap();

        let events = reassembler.push(segment(100, b"a"), now).unwrap();

        assert!(events.iter().any(
            |event| matches!(event, Event::Data { sequence: 100, bytes, .. } if bytes.as_ref() == b"a")
        ));
        assert_eq!(reassembler.flows[&flow()].pending.len(), 2);
        assert_eq!(
            reassembler.push(segment(106, b"f"), now).unwrap_err(),
            Error::SegmentLimit { limit: 2 }
        );
        assert_eq!(reassembler.flows[&flow()].pending.len(), 2);
    }

    #[test]
    fn aggregate_limit_charges_sparse_segment_metadata() {
        let now = Instant::now();
        let limits = ReassemblyLimits {
            max_aggregate_bytes: 130,
            ..ReassemblyLimits::default()
        };
        let mut reassembler = Reassembler::new(limits);
        reassembler.open_flow(flow(), 100, now).unwrap();
        reassembler.push(segment(101, b"a"), now).unwrap();
        reassembler.push(segment(103, b"b"), now).unwrap();
        assert_eq!(reassembler.aggregate_bytes(), 2);
        assert_eq!(reassembler.aggregate_memory_charge(), 130);
        assert_eq!(
            reassembler.push(segment(105, b"c"), now).unwrap_err(),
            Error::AggregateByteLimit { limit: 130 }
        );
        assert_eq!(reassembler.aggregate_bytes(), 2);
        assert_eq!(reassembler.aggregate_memory_charge(), 130);
    }

    #[test]
    fn established_fin_bounds_later_data_and_conflicting_fin() {
        let now = Instant::now();
        let mut reassembler = Reassembler::new(ReassemblyLimits::default());
        reassembler.open_flow(flow(), 100, now).unwrap();
        let mut fin = segment(105, b"x");
        fin.fin = true;
        reassembler.push(fin, now).unwrap();

        assert_eq!(
            reassembler.push(segment(106, b"y"), now).unwrap_err(),
            Error::BeyondFinalSequence { final_offset: 6 }
        );
        let mut conflicting = segment(104, b"");
        conflicting.fin = true;
        assert_eq!(
            reassembler.push(conflicting, now).unwrap_err(),
            Error::ConflictingFinalSequence {
                existing_offset: 6,
                new_offset: 4
            }
        );
    }

    #[test]
    fn stale_fin_before_base_is_ignored_but_exact_and_partially_trimmed_fin_are_kept() {
        let now = Instant::now();
        let mut reassembler = Reassembler::new(ReassemblyLimits::default());
        reassembler.open_flow(flow(), 100, now).unwrap();
        reassembler.push(segment(100, b"abc"), now).unwrap();
        let mut stale = segment(90, b"12345");
        stale.fin = true;
        let events = reassembler.push(stale, now).unwrap();
        assert!(
            !events
                .iter()
                .any(|event| matches!(event, Event::Closed { .. }))
        );
        assert!(
            reassembler
                .push(segment(103, b"d"), now)
                .unwrap()
                .iter()
                .any(|event| matches!(event, Event::Data { sequence: 103, .. }))
        );

        let mut exact = Reassembler::new(ReassemblyLimits::default());
        exact.open_flow(flow(), 100, now).unwrap();
        let mut at_base = segment(90, b"0123456789");
        at_base.fin = true;
        assert!(
            exact
                .push(at_base, now)
                .unwrap()
                .iter()
                .any(|event| matches!(event, Event::Closed { reset: false, .. }))
        );

        let mut partial = Reassembler::new(ReassemblyLimits::default());
        partial.open_flow(flow(), 100, now).unwrap();
        let mut crosses_base = segment(98, b"abcd");
        crosses_base.fin = true;
        let events = partial.push(crosses_base, now).unwrap();
        assert!(events.iter().any(
            |event| matches!(event, Event::Data { sequence: 100, bytes, .. } if bytes.as_ref() == b"cd")
        ));
        assert!(
            events
                .iter()
                .any(|event| matches!(event, Event::Closed { reset: false, .. }))
        );
    }

    #[test]
    fn a_new_syn_replaces_an_incompatible_tuple_generation() {
        let now = Instant::now();
        let mut reassembler = Reassembler::new(ReassemblyLimits::default());
        let mut original = segment(99, b"old");
        original.syn = true;
        reassembler.push(original.clone(), now).unwrap();

        let retransmission = reassembler.push(original, now).unwrap();
        assert!(retransmission.iter().any(|event| matches!(
            event,
            Event::Retransmission {
                bytes: 3,
                conflicting: false,
                ..
            }
        )));

        let mut replacement = segment(999, b"new");
        replacement.syn = true;
        let events = reassembler.push(replacement, now).unwrap();
        assert!(events.iter().any(
            |event| matches!(event, Event::Data { sequence: 1000, bytes, .. } if bytes.as_ref() == b"new")
        ));
        assert!(
            !events
                .iter()
                .any(|event| matches!(event, Event::Retransmission { .. }))
        );
    }

    #[test]
    fn serial_half_space_limits_are_rejected_at_public_entry_points() {
        let now = Instant::now();
        let mut invalid = Reassembler::new(ReassemblyLimits {
            max_bytes_per_flow: TCP_SERIAL_HALF_SPACE,
            ..ReassemblyLimits::default()
        });
        assert_eq!(
            invalid.open_flow(flow(), 100, now),
            Err(Error::InvalidWindowLimit {
                limit: TCP_SERIAL_HALF_SPACE
            })
        );
        assert_eq!(
            invalid.push(segment(100, b"a"), now),
            Err(Error::InvalidWindowLimit {
                limit: TCP_SERIAL_HALF_SPACE
            })
        );

        let mut valid = Reassembler::new(ReassemblyLimits {
            max_bytes_per_flow: TCP_SERIAL_HALF_SPACE - 1,
            ..ReassemblyLimits::default()
        });
        valid.open_flow(flow(), 100, now).unwrap();
    }

    #[test]
    fn sparse_aggregate_rejection_precedes_span_sized_scratch_allocation() {
        let now = Instant::now();
        let limits = ReassemblyLimits {
            max_bytes_per_flow: 10_000_001,
            max_aggregate_bytes: PENDING_SEGMENT_METADATA_CHARGE,
            ..ReassemblyLimits::default()
        };
        let mut reassembler = Reassembler::new(limits);
        reassembler.open_flow(flow(), 100, now).unwrap();
        assert_eq!(
            reassembler
                .push(segment(10_000_100, b"x"), now)
                .unwrap_err(),
            Error::AggregateByteLimit {
                limit: PENDING_SEGMENT_METADATA_CHARGE
            }
        );
        assert_eq!(reassembler.aggregate_bytes(), 0);
    }
}
