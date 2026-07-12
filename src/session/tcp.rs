// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use std::time::Instant;

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::Limits;

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

#[derive(Clone, Debug)]
struct TcpFlowState {
    base_sequence: u32,
    next_offset: u64,
    // A contiguous tail ending at `next_offset`. It is deliberately bounded
    // by the same per-flow budget as pending data so retransmission checking
    // cannot turn a long-lived stream into an unbounded byte log.
    history_start_offset: u64,
    emitted_history: Bytes,
    pending: BTreeMap<u64, Bytes>,
    pending_bytes: usize,
    fin_offset: Option<u64>,
    last_update: Instant,
}

#[derive(Debug)]
pub struct Reassembler {
    limits: Limits,
    flows: HashMap<FlowKey, TcpFlowState>,
    aggregate_bytes: usize,
    aggregate_memory_charge: usize,
}

impl Reassembler {
    pub fn new(limits: Limits) -> Self {
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
        if let Some(existing) = self.flows.get(&flow) {
            if existing.base_sequence == first_payload_sequence {
                return Ok(());
            }
        }
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
        self.flows.insert(
            flow,
            TcpFlowState {
                base_sequence: first_payload_sequence,
                next_offset: 0,
                history_start_offset: 0,
                emitted_history: Bytes::new(),
                pending: BTreeMap::new(),
                pending_bytes: 0,
                fin_offset: None,
                last_update: now,
            },
        );
        Ok(())
    }

    pub fn push(&mut self, segment: Segment, now: Instant) -> Result<Vec<Event>, Error> {
        // Opening a previously unseen tuple (or replacing a tuple generation
        // on SYN) mutates the table before payload validation. Preserve the
        // prior entry and counters so a rejected first segment cannot leave
        // an empty flow behind or discard an established generation.
        let first_payload_sequence = segment.sequence.wrapping_add(u32::from(segment.syn));
        let changes_generation = (segment.syn || !self.flows.contains_key(&segment.flow))
            && self
                .flows
                .get(&segment.flow)
                .is_none_or(|state| state.base_sequence != first_payload_sequence);
        let rollback = changes_generation.then(|| {
            (
                segment.flow.clone(),
                self.flows.get(&segment.flow).cloned(),
                self.aggregate_bytes,
                self.aggregate_memory_charge,
            )
        });
        let result = self.push_inner(segment, now);
        if result.is_err() {
            if let Some((flow, prior, aggregate_bytes, aggregate_memory_charge)) = rollback {
                match prior {
                    Some(state) => {
                        self.flows.insert(flow, state);
                    }
                    None => {
                        self.flows.remove(&flow);
                    }
                }
                self.aggregate_bytes = aggregate_bytes;
                self.aggregate_memory_charge = aggregate_memory_charge;
            }
        }
        result
    }

    fn push_inner(&mut self, segment: Segment, now: Instant) -> Result<Vec<Event>, Error> {
        self.validate_limits()?;
        let first_payload_sequence = segment.sequence.wrapping_add(u32::from(segment.syn));
        if segment.syn || !self.flows.contains_key(&segment.flow) {
            self.open_flow(segment.flow.clone(), first_payload_sequence, now)?;
        }
        let state = self
            .flows
            .get(&segment.flow)
            .expect("flow was inserted above")
            .clone();
        let mut candidate = state;
        candidate.last_update = now;

        let payload_sequence = segment.sequence.wrapping_add(u32::from(segment.syn));
        // Unwrap the 32-bit sequence number around the current receive
        // cursor. TCP windows are bounded well below the signed half-space,
        // so this remains unambiguous across the 4 GiB wrap boundary and
        // treats packets preceding the capture base as old data rather than a
        // multi-gigabyte forward gap.
        let expected_sequence = candidate
            .base_sequence
            .wrapping_add(candidate.next_offset as u32);
        let signed_delta = i64::from(payload_sequence.wrapping_sub(expected_sequence) as i32);
        let absolute = i128::from(candidate.next_offset) + i128::from(signed_delta);
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
        let mut events = Vec::new();
        let mut retransmitted = 0usize;
        let mut conflicting = false;
        let before_base = if absolute < 0 {
            usize::try_from((-absolute).min(payload.len() as i128)).unwrap_or(payload.len())
        } else {
            0
        };
        retransmitted += before_base;
        payload = &payload[before_base..];
        let mut offset = u64::try_from(absolute.max(0)).map_err(|_| Error::FlowByteLimit {
            limit: self.limits.max_bytes_per_flow,
        })?;
        if offset < candidate.next_offset {
            let consumed =
                usize::try_from((candidate.next_offset - offset).min(payload.len() as u64))
                    .unwrap_or(payload.len());
            conflicting |= emitted_history_conflicts(&candidate, offset, &payload[..consumed]);
            retransmitted += consumed;
            payload = &payload[consumed..];
            offset = candidate.next_offset;
        }

        let window_end = candidate
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
        if let Some(final_offset) = candidate.fin_offset {
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
        if let Some(fin_offset) = incoming_fin_offset {
            if candidate.next_offset > fin_offset {
                return Err(Error::BeyondFinalSequence {
                    final_offset: fin_offset,
                });
            }
        }
        if offset > window_end || remaining_end > window_end {
            return Err(Error::FlowByteLimit {
                limit: self.limits.max_bytes_per_flow,
            });
        }

        let old_retained_bytes = retained_bytes(&candidate).ok_or(Error::AggregateByteLimit {
            limit: self.limits.max_aggregate_bytes,
        })?;
        let old_memory_charge =
            flow_memory_charge(&candidate).ok_or(Error::AggregateByteLimit {
                limit: self.limits.max_aggregate_bytes,
            })?;
        let merge = plan_pending_merge(&candidate.pending, offset, payload, candidate.next_offset)
            .ok_or(Error::FlowByteLimit {
                limit: self.limits.max_bytes_per_flow,
            })?;
        let pending_bytes =
            candidate
                .pending_bytes
                .checked_add(merge.added)
                .ok_or(Error::FlowByteLimit {
                    limit: self.limits.max_bytes_per_flow,
                })?;
        if pending_bytes > self.limits.max_bytes_per_flow {
            return Err(Error::FlowByteLimit {
                limit: self.limits.max_bytes_per_flow,
            });
        }
        if merge.segments > self.limits.max_tcp_segments_per_flow {
            return Err(Error::SegmentLimit {
                limit: self.limits.max_tcp_segments_per_flow,
            });
        }
        if let Some(fin_offset) = incoming_fin_offset {
            if candidate.pending.iter().any(|(start, bytes)| {
                start
                    .checked_add(bytes.len() as u64)
                    .is_none_or(|end| end > fin_offset)
            }) || remaining_end > fin_offset
            {
                return Err(Error::BeyondFinalSequence {
                    final_offset: fin_offset,
                });
            }
        }
        let initial_history_capacity = self.limits.max_bytes_per_flow.saturating_sub(pending_bytes);
        let final_pending_bytes = pending_bytes.saturating_sub(merge.emitted_segment_bytes);
        let final_pending_segments = merge
            .segments
            .saturating_sub(usize::from(merge.emitted_segment_bytes != 0));
        let final_history_capacity = self
            .limits
            .max_bytes_per_flow
            .saturating_sub(final_pending_bytes);
        let prospective_history = candidate
            .emitted_history
            .len()
            .min(initial_history_capacity)
            .saturating_add(merge.emitted_segment_bytes)
            .min(final_history_capacity);
        let prospective_retained = final_pending_bytes.checked_add(prospective_history).ok_or(
            Error::AggregateByteLimit {
                limit: self.limits.max_aggregate_bytes,
            },
        )?;
        let prospective_memory = pending_memory_charge(final_pending_bytes, final_pending_segments)
            .and_then(|charge| charge.checked_add(prospective_history))
            .ok_or(Error::AggregateByteLimit {
                limit: self.limits.max_aggregate_bytes,
            })?;
        let prospective_aggregate_bytes = self
            .aggregate_bytes
            .checked_sub(old_retained_bytes)
            .and_then(|bytes| bytes.checked_add(prospective_retained))
            .ok_or(Error::AggregateByteLimit {
                limit: self.limits.max_aggregate_bytes,
            })?;
        let prospective_aggregate_memory = self
            .aggregate_memory_charge
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

        retransmitted += merge.overlap;
        conflicting |= merge.conflicting;
        trim_emitted_history(&mut candidate, initial_history_capacity);
        candidate.pending = merge_pending(&candidate.pending, offset, payload, &merge).ok_or(
            Error::FlowByteLimit {
                limit: self.limits.max_bytes_per_flow,
            },
        )?;
        candidate.pending_bytes = pending_bytes;
        if candidate.fin_offset.is_none() {
            candidate.fin_offset = incoming_fin_offset;
        }

        if retransmitted != 0 || conflicting {
            events.push(Event::Retransmission {
                flow: segment.flow.clone(),
                sequence: payload_sequence,
                bytes: retransmitted,
                conflicting,
            });
        }

        loop {
            let next = candidate
                .pending
                .range(..=candidate.next_offset)
                .next_back()
                .map(|(start, bytes)| (*start, bytes.clone()));
            let Some((start, bytes)) = next else {
                break;
            };
            let end = start + bytes.len() as u64;
            if end <= candidate.next_offset {
                candidate.pending.remove(&start);
                candidate.pending_bytes = candidate.pending_bytes.saturating_sub(bytes.len());
                continue;
            }
            let skip = (candidate.next_offset - start) as usize;
            let output = bytes.slice(skip..);
            let sequence = candidate
                .base_sequence
                .wrapping_add(candidate.next_offset as u32);
            let output_start = candidate.next_offset;
            candidate.next_offset += output.len() as u64;
            candidate.pending.remove(&start);
            candidate.pending_bytes = candidate.pending_bytes.saturating_sub(bytes.len());
            let history_capacity = self
                .limits
                .max_bytes_per_flow
                .saturating_sub(candidate.pending_bytes);
            append_emitted_history(
                &mut candidate,
                output_start,
                output.as_ref(),
                history_capacity,
            );
            events.push(Event::Data {
                flow: segment.flow.clone(),
                sequence,
                bytes: output,
            });
        }
        let closed = segment.rst
            || candidate
                .fin_offset
                .is_some_and(|fin_offset| candidate.next_offset >= fin_offset);
        let (new_retained_bytes, new_memory_charge) = if closed {
            (0, 0)
        } else {
            (
                retained_bytes(&candidate).ok_or(Error::AggregateByteLimit {
                    limit: self.limits.max_aggregate_bytes,
                })?,
                flow_memory_charge(&candidate).ok_or(Error::AggregateByteLimit {
                    limit: self.limits.max_aggregate_bytes,
                })?,
            )
        };
        let aggregate_bytes = self
            .aggregate_bytes
            .checked_sub(old_retained_bytes)
            .and_then(|bytes| bytes.checked_add(new_retained_bytes))
            .ok_or(Error::AggregateByteLimit {
                limit: self.limits.max_aggregate_bytes,
            })?;
        let aggregate_memory_charge = self
            .aggregate_memory_charge
            .checked_sub(old_memory_charge)
            .and_then(|charge| charge.checked_add(new_memory_charge))
            .ok_or(Error::AggregateByteLimit {
                limit: self.limits.max_aggregate_bytes,
            })?;
        if aggregate_bytes > self.limits.max_aggregate_bytes
            || aggregate_memory_charge > self.limits.max_aggregate_bytes
        {
            return Err(Error::AggregateByteLimit {
                limit: self.limits.max_aggregate_bytes,
            });
        }
        self.aggregate_bytes = aggregate_bytes;
        self.aggregate_memory_charge = aggregate_memory_charge;
        if closed {
            self.flows.remove(&segment.flow);
            events.push(Event::Closed {
                flow: segment.flow,
                reset: segment.rst,
            });
        } else {
            self.flows.insert(segment.flow, candidate);
        }
        Ok(events)
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
            if let Some((&next, _)) = state.pending.first_key_value() {
                if next > state.next_offset {
                    events.push(Event::Gap {
                        flow: key.clone(),
                        expected_sequence: state
                            .base_sequence
                            .wrapping_add(state.next_offset as u32),
                        next_sequence: state.base_sequence.wrapping_add(next as u32),
                    });
                }
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

fn pending_memory_charge(pending_bytes: usize, segments: usize) -> Option<usize> {
    segments
        .checked_mul(PENDING_SEGMENT_METADATA_CHARGE)
        .and_then(|metadata| pending_bytes.checked_add(metadata))
}

fn retained_bytes(state: &TcpFlowState) -> Option<usize> {
    state.pending_bytes.checked_add(state.emitted_history.len())
}

fn flow_memory_charge(state: &TcpFlowState) -> Option<usize> {
    pending_memory_charge(state.pending_bytes, state.pending.len())?
        .checked_add(state.emitted_history.len())
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
    payload[payload_start..payload_start + length]
        != state.emitted_history[history_start..history_start + length]
}

fn trim_emitted_history(state: &mut TcpFlowState, capacity: usize) {
    if state.emitted_history.len() <= capacity {
        return;
    }
    let remove = state.emitted_history.len() - capacity;
    state.history_start_offset = state.history_start_offset.saturating_add(remove as u64);
    state.emitted_history = Bytes::copy_from_slice(&state.emitted_history[remove..]);
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
        state.emitted_history = Bytes::new();
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
    let mut retained = Vec::with_capacity(keep);
    if !state.emitted_history.is_empty() && history_start_offset < output_start {
        let old_start = (history_start_offset - state.history_start_offset) as usize;
        retained.extend_from_slice(&state.emitted_history[old_start..]);
    }
    let output_skip = history_start_offset.saturating_sub(output_start) as usize;
    retained.extend_from_slice(&output[output_skip..]);
    state.history_start_offset = history_start_offset;
    state.emitted_history = Bytes::from(retained);
}

#[derive(Clone, Copy, Debug)]
struct PendingMergePlan {
    added: usize,
    overlap: usize,
    conflicting: bool,
    segments: usize,
    emitted_segment_bytes: usize,
}

fn plan_pending_merge(
    existing: &BTreeMap<u64, Bytes>,
    offset: u64,
    payload: &[u8],
    next_offset: u64,
) -> Option<PendingMergePlan> {
    if payload.is_empty() {
        return Some(PendingMergePlan {
            added: 0,
            overlap: 0,
            conflicting: false,
            segments: existing.len(),
            emitted_segment_bytes: 0,
        });
    }
    let payload_end = offset.checked_add(payload.len() as u64)?;
    let mut overlap = 0usize;
    let mut conflicting = false;
    let mut connected = 0usize;
    let mut connected_end = payload_end;
    for (start, value) in existing {
        let end = start.checked_add(value.len() as u64)?;
        if end >= offset && *start <= payload_end {
            connected += 1;
            connected_end = connected_end.max(end);
        }
        let overlap_start = (*start).max(offset);
        let overlap_end = end.min(payload_end);
        if overlap_start < overlap_end {
            let length = usize::try_from(overlap_end - overlap_start).ok()?;
            let existing_start = usize::try_from(overlap_start - *start).ok()?;
            let payload_start = usize::try_from(overlap_start - offset).ok()?;
            overlap = overlap.checked_add(length)?;
            conflicting |= value[existing_start..existing_start + length]
                != payload[payload_start..payload_start + length];
        }
    }
    Some(PendingMergePlan {
        added: payload.len().checked_sub(overlap)?,
        overlap,
        conflicting,
        segments: existing.len().checked_add(1)?.checked_sub(connected)?,
        emitted_segment_bytes: (offset == next_offset)
            .then(|| usize::try_from(connected_end.checked_sub(next_offset)?).ok())
            .flatten()
            .unwrap_or(0),
    })
}

fn merge_pending(
    existing: &BTreeMap<u64, Bytes>,
    offset: u64,
    payload: &[u8],
    plan: &PendingMergePlan,
) -> Option<BTreeMap<u64, Bytes>> {
    if payload.is_empty() {
        return Some(existing.clone());
    }
    let payload_end = offset.checked_add(payload.len() as u64)?;
    let affected = existing
        .iter()
        .filter_map(|(start, bytes)| {
            let end = start.checked_add(bytes.len() as u64)?;
            (end >= offset && *start <= payload_end).then_some((*start, end, bytes.clone()))
        })
        .collect::<Vec<_>>();
    let mut pending = existing.clone();
    if affected.is_empty() {
        pending.insert(offset, Bytes::copy_from_slice(payload));
        debug_assert_eq!(pending.len(), plan.segments);
        return Some(pending);
    }

    let union_start = affected
        .iter()
        .map(|(start, _, _)| *start)
        .min()
        .unwrap_or(offset)
        .min(offset);
    let union_end = affected
        .iter()
        .map(|(_, end, _)| *end)
        .max()
        .unwrap_or(payload_end)
        .max(payload_end);
    let union_len = usize::try_from(union_end.checked_sub(union_start)?).ok()?;
    let mut bytes = vec![0u8; union_len];
    let payload_start = usize::try_from(offset.checked_sub(union_start)?).ok()?;
    bytes[payload_start..payload_start + payload.len()].copy_from_slice(payload);
    for (start, _, value) in &affected {
        let relative = usize::try_from(start.checked_sub(union_start)?).ok()?;
        // Retained bytes win overlaps, preserving the existing retransmission
        // semantics after conflict detection.
        bytes[relative..relative + value.len()].copy_from_slice(value);
        pending.remove(start);
    }
    pending.insert(union_start, Bytes::from(bytes));
    debug_assert_eq!(pending.len(), plan.segments);
    Some(pending)
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

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

    #[test]
    fn out_of_order_segments_emit_in_sequence() {
        let now = Instant::now();
        let mut reassembler = Reassembler::new(Limits::default());
        reassembler.open_flow(flow(), 100, now).unwrap();
        assert!(reassembler
            .push(segment(103, b"def"), now)
            .unwrap()
            .is_empty());
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
    fn retransmission_is_reported_without_duplicate_data() {
        let now = Instant::now();
        let mut reassembler = Reassembler::new(Limits::default());
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
        assert!(!events
            .iter()
            .any(|event| matches!(event, Event::Data { .. })));
    }

    #[test]
    fn contradictory_retransmission_of_emitted_bytes_is_reported() {
        let now = Instant::now();
        let mut reassembler = Reassembler::new(Limits::default());
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
        assert!(!events
            .iter()
            .any(|event| matches!(event, Event::Data { .. })));
    }

    #[test]
    fn sequence_numbers_unwrap_across_u32_boundary() {
        let now = Instant::now();
        let mut reassembler = Reassembler::new(Limits::default());
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
        let mut reassembler = Reassembler::new(Limits::default());
        reassembler.open_flow(flow(), 100, now).unwrap();
        reassembler.push(segment(100, b"abc"), now).unwrap();
        let events = reassembler.push(segment(99, b"z"), now).unwrap();
        assert!(events
            .iter()
            .any(|event| matches!(event, Event::Retransmission { bytes: 1, .. })));
    }

    #[test]
    fn byte_limit_bounds_buffered_window_not_flow_lifetime() {
        let now = Instant::now();
        let limits = Limits {
            max_bytes_per_flow: 4,
            ..Limits::default()
        };
        let mut reassembler = Reassembler::new(limits);
        reassembler.open_flow(flow(), 100, now).unwrap();

        for (sequence, payload) in [(100, b"abcd"), (104, b"efgh"), (108, b"ijkl")] {
            assert!(reassembler
                .push(segment(sequence, payload), now)
                .unwrap()
                .iter()
                .any(|event| matches!(event, Event::Data { .. })));
        }
        assert_eq!(reassembler.aggregate_bytes(), 4);
        assert_eq!(reassembler.aggregate_memory_charge(), 4);
    }

    #[test]
    fn emitted_history_shares_per_flow_and_aggregate_limits_with_pending_data() {
        let now = Instant::now();
        let limits = Limits {
            max_bytes_per_flow: 4,
            ..Limits::default()
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
    fn aggregate_limit_rejects_emitted_history_atomically() {
        let now = Instant::now();
        let limits = Limits {
            max_bytes_per_flow: 4,
            max_aggregate_bytes: 3,
            ..Limits::default()
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
        assert!(events
            .iter()
            .any(|event| matches!(event, Event::Data { sequence: 100, .. })));
        assert_eq!(reassembler.aggregate_bytes(), 3);
    }

    #[test]
    fn rejected_first_segment_does_not_leave_an_empty_flow() {
        let now = Instant::now();
        let limits = Limits {
            max_bytes_per_flow: 4,
            max_aggregate_bytes: 3,
            ..Limits::default()
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
        let mut reassembler = Reassembler::new(Limits {
            max_bytes_per_flow: 4,
            ..Limits::default()
        });
        reassembler.open_flow(flow(), 100, now).unwrap();
        reassembler.push(segment(102, b"cd"), now).unwrap();

        let mut replacement = segment(199, b"abcde");
        replacement.syn = true;
        assert_eq!(
            reassembler.push(replacement, now).unwrap_err(),
            Error::FlowByteLimit { limit: 4 }
        );

        let events = reassembler.push(segment(100, b"ab"), now).unwrap();
        assert!(events.iter().any(
            |event| matches!(event, Event::Data { sequence: 100, bytes, .. } if bytes.as_ref() == b"abcd")
        ));
    }

    #[test]
    fn pending_segment_limit_is_typed_and_atomic() {
        let now = Instant::now();
        let limits = Limits {
            max_tcp_segments_per_flow: 2,
            ..Limits::default()
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
    fn aggregate_limit_charges_sparse_segment_metadata() {
        let now = Instant::now();
        let limits = Limits {
            max_aggregate_bytes: 130,
            ..Limits::default()
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
        let mut reassembler = Reassembler::new(Limits::default());
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
        let mut reassembler = Reassembler::new(Limits::default());
        reassembler.open_flow(flow(), 100, now).unwrap();
        reassembler.push(segment(100, b"abc"), now).unwrap();
        let mut stale = segment(90, b"12345");
        stale.fin = true;
        let events = reassembler.push(stale, now).unwrap();
        assert!(!events
            .iter()
            .any(|event| matches!(event, Event::Closed { .. })));
        assert!(reassembler
            .push(segment(103, b"d"), now)
            .unwrap()
            .iter()
            .any(|event| matches!(event, Event::Data { sequence: 103, .. })));

        let mut exact = Reassembler::new(Limits::default());
        exact.open_flow(flow(), 100, now).unwrap();
        let mut at_base = segment(90, b"0123456789");
        at_base.fin = true;
        assert!(exact
            .push(at_base, now)
            .unwrap()
            .iter()
            .any(|event| matches!(event, Event::Closed { reset: false, .. })));

        let mut partial = Reassembler::new(Limits::default());
        partial.open_flow(flow(), 100, now).unwrap();
        let mut crosses_base = segment(98, b"abcd");
        crosses_base.fin = true;
        let events = partial.push(crosses_base, now).unwrap();
        assert!(events.iter().any(
            |event| matches!(event, Event::Data { sequence: 100, bytes, .. } if bytes.as_ref() == b"cd")
        ));
        assert!(events
            .iter()
            .any(|event| matches!(event, Event::Closed { reset: false, .. })));
    }

    #[test]
    fn a_new_syn_replaces_an_incompatible_tuple_generation() {
        let now = Instant::now();
        let mut reassembler = Reassembler::new(Limits::default());
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
        assert!(!events
            .iter()
            .any(|event| matches!(event, Event::Retransmission { .. })));
    }

    #[test]
    fn serial_half_space_limits_are_rejected_at_public_entry_points() {
        let now = Instant::now();
        let mut invalid = Reassembler::new(Limits {
            max_bytes_per_flow: TCP_SERIAL_HALF_SPACE,
            ..Limits::default()
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

        let mut valid = Reassembler::new(Limits {
            max_bytes_per_flow: TCP_SERIAL_HALF_SPACE - 1,
            ..Limits::default()
        });
        valid.open_flow(flow(), 100, now).unwrap();
    }

    #[test]
    fn sparse_aggregate_rejection_precedes_span_sized_scratch_allocation() {
        let now = Instant::now();
        let limits = Limits {
            max_bytes_per_flow: 10_000_001,
            max_aggregate_bytes: PENDING_SEGMENT_METADATA_CHARGE,
            ..Limits::default()
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
