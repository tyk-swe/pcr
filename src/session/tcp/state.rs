// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::{BTreeMap, VecDeque};
use std::time::Instant;

use bytes::Bytes;

use super::PENDING_SEGMENT_METADATA_CHARGE;

#[derive(Debug)]
pub(super) struct TcpFlowState {
    pub(super) base_sequence: u32,
    pub(super) next_offset: u64,
    // A contiguous tail ending at `next_offset`. It is deliberately bounded
    // by the same per-flow budget as pending data so retransmission checking
    // cannot turn a long-lived stream into an unbounded byte log.
    pub(super) history_start_offset: u64,
    pub(super) emitted_history: VecDeque<u8>,
    pub(super) pending: BTreeMap<u64, Bytes>,
    pub(super) pending_bytes: usize,
    pub(super) fin_offset: Option<u64>,
    pub(super) last_update: Instant,
}

impl TcpFlowState {
    pub(super) fn new(base_sequence: u32, now: Instant) -> Self {
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

pub(super) fn pending_memory_charge(pending_bytes: usize, segment_count: usize) -> Option<usize> {
    segment_count
        .checked_mul(PENDING_SEGMENT_METADATA_CHARGE)
        .and_then(|metadata| pending_bytes.checked_add(metadata))
}

pub(super) fn retained_bytes(state: &TcpFlowState) -> Option<usize> {
    state.pending_bytes.checked_add(state.emitted_history.len())
}

pub(super) fn flow_memory_charge(state: &TcpFlowState) -> Option<usize> {
    pending_memory_charge(state.pending_bytes, state.pending.len())?
        .checked_add(state.emitted_history.capacity())
}

pub(super) fn planned_history_allocation(current: usize, required: usize, limit: usize) -> usize {
    let retained = current.min(limit);
    if required <= retained {
        return retained;
    }
    retained.saturating_mul(2).max(required).min(limit)
}

pub(super) fn emitted_history_conflicts(state: &TcpFlowState, offset: u64, payload: &[u8]) -> bool {
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

pub(super) fn trim_emitted_history(state: &mut TcpFlowState, capacity: usize) {
    if state.emitted_history.len() > capacity {
        let remove = state.emitted_history.len() - capacity;
        state.history_start_offset = state.history_start_offset.saturating_add(remove as u64);
        state.emitted_history.drain(..remove);
    }
}

pub(super) fn resize_emitted_history(state: &mut TcpFlowState, capacity: usize) {
    if state.emitted_history.capacity() == capacity {
        return;
    }
    let mut resized = VecDeque::with_capacity(capacity);
    resized.extend(state.emitted_history.drain(..));
    state.emitted_history = resized;
}

pub(super) fn append_emitted_history(
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
