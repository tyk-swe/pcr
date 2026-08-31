// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::{BTreeMap, VecDeque};
use std::time::Instant;

use bytes::Bytes;

use super::{Error, ResourceError};
use super::{PENDING_SEGMENT_METADATA_CHARGE, TCP_FLOW_STATE_METADATA_CHARGE};

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
    pub(super) deadline: Option<Instant>,
}

impl TcpFlowState {
    pub(super) fn new(base_sequence: u32, now: Instant, deadline: Option<Instant>) -> Self {
        Self {
            base_sequence,
            next_offset: 0,
            history_start_offset: 0,
            emitted_history: VecDeque::new(),
            pending: BTreeMap::new(),
            pending_bytes: 0,
            fin_offset: None,
            last_update: now,
            deadline,
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

pub(super) fn buffer_memory_charge_parts(
    pending_bytes: usize,
    segment_count: usize,
    history_capacity: usize,
) -> Option<usize> {
    pending_memory_charge(pending_bytes, segment_count)?.checked_add(history_capacity)
}

pub(super) fn flow_memory_charge_parts(
    pending_bytes: usize,
    segment_count: usize,
    history_capacity: usize,
) -> Option<usize> {
    buffer_memory_charge_parts(pending_bytes, segment_count, history_capacity)
        .and_then(|charge| charge.checked_add(TCP_FLOW_STATE_METADATA_CHARGE))
}

pub(super) fn flow_memory_charge(state: &TcpFlowState) -> Option<usize> {
    flow_memory_charge_parts(
        state.pending_bytes,
        state.pending.len(),
        state.emitted_history.capacity(),
    )
}

pub(super) fn planned_history_allocation(current: usize, required: usize, limit: usize) -> usize {
    let retained = current.min(limit);
    if required <= retained {
        return retained;
    }
    retained.saturating_mul(2).max(required).min(limit)
}

#[expect(
    clippy::cast_possible_truncation,
    reason = "each difference is clamped by overlap_start/overlap_end into payload or \
              emitted_history, whose lengths are already usize, so no target can truncate"
)]
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
    let payload_start = overlap_start.saturating_sub(offset) as usize;
    let history_start = overlap_start.saturating_sub(state.history_start_offset) as usize;
    let length = overlap_end.saturating_sub(overlap_start) as usize;
    let history_end = history_start.saturating_add(length);
    let Some(payload_overlap) = payload
        .get(payload_start..)
        .and_then(|tail| tail.get(..length))
    else {
        return true;
    };
    !state
        .emitted_history
        .range(history_start..history_end)
        .eq(payload_overlap.iter())
}

pub(super) fn trim_emitted_history(state: &mut TcpFlowState, capacity: usize) {
    if state.emitted_history.len() > capacity {
        let remove = state.emitted_history.len().saturating_sub(capacity);
        state.history_start_offset = state.history_start_offset.saturating_add(remove as u64);
        if !checked_drain_prefix(&mut state.emitted_history, remove) {
            state.emitted_history.clear();
        }
    }
}

pub(super) fn prepare_emitted_history(
    state: &TcpFlowState,
    retained_capacity: usize,
    capacity: usize,
) -> Result<Option<VecDeque<u8>>, Error> {
    if state.emitted_history.capacity() == capacity {
        return Ok(None);
    }
    let mut resized = VecDeque::new();
    resized
        .try_reserve_exact(capacity)
        .map_err(|_| ResourceError::AllocationFailed {
            requested: capacity,
        })?;
    if resized.capacity() != capacity {
        return Err(ResourceError::AllocationFailed {
            requested: capacity,
        }
        .into());
    }
    let skip = state
        .emitted_history
        .len()
        .saturating_sub(retained_capacity);
    resized.extend(state.emitted_history.range(skip..).copied());
    Ok(Some(resized))
}

#[expect(
    clippy::cast_possible_truncation,
    reason = "history_start_offset lies between output_start and output_end, so each difference \
              is bounded by emitted_history.len() or output.len(), both already usize"
)]
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
        let old_start = history_start_offset.saturating_sub(state.history_start_offset) as usize;
        if !checked_drain_prefix(&mut state.emitted_history, old_start) {
            state.emitted_history.clear();
        }
    } else {
        state.emitted_history.clear();
    }
    let output_skip = history_start_offset.saturating_sub(output_start) as usize;
    state.emitted_history.extend(
        output
            .get(output_skip..)
            .unwrap_or_default()
            .iter()
            .copied(),
    );
    state.history_start_offset = history_start_offset;
}

fn checked_drain_prefix<T>(values: &mut VecDeque<T>, end: usize) -> bool {
    if end > values.len() {
        return false;
    }
    values.drain(..end);
    true
}

#[cfg(test)]
mod tests {
    use super::checked_drain_prefix;
    use std::collections::VecDeque;

    #[test]
    fn drain_endpoint_at_length_succeeds_and_one_past_is_rejected() {
        let mut exact = VecDeque::from([1, 2, 3]);
        assert!(checked_drain_prefix(&mut exact, 3));
        assert!(exact.is_empty());

        let mut past = VecDeque::from([1, 2, 3]);
        assert!(!checked_drain_prefix(&mut past, 4));
        assert_eq!(past, VecDeque::from([1, 2, 3]));
    }
}
