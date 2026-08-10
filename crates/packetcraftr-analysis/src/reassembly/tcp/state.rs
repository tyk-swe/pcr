// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::{BTreeMap, VecDeque};
use std::time::Instant;

use bytes::Bytes;

use super::Error;
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

pub(super) fn prepare_emitted_history(
    state: &TcpFlowState,
    retained_capacity: usize,
    capacity: usize,
) -> Result<(Option<VecDeque<u8>>, usize), Error> {
    prepare_emitted_history_with(state, retained_capacity, capacity, |buffer, requested| {
        buffer.try_reserve_exact(requested)
    })
}

fn prepare_emitted_history_with<F>(
    state: &TcpFlowState,
    retained_capacity: usize,
    capacity: usize,
    reserve: F,
) -> Result<(Option<VecDeque<u8>>, usize), Error>
where
    F: FnOnce(&mut VecDeque<u8>, usize) -> Result<(), std::collections::TryReserveError>,
{
    if state.emitted_history.capacity() == capacity {
        return Ok((None, capacity));
    }
    let mut resized = VecDeque::new();
    reserve(&mut resized, capacity).map_err(|_| Error::AllocationFailed {
        requested: capacity,
    })?;
    let skip = state
        .emitted_history
        .len()
        .saturating_sub(retained_capacity);
    resized.extend(state.emitted_history.range(skip..).copied());
    let allocated_capacity = resized.capacity();
    Ok((Some(resized), allocated_capacity))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prepared_history_reports_allocator_overallocation_without_mutating_flow() {
        let mut state = TcpFlowState::new(1, Instant::now());
        state.emitted_history.extend([1, 2, 3]);
        let old_history = state.emitted_history.clone();
        let old_capacity = state.emitted_history.capacity();
        let requested = old_capacity.saturating_add(1);

        let (replacement, allocated_capacity) = prepare_emitted_history_with(
            &state,
            state.emitted_history.len(),
            requested,
            |buffer, requested| buffer.try_reserve_exact(requested.saturating_add(17)),
        )
        .expect("simulated over-allocation is accepted for accounting");

        assert!(allocated_capacity > requested);
        assert_eq!(
            replacement.as_ref().map(VecDeque::capacity),
            Some(allocated_capacity)
        );
        assert_eq!(state.emitted_history, old_history);
        assert_eq!(flow_memory_charge(&state), Some(old_capacity));
    }
}
