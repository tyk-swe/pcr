// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;
use std::time::Instant;

use super::history::History;
use super::pages::{PAGE_CHARGE, Page};

use super::Error;
use super::{PENDING_SEGMENT_METADATA_CHARGE, TCP_FLOW_STATE_METADATA_CHARGE};

#[derive(Debug)]
pub(super) struct TcpFlowState {
    pub(super) base_sequence: u32,
    pub(super) next_offset: u64,
    // Bounded by the per-flow budget so retransmission checks cannot keep an unbounded byte log.
    pub(super) history_start_offset: u64,
    pub(super) emitted_history: History,
    pub(super) pending: BTreeMap<u64, u64>,
    pub(super) pages: BTreeMap<u64, Page>,
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
            emitted_history: History::default(),
            pending: BTreeMap::new(),
            pages: BTreeMap::new(),
            pending_bytes: 0,
            fin_offset: None,
            last_update: now,
            deadline,
        }
    }
}

pub(super) fn retained_bytes(state: &TcpFlowState) -> Option<usize> {
    state.pending_bytes.checked_add(state.emitted_history.len())
}

pub(super) fn memory_charge_parts(
    pending_storage_charge: usize,
    segment_count: usize,
    history_capacity: usize,
    flow_state: bool,
) -> Option<usize> {
    let buffers = segment_count
        .checked_mul(PENDING_SEGMENT_METADATA_CHARGE)
        .and_then(|metadata| pending_storage_charge.checked_add(metadata))
        .and_then(|charge| charge.checked_add(history_capacity))?;
    if flow_state {
        buffers.checked_add(TCP_FLOW_STATE_METADATA_CHARGE)
    } else {
        Some(buffers)
    }
}

pub(super) fn flow_memory_charge(state: &TcpFlowState) -> Option<usize> {
    memory_charge_parts(
        state.pages.len().checked_mul(PAGE_CHARGE)?,
        state.pending.len(),
        state.emitted_history.capacity(),
        true,
    )
}

pub(super) fn planned_history_allocation(current: usize, required: usize, limit: usize) -> usize {
    let retained = current;
    if required <= retained {
        return retained;
    }
    retained.saturating_mul(2).max(required).min(limit)
}

// Each difference is clamped into payload or emitted_history, so no usize cast can truncate.
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
        if !state.emitted_history.drain_prefix(remove) {
            state.emitted_history.clear();
        }
    }
}

pub(super) fn prepare_emitted_history(
    state: &TcpFlowState,
    retained_capacity: usize,
    capacity: usize,
) -> Result<Option<History>, Error> {
    if state.emitted_history.capacity() == capacity {
        return Ok(None);
    }
    let mut resized = History::new(capacity)?;
    let skip = state
        .emitted_history
        .len()
        .saturating_sub(retained_capacity);
    resized.extend(state.emitted_history.range(skip..).copied());
    Ok(Some(resized))
}

// Each difference is bounded by emitted_history.len() or output.len(), so no cast truncates.
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
        if !state.emitted_history.drain_prefix(old_start) {
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
