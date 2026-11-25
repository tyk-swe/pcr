// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;
use std::ops::Range;
use std::time::Instant;

use super::history::History;
use super::pages::{PAGE_CHARGE, Page};

use super::Error;
use super::{
    PENDING_SEGMENT_METADATA_CHARGE, PENDING_SOURCE_SPAN_CHARGE, TCP_FLOW_STATE_METADATA_CHARGE,
};
use crate::analysis::provenance::SourceSet;

#[derive(Debug)]
pub(super) struct TcpFlowState {
    pub(super) base_sequence: u32,
    pub(super) next_offset: u64,
    // Bounded by the per-flow budget so retransmission checks cannot keep an unbounded byte log.
    pub(super) history_start_offset: u64,
    pub(super) emitted_history: History,
    pub(super) pending: BTreeMap<u64, u64>,
    pub(super) pending_sources: BTreeMap<u64, (u64, SourceSet)>,
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
            pending_sources: BTreeMap::new(),
            pages: BTreeMap::new(),
            pending_bytes: 0,
            fin_offset: None,
            last_update: now,
            deadline,
        }
    }
}

fn overlapping_sources<V>(
    sources: &BTreeMap<u64, (u64, V)>,
    start: u64,
    end: u64,
) -> Vec<(u64, u64)> {
    let prior = sources
        .range(..=start)
        .next_back()
        .filter(|&(&source_start, &(source_end, _))| source_start < start && source_end > start)
        .map(|(&source_start, &(source_end, _))| (source_start, source_end));
    prior
        .into_iter()
        .chain(
            sources
                .range(start..end)
                .map(|(&source_start, &(source_end, _))| (source_start, source_end)),
        )
        .collect()
}

fn uncovered_pieces<V>(sources: &BTreeMap<u64, (u64, V)>, start: u64, end: u64) -> Vec<(u64, u64)> {
    if start >= end {
        return Vec::new();
    }
    let mut pieces = vec![(start, end)];
    for (existing_start, existing_end) in overlapping_sources(sources, start, end) {
        let mut next = Vec::with_capacity(pieces.len());
        for (piece_start, piece_end) in pieces {
            if existing_end <= piece_start || existing_start >= piece_end {
                next.push((piece_start, piece_end));
                continue;
            }
            if piece_start < existing_start {
                next.push((piece_start, existing_start));
            }
            if existing_end < piece_end {
                next.push((existing_end, piece_end));
            }
        }
        pieces = next;
    }
    pieces
}

/// Insert the not-yet-seen portions of a wire span. Existing spans win, so a
/// retransmission never replaces the provenance of the first observation.
pub(super) fn insert_pending_source(
    state: &mut TcpFlowState,
    start: u64,
    end: u64,
    set: SourceSet,
) {
    for (piece_start, piece_end) in uncovered_pieces(&state.pending_sources, start, end) {
        state
            .pending_sources
            .insert(piece_start, (piece_end, set.clone()));
    }
}

fn take_source_ranges<V: Clone>(
    sources: &mut BTreeMap<u64, (u64, V)>,
    start: u64,
    end: u64,
) -> Vec<(u64, u64, V)> {
    let mut output = Vec::new();
    let mut cursor = start;
    while cursor < end {
        let containing = sources
            .range(..=cursor)
            .next_back()
            .filter(|&(_, &(source_end, _))| source_end > cursor)
            .map(|(&source_start, _)| source_start);
        let Some(source_start) = containing else {
            break;
        };
        let Some((source_end, set)) = sources.remove(&source_start) else {
            break;
        };
        if source_start < cursor {
            sources.insert(source_start, (cursor, set.clone()));
        }
        let take_end = source_end.min(end);
        output.push((cursor, take_end, set.clone()));
        if source_end > end {
            sources.insert(end, (source_end, set));
        }
        cursor = take_end;
    }
    output
}

/// Remove `[start, end)` and return contiguous byte-length/source-set spans.
/// Missing provenance is represented by a zero-length gap that callers merge
/// into an unprovenanced tail; reassembly invariants should prevent it.
pub(super) fn take_pending_sources(
    state: &mut TcpFlowState,
    start: u64,
    end: u64,
) -> Vec<(usize, SourceSet)> {
    take_source_ranges(&mut state.pending_sources, start, end)
        .into_iter()
        .map(|(start, end, set)| {
            (
                usize::try_from(end.saturating_sub(start)).unwrap_or(usize::MAX),
                set,
            )
        })
        .collect()
}

pub(super) fn projected_pending_source_count(
    state: &TcpFlowState,
    insert: Option<Range<u64>>,
    take: Option<Range<u64>>,
) -> usize {
    let insert = insert.filter(|range| range.start < range.end);
    let take = take.filter(|range| range.start < range.end);
    let start = match (&insert, &take) {
        (None, None) => return state.pending_sources.len(),
        (Some(range), None) | (None, Some(range)) => range.start,
        (Some(insert), Some(take)) => insert.start.min(take.start),
    };
    let end = match (&insert, &take) {
        (Some(range), None) | (None, Some(range)) => range.end,
        (Some(insert), Some(take)) => insert.end.max(take.end),
        (None, None) => unreachable!(),
    };
    let overlapping = overlapping_sources(&state.pending_sources, start, end);
    let outside = state.pending_sources.len() - overlapping.len();
    let mut spans: BTreeMap<u64, (u64, ())> = overlapping
        .into_iter()
        .map(|(start, end)| (start, (end, ())))
        .collect();
    if let Some(range) = insert {
        for (piece_start, piece_end) in uncovered_pieces(&spans, range.start, range.end) {
            spans.insert(piece_start, (piece_end, ()));
        }
    }
    if let Some(range) = take {
        take_source_ranges(&mut spans, range.start, range.end);
    }
    outside + spans.len()
}

pub(super) fn retained_bytes(state: &TcpFlowState) -> Option<usize> {
    state.pending_bytes.checked_add(state.emitted_history.len())
}

pub(super) fn memory_charge_parts(
    pending_storage_charge: usize,
    segment_count: usize,
    source_span_count: usize,
    history_capacity: usize,
    flow_state: bool,
) -> Option<usize> {
    let buffers = segment_count
        .checked_mul(PENDING_SEGMENT_METADATA_CHARGE)
        .and_then(|metadata| {
            source_span_count
                .checked_mul(PENDING_SOURCE_SPAN_CHARGE)
                .and_then(|sources| metadata.checked_add(sources))
        })
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
        state.pending_sources.len(),
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
    let (head, tail) = state.emitted_history.slices(history_start..history_end);
    let (payload_head, payload_tail) = payload_overlap.split_at(head.len());
    head != payload_head || tail != payload_tail
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
    let (head, tail) = state.emitted_history.slices(skip..);
    resized.extend(head);
    resized.extend(tail);
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
    state
        .emitted_history
        .extend(output.get(output_skip..).unwrap_or_default());
    state.history_start_offset = history_start_offset;
}
