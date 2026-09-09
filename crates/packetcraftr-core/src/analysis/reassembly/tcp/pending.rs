// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;

use super::history::History;
use super::pages::{self, PAGE_CHARGE, Page};
use std::ops::Range;

use bytes::Bytes;

use super::state::{
    TcpFlowState, emitted_history_conflicts, flow_memory_charge, prepare_emitted_history,
    retained_bytes,
};
use super::{Error, Limits, MalformedError, ResourceError, Segment};

use accounting::{PushAccountingInput, plan_push_accounting};

mod accounting;
pub(super) mod commit;

pub(super) fn plan_push(
    limits: &Limits,
    state: &TcpFlowState,
    state_is_accounted: bool,
    aggregate_base_bytes: usize,
    aggregate_base_memory_charge: usize,
    transient_base_memory_charge: usize,
    segment: &Segment,
) -> Result<PushPlan, Error> {
    let incoming = normalize_payload(limits, state, segment)?;
    let mut planned = plan_merge_and_accounting(
        limits,
        state,
        state_is_accounted,
        aggregate_base_bytes,
        aggregate_base_memory_charge,
        segment,
        &incoming,
    )?;
    // Includes old generations until commit, plus every prepared buffer.
    let error = || ResourceError::AggregateByteLimit {
        limit: limits.max_aggregate_bytes,
    };
    let new_pages = if planned.merge.emitted_segment_bytes == 0 {
        pages::page_keys(incoming.offset..incoming.remaining_end)
            .filter(|key| !state.pages.contains_key(key))
            .count()
    } else {
        0
    };
    let history = if state.emitted_history.capacity() != planned.history_allocation {
        planned.history_allocation
    } else {
        0
    };
    let descriptors = planned
        .merge
        .segment_count
        .saturating_sub(state.pending.len())
        .checked_mul(super::PENDING_SEGMENT_METADATA_CHARGE)
        .ok_or_else(error)?;
    let peak = transient_base_memory_charge
        .checked_add(new_pages.checked_mul(PAGE_CHARGE).ok_or_else(error)?)
        .and_then(|value| {
            value.checked_add(if planned.merge.direct_output {
                0
            } else {
                planned.merge.emitted_segment_bytes
            })
        })
        .and_then(|value| value.checked_add(history))
        .and_then(|value| {
            value.checked_add(if planned.merge.emitted_segment_bytes == 0 {
                descriptors
            } else {
                0
            })
        })
        .ok_or_else(error)?;
    if peak > limits.max_aggregate_bytes {
        return Err(error().into());
    }
    materialize_pending_merge(state, incoming.offset, incoming.payload, &mut planned.merge)?
        .ok_or(ResourceError::FlowByteLimit {
            limit: limits.max_bytes_per_flow,
        })?;
    planned.merge.payload_start = incoming.payload_start;
    let history_replacement = prepare_emitted_history(
        state,
        planned.initial_history_capacity,
        planned.history_allocation,
    )?;
    let direct_payload = if planned.merge.direct_output {
        let end = incoming
            .payload_start
            .checked_add(incoming.payload.len())
            .ok_or(ResourceError::FlowByteLimit {
                limit: limits.max_bytes_per_flow,
            })?;
        Some(incoming.payload_start..end)
    } else {
        None
    };
    Ok(PushPlan {
        payload_sequence: incoming.sequence,
        incoming_fin_offset: incoming.fin_offset,
        retransmitted: incoming.retransmitted,
        conflicting: incoming.conflicting,
        merge: planned.merge,
        direct_payload,
        pending_bytes: planned.pending_bytes,
        initial_history_capacity: planned.initial_history_capacity,
        history_replacement,
        closed: planned.closed,
        aggregate_bytes: planned.aggregate_bytes,
        aggregate_memory_charge: planned.aggregate_memory_charge,
    })
}

struct IncomingPayload<'a> {
    sequence: u32,
    fin_offset: Option<u64>,
    payload: &'a [u8],
    payload_start: usize,
    offset: u64,
    remaining_end: u64,
    retransmitted: usize,
    conflicting: bool,
}

// validate_limits rejects max_bytes_per_flow above MAX_BYTES_PER_FLOW (2^31 - 1), so next_offset
// never reaches 2^32
// reinterpreting the wrapped 32-bit difference as i32 is the sequence-unwrapping step
fn normalize_payload<'a>(
    limits: &Limits,
    state: &TcpFlowState,
    segment: &'a Segment,
) -> Result<IncomingPayload<'a>, Error> {
    let sequence = segment.sequence.wrapping_add(u32::from(segment.syn));
    let expected = state.base_sequence.wrapping_add(state.next_offset as u32);
    let delta = i64::from(sequence.wrapping_sub(expected) as i32);
    let absolute = i128::from(state.next_offset).saturating_add(i128::from(delta));
    let fin_offset = if segment.fin {
        absolute
            .checked_add(segment.payload.len() as i128)
            .and_then(|offset| u64::try_from(offset).ok())
    } else {
        None
    };
    let before_base = if absolute < 0 {
        usize::try_from(absolute.saturating_neg().min(segment.payload.len() as i128))
            .unwrap_or(segment.payload.len())
    } else {
        0
    };
    // before_base is clamped to segment.payload.len() just above
    let mut payload = &segment.payload[before_base..];
    let mut payload_start = before_base;
    let mut retransmitted = before_base;
    let mut conflicting = false;
    let mut offset = u64::try_from(absolute.max(0)).map_err(|_| ResourceError::FlowByteLimit {
        limit: limits.max_bytes_per_flow,
    })?;
    if offset < state.next_offset {
        let consumed = usize::try_from(
            state
                .next_offset
                .saturating_sub(offset)
                .min(payload.len() as u64),
        )
        .unwrap_or(payload.len());
        let (overlap, rest) = payload.split_at(consumed.min(payload.len()));
        conflicting = emitted_history_conflicts(state, offset, overlap);
        retransmitted = retransmitted.saturating_add(consumed);
        payload_start =
            payload_start
                .checked_add(consumed)
                .ok_or(ResourceError::FlowByteLimit {
                    limit: limits.max_bytes_per_flow,
                })?;
        payload = rest;
        offset = state.next_offset;
    }
    let remaining_end = validate_sequence_bounds(limits, state, offset, payload, fin_offset)?;
    Ok(IncomingPayload {
        sequence,
        fin_offset,
        payload,
        payload_start,
        offset,
        remaining_end,
        retransmitted,
        conflicting,
    })
}

fn validate_sequence_bounds(
    limits: &Limits,
    state: &TcpFlowState,
    offset: u64,
    payload: &[u8],
    fin_offset: Option<u64>,
) -> Result<u64, Error> {
    let window_end = state
        .next_offset
        .checked_add(limits.max_bytes_per_flow as u64)
        .ok_or(ResourceError::FlowByteLimit {
            limit: limits.max_bytes_per_flow,
        })?;
    let remaining_end =
        offset
            .checked_add(payload.len() as u64)
            .ok_or(ResourceError::FlowByteLimit {
                limit: limits.max_bytes_per_flow,
            })?;
    if let Some(final_offset) = state.fin_offset {
        if fin_offset.is_some_and(|incoming| incoming != final_offset) {
            return Err(MalformedError::ConflictingFinalSequence {
                existing_offset: final_offset,
                new_offset: fin_offset.expect("checked as present"),
            }
            .into());
        }
        if remaining_end > final_offset {
            return Err(MalformedError::BeyondFinalSequence { final_offset }.into());
        }
    }
    if let Some(final_offset) = fin_offset
        && state.next_offset > final_offset
    {
        return Err(MalformedError::BeyondFinalSequence { final_offset }.into());
    }
    if offset > window_end || remaining_end > window_end {
        return Err(ResourceError::FlowByteLimit {
            limit: limits.max_bytes_per_flow,
        }
        .into());
    }
    Ok(remaining_end)
}

struct PlannedMerge {
    merge: PendingMergePlan,
    pending_bytes: usize,
    initial_history_capacity: usize,
    history_allocation: usize,
    closed: bool,
    aggregate_bytes: usize,
    aggregate_memory_charge: usize,
}

fn plan_merge_and_accounting(
    limits: &Limits,
    state: &TcpFlowState,
    state_is_accounted: bool,
    aggregate_base_bytes: usize,
    aggregate_base_memory_charge: usize,
    segment: &Segment,
    incoming: &IncomingPayload<'_>,
) -> Result<PlannedMerge, Error> {
    let accounting_error = || ResourceError::AggregateByteLimit {
        limit: limits.max_aggregate_bytes,
    };
    let old_retained_bytes = if state_is_accounted {
        retained_bytes(state).ok_or_else(accounting_error)?
    } else {
        0
    };
    let old_memory_charge = if state_is_accounted {
        flow_memory_charge(state).ok_or_else(accounting_error)?
    } else {
        0
    };
    let merge = plan_pending_merge(state, incoming.offset, incoming.payload, state.next_offset)
        .ok_or(ResourceError::FlowByteLimit {
            limit: limits.max_bytes_per_flow,
        })?;
    let pending_bytes = state
        .pending_bytes
        .checked_add(merge.added_bytes)
        .filter(|bytes| *bytes <= limits.max_bytes_per_flow)
        .ok_or(ResourceError::FlowByteLimit {
            limit: limits.max_bytes_per_flow,
        })?;
    validate_pending_final_offset(state, incoming)?;
    let final_next_offset = state
        .next_offset
        .checked_add(merge.emitted_segment_bytes as u64)
        .ok_or(ResourceError::FlowByteLimit {
            limit: limits.max_bytes_per_flow,
        })?;
    let final_fin_offset = state.fin_offset.or(incoming.fin_offset);
    let closed = segment.rst || final_fin_offset.is_some_and(|offset| final_next_offset >= offset);
    let final_page_count = if merge.emitted_segment_bytes != 0 {
        pages::remaining_count(
            &state.pages,
            &state.pending,
            merge.union_start..merge.union_end,
        )
    } else {
        state
            .pages
            .len()
            .checked_add(
                pages::page_keys(incoming.offset..incoming.remaining_end)
                    .filter(|key| !state.pages.contains_key(key))
                    .count(),
            )
            .ok_or_else(accounting_error)?
    };
    let storage_bytes = final_page_count
        .checked_mul(PAGE_CHARGE)
        .ok_or_else(accounting_error)?;
    let accounting = plan_push_accounting(PushAccountingInput {
        limits,
        state,
        pending_bytes,
        storage_bytes,
        emitted_segment_bytes: merge.emitted_segment_bytes,
        segment_count: merge.segment_count,
        old_retained_bytes,
        old_memory_charge,
        aggregate_base_bytes,
        aggregate_base_memory_charge,
        retains_flow_state: !closed,
    })?;
    let (aggregate_bytes, aggregate_memory_charge) =
        accounting.final_aggregates(closed, limits.max_aggregate_bytes)?;
    Ok(PlannedMerge {
        merge,
        pending_bytes,
        initial_history_capacity: accounting.initial_history_capacity,
        history_allocation: accounting.history_allocation,
        closed,
        aggregate_bytes,
        aggregate_memory_charge,
    })
}

fn validate_pending_final_offset(
    state: &TcpFlowState,
    incoming: &IncomingPayload<'_>,
) -> Result<(), Error> {
    if let Some(final_offset) = incoming.fin_offset
        && (state
            .pending
            .last_key_value()
            .is_some_and(|(_, end)| *end > final_offset)
            || incoming.remaining_end > final_offset)
    {
        return Err(MalformedError::BeyondFinalSequence { final_offset }.into());
    }
    Ok(())
}

#[derive(Debug)]
pub(super) struct PushPlan {
    payload_sequence: u32,
    incoming_fin_offset: Option<u64>,
    retransmitted: usize,
    conflicting: bool,
    merge: PendingMergePlan,
    direct_payload: Option<Range<usize>>,
    pending_bytes: usize,
    initial_history_capacity: usize,
    history_replacement: Option<History>,
    closed: bool,
    aggregate_bytes: usize,
    aggregate_memory_charge: usize,
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
    offset: u64,
    payload_start: usize,
    new_pages: BTreeMap<u64, Page>,
    output: Option<Bytes>,
}

fn plan_pending_merge(
    state: &TcpFlowState,
    offset: u64,
    payload: &[u8],
    next_offset: u64,
) -> Option<PendingMergePlan> {
    let existing = &state.pending;
    let payload_end = offset.checked_add(payload.len() as u64)?;
    let mut plan = PendingMergePlan {
        added_bytes: payload.len(),
        overlapping_bytes: 0,
        has_conflicting_overlap: false,
        segment_count: existing.len(),
        emitted_segment_bytes: 0,
        direct_output: false,
        first_affected: None,
        affected_segment_count: 0,
        union_start: offset,
        union_end: payload_end,
        offset,
        payload_start: 0,
        new_pages: BTreeMap::new(),
        output: None,
    };
    if payload.is_empty() {
        return Some(plan);
    }
    let mut record = |start: u64, end: u64| -> Option<()> {
        if end < offset || start > payload_end {
            return Some(());
        }
        plan.first_affected.get_or_insert(start);
        plan.affected_segment_count = plan.affected_segment_count.checked_add(1)?;
        plan.union_start = plan.union_start.min(start);
        plan.union_end = plan.union_end.max(end);
        let overlap_start = start.max(offset);
        let overlap_end = end.min(payload_end);
        if overlap_start < overlap_end {
            let length = usize::try_from(overlap_end - overlap_start).ok()?;
            let first = usize::try_from(overlap_start - offset).ok()?;
            plan.overlapping_bytes = plan.overlapping_bytes.checked_add(length)?;
            plan.has_conflicting_overlap |=
                !pages::equals(&state.pages, overlap_start, &payload[first..first + length]);
        }
        Some(())
    };
    if let Some((&start, &end)) = existing.range(..offset).next_back() {
        record(start, end)?;
    }
    for (&start, &end) in existing.range(offset..=payload_end) {
        record(start, end)?;
    }
    plan.added_bytes = payload.len().checked_sub(plan.overlapping_bytes)?;
    plan.direct_output = offset == next_offset && plan.first_affected.is_none();
    plan.segment_count = existing
        .len()
        .checked_add(1)?
        .checked_sub(plan.affected_segment_count)?;
    if offset == next_offset {
        plan.emitted_segment_bytes = usize::try_from(plan.union_end - next_offset).ok()?;
    }
    Some(plan)
}

fn materialize_pending_merge(
    state: &TcpFlowState,
    offset: u64,
    payload: &[u8],
    plan: &mut PendingMergePlan,
) -> Result<Option<()>, Error> {
    if plan.added_bytes == 0 || plan.direct_output {
        return Ok(Some(()));
    }
    if plan.emitted_segment_bytes == 0 {
        for key in pages::page_keys(offset..offset + payload.len() as u64) {
            if !state.pages.contains_key(&key) {
                plan.new_pages.insert(key, pages::allocate()?);
            }
        }
        return Ok(Some(()));
    }
    let mut output = Vec::new();
    output
        .try_reserve_exact(plan.emitted_segment_bytes)
        .map_err(|_| ResourceError::AllocationFailed {
            requested: plan.emitted_segment_bytes,
        })?;
    output.resize(plan.emitted_segment_bytes, 0);
    #[cfg(test)]
    pages::work::record(|work| {
        work.output_allocations += 1;
        work.incoming_copies += payload.len();
    });
    let first = (offset - plan.union_start) as usize;
    output[first..first + payload.len()].copy_from_slice(payload);
    if let Some(first) = plan.first_affected {
        for (&start, &end) in state
            .pending
            .range(first..)
            .take(plan.affected_segment_count)
        {
            let relative = (start - plan.union_start) as usize;
            pages::copy_out(
                &state.pages,
                start,
                &mut output[relative..relative + (end - start) as usize],
            );
        }
    }
    plan.output = Some(Bytes::from(output));
    Ok(Some(()))
}
