// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;
use std::ops::Range;

use bytes::Bytes;

use super::state::{
    TcpFlowState, emitted_history_conflicts, flow_memory_charge, pending_memory_charge,
    planned_history_allocation, retained_bytes,
};
use super::{Error, ReassemblyLimits, Segment};

mod commit;

pub(super) use commit::commit_push;

pub(super) fn plan_push(
    limits: &ReassemblyLimits,
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
                    limit: limits.max_bytes_per_flow,
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
        limit: limits.max_bytes_per_flow,
    })?;
    if offset < state.next_offset {
        let consumed = usize::try_from((state.next_offset - offset).min(payload.len() as u64))
            .unwrap_or(payload.len());
        conflicting |= emitted_history_conflicts(state, offset, &payload[..consumed]);
        retransmitted += consumed;
        payload_start = payload_start
            .checked_add(consumed)
            .ok_or(Error::FlowByteLimit {
                limit: limits.max_bytes_per_flow,
            })?;
        payload = &payload[consumed..];
        offset = state.next_offset;
    }

    let window_end = state
        .next_offset
        .checked_add(limits.max_bytes_per_flow as u64)
        .ok_or(Error::FlowByteLimit {
            limit: limits.max_bytes_per_flow,
        })?;
    let remaining_end = offset
        .checked_add(payload.len() as u64)
        .ok_or(Error::FlowByteLimit {
            limit: limits.max_bytes_per_flow,
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
            limit: limits.max_bytes_per_flow,
        });
    }

    let old_retained_bytes = retained_bytes(state).ok_or(Error::AggregateByteLimit {
        limit: limits.max_aggregate_bytes,
    })?;
    let old_memory_charge = flow_memory_charge(state).ok_or(Error::AggregateByteLimit {
        limit: limits.max_aggregate_bytes,
    })?;
    let mut merge = plan_pending_merge(&state.pending, offset, payload, state.next_offset).ok_or(
        Error::FlowByteLimit {
            limit: limits.max_bytes_per_flow,
        },
    )?;
    let pending_bytes =
        state
            .pending_bytes
            .checked_add(merge.added_bytes)
            .ok_or(Error::FlowByteLimit {
                limit: limits.max_bytes_per_flow,
            })?;
    if pending_bytes > limits.max_bytes_per_flow {
        return Err(Error::FlowByteLimit {
            limit: limits.max_bytes_per_flow,
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
    let initial_history_capacity = limits.max_bytes_per_flow.saturating_sub(pending_bytes);
    let final_pending_bytes = pending_bytes.saturating_sub(merge.emitted_segment_bytes);
    let final_pending_segments = merge
        .segment_count
        .saturating_sub(usize::from(merge.emitted_segment_bytes != 0));
    if final_pending_segments > limits.max_tcp_segments_per_flow {
        return Err(Error::SegmentLimit {
            limit: limits.max_tcp_segments_per_flow,
        });
    }
    let final_history_capacity = limits
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
    let prospective_retained =
        final_pending_bytes
            .checked_add(prospective_history)
            .ok_or(Error::AggregateByteLimit {
                limit: limits.max_aggregate_bytes,
            })?;
    let prospective_memory = pending_memory_charge(final_pending_bytes, final_pending_segments)
        .and_then(|charge| charge.checked_add(history_allocation))
        .ok_or(Error::AggregateByteLimit {
            limit: limits.max_aggregate_bytes,
        })?;
    let prospective_aggregate_bytes = aggregate_base_bytes
        .checked_sub(old_retained_bytes)
        .and_then(|bytes| bytes.checked_add(prospective_retained))
        .ok_or(Error::AggregateByteLimit {
            limit: limits.max_aggregate_bytes,
        })?;
    let prospective_aggregate_memory = aggregate_base_memory_charge
        .checked_sub(old_memory_charge)
        .and_then(|charge| charge.checked_add(prospective_memory))
        .ok_or(Error::AggregateByteLimit {
            limit: limits.max_aggregate_bytes,
        })?;
    if prospective_aggregate_bytes > limits.max_aggregate_bytes
        || prospective_aggregate_memory > limits.max_aggregate_bytes
    {
        return Err(Error::AggregateByteLimit {
            limit: limits.max_aggregate_bytes,
        });
    }

    materialize_pending_merge(&state.pending, offset, payload, &mut merge).ok_or(
        Error::FlowByteLimit {
            limit: limits.max_bytes_per_flow,
        },
    )?;
    let direct_payload = if merge.direct_output {
        let end = payload_start
            .checked_add(payload.len())
            .ok_or(Error::FlowByteLimit {
                limit: limits.max_bytes_per_flow,
            })?;
        Some(payload_start..end)
    } else {
        None
    };

    let final_next_offset = state
        .next_offset
        .checked_add(merge.emitted_segment_bytes as u64)
        .ok_or(Error::FlowByteLimit {
            limit: limits.max_bytes_per_flow,
        })?;
    let final_fin_offset = state.fin_offset.or(incoming_fin_offset);
    let closed =
        segment.rst || final_fin_offset.is_some_and(|fin_offset| final_next_offset >= fin_offset);
    let (aggregate_bytes, aggregate_memory_charge) = if closed {
        (
            aggregate_base_bytes.checked_sub(old_retained_bytes).ok_or(
                Error::AggregateByteLimit {
                    limit: limits.max_aggregate_bytes,
                },
            )?,
            aggregate_base_memory_charge
                .checked_sub(old_memory_charge)
                .ok_or(Error::AggregateByteLimit {
                    limit: limits.max_aggregate_bytes,
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
