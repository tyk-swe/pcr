// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Instant;

use bytes::Bytes;

use super::{PendingMergePlan, PushPlan};
use crate::analysis::reassembly::tcp::pages;
use crate::analysis::reassembly::tcp::state::{
    TcpFlowState, append_emitted_history, trim_emitted_history,
};
use crate::analysis::reassembly::tcp::{Event, Reassembler, ScopedFlowKey, Segment};

pub(in crate::analysis::reassembly::tcp) fn commit_push(
    reassembler: &mut Reassembler,
    segment: Segment,
    now: Instant,
    changes_generation: bool,
    plan: PushPlan,
) -> Vec<Event> {
    let first_payload_sequence = segment.sequence.wrapping_add(u32::from(segment.syn));
    let closed = plan.closed;
    let aggregate_bytes = plan.aggregate_bytes;
    let aggregate_memory_charge = plan.aggregate_memory_charge;
    let max_bytes_per_flow = reassembler.limits.max_bytes_per_flow;
    let previous_deadline = reassembler
        .flows
        .get(&segment.flow)
        .and_then(|state| state.deadline);
    let last_update = reassembler
        .flows
        .get(&segment.flow)
        .map_or(now, |state| state.last_update.max(now));
    let deadline = last_update.checked_add(reassembler.limits.idle_expiry);
    let Segment {
        flow, rst, payload, ..
    } = segment;
    let direct_payload = plan
        .direct_payload
        .as_ref()
        .and_then(|range| crate::byte_slice::checked_slice(&payload, range.start, range.end));
    let (replacement, mut events) = if changes_generation {
        let mut state = TcpFlowState::new(first_payload_sequence, last_update, deadline);
        let events = commit_flow_push(
            &mut state,
            &flow,
            now,
            max_bytes_per_flow,
            plan,
            direct_payload,
            &payload,
        );
        (Some(state), events)
    } else {
        let state = reassembler
            .flows
            .get_mut(&flow)
            .expect("an unchanged generation has an established flow");
        let events = commit_flow_push(
            state,
            &flow,
            now,
            max_bytes_per_flow,
            plan,
            direct_payload,
            &payload,
        );
        state.deadline = deadline;
        (None, events)
    };

    reassembler.aggregate_bytes = aggregate_bytes;
    reassembler.aggregate_memory_charge = aggregate_memory_charge;
    reassembler.expiry.remove(previous_deadline, &flow);
    if closed {
        reassembler.flows.remove(&flow);
        events.push(Event::Closed { flow, reset: rst });
    } else {
        if let Some(state) = replacement {
            reassembler.flows.insert(flow.clone(), state);
        }
        reassembler.expiry.insert(deadline, flow);
    }
    events
}

fn commit_flow_push(
    state: &mut TcpFlowState,
    flow: &ScopedFlowKey,
    now: Instant,
    max_bytes_per_flow: usize,
    plan: PushPlan,
    direct_payload: Option<Bytes>,
    incoming_payload: &[u8],
) -> Vec<Event> {
    let PushPlan {
        payload_sequence,
        incoming_fin_offset,
        mut retransmitted,
        mut conflicting,
        merge,
        pending_bytes,
        initial_history_capacity,
        history_replacement,
        ..
    } = plan;
    retransmitted = retransmitted.saturating_add(merge.overlapping_bytes);
    conflicting |= merge.has_conflicting_overlap;

    state.last_update = state.last_update.max(now);
    trim_emitted_history(state, initial_history_capacity);
    if let Some(history) = history_replacement {
        state.emitted_history = history;
    }
    let output = apply_pending_merge(state, merge, incoming_payload);
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

    if let Some(bytes) = output {
        state.pending_bytes = state
            .pending_bytes
            .checked_sub(bytes.len())
            .expect("planned delivery charge");
        emit_data(state, flow, bytes, max_bytes_per_flow, &mut events);
    }
    events
}

// validate_limits rejects max_bytes_per_flow above MAX_BYTES_PER_FLOW (2^31 - 1), so next_offset
// never reaches 2^32 and the narrowing to a wire sequence is lossless
fn emit_data(
    state: &mut TcpFlowState,
    flow: &ScopedFlowKey,
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

fn apply_pending_merge(
    state: &mut TcpFlowState,
    merge: PendingMergePlan,
    payload: &[u8],
) -> Option<Bytes> {
    let PendingMergePlan {
        added_bytes,
        first_affected,
        affected_segment_count,
        segment_count,
        direct_output,
        emitted_segment_bytes,
        union_start,
        union_end,
        offset,
        payload_start,
        new_pages,
        output,
        ..
    } = merge;
    if added_bytes == 0 || direct_output {
        return output;
    }
    if emitted_segment_bytes == 0 {
        for (key, page) in new_pages {
            assert!(
                state.pages.insert(key, page).is_none(),
                "prepared page is new"
            );
        }
        let payload = &payload[payload_start..];
        let payload_end = offset + payload.len() as u64;
        let mut cursor = offset;
        if let Some(first) = first_affected {
            for (&start, &end) in state.pending.range(first..).take(affected_segment_count) {
                let stop = start.min(payload_end);
                if cursor < stop {
                    pages::insert(
                        &mut state.pages,
                        cursor,
                        &payload[(cursor - offset) as usize..(stop - offset) as usize],
                    );
                }
                cursor = cursor.max(end).min(payload_end);
            }
        }
        if cursor < payload_end {
            pages::insert(
                &mut state.pages,
                cursor,
                &payload[(cursor - offset) as usize..],
            );
        }
    }
    if let Some(first) = first_affected {
        for _ in 0..affected_segment_count {
            let start = *state
                .pending
                .range(first..)
                .next()
                .expect("planned interval exists")
                .0;
            let end = state
                .pending
                .remove(&start)
                .expect("planned interval exists");
            if emitted_segment_bytes != 0 {
                pages::remove(&mut state.pages, start..end);
            }
        }
    }
    if emitted_segment_bytes == 0 {
        assert!(state.pending.insert(union_start, union_end).is_none());
    }
    debug_assert_eq!(
        state.pending.len(),
        segment_count - usize::from(emitted_segment_bytes != 0)
    );
    output
}
