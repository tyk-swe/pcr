// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Instant;

use bytes::Bytes;

use super::{PendingMergePlan, PushPlan};
use crate::session::tcp::state::{
    TcpFlowState, append_emitted_history, resize_emitted_history, trim_emitted_history,
};
use crate::session::tcp::{Event, FlowKey, Reassembler, Segment};

pub(in crate::session::tcp) fn commit_push(
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
    let last_update = reassembler
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
        let state = reassembler
            .flows
            .get_mut(&flow)
            .expect("an unchanged generation has an established flow");
        (
            None,
            commit_flow_push(state, &flow, now, max_bytes_per_flow, plan, direct_payload),
        )
    };

    reassembler.aggregate_bytes = aggregate_bytes;
    reassembler.aggregate_memory_charge = aggregate_memory_charge;
    if closed {
        reassembler.flows.remove(&flow);
        events.push(Event::Closed { flow, reset: rst });
    } else if let Some(state) = replacement {
        reassembler.flows.insert(flow, state);
    }
    events
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
