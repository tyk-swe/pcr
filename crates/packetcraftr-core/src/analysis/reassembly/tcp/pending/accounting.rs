// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::analysis::reassembly::tcp::{
    Error, Limits, Resource,
    state::{TcpFlowState, memory_charge_parts, planned_history_allocation},
};

#[derive(Clone, Copy, Debug)]
pub(super) struct PushAccountingPlan {
    pub(super) initial_history_capacity: usize,
    pub(super) history_allocation: usize,
    pub(super) aggregate_bytes: usize,
    pub(super) aggregate_memory_charge: usize,
}

pub(super) struct PushAccountingInput<'a> {
    pub(super) limits: &'a Limits,
    pub(super) state: &'a TcpFlowState,
    pub(super) pending_bytes: usize,
    pub(super) storage_bytes: usize,
    pub(super) emitted_segment_bytes: usize,
    pub(super) segment_count: usize,
    pub(super) aggregate_base_bytes: usize,
    pub(super) aggregate_base_memory_charge: usize,
    pub(super) retains_flow_state: bool,
}

pub(super) fn plan_push_accounting(
    input: PushAccountingInput<'_>,
) -> Result<PushAccountingPlan, Error> {
    let PushAccountingInput {
        limits,
        state,
        pending_bytes,
        storage_bytes,
        emitted_segment_bytes,
        segment_count,
        aggregate_base_bytes,
        aggregate_base_memory_charge,
        retains_flow_state,
    } = input;
    let initial_history_capacity = limits.max_bytes_per_flow.saturating_sub(pending_bytes);
    let final_pending_bytes = pending_bytes.saturating_sub(emitted_segment_bytes);
    let final_pending_segments =
        segment_count.saturating_sub(usize::from(emitted_segment_bytes != 0));
    if final_pending_segments > limits.max_segments_per_flow {
        return Err(Resource::SegmentLimit {
            limit: limits.max_segments_per_flow,
        }
        .into());
    }
    let final_history_capacity = limits
        .max_bytes_per_flow
        .saturating_sub(final_pending_bytes);
    let prospective_history = state
        .emitted_history
        .len()
        .min(initial_history_capacity)
        .saturating_add(emitted_segment_bytes)
        .min(final_history_capacity);
    let history_allocation = planned_history_allocation(
        state.emitted_history.capacity(),
        prospective_history,
        final_history_capacity,
    );
    let prospective_retained = final_pending_bytes
        .checked_add(prospective_history)
        .ok_or(limits.aggregate_byte_error())?;
    // A closed generation never enters the flow table, but its buffers remain budgeted.
    let prospective_memory = memory_charge_parts(
        storage_bytes,
        final_pending_segments,
        history_allocation,
        retains_flow_state,
    )
    .ok_or(limits.aggregate_byte_error())?;
    let prospective_aggregate_bytes = aggregate_base_bytes
        .checked_add(prospective_retained)
        .ok_or(limits.aggregate_byte_error())?;
    let prospective_aggregate_memory = aggregate_base_memory_charge
        .checked_add(prospective_memory)
        .ok_or(limits.aggregate_byte_error())?;
    if prospective_aggregate_bytes > limits.max_aggregate_bytes
        || prospective_aggregate_memory > limits.max_aggregate_bytes
    {
        return Err(limits.aggregate_byte_error().into());
    }
    let (aggregate_bytes, aggregate_memory_charge) = if retains_flow_state {
        (prospective_aggregate_bytes, prospective_aggregate_memory)
    } else {
        (aggregate_base_bytes, aggregate_base_memory_charge)
    };
    Ok(PushAccountingPlan {
        initial_history_capacity,
        history_allocation,
        aggregate_bytes,
        aggregate_memory_charge,
    })
}
