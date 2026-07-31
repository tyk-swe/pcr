// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Checked immutable accounting plans for a TCP push.

use super::super::{
    Error, ReassemblyLimits,
    state::{TcpFlowState, pending_memory_charge, planned_history_allocation},
};

#[derive(Clone, Copy, Debug)]
pub(super) struct PushAccountingPlan {
    pub(super) initial_history_capacity: usize,
    pub(super) history_allocation: usize,
    prospective_aggregate_bytes: usize,
    prospective_aggregate_memory: usize,
    aggregate_base_bytes: usize,
    aggregate_base_memory_charge: usize,
    old_retained_bytes: usize,
    old_memory_charge: usize,
}

pub(super) struct PushAccountingInput<'a> {
    pub(super) limits: &'a ReassemblyLimits,
    pub(super) state: &'a TcpFlowState,
    pub(super) pending_bytes: usize,
    pub(super) emitted_segment_bytes: usize,
    pub(super) segment_count: usize,
    pub(super) old_retained_bytes: usize,
    pub(super) old_memory_charge: usize,
    pub(super) aggregate_base_bytes: usize,
    pub(super) aggregate_base_memory_charge: usize,
}

pub(super) fn plan_push_accounting(
    input: PushAccountingInput<'_>,
) -> Result<PushAccountingPlan, Error> {
    let PushAccountingInput {
        limits,
        state,
        pending_bytes,
        emitted_segment_bytes,
        segment_count,
        old_retained_bytes,
        old_memory_charge,
        aggregate_base_bytes,
        aggregate_base_memory_charge,
    } = input;
    let initial_history_capacity = limits.max_bytes_per_flow.saturating_sub(pending_bytes);
    let final_pending_bytes = pending_bytes.saturating_sub(emitted_segment_bytes);
    let final_pending_segments =
        segment_count.saturating_sub(usize::from(emitted_segment_bytes != 0));
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
        .saturating_add(emitted_segment_bytes)
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
    Ok(PushAccountingPlan {
        initial_history_capacity,
        history_allocation,
        prospective_aggregate_bytes,
        prospective_aggregate_memory,
        aggregate_base_bytes,
        aggregate_base_memory_charge,
        old_retained_bytes,
        old_memory_charge,
    })
}

impl PushAccountingPlan {
    pub(super) fn account_actual_history_allocation(
        mut self,
        actual: usize,
        limit: usize,
    ) -> Result<Self, Error> {
        self.prospective_aggregate_memory = replace_history_allocation(
            self.prospective_aggregate_memory,
            self.history_allocation,
            actual,
            limit,
        )?;
        Ok(self)
    }

    pub(super) fn final_aggregates(
        self,
        closed: bool,
        limit: usize,
    ) -> Result<(usize, usize), Error> {
        if !closed {
            return Ok((
                self.prospective_aggregate_bytes,
                self.prospective_aggregate_memory,
            ));
        }
        Ok((
            self.aggregate_base_bytes
                .checked_sub(self.old_retained_bytes)
                .ok_or(Error::AggregateByteLimit { limit })?,
            self.aggregate_base_memory_charge
                .checked_sub(self.old_memory_charge)
                .ok_or(Error::AggregateByteLimit { limit })?,
        ))
    }
}

fn replace_history_allocation(
    prospective_memory: usize,
    planned: usize,
    actual: usize,
    limit: usize,
) -> Result<usize, Error> {
    let adjusted = prospective_memory
        .checked_sub(planned)
        .and_then(|memory| memory.checked_add(actual))
        .ok_or(Error::AggregateByteLimit { limit })?;
    if adjusted > limit {
        return Err(Error::AggregateByteLimit { limit });
    }
    Ok(adjusted)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn actual_history_capacity_replaces_the_planned_memory_charge() {
        assert_eq!(replace_history_allocation(10, 4, 8, 14), Ok(14));
        assert_eq!(
            replace_history_allocation(10, 4, 8, 13),
            Err(Error::AggregateByteLimit { limit: 13 })
        );
    }
}
