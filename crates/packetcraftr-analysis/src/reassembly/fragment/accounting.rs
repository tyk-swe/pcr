// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Checked immutable accounting plans for retained fragment state.

use super::{Error, Limits};

pub(super) const DATAGRAM_STATE_METADATA_CHARGE: usize = 128;
pub(super) const FRAGMENT_SEGMENT_METADATA_CHARGE: usize = 64;

#[derive(Clone, Copy, Debug)]
pub(super) struct FragmentAccountingPlan {
    pub(super) stored_bytes: usize,
    pub(super) aggregate_bytes: usize,
    pub(super) new_memory_charge: usize,
    pub(super) aggregate_memory_charge: usize,
    pub(super) fragment_count: usize,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct FragmentAccountingInput {
    pub(super) previous_stored_bytes: usize,
    pub(super) previous_fragment_count: usize,
    pub(super) added_bytes: usize,
    pub(super) segment_count: usize,
    pub(super) aggregate_bytes: usize,
    pub(super) old_memory_charge: usize,
    pub(super) aggregate_memory_charge: usize,
}

pub(super) fn plan_accounting(
    limits: &Limits,
    input: FragmentAccountingInput,
) -> Result<FragmentAccountingPlan, Error> {
    let FragmentAccountingInput {
        previous_stored_bytes,
        previous_fragment_count,
        added_bytes,
        segment_count,
        aggregate_bytes,
        old_memory_charge,
        aggregate_memory_charge,
    } = input;
    let stored_bytes =
        previous_stored_bytes
            .checked_add(added_bytes)
            .ok_or(Error::AggregateByteLimit {
                limit: limits.max_aggregate_bytes,
            })?;
    let aggregate_bytes =
        aggregate_bytes
            .checked_add(added_bytes)
            .ok_or(Error::AggregateByteLimit {
                limit: limits.max_aggregate_bytes,
            })?;
    if aggregate_bytes > limits.max_aggregate_bytes {
        return Err(Error::AggregateByteLimit {
            limit: limits.max_aggregate_bytes,
        });
    }
    let new_memory_charge = datagram_memory_charge_parts(stored_bytes, segment_count).ok_or(
        Error::AggregateByteLimit {
            limit: limits.max_aggregate_bytes,
        },
    )?;
    let aggregate_memory_charge = aggregate_memory_charge
        .checked_sub(old_memory_charge)
        .and_then(|charge| charge.checked_add(new_memory_charge))
        .ok_or(Error::AggregateByteLimit {
            limit: limits.max_aggregate_bytes,
        })?;
    if aggregate_memory_charge > limits.max_aggregate_bytes {
        return Err(Error::AggregateByteLimit {
            limit: limits.max_aggregate_bytes,
        });
    }
    Ok(FragmentAccountingPlan {
        stored_bytes,
        aggregate_bytes,
        new_memory_charge,
        aggregate_memory_charge,
        fragment_count: previous_fragment_count + 1,
    })
}

pub(super) fn datagram_memory_charge_parts(
    stored_bytes: usize,
    segment_count: usize,
) -> Option<usize> {
    segment_count
        .checked_mul(FRAGMENT_SEGMENT_METADATA_CHARGE)
        .and_then(|metadata| metadata.checked_add(DATAGRAM_STATE_METADATA_CHARGE))
        .and_then(|metadata| metadata.checked_add(stored_bytes))
}
