// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Immutable fragment merge and resource-accounting planning.

use std::collections::BTreeMap;
use std::ops::Bound::{Excluded, Included};

use bytes::Bytes;

use super::{Error, Fragment, OverlapPolicy, Reassembler, datagram_memory_charge};

// Conservative accounting for a datagram's flow-table and expiry-index entries
// plus otherwise-empty state.
pub(super) const DATAGRAM_STATE_METADATA_CHARGE: usize = 256;
pub(super) const FRAGMENT_SEGMENT_METADATA_CHARGE: usize = 64;

#[derive(Clone, Copy, Debug)]
pub(super) enum FragmentPlan {
    Complete,
    Retain(FragmentRetentionPlan),
}

#[derive(Clone, Copy, Debug)]
pub(super) struct FragmentRetentionPlan {
    pub(super) has_existing_flow: bool,
    pub(super) final_length: Option<u32>,
    pub(super) merge: FragmentMergePlan,
    pub(super) accounting: FragmentAccountingPlan,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct FragmentAccountingPlan {
    pub(super) stored_bytes: usize,
    pub(super) aggregate_bytes: usize,
    pub(super) new_memory_charge: usize,
    pub(super) aggregate_memory_charge: usize,
    pub(super) fragment_count: usize,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct FragmentMergePlan {
    pub(super) added_bytes: usize,
    pub(super) has_conflicting_overlap: bool,
    pub(super) segment_count: usize,
    pub(super) first_affected: Option<u32>,
    pub(super) affected_segment_count: usize,
    pub(super) union_start: u32,
    pub(super) union_end: u32,
}

impl FragmentMergePlan {
    pub(super) fn disjoint(
        added_bytes: usize,
        offset: u32,
        end: u32,
        segment_count: usize,
    ) -> Self {
        Self {
            added_bytes,
            has_conflicting_overlap: false,
            segment_count,
            first_affected: None,
            affected_segment_count: 0,
            union_start: offset,
            union_end: end,
        }
    }
}

impl Reassembler {
    pub(super) fn plan_fragment(&self, fragment: &Fragment) -> Result<FragmentPlan, Error> {
        if fragment.bytes.is_empty() {
            return Err(Error::EmptyFragment);
        }
        if fragment.more_fragments && !fragment.bytes.len().is_multiple_of(8) {
            return Err(Error::UnalignedNonFinalFragment {
                length: fragment.bytes.len(),
            });
        }
        if !fragment.offset.is_multiple_of(8) {
            return Err(Error::UnalignedFragmentOffset {
                offset: fragment.offset,
            });
        }

        let end = fragment
            .offset
            .checked_add(u32::try_from(fragment.bytes.len()).map_err(|_| Error::OffsetOverflow)?)
            .ok_or(Error::OffsetOverflow)?;
        if usize::try_from(end).map_or(true, |end| end > self.limits.max_bytes_per_flow) {
            return Err(Error::FlowByteLimit {
                limit: self.limits.max_bytes_per_flow,
            });
        }

        let existing_state = self.flows.get(&fragment.key);
        if existing_state.is_none() && !fragment.more_fragments && fragment.offset == 0 {
            if self.limits.max_fragments_per_datagram == 0 {
                return Err(Error::FragmentLimit { limit: 0 });
            }
            return Ok(FragmentPlan::Complete);
        }
        if existing_state.is_none() && self.flows.len() >= self.limits.max_flows {
            return Err(Error::FlowLimit {
                limit: self.limits.max_flows,
            });
        }

        let old_memory_charge = existing_state.and_then(datagram_memory_charge).unwrap_or(0);
        let previous_stored_bytes = existing_state.map_or(0, |state| state.stored_bytes);
        let previous_fragment_count = existing_state.map_or(0, |state| state.fragment_count);
        let existing_final_length = existing_state.and_then(|state| state.final_length);

        if previous_fragment_count >= self.limits.max_fragments_per_datagram {
            return Err(Error::FragmentLimit {
                limit: self.limits.max_fragments_per_datagram,
            });
        }
        if let Some(final_length) = existing_final_length
            && end > final_length
        {
            return Err(Error::BeyondFinalLength { final_length });
        }
        if !fragment.more_fragments {
            match existing_final_length {
                Some(existing_length) if existing_length != end => {
                    return Err(Error::ConflictingFinalLength {
                        existing_length,
                        new_length: end,
                    });
                }
                _ => {
                    let prior_fragment_extends_past_end = existing_state.is_some_and(|state| {
                        state
                            .segments
                            .last_key_value()
                            .is_some_and(|(offset, bytes)| {
                                u64::from(*offset) + bytes.len() as u64 > u64::from(end)
                            })
                    });
                    if prior_fragment_extends_past_end {
                        return Err(Error::BeyondFinalLength { final_length: end });
                    }
                }
            }
        }

        let merge = match existing_state {
            Some(state) => plan_fragment_merge(
                &state.segments,
                fragment.offset,
                &fragment.bytes,
                self.overlap_policy,
            )?,
            None => FragmentMergePlan::disjoint(fragment.bytes.len(), fragment.offset, end, 1),
        };
        let accounting = self.plan_fragment_accounting(
            previous_stored_bytes,
            previous_fragment_count,
            old_memory_charge,
            &merge,
        )?;
        Ok(FragmentPlan::Retain(FragmentRetentionPlan {
            has_existing_flow: existing_state.is_some(),
            final_length: (!fragment.more_fragments)
                .then_some(end)
                .or(existing_final_length),
            merge,
            accounting,
        }))
    }

    fn plan_fragment_accounting(
        &self,
        previous_stored_bytes: usize,
        previous_fragment_count: usize,
        old_memory_charge: usize,
        merge: &FragmentMergePlan,
    ) -> Result<FragmentAccountingPlan, Error> {
        let stored_bytes = previous_stored_bytes.checked_add(merge.added_bytes).ok_or(
            Error::AggregateByteLimit {
                limit: self.limits.max_aggregate_bytes,
            },
        )?;
        let aggregate_bytes = self.aggregate_bytes.checked_add(merge.added_bytes).ok_or(
            Error::AggregateByteLimit {
                limit: self.limits.max_aggregate_bytes,
            },
        )?;
        if aggregate_bytes > self.limits.max_aggregate_bytes {
            return Err(Error::AggregateByteLimit {
                limit: self.limits.max_aggregate_bytes,
            });
        }
        let new_memory_charge = datagram_memory_charge_parts(stored_bytes, merge.segment_count)
            .ok_or(Error::AggregateByteLimit {
                limit: self.limits.max_aggregate_bytes,
            })?;
        let aggregate_memory_charge = self
            .aggregate_memory_charge
            .checked_sub(old_memory_charge)
            .and_then(|charge| charge.checked_add(new_memory_charge))
            .ok_or(Error::AggregateByteLimit {
                limit: self.limits.max_aggregate_bytes,
            })?;
        if aggregate_memory_charge > self.limits.max_aggregate_bytes {
            return Err(Error::AggregateByteLimit {
                limit: self.limits.max_aggregate_bytes,
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

pub(super) fn plan_fragment_merge(
    existing: &BTreeMap<u32, Bytes>,
    offset: u32,
    fragment: &[u8],
    policy: OverlapPolicy,
) -> Result<FragmentMergePlan, Error> {
    debug_assert!(!fragment.is_empty());
    let new_end = offset
        .checked_add(u32::try_from(fragment.len()).map_err(|_| Error::OffsetOverflow)?)
        .ok_or(Error::OffsetOverflow)?;
    let segment_count = existing.len().checked_add(1).ok_or(Error::OffsetOverflow)?;
    let mut plan = FragmentMergePlan::disjoint(fragment.len(), offset, new_end, segment_count);
    let mut overlapping_bytes = 0usize;
    {
        let mut consider = |start: u32, existing_bytes: &[u8]| -> Result<(), Error> {
            let end = start
                .checked_add(
                    u32::try_from(existing_bytes.len()).map_err(|_| Error::OffsetOverflow)?,
                )
                .ok_or(Error::OffsetOverflow)?;
            if end < offset || start > new_end {
                return Ok(());
            }

            if plan.first_affected.is_none() {
                plan.first_affected = Some(start);
            }
            plan.affected_segment_count = plan
                .affected_segment_count
                .checked_add(1)
                .ok_or(Error::OffsetOverflow)?;
            plan.union_start = plan.union_start.min(start);
            plan.union_end = plan.union_end.max(end);

            let overlap_start = start.max(offset);
            let overlap_end = end.min(new_end);
            if overlap_start < overlap_end {
                let length = (overlap_end - overlap_start) as usize;
                let existing_start = (overlap_start - start) as usize;
                let fragment_start = (overlap_start - offset) as usize;
                overlapping_bytes = overlapping_bytes
                    .checked_add(length)
                    .ok_or(Error::OffsetOverflow)?;
                let existing_overlap = &existing_bytes[existing_start..existing_start + length];
                let fragment_overlap = &fragment[fragment_start..fragment_start + length];
                if existing_overlap != fragment_overlap {
                    plan.has_conflicting_overlap = true;
                    if policy == OverlapPolicy::RejectConflicting {
                        #[expect(
                            clippy::cast_possible_truncation,
                            reason = "mismatch indexes within length, itself the difference of \
                                      the u32 offsets overlap_end and overlap_start, so the \
                                      conversion back to a wire offset is lossless"
                        )]
                        let mismatch = existing_overlap
                            .iter()
                            .zip(fragment_overlap)
                            .position(|(left, right)| left != right)
                            .unwrap_or(0) as u32;
                        return Err(Error::ConflictingOverlap {
                            offset: overlap_start + mismatch,
                        });
                    }
                }
            }
            Ok(())
        };

        if let Some((start, existing_bytes)) = existing.range(..=offset).next_back() {
            consider(*start, existing_bytes)?;
        }
        for (start, existing_bytes) in existing.range((Excluded(offset), Included(new_end))) {
            consider(*start, existing_bytes)?;
        }
    }
    plan.added_bytes = plan
        .added_bytes
        .checked_sub(overlapping_bytes)
        .ok_or(Error::OffsetOverflow)?;
    plan.segment_count = plan
        .segment_count
        .checked_sub(plan.affected_segment_count)
        .ok_or(Error::OffsetOverflow)?;
    Ok(plan)
}
