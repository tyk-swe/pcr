// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Immutable fragment merge planning.

use std::collections::BTreeMap;
use std::ops::Bound::{Excluded, Included};

use bytes::Bytes;

use super::{Error, OverlapPolicy};

#[derive(Clone, Copy, Debug)]
pub(super) struct FragmentMergePlan {
    pub(super) added_bytes: usize,
    pub(super) has_conflicting_overlap: bool,
    pub(super) overlap_start: Option<u32>,
    pub(super) overlap_end: u32,
    pub(super) overlap_length: usize,
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
            overlap_start: None,
            overlap_end: offset,
            overlap_length: 0,
            segment_count,
            first_affected: None,
            affected_segment_count: 0,
            union_start: offset,
            union_end: end,
        }
    }
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
                plan.overlap_start = Some(
                    plan.overlap_start
                        .map_or(overlap_start, |start| start.min(overlap_start)),
                );
                plan.overlap_end = plan.overlap_end.max(overlap_end);
                plan.overlap_length = plan
                    .overlap_length
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
        .checked_sub(plan.overlap_length)
        .ok_or(Error::OffsetOverflow)?;
    plan.segment_count = plan
        .segment_count
        .checked_sub(plan.affected_segment_count)
        .ok_or(Error::OffsetOverflow)?;
    Ok(plan)
}
