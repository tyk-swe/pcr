// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Transactional fragment merging: plan overlap/accounting, build a
//! replacement, then commit. Planning and allocation failures leave retained
//! bytes unchanged.

use super::super::RANGE_METADATA_CHARGE;
use super::{Error, Incoming, Malformed, OverlapPolicy, Resource, RetainedRange};

pub(super) struct MergePlan {
    pub(super) first_affected: usize,
    pub(super) affected_count: usize,
    pub(super) union_start: usize,
    pub(super) union_end: usize,
    pub(super) added_bytes: usize,
    pub(super) conflicting_bytes: usize,
    pub(super) result_range_count: usize,
    pub(super) kind: UpdateKind,
}

/// How the retained ranges absorb one admitted fragment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum UpdateKind {
    /// Every incoming byte is already retained; nothing is stored.
    Unchanged,
    /// The fragment starts exactly where one retained range ends and touches
    /// no other range, so its bytes extend that range in place.
    Append,
    /// The affected ranges and the fragment are rebuilt into one new range.
    Replace,
}

/// The prepared range update: `Replace` carries the merged range, allocated
/// before any retained state changes.
pub(super) enum RangeUpdate {
    Unchanged,
    Append,
    Replace(RetainedRange),
}

pub(super) fn plan_merge(
    ranges: &[RetainedRange],
    incoming: &Incoming,
) -> Result<MergePlan, Error> {
    let mut first_affected = ranges.len();
    let mut affected_count = 0usize;
    let mut union_start = incoming.offset;
    let mut union_end = incoming.end;
    let mut overlapping_bytes = 0usize;
    let mut conflicting_bytes = 0usize;
    for (index, retained) in ranges.iter().enumerate() {
        let end = retained.end().ok_or(Malformed::OffsetOverflow)?;
        if end < incoming.offset {
            first_affected = index.checked_add(1).ok_or(Malformed::OffsetOverflow)?;
            continue;
        }
        if retained.start > incoming.end {
            if affected_count == 0 {
                first_affected = index;
            }
            break;
        }
        if affected_count == 0 {
            first_affected = index;
        }
        affected_count = affected_count
            .checked_add(1)
            .ok_or(Malformed::OffsetOverflow)?;
        union_start = union_start.min(retained.start);
        union_end = union_end.max(end);
        let overlap_start = retained.start.max(incoming.offset);
        let overlap_end = end.min(incoming.end);
        if overlap_start < overlap_end {
            let (overlapping, conflicting) = measure_overlap(retained, end, incoming)?;
            overlapping_bytes = overlapping_bytes
                .checked_add(overlapping)
                .ok_or(Malformed::OffsetOverflow)?;
            conflicting_bytes = conflicting_bytes
                .checked_add(conflicting)
                .ok_or(Malformed::OffsetOverflow)?;
        }
    }
    let added_bytes = incoming
        .payload
        .len()
        .checked_sub(overlapping_bytes)
        .ok_or(Malformed::OffsetOverflow)?;
    let result_range_count = ranges
        .len()
        .checked_add(1)
        .and_then(|count| count.checked_sub(affected_count))
        .ok_or(Malformed::OffsetOverflow)?;
    let kind = if added_bytes == 0 && conflicting_bytes == 0 {
        UpdateKind::Unchanged
    } else if affected_count == 1
        && added_bytes == incoming.payload.len()
        && ranges
            .get(first_affected)
            .and_then(RetainedRange::end)
            .is_some_and(|end| end == incoming.offset)
    {
        UpdateKind::Append
    } else {
        UpdateKind::Replace
    };
    Ok(MergePlan {
        first_affected,
        affected_count,
        union_start,
        union_end,
        added_bytes,
        conflicting_bytes,
        result_range_count,
        kind,
    })
}

/// Measures one retained range's overlap with the incoming fragment,
/// reporting `(overlapping, conflicting)` byte counts.
fn measure_overlap(
    retained: &RetainedRange,
    retained_end: usize,
    incoming: &Incoming,
) -> Result<(usize, usize), Error> {
    let overlap_start = retained.start.max(incoming.offset);
    let overlap_end = retained_end.min(incoming.end);
    let length = overlap_end
        .checked_sub(overlap_start)
        .ok_or(Malformed::OffsetOverflow)?;
    let retained_start = overlap_start
        .checked_sub(retained.start)
        .ok_or(Malformed::OffsetOverflow)?;
    let incoming_start = overlap_start
        .checked_sub(incoming.offset)
        .ok_or(Malformed::OffsetOverflow)?;
    let retained_stop = retained_start
        .checked_add(length)
        .ok_or(Malformed::OffsetOverflow)?;
    let incoming_stop = incoming_start
        .checked_add(length)
        .ok_or(Malformed::OffsetOverflow)?;
    let retained_overlap = retained
        .bytes
        .get(retained_start..retained_stop)
        .ok_or(Malformed::OffsetOverflow)?;
    let incoming_overlap = incoming
        .payload
        .get(incoming_start..incoming_stop)
        .ok_or(Malformed::OffsetOverflow)?;
    // A retransmitted fragment overlaps byte-for-byte, so settle that
    // case with one slice compare before counting byte by byte.
    let conflicting = if retained_overlap == incoming_overlap {
        0
    } else {
        retained_overlap
            .iter()
            .zip(incoming_overlap)
            .filter(|(first, second)| first != second)
            .count()
    };
    Ok((length, conflicting))
}

/// Builds the single range covering the fragment and every retained range it
/// touches. Nothing retained is modified.
pub(super) fn merge_affected(
    ranges: &[RetainedRange],
    incoming: &Incoming,
    plan: &MergePlan,
    policy: OverlapPolicy,
) -> Result<RetainedRange, Error> {
    let union_length = plan
        .union_end
        .checked_sub(plan.union_start)
        .ok_or(Malformed::OffsetOverflow)?;
    let mut merged = Vec::new();
    merged
        .try_reserve_exact(union_length)
        .map_err(|_| Resource::AllocationFailed {
            requested: union_length,
        })?;
    merged.resize(union_length, 0);

    let incoming_start = incoming
        .offset
        .checked_sub(plan.union_start)
        .ok_or(Malformed::OffsetOverflow)?;
    // Overlapping bytes are resolved by write order: whichever side is
    // written last wins the contested region.
    let incoming_last = policy == OverlapPolicy::Last;
    if !incoming_last {
        copy_into(&mut merged, incoming_start, &incoming.payload)?;
    }
    for retained in ranges
        .iter()
        .skip(plan.first_affected)
        .take(plan.affected_count)
    {
        let relative = retained
            .start
            .checked_sub(plan.union_start)
            .ok_or(Malformed::OffsetOverflow)?;
        copy_into(&mut merged, relative, &retained.bytes)?;
    }
    if incoming_last {
        copy_into(&mut merged, incoming_start, &incoming.payload)?;
    }
    Ok(RetainedRange {
        start: plan.union_start,
        bytes: merged,
    })
}

/// Stores the prepared update in `ranges`. Every reservation precedes every
/// write, so an error leaves `ranges` untouched.
pub(super) fn apply_range_update(
    ranges: &mut Vec<RetainedRange>,
    update: RangeUpdate,
    incoming: &Incoming,
    plan: &MergePlan,
) -> Result<(), Error> {
    match update {
        RangeUpdate::Unchanged => Ok(()),
        RangeUpdate::Append => {
            let range = ranges
                .get_mut(plan.first_affected)
                .ok_or(Malformed::OffsetOverflow)?;
            range
                .bytes
                .try_reserve_exact(incoming.payload.len())
                .map_err(|_| Resource::AllocationFailed {
                    requested: incoming.payload.len(),
                })?;
            range.bytes.extend_from_slice(&incoming.payload);
            Ok(())
        }
        RangeUpdate::Replace(merged) => {
            let replaced_end = plan
                .first_affected
                .checked_add(plan.affected_count)
                .ok_or(Malformed::OffsetOverflow)?;
            if ranges.get(plan.first_affected..replaced_end).is_none() {
                return Err(Malformed::OffsetOverflow.into());
            }
            if plan.affected_count == 0 {
                ranges
                    .try_reserve(1)
                    .map_err(|_| Resource::AllocationFailed {
                        requested: RANGE_METADATA_CHARGE,
                    })?;
            }
            // The range slot is reserved above, so the splice cannot allocate.
            ranges.splice(plan.first_affected..replaced_end, std::iter::once(merged));
            Ok(())
        }
    }
}

fn copy_into(target: &mut [u8], start: usize, bytes: &[u8]) -> Result<(), Error> {
    let end = start
        .checked_add(bytes.len())
        .ok_or(Malformed::OffsetOverflow)?;
    target
        .get_mut(start..end)
        .ok_or(Malformed::OffsetOverflow)?
        .copy_from_slice(bytes);
    Ok(())
}
