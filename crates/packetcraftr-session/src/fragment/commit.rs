// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Infallible fragment-map mutation from a validated merge plan.

use std::collections::BTreeMap;
use std::ops::Bound::{Excluded, Unbounded};

use bytes::Bytes;

use super::plan::FragmentMergePlan;

pub(super) fn commit_fragment(
    segments: &mut BTreeMap<u32, Bytes>,
    offset: u32,
    fragment: Bytes,
    plan: FragmentMergePlan,
) {
    let Some(mut current) = plan.first_affected else {
        let replaced = segments.insert(offset, Bytes::copy_from_slice(&fragment));
        debug_assert!(replaced.is_none());
        debug_assert_eq!(segments.len(), plan.segment_count);
        return;
    };
    if plan.added_bytes == 0 {
        debug_assert_eq!(plan.affected_segment_count, 1);
        debug_assert_eq!(segments.len(), plan.segment_count);
        return;
    }

    let mut bytes = vec![0u8; (plan.union_end - plan.union_start) as usize];
    let fragment_start = (offset - plan.union_start) as usize;
    bytes[fragment_start..fragment_start + fragment.len()].copy_from_slice(&fragment);
    for index in 0..plan.affected_segment_count {
        let value = segments
            .remove(&current)
            .expect("merge plan contains each affected segment");
        let relative = (current - plan.union_start) as usize;
        bytes[relative..relative + value.len()].copy_from_slice(&value);
        if index + 1 < plan.affected_segment_count {
            current = *segments
                .range((Excluded(current), Unbounded))
                .next()
                .map(|(start, _)| start)
                .expect("merge plan affected segments remain contiguous");
        }
    }
    segments.insert(plan.union_start, Bytes::from(bytes));
    debug_assert_eq!(segments.len(), plan.segment_count);
}
