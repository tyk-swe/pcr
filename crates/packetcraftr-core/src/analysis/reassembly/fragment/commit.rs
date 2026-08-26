// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Fragment-map mutation from a validated merge plan.

use std::collections::BTreeMap;
use std::ops::Bound::{Excluded, Unbounded};
use std::time::Instant;

use bytes::Bytes;

use super::plan::{FragmentAccountingPlan, FragmentMergePlan, FragmentRetentionPlan};
use super::{Datagram, DatagramState, Error, Event, Fragment, Reassembler, is_complete};

impl Reassembler {
    pub(super) fn commit_fragment(
        &mut self,
        fragment: Fragment,
        now: Instant,
        plan: FragmentRetentionPlan,
    ) -> Result<Option<Event>, Error> {
        let Fragment {
            key, offset, bytes, ..
        } = fragment;
        let FragmentRetentionPlan {
            has_existing_flow,
            final_length,
            merge,
            accounting,
        } = plan;
        let FragmentAccountingPlan {
            stored_bytes,
            aggregate_bytes,
            new_memory_charge,
            aggregate_memory_charge,
            fragment_count,
        } = accounting;

        if has_existing_flow {
            let previous_deadline = self.flows.get(&key).and_then(|state| state.deadline);
            let (complete, deadline) = {
                let state = self
                    .flows
                    .get_mut(&key)
                    .expect("validated fragment flow remains present");
                commit_merge(&mut state.segments, offset, bytes, merge)?;
                state.final_length = final_length;
                state.stored_bytes = stored_bytes;
                state.fragment_count = fragment_count;
                state.last_update = state.last_update.max(now);
                state.deadline = state.last_update.checked_add(self.limits.fragment_expiry);
                state.had_conflicting_overlap |= merge.has_conflicting_overlap;
                (
                    state
                        .final_length
                        .filter(|length| is_complete(&state.segments, *length)),
                    state.deadline,
                )
            };

            self.expiry.remove(previous_deadline, &key);
            self.aggregate_bytes = aggregate_bytes;
            self.aggregate_memory_charge = aggregate_memory_charge;
            if let Some(length) = complete {
                let state = self
                    .flows
                    .remove(&key)
                    .expect("completed fragment flow remains present");
                self.aggregate_bytes = self.aggregate_bytes.saturating_sub(state.stored_bytes);
                self.aggregate_memory_charge = self
                    .aggregate_memory_charge
                    .saturating_sub(new_memory_charge);
                let (_, datagram_bytes) = state
                    .segments
                    .into_iter()
                    .next()
                    .expect("complete datagram retains its coalesced segment");
                debug_assert_eq!(datagram_bytes.len(), length as usize);
                return Ok(Some(Event::Complete(Datagram {
                    key,
                    bytes: datagram_bytes,
                    fragment_count: state.fragment_count,
                    had_conflicting_overlap: state.had_conflicting_overlap,
                })));
            }
            self.expiry.insert(deadline, key);
            return Ok(None);
        }

        let deadline = now.checked_add(self.limits.fragment_expiry);
        let mut state = DatagramState {
            segments: BTreeMap::new(),
            final_length,
            fragment_count,
            stored_bytes,
            last_update: now,
            deadline,
            had_conflicting_overlap: merge.has_conflicting_overlap,
        };
        commit_merge(&mut state.segments, offset, bytes, merge)?;
        self.flows.insert(key.clone(), state);
        self.expiry.insert(deadline, key);
        self.aggregate_bytes = aggregate_bytes;
        self.aggregate_memory_charge = aggregate_memory_charge;
        Ok(None)
    }
}

fn commit_merge(
    segments: &mut BTreeMap<u32, Bytes>,
    offset: u32,
    fragment: Bytes,
    plan: FragmentMergePlan,
) -> Result<(), Error> {
    let Some(mut current) = plan.first_affected else {
        let replaced = segments.insert(offset, copy_bytes(&fragment)?);
        debug_assert!(replaced.is_none());
        debug_assert_eq!(segments.len(), plan.segment_count);
        return Ok(());
    };
    if plan.added_bytes == 0 {
        debug_assert_eq!(plan.affected_segment_count, 1);
        debug_assert_eq!(segments.len(), plan.segment_count);
        return Ok(());
    }

    let union_len = plan
        .union_end
        .checked_sub(plan.union_start)
        .and_then(|length| usize::try_from(length).ok())
        .ok_or(Error::InconsistentMergePlan)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(union_len)
        .map_err(|_| Error::AllocationFailed {
            requested: union_len,
        })?;
    bytes.resize(union_len, 0);
    let fragment_start = offset
        .checked_sub(plan.union_start)
        .and_then(|start| usize::try_from(start).ok())
        .ok_or(Error::InconsistentMergePlan)?;
    let fragment_end = fragment_start
        .checked_add(fragment.len())
        .ok_or(Error::InconsistentMergePlan)?;
    bytes
        .get_mut(fragment_start..fragment_end)
        .ok_or(Error::InconsistentMergePlan)?
        .copy_from_slice(&fragment);
    for index in 0..plan.affected_segment_count {
        let value = segments
            .remove(&current)
            .ok_or(Error::InconsistentMergePlan)?;
        let relative = current
            .checked_sub(plan.union_start)
            .and_then(|start| usize::try_from(start).ok())
            .ok_or(Error::InconsistentMergePlan)?;
        let end = relative
            .checked_add(value.len())
            .ok_or(Error::InconsistentMergePlan)?;
        bytes
            .get_mut(relative..end)
            .ok_or(Error::InconsistentMergePlan)?
            .copy_from_slice(&value);
        if index.saturating_add(1) < plan.affected_segment_count {
            current = *segments
                .range((Excluded(current), Unbounded))
                .next()
                .map(|(start, _)| start)
                .ok_or(Error::InconsistentMergePlan)?;
        }
    }
    segments.insert(plan.union_start, Bytes::from(bytes));
    debug_assert_eq!(segments.len(), plan.segment_count);
    Ok(())
}

fn copy_bytes(bytes: &[u8]) -> Result<Bytes, Error> {
    let mut copy = Vec::new();
    copy.try_reserve_exact(bytes.len())
        .map_err(|_| Error::AllocationFailed {
            requested: bytes.len(),
        })?;
    copy.extend_from_slice(bytes);
    Ok(Bytes::from(copy))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

    use super::*;

    fn merge_plan(
        first_affected: Option<u32>,
        affected_segment_count: usize,
        union_start: u32,
        union_end: u32,
    ) -> FragmentMergePlan {
        FragmentMergePlan {
            added_bytes: 4,
            has_conflicting_overlap: false,
            segment_count: 1,
            first_affected,
            affected_segment_count,
            union_start,
            union_end,
        }
    }

    #[test]
    fn commit_merge_reports_a_plan_whose_affected_segment_is_absent() {
        let mut segments = BTreeMap::new();
        segments.insert(8u32, Bytes::from_static(b"abcd"));

        let result = commit_merge(
            &mut segments,
            4,
            Bytes::from_static(b"wxyz"),
            merge_plan(Some(0), 1, 0, 12),
        );

        assert_eq!(result, Err(Error::InconsistentMergePlan));
    }

    #[test]
    fn commit_merge_reports_a_union_shorter_than_the_incoming_fragment() {
        let mut segments = BTreeMap::new();
        segments.insert(0u32, Bytes::from_static(b"ab"));

        let result = commit_merge(
            &mut segments,
            0,
            Bytes::from_static(b"wxyz"),
            merge_plan(Some(0), 1, 0, 2),
        );

        assert_eq!(result, Err(Error::InconsistentMergePlan));
    }
}
