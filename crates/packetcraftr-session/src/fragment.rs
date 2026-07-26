// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use std::ops::Bound::{Excluded, Included, Unbounded};
use std::time::Instant;

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::ReassemblyLimits;

const DATAGRAM_STATE_METADATA_CHARGE: usize = 128;
const FRAGMENT_SEGMENT_METADATA_CHARGE: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DatagramKey {
    pub source: IpAddr,
    pub destination: IpAddr,
    pub identification: u32,
    pub next_header: u8,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fragment {
    pub key: DatagramKey,
    /// Byte offset in the reassembled payload.
    pub offset: u32,
    pub more_fragments: bool,
    pub bytes: Bytes,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum OverlapPolicy {
    #[default]
    RejectConflicting,
    KeepFirst,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Datagram {
    pub key: DatagramKey,
    pub bytes: Bytes,
    pub fragment_count: usize,
    pub had_conflicting_overlap: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    Complete(Datagram),
    Expired {
        key: DatagramKey,
        received_bytes: usize,
        fragment_count: usize,
    },
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    #[error("zero-length fragments are not accepted for reassembly")]
    EmptyFragment,
    #[error("fragment range overflows its 32-bit offset")]
    OffsetOverflow,
    #[error("fragment datagram exceeds per-flow limit {limit} bytes")]
    FlowByteLimit { limit: usize },
    #[error("fragment table reached flow limit {limit}")]
    FlowLimit { limit: usize },
    #[error("fragment table would exceed aggregate byte limit {limit}")]
    AggregateByteLimit { limit: usize },
    #[error("datagram reached fragment limit {limit}")]
    FragmentLimit { limit: usize },
    #[error("conflicting fragment overlap at byte offset {offset}")]
    ConflictingOverlap { offset: u32 },
    #[error(
        "fragment marked final at length {new_length}, conflicting with prior final length {existing_length}"
    )]
    ConflictingFinalLength {
        existing_length: u32,
        new_length: u32,
    },
    #[error("fragment extends beyond declared final datagram length {final_length}")]
    BeyondFinalLength { final_length: u32 },
}

#[derive(Debug)]
struct DatagramState {
    segments: BTreeMap<u32, Bytes>,
    final_length: Option<u32>,
    fragment_count: usize,
    stored_bytes: usize,
    last_update: Instant,
    had_conflicting_overlap: bool,
}

#[derive(Debug)]
pub struct Reassembler {
    limits: ReassemblyLimits,
    overlap_policy: OverlapPolicy,
    flows: HashMap<DatagramKey, DatagramState>,
    aggregate_bytes: usize,
    aggregate_memory_charge: usize,
}

impl Reassembler {
    pub fn new(limits: ReassemblyLimits, overlap_policy: OverlapPolicy) -> Self {
        Self {
            limits,
            overlap_policy,
            flows: HashMap::new(),
            aggregate_bytes: 0,
            aggregate_memory_charge: 0,
        }
    }

    pub fn limits(&self) -> &ReassemblyLimits {
        &self.limits
    }

    pub fn flow_count(&self) -> usize {
        self.flows.len()
    }

    pub fn aggregate_bytes(&self) -> usize {
        self.aggregate_bytes
    }

    pub fn aggregate_memory_charge(&self) -> usize {
        self.aggregate_memory_charge
    }

    pub fn push(&mut self, fragment: Fragment, now: Instant) -> Result<Option<Event>, Error> {
        let Fragment {
            key,
            offset,
            more_fragments,
            bytes,
        } = fragment;

        if bytes.is_empty() {
            return Err(Error::EmptyFragment);
        }
        let end = offset
            .checked_add(u32::try_from(bytes.len()).map_err(|_| Error::OffsetOverflow)?)
            .ok_or(Error::OffsetOverflow)?;
        if end as usize > self.limits.max_bytes_per_flow {
            return Err(Error::FlowByteLimit {
                limit: self.limits.max_bytes_per_flow,
            });
        }
        let has_existing_flow = self.flows.contains_key(&key);
        if !has_existing_flow && self.flows.len() >= self.limits.max_flows {
            return Err(Error::FlowLimit {
                limit: self.limits.max_flows,
            });
        }

        let (
            old_memory_charge,
            previous_stored_bytes,
            previous_fragment_count,
            final_length,
            merge,
        ) = {
            let existing_state = self.flows.get(&key);
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
            if !more_fragments {
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
                Some(state) => {
                    plan_fragment_merge(&state.segments, offset, &bytes, self.overlap_policy)?
                }
                None => FragmentMergePlan::disjoint(bytes.len(), offset, end, 1),
            };
            (
                old_memory_charge,
                previous_stored_bytes,
                previous_fragment_count,
                (!more_fragments).then_some(end).or(existing_final_length),
                merge,
            )
        };

        let stored_bytes = previous_stored_bytes.checked_add(merge.added_bytes).ok_or(
            Error::AggregateByteLimit {
                limit: self.limits.max_aggregate_bytes,
            },
        )?;
        let aggregate = self.aggregate_bytes.checked_add(merge.added_bytes).ok_or(
            Error::AggregateByteLimit {
                limit: self.limits.max_aggregate_bytes,
            },
        )?;
        if aggregate > self.limits.max_aggregate_bytes {
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
        let fragment_count = previous_fragment_count + 1;

        if !has_existing_flow && !more_fragments && offset == 0 {
            return Ok(Some(Event::Complete(Datagram {
                key,
                bytes,
                fragment_count,
                had_conflicting_overlap: false,
            })));
        }

        if has_existing_flow {
            let complete = {
                let state = self
                    .flows
                    .get_mut(&key)
                    .expect("validated fragment flow remains present");
                commit_fragment(&mut state.segments, offset, bytes, merge);
                state.final_length = final_length;
                state.stored_bytes = stored_bytes;
                state.fragment_count = fragment_count;
                state.last_update = now;
                state.had_conflicting_overlap |= merge.has_conflicting_overlap;
                state
                    .final_length
                    .filter(|length| is_complete(&state.segments, *length))
            };

            self.aggregate_bytes = aggregate;
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
                let datagram_bytes = if state.segments.len() == 1 {
                    let (_, bytes) = state
                        .segments
                        .into_iter()
                        .next()
                        .expect("complete datagram retains its coalesced segment");
                    debug_assert_eq!(bytes.len(), length as usize);
                    bytes
                } else {
                    let mut bytes = Vec::with_capacity(length as usize);
                    for segment in state.segments.values() {
                        bytes.extend_from_slice(segment);
                    }
                    bytes.truncate(length as usize);
                    Bytes::from(bytes)
                };
                return Ok(Some(Event::Complete(Datagram {
                    key,
                    bytes: datagram_bytes,
                    fragment_count: state.fragment_count,
                    had_conflicting_overlap: state.had_conflicting_overlap,
                })));
            }
            return Ok(None);
        }

        let mut state = DatagramState {
            segments: BTreeMap::new(),
            final_length,
            fragment_count,
            stored_bytes,
            last_update: now,
            had_conflicting_overlap: merge.has_conflicting_overlap,
        };
        commit_fragment(&mut state.segments, offset, bytes, merge);
        self.flows.insert(key, state);
        self.aggregate_bytes = aggregate;
        self.aggregate_memory_charge = aggregate_memory_charge;
        Ok(None)
    }

    pub fn expire(&mut self, now: Instant) -> Vec<Event> {
        let mut expired = self
            .flows
            .iter()
            .filter_map(|(key, state)| {
                now.checked_duration_since(state.last_update)
                    .filter(|idle| *idle >= self.limits.fragment_expiry)
                    .map(|_| key.clone())
            })
            .collect::<Vec<_>>();
        expired.sort_by_cached_key(|key| {
            (
                key.source.to_string(),
                key.destination.to_string(),
                key.identification,
                key.next_header,
            )
        });
        expired
            .into_iter()
            .filter_map(|key| {
                let state = self.flows.remove(&key)?;
                self.aggregate_bytes = self.aggregate_bytes.saturating_sub(state.stored_bytes);
                let charge = datagram_memory_charge(&state).unwrap_or(0);
                self.aggregate_memory_charge = self.aggregate_memory_charge.saturating_sub(charge);
                Some(Event::Expired {
                    key,
                    received_bytes: state.stored_bytes,
                    fragment_count: state.fragment_count,
                })
            })
            .collect()
    }

    pub fn flush(&mut self) -> Vec<Event> {
        let mut keys = self.flows.keys().cloned().collect::<Vec<_>>();
        keys.sort_by_key(|key| {
            (
                key.source.to_string(),
                key.destination.to_string(),
                key.identification,
                key.next_header,
            )
        });
        let events = keys
            .into_iter()
            .filter_map(|key| {
                let state = self.flows.remove(&key)?;
                Some(Event::Expired {
                    key,
                    received_bytes: state.stored_bytes,
                    fragment_count: state.fragment_count,
                })
            })
            .collect();
        self.aggregate_bytes = 0;
        self.aggregate_memory_charge = 0;
        events
    }
}

fn datagram_memory_charge(state: &DatagramState) -> Option<usize> {
    datagram_memory_charge_parts(state.stored_bytes, state.segments.len())
}

fn datagram_memory_charge_parts(stored_bytes: usize, segment_count: usize) -> Option<usize> {
    segment_count
        .checked_mul(FRAGMENT_SEGMENT_METADATA_CHARGE)
        .and_then(|metadata| metadata.checked_add(DATAGRAM_STATE_METADATA_CHARGE))
        .and_then(|metadata| metadata.checked_add(stored_bytes))
}

#[derive(Clone, Copy, Debug)]
struct FragmentMergePlan {
    added_bytes: usize,
    has_conflicting_overlap: bool,
    segment_count: usize,
    first_affected: Option<u32>,
    affected_segment_count: usize,
    union_start: u32,
    union_end: u32,
}

impl FragmentMergePlan {
    fn disjoint(added_bytes: usize, offset: u32, end: u32, segment_count: usize) -> Self {
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

fn plan_fragment_merge(
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
                        let mismatch = existing_overlap
                            .iter()
                            .zip(fragment_overlap)
                            .position(|(left, right)| left != right)
                            .unwrap_or(0);
                        return Err(Error::ConflictingOverlap {
                            offset: overlap_start + mismatch as u32,
                        });
                    }
                }
            }
            Ok(())
        };

        // Coalesced ranges have gaps between them, so only the predecessor can reach `offset`.
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

fn commit_fragment(
    segments: &mut BTreeMap<u32, Bytes>,
    offset: u32,
    fragment: Bytes,
    plan: FragmentMergePlan,
) {
    let Some(mut current) = plan.first_affected else {
        // A short Bytes slice can retain an arbitrarily large caller-owned
        // allocation. Retained fragment accounting is by logical byte count,
        // so normalize disjoint input to a right-sized backing buffer too.
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
        // Existing bytes win under KeepFirst; RejectConflicting reached here
        // only when the overlapping bytes were equal.
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

fn is_complete(segments: &BTreeMap<u32, Bytes>, final_length: u32) -> bool {
    let mut cursor = 0u32;
    for (offset, bytes) in segments {
        if *offset != cursor {
            return false;
        }
        let Ok(length) = u32::try_from(bytes.len()) else {
            return false;
        };
        let Some(end) = cursor.checked_add(length) else {
            return false;
        };
        cursor = end;
    }
    cursor == final_length
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    use super::*;

    fn key() -> DatagramKey {
        DatagramKey {
            source: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            destination: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)),
            identification: 7,
            next_header: 17,
        }
    }

    #[test]
    fn out_of_order_fragments_reassemble() {
        let now = Instant::now();
        let mut reassembler = Reassembler::new(
            ReassemblyLimits::default(),
            OverlapPolicy::RejectConflicting,
        );
        assert!(
            reassembler
                .push(
                    Fragment {
                        key: key(),
                        offset: 3,
                        more_fragments: false,
                        bytes: Bytes::from_static(b"def"),
                    },
                    now,
                )
                .unwrap()
                .is_none()
        );
        let event = reassembler
            .push(
                Fragment {
                    key: key(),
                    offset: 0,
                    more_fragments: true,
                    bytes: Bytes::from_static(b"abc"),
                },
                now,
            )
            .unwrap()
            .unwrap();
        assert!(matches!(
            event,
            Event::Complete(value) if value.bytes == Bytes::from_static(b"abcdef")
        ));
    }

    #[test]
    fn adjacent_fragments_coalesce() {
        let now = Instant::now();
        let mut reassembler = Reassembler::new(
            ReassemblyLimits::default(),
            OverlapPolicy::RejectConflicting,
        );
        reassembler
            .push(
                Fragment {
                    key: key(),
                    offset: 0,
                    more_fragments: true,
                    bytes: Bytes::from_static(b"ab"),
                },
                now,
            )
            .unwrap();
        reassembler
            .push(
                Fragment {
                    key: key(),
                    offset: 2,
                    more_fragments: true,
                    bytes: Bytes::from_static(b"cd"),
                },
                now,
            )
            .unwrap();

        let state = reassembler.flows.get(&key()).unwrap();
        assert_eq!(state.segments.len(), 1);
        assert_eq!(&state.segments[&0][..], b"abcd");
        assert_eq!(state.fragment_count, 2);
    }

    #[test]
    fn bridging_fragments_coalesce_both_neighbors() {
        let now = Instant::now();
        let mut reassembler = Reassembler::new(
            ReassemblyLimits::default(),
            OverlapPolicy::RejectConflicting,
        );
        for (offset, bytes) in [
            (0, b"ab".as_slice()),
            (4, b"ef".as_slice()),
            (2, b"cd".as_slice()),
        ] {
            reassembler
                .push(
                    Fragment {
                        key: key(),
                        offset,
                        more_fragments: true,
                        bytes: Bytes::copy_from_slice(bytes),
                    },
                    now,
                )
                .unwrap();
        }

        let state = reassembler.flows.get(&key()).unwrap();
        assert_eq!(state.segments.len(), 1);
        assert_eq!(&state.segments[&0][..], b"abcdef");
        assert_eq!(state.fragment_count, 3);
        assert_eq!(
            reassembler.aggregate_memory_charge(),
            DATAGRAM_STATE_METADATA_CHARGE + FRAGMENT_SEGMENT_METADATA_CHARGE + 6
        );
    }

    #[test]
    fn keep_first_preserves_existing_overlapping_bytes() {
        let now = Instant::now();
        let mut reassembler =
            Reassembler::new(ReassemblyLimits::default(), OverlapPolicy::KeepFirst);
        reassembler
            .push(
                Fragment {
                    key: key(),
                    offset: 0,
                    more_fragments: true,
                    bytes: Bytes::from_static(b"abc"),
                },
                now,
            )
            .unwrap();
        let event = reassembler
            .push(
                Fragment {
                    key: key(),
                    offset: 1,
                    more_fragments: false,
                    bytes: Bytes::from_static(b"XYZ"),
                },
                now,
            )
            .unwrap()
            .unwrap();

        assert!(matches!(
            event,
            Event::Complete(Datagram {
                bytes,
                fragment_count: 2,
                had_conflicting_overlap: true,
                ..
            }) if bytes == Bytes::from_static(b"abcZ")
        ));
    }

    #[test]
    fn fully_covered_keep_first_fragment_keeps_the_retained_segment() {
        let now = Instant::now();
        let mut reassembler =
            Reassembler::new(ReassemblyLimits::default(), OverlapPolicy::KeepFirst);
        reassembler
            .push(
                Fragment {
                    key: key(),
                    offset: 10,
                    more_fragments: true,
                    bytes: Bytes::from_static(b"abc"),
                },
                now,
            )
            .unwrap();
        let pointer = reassembler.flows[&key()].segments[&10].as_ptr();

        reassembler
            .push(
                Fragment {
                    key: key(),
                    offset: 10,
                    more_fragments: true,
                    bytes: Bytes::from_static(b"abc"),
                },
                now,
            )
            .unwrap();

        let state = &reassembler.flows[&key()];
        assert_eq!(state.segments.len(), 1);
        assert_eq!(state.segments[&10].as_ptr(), pointer);
    }

    #[test]
    fn conflicting_overlap_rejection_preserves_state() {
        let now = Instant::now();
        let mut reassembler = Reassembler::new(
            ReassemblyLimits::default(),
            OverlapPolicy::RejectConflicting,
        );
        reassembler
            .push(
                Fragment {
                    key: key(),
                    offset: 0,
                    more_fragments: true,
                    bytes: Bytes::from_static(b"abcd"),
                },
                now,
            )
            .unwrap();
        let before = (
            reassembler.flow_count(),
            reassembler.aggregate_bytes(),
            reassembler.aggregate_memory_charge(),
        );
        let error = reassembler
            .push(
                Fragment {
                    key: key(),
                    offset: 2,
                    more_fragments: false,
                    bytes: Bytes::from_static(b"XY"),
                },
                now,
            )
            .unwrap_err();
        assert!(matches!(error, Error::ConflictingOverlap { offset: 2 }));
        assert_eq!(
            before,
            (
                reassembler.flow_count(),
                reassembler.aggregate_bytes(),
                reassembler.aggregate_memory_charge(),
            )
        );
        let state = reassembler.flows.get(&key()).unwrap();
        assert_eq!(state.final_length, None);
        assert_eq!(state.fragment_count, 1);
        assert_eq!(&state.segments[&0][..], b"abcd");
    }

    #[test]
    fn expiry_emits_incomplete_event_and_releases_bytes() {
        let now = Instant::now();
        let limits = ReassemblyLimits {
            fragment_expiry: Duration::from_secs(1),
            ..ReassemblyLimits::default()
        };
        let mut reassembler = Reassembler::new(limits, OverlapPolicy::RejectConflicting);
        reassembler
            .push(
                Fragment {
                    key: key(),
                    offset: 0,
                    more_fragments: true,
                    bytes: Bytes::from_static(b"abc"),
                },
                now,
            )
            .unwrap();
        assert_eq!(reassembler.expire(now + Duration::from_secs(1)).len(), 1);
        assert_eq!(reassembler.aggregate_bytes(), 0);
    }

    #[test]
    fn final_length_rejects_prior_fragment_beyond_end_atomically() {
        let now = Instant::now();
        let mut reassembler = Reassembler::new(
            ReassemblyLimits::default(),
            OverlapPolicy::RejectConflicting,
        );
        reassembler
            .push(
                Fragment {
                    key: key(),
                    offset: 8,
                    more_fragments: true,
                    bytes: Bytes::from_static(b"ij"),
                },
                now,
            )
            .unwrap();

        assert_eq!(
            reassembler
                .push(
                    Fragment {
                        key: key(),
                        offset: 0,
                        more_fragments: false,
                        bytes: Bytes::from_static(b"abcd"),
                    },
                    now,
                )
                .unwrap_err(),
            Error::BeyondFinalLength { final_length: 4 }
        );
        assert_eq!(reassembler.flow_count(), 1);
        assert_eq!(reassembler.aggregate_bytes(), 2);
        assert!(matches!(
            reassembler.flush().as_slice(),
            [Event::Expired {
                received_bytes: 2,
                fragment_count: 1,
                ..
            }]
        ));
    }

    #[test]
    fn aggregate_limit_charges_sparse_fragment_metadata() {
        let now = Instant::now();
        let limits = ReassemblyLimits {
            max_aggregate_bytes: 193,
            ..ReassemblyLimits::default()
        };
        let mut reassembler = Reassembler::new(limits, OverlapPolicy::RejectConflicting);
        reassembler
            .push(
                Fragment {
                    key: key(),
                    offset: 0,
                    more_fragments: true,
                    bytes: Bytes::from_static(b"a"),
                },
                now,
            )
            .unwrap();
        assert_eq!(reassembler.aggregate_bytes(), 1);
        assert_eq!(reassembler.aggregate_memory_charge(), 193);
        assert_eq!(
            reassembler
                .push(
                    Fragment {
                        key: key(),
                        offset: 2,
                        more_fragments: true,
                        bytes: Bytes::from_static(b"b"),
                    },
                    now,
                )
                .unwrap_err(),
            Error::AggregateByteLimit { limit: 193 }
        );
        assert_eq!(reassembler.aggregate_bytes(), 1);
        assert_eq!(reassembler.aggregate_memory_charge(), 193);
    }

    #[test]
    fn empty_fragments_are_rejected_without_creating_state() {
        let now = Instant::now();
        let mut reassembler = Reassembler::new(
            ReassemblyLimits::default(),
            OverlapPolicy::RejectConflicting,
        );
        assert_eq!(
            reassembler
                .push(
                    Fragment {
                        key: key(),
                        offset: 0,
                        more_fragments: false,
                        bytes: Bytes::new(),
                    },
                    now,
                )
                .unwrap_err(),
            Error::EmptyFragment
        );
        assert_eq!(reassembler.flow_count(), 0);
    }

    #[test]
    fn disjoint_fragments_do_not_retain_a_large_input_slice() {
        let now = Instant::now();
        let backing = Bytes::from(vec![7_u8; 4_096]);
        let slice = backing.slice(2_048..2_049);
        let slice_pointer = slice.as_ptr();
        let mut reassembler = Reassembler::new(
            ReassemblyLimits::default(),
            OverlapPolicy::RejectConflicting,
        );

        reassembler
            .push(
                Fragment {
                    key: key(),
                    offset: 10,
                    more_fragments: true,
                    bytes: slice,
                },
                now,
            )
            .unwrap();

        let stored = &reassembler.flows[&key()].segments[&10];
        assert_eq!(stored.as_ref(), b"\x07");
        assert_ne!(stored.as_ptr(), slice_pointer);
    }

    #[test]
    fn sparse_aggregate_rejection_precedes_span_sized_scratch_allocation() {
        let now = Instant::now();
        let limits = ReassemblyLimits {
            max_bytes_per_flow: 10_000_001,
            max_aggregate_bytes: DATAGRAM_STATE_METADATA_CHARGE + FRAGMENT_SEGMENT_METADATA_CHARGE,
            ..ReassemblyLimits::default()
        };
        let mut reassembler = Reassembler::new(limits, OverlapPolicy::RejectConflicting);
        assert_eq!(
            reassembler
                .push(
                    Fragment {
                        key: key(),
                        offset: 10_000_000,
                        more_fragments: true,
                        bytes: Bytes::from_static(b"x"),
                    },
                    now,
                )
                .unwrap_err(),
            Error::AggregateByteLimit {
                limit: DATAGRAM_STATE_METADATA_CHARGE + FRAGMENT_SEGMENT_METADATA_CHARGE
            }
        );
        assert_eq!(reassembler.flow_count(), 0);
    }
}
