// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use std::time::Instant;

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::ReassemblyLimits;

#[cfg(test)]
use accounting::{DATAGRAM_STATE_METADATA_CHARGE, FRAGMENT_SEGMENT_METADATA_CHARGE};
use accounting::{FragmentAccountingInput, datagram_memory_charge_parts, plan_accounting};
use commit::commit_fragment;
use plan::{FragmentMergePlan, plan_fragment_merge};

mod accounting;
mod commit;
mod plan;

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
    #[error("non-final fragment payload length {length} is not a multiple of eight bytes")]
    UnalignedNonFinalFragment { length: usize },
    #[error("fragment byte offset {offset} is not a multiple of eight")]
    UnalignedFragmentOffset { offset: u32 },
    #[error("fragment range overflows its 32-bit offset")]
    OffsetOverflow,
    #[error("fragment datagram exceeds per-flow limit {limit} bytes")]
    FlowByteLimit { limit: usize },
    #[error("fragment table reached flow limit {limit}")]
    FlowLimit { limit: usize },
    #[error("fragment table would exceed aggregate byte limit {limit}")]
    AggregateByteLimit { limit: usize },
    #[error("could not allocate {requested} bytes for fragment reassembly")]
    AllocationFailed { requested: usize },
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

    pub fn flow_count(&self) -> usize {
        self.flows.len()
    }

    pub fn aggregate_bytes(&self) -> usize {
        self.aggregate_bytes
    }

    pub fn aggregate_memory_charge(&self) -> usize {
        self.aggregate_memory_charge
    }

    /// Admits one fragment, returning an event once a datagram completes.
    ///
    /// # Panics
    ///
    /// Panics if a flow validated earlier in the same call has since
    /// disappeared, or if a completed datagram is missing the segment the
    /// merge plan just placed in it. Both would mean this reassembler had
    /// corrupted its own state; every input-driven rejection, including
    /// conflicting overlaps and exhausted budgets, is reported through
    /// [`enum@Error`].
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
        if more_fragments && !bytes.len().is_multiple_of(8) {
            return Err(Error::UnalignedNonFinalFragment {
                length: bytes.len(),
            });
        }
        if !offset.is_multiple_of(8) {
            return Err(Error::UnalignedFragmentOffset { offset });
        }
        let end = offset
            .checked_add(u32::try_from(bytes.len()).map_err(|_| Error::OffsetOverflow)?)
            .ok_or(Error::OffsetOverflow)?;
        if usize::try_from(end).map_or(true, |end| end > self.limits.max_bytes_per_flow) {
            return Err(Error::FlowByteLimit {
                limit: self.limits.max_bytes_per_flow,
            });
        }
        let has_existing_flow = self.flows.contains_key(&key);
        if !has_existing_flow && !more_fragments && offset == 0 {
            if self.limits.max_fragments_per_datagram == 0 {
                return Err(Error::FragmentLimit { limit: 0 });
            }
            return Ok(Some(Event::Complete(Datagram {
                key,
                bytes,
                fragment_count: 1,
                had_conflicting_overlap: false,
            })));
        }
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

        let accounting = plan_accounting(
            &self.limits,
            FragmentAccountingInput {
                previous_stored_bytes,
                previous_fragment_count,
                added_bytes: merge.added_bytes,
                segment_count: merge.segment_count,
                aggregate_bytes: self.aggregate_bytes,
                old_memory_charge,
                aggregate_memory_charge: self.aggregate_memory_charge,
            },
        )?;
        let stored_bytes = accounting.stored_bytes;
        let aggregate = accounting.aggregate_bytes;
        let new_memory_charge = accounting.new_memory_charge;
        let aggregate_memory_charge = accounting.aggregate_memory_charge;
        let fragment_count = accounting.fragment_count;

        if has_existing_flow {
            let complete = {
                let state = self
                    .flows
                    .get_mut(&key)
                    .expect("validated fragment flow remains present");
                commit_fragment(&mut state.segments, offset, bytes, merge)?;
                state.final_length = final_length;
                state.stored_bytes = stored_bytes;
                state.fragment_count = fragment_count;
                state.last_update = state.last_update.max(now);
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
        commit_fragment(&mut state.segments, offset, bytes, merge)?;
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
        expired.sort_by_key(|key| {
            (
                key.source,
                key.destination,
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
                key.source,
                key.destination,
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
                        offset: 8,
                        more_fragments: false,
                        bytes: Bytes::from_static(b"ijk"),
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
                    bytes: Bytes::from_static(b"abcdefgh"),
                },
                now,
            )
            .unwrap()
            .unwrap();
        assert!(matches!(
            event,
            Event::Complete(value) if value.bytes == Bytes::from_static(b"abcdefghijk")
        ));
    }

    #[test]
    fn bridging_fragments_coalesce_both_neighbors() {
        let now = Instant::now();
        let mut reassembler = Reassembler::new(
            ReassemblyLimits::default(),
            OverlapPolicy::RejectConflicting,
        );
        for (offset, bytes) in [
            (0, b"abcdefgh".as_slice()),
            (16, b"qrstuvwx".as_slice()),
            (8, b"ijklmnop".as_slice()),
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
        assert_eq!(&state.segments[&0][..], b"abcdefghijklmnopqrstuvwx");
        assert_eq!(state.fragment_count, 3);
        assert_eq!(
            reassembler.aggregate_memory_charge(),
            DATAGRAM_STATE_METADATA_CHARGE + FRAGMENT_SEGMENT_METADATA_CHARGE + 24
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
                    bytes: Bytes::from_static(b"abcdefghijklmnop"),
                },
                now,
            )
            .unwrap();
        let event = reassembler
            .push(
                Fragment {
                    key: key(),
                    offset: 8,
                    more_fragments: false,
                    bytes: Bytes::from_static(b"XXXXXXXXZ"),
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
            }) if bytes == Bytes::from_static(b"abcdefghijklmnopZ")
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
                    offset: 8,
                    more_fragments: true,
                    bytes: Bytes::from_static(b"abcdefgh"),
                },
                now,
            )
            .unwrap();
        let pointer = reassembler.flows[&key()].segments[&8].as_ptr();

        reassembler
            .push(
                Fragment {
                    key: key(),
                    offset: 8,
                    more_fragments: true,
                    bytes: Bytes::from_static(b"abcdefgh"),
                },
                now,
            )
            .unwrap();

        let state = &reassembler.flows[&key()];
        assert_eq!(state.segments.len(), 1);
        assert_eq!(state.segments[&8].as_ptr(), pointer);
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
                    bytes: Bytes::from_static(b"abcdefghijklmnop"),
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
                    offset: 8,
                    more_fragments: false,
                    bytes: Bytes::from_static(b"XXXXXXXX"),
                },
                now,
            )
            .unwrap_err();
        assert!(matches!(error, Error::ConflictingOverlap { offset: 8 }));
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
        assert_eq!(&state.segments[&0][..], b"abcdefghijklmnop");
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
                    bytes: Bytes::from_static(b"abcdefgh"),
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
                    bytes: Bytes::from_static(b"ijklmnop"),
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
        assert_eq!(reassembler.aggregate_bytes(), 8);
        assert!(matches!(
            reassembler.flush().as_slice(),
            [Event::Expired {
                received_bytes: 8,
                fragment_count: 1,
                ..
            }]
        ));
    }

    #[test]
    fn aggregate_limit_charges_sparse_fragment_metadata() {
        let now = Instant::now();
        let limits = ReassemblyLimits {
            max_aggregate_bytes: 200,
            ..ReassemblyLimits::default()
        };
        let mut reassembler = Reassembler::new(limits, OverlapPolicy::RejectConflicting);
        reassembler
            .push(
                Fragment {
                    key: key(),
                    offset: 0,
                    more_fragments: true,
                    bytes: Bytes::from_static(b"abcdefgh"),
                },
                now,
            )
            .unwrap();
        assert_eq!(reassembler.aggregate_bytes(), 8);
        assert_eq!(reassembler.aggregate_memory_charge(), 200);
        assert_eq!(
            reassembler
                .push(
                    Fragment {
                        key: key(),
                        offset: 16,
                        more_fragments: true,
                        bytes: Bytes::from_static(b"ijklmnop"),
                    },
                    now,
                )
                .unwrap_err(),
            Error::AggregateByteLimit { limit: 200 }
        );
        assert_eq!(reassembler.aggregate_bytes(), 8);
        assert_eq!(reassembler.aggregate_memory_charge(), 200);
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
    fn wire_alignment_is_validated_without_creating_state() {
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
                        more_fragments: true,
                        bytes: Bytes::from_static(b"short"),
                    },
                    now,
                )
                .unwrap_err(),
            Error::UnalignedNonFinalFragment { length: 5 }
        );
        assert_eq!(
            reassembler
                .push(
                    Fragment {
                        key: key(),
                        offset: 1,
                        more_fragments: false,
                        bytes: Bytes::from_static(b"x"),
                    },
                    now,
                )
                .unwrap_err(),
            Error::UnalignedFragmentOffset { offset: 1 }
        );
        assert_eq!(reassembler.flow_count(), 0);
    }

    #[test]
    fn complete_single_fragment_does_not_consume_retained_state_budgets() {
        let fragment = Fragment {
            key: key(),
            offset: 0,
            more_fragments: false,
            bytes: Bytes::from_static(b"complete"),
        };
        let mut denied = Reassembler::new(
            ReassemblyLimits {
                max_fragments_per_datagram: 0,
                ..ReassemblyLimits::default()
            },
            OverlapPolicy::RejectConflicting,
        );
        assert_eq!(
            denied.push(fragment.clone(), Instant::now()).unwrap_err(),
            Error::FragmentLimit { limit: 0 }
        );

        let limits = ReassemblyLimits {
            max_flows: 0,
            max_aggregate_bytes: 0,
            max_fragments_per_datagram: 1,
            ..ReassemblyLimits::default()
        };
        let mut reassembler = Reassembler::new(limits, OverlapPolicy::RejectConflicting);

        let event = reassembler.push(fragment, Instant::now()).unwrap();

        assert!(matches!(event, Some(Event::Complete(_))));
        assert_eq!(reassembler.flow_count(), 0);
        assert_eq!(reassembler.aggregate_memory_charge(), 0);
    }

    #[test]
    fn older_fragment_timestamp_does_not_regress_idle_expiry() {
        let start = Instant::now();
        let limits = ReassemblyLimits {
            fragment_expiry: Duration::from_secs(5),
            ..ReassemblyLimits::default()
        };
        let mut reassembler = Reassembler::new(limits, OverlapPolicy::RejectConflicting);
        for (offset, now) in [
            (0, start + Duration::from_secs(10)),
            (16, start + Duration::from_secs(5)),
        ] {
            reassembler
                .push(
                    Fragment {
                        key: key(),
                        offset,
                        more_fragments: true,
                        bytes: Bytes::from_static(b"abcdefgh"),
                    },
                    now,
                )
                .unwrap();
        }

        assert!(
            reassembler
                .expire(start + Duration::from_secs(11))
                .is_empty()
        );
        assert_eq!(reassembler.expire(start + Duration::from_secs(15)).len(), 1);
    }

    #[test]
    fn disjoint_fragments_do_not_retain_a_large_input_slice() {
        let now = Instant::now();
        let backing = Bytes::from(vec![7_u8; 4_096]);
        let slice = backing.slice(2_048..2_056);
        let slice_pointer = slice.as_ptr();
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
                    bytes: slice,
                },
                now,
            )
            .unwrap();

        let stored = &reassembler.flows[&key()].segments[&8];
        assert_eq!(stored.as_ref(), b"\x07\x07\x07\x07\x07\x07\x07\x07");
        assert_ne!(stored.as_ptr(), slice_pointer);
    }
}
