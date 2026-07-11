// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use std::time::Instant;

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::Limits;

const DATAGRAM_STATE_METADATA_CHARGE: usize = 128;
const FRAGMENT_SEGMENT_METADATA_CHARGE: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Key {
    pub source: IpAddr,
    pub destination: IpAddr,
    pub identification: u32,
    pub next_header: u8,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fragment {
    pub key: Key,
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
    pub key: Key,
    pub bytes: Bytes,
    pub fragment_count: usize,
    pub had_conflicting_overlap: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    Complete(Datagram),
    Expired {
        key: Key,
        received_bytes: usize,
        fragment_count: usize,
    },
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
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

#[derive(Clone, Debug)]
struct DatagramState {
    segments: BTreeMap<u32, Bytes>,
    final_length: Option<u32>,
    fragments: usize,
    stored_bytes: usize,
    last_update: Instant,
    had_conflict: bool,
}

#[derive(Debug)]
pub struct Reassembler {
    limits: Limits,
    overlap_policy: OverlapPolicy,
    flows: HashMap<Key, DatagramState>,
    aggregate_bytes: usize,
    aggregate_memory_charge: usize,
}

impl Reassembler {
    pub fn new(limits: Limits, overlap_policy: OverlapPolicy) -> Self {
        Self {
            limits,
            overlap_policy,
            flows: HashMap::new(),
            aggregate_bytes: 0,
            aggregate_memory_charge: 0,
        }
    }

    pub fn limits(&self) -> &Limits {
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
        let end = fragment
            .offset
            .checked_add(u32::try_from(fragment.bytes.len()).map_err(|_| Error::OffsetOverflow)?)
            .ok_or(Error::OffsetOverflow)?;
        if end as usize > self.limits.max_bytes_per_flow {
            return Err(Error::FlowByteLimit {
                limit: self.limits.max_bytes_per_flow,
            });
        }
        if !self.flows.contains_key(&fragment.key) && self.flows.len() >= self.limits.max_flows {
            return Err(Error::FlowLimit {
                limit: self.limits.max_flows,
            });
        }

        let existing_state = self.flows.get(&fragment.key);
        let old_memory_charge = existing_state.and_then(datagram_memory_charge).unwrap_or(0);
        let mut candidate = existing_state.cloned().unwrap_or_else(|| DatagramState {
            segments: BTreeMap::new(),
            final_length: None,
            fragments: 0,
            stored_bytes: 0,
            last_update: now,
            had_conflict: false,
        });
        if candidate.fragments >= self.limits.max_fragments_per_datagram {
            return Err(Error::FragmentLimit {
                limit: self.limits.max_fragments_per_datagram,
            });
        }
        if let Some(final_length) = candidate.final_length {
            if end > final_length {
                return Err(Error::BeyondFinalLength { final_length });
            }
        }
        if !fragment.more_fragments {
            match candidate.final_length {
                Some(existing_length) if existing_length != end => {
                    return Err(Error::ConflictingFinalLength {
                        existing_length,
                        new_length: end,
                    });
                }
                _ => {
                    let prior_fragment_extends_past_end =
                        candidate.segments.iter().any(|(offset, bytes)| {
                            u64::from(*offset) + bytes.len() as u64 > u64::from(end)
                        });
                    if prior_fragment_extends_past_end {
                        return Err(Error::BeyondFinalLength { final_length: end });
                    }
                    candidate.final_length = Some(end);
                }
            }
        }

        let (segments, stored_bytes, conflict) = merge_fragment(
            &candidate.segments,
            fragment.offset,
            &fragment.bytes,
            self.overlap_policy,
        )?;
        let added = stored_bytes.saturating_sub(candidate.stored_bytes);
        let aggregate =
            self.aggregate_bytes
                .checked_add(added)
                .ok_or(Error::AggregateByteLimit {
                    limit: self.limits.max_aggregate_bytes,
                })?;
        if aggregate > self.limits.max_aggregate_bytes {
            return Err(Error::AggregateByteLimit {
                limit: self.limits.max_aggregate_bytes,
            });
        }
        let new_memory_charge = datagram_memory_charge_parts(stored_bytes, segments.len()).ok_or(
            Error::AggregateByteLimit {
                limit: self.limits.max_aggregate_bytes,
            },
        )?;
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
        self.aggregate_bytes = aggregate;
        self.aggregate_memory_charge = aggregate_memory_charge;
        candidate.segments = segments;
        candidate.stored_bytes = stored_bytes;
        candidate.fragments += 1;
        candidate.last_update = now;
        candidate.had_conflict |= conflict;

        let complete = candidate
            .final_length
            .filter(|length| is_complete(&candidate.segments, *length));
        if let Some(length) = complete {
            self.flows.remove(&fragment.key);
            self.aggregate_bytes = self.aggregate_bytes.saturating_sub(candidate.stored_bytes);
            self.aggregate_memory_charge = self
                .aggregate_memory_charge
                .saturating_sub(new_memory_charge);
            let mut bytes = Vec::with_capacity(length as usize);
            for segment in candidate.segments.values() {
                bytes.extend_from_slice(segment);
            }
            bytes.truncate(length as usize);
            return Ok(Some(Event::Complete(Datagram {
                key: fragment.key,
                bytes: Bytes::from(bytes),
                fragment_count: candidate.fragments,
                had_conflicting_overlap: candidate.had_conflict,
            })));
        }
        self.flows.insert(fragment.key, candidate);
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
        expired.sort_by(|left, right| {
            left.source
                .to_string()
                .cmp(&right.source.to_string())
                .then_with(|| {
                    left.destination
                        .to_string()
                        .cmp(&right.destination.to_string())
                })
                .then_with(|| left.identification.cmp(&right.identification))
                .then_with(|| left.next_header.cmp(&right.next_header))
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
                    fragment_count: state.fragments,
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
                    fragment_count: state.fragments,
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

fn datagram_memory_charge_parts(stored_bytes: usize, segments: usize) -> Option<usize> {
    segments
        .checked_mul(FRAGMENT_SEGMENT_METADATA_CHARGE)
        .and_then(|metadata| metadata.checked_add(DATAGRAM_STATE_METADATA_CHARGE))
        .and_then(|metadata| metadata.checked_add(stored_bytes))
}

fn merge_fragment(
    existing: &BTreeMap<u32, Bytes>,
    offset: u32,
    fragment: &[u8],
    policy: OverlapPolicy,
) -> Result<(BTreeMap<u32, Bytes>, usize, bool), Error> {
    let existing_end = existing
        .iter()
        .map(|(start, bytes)| *start as usize + bytes.len())
        .max()
        .unwrap_or(0);
    let new_end = offset as usize + fragment.len();
    let length = existing_end.max(new_end);
    let mut bytes = vec![0u8; length];
    let mut present = vec![false; length];
    for (start, value) in existing {
        let start = *start as usize;
        bytes[start..start + value.len()].copy_from_slice(value);
        present[start..start + value.len()].fill(true);
    }
    let mut conflict = false;
    for (index, value) in fragment.iter().copied().enumerate() {
        let position = offset as usize + index;
        if present[position] {
            if bytes[position] != value {
                conflict = true;
                if policy == OverlapPolicy::RejectConflicting {
                    return Err(Error::ConflictingOverlap {
                        offset: position as u32,
                    });
                }
            }
        } else {
            bytes[position] = value;
            present[position] = true;
        }
    }

    let mut segments = BTreeMap::new();
    let mut stored = 0usize;
    let mut cursor = 0usize;
    while cursor < length {
        while cursor < length && !present[cursor] {
            cursor += 1;
        }
        if cursor == length {
            break;
        }
        let start = cursor;
        while cursor < length && present[cursor] {
            cursor += 1;
        }
        stored += cursor - start;
        segments.insert(start as u32, Bytes::copy_from_slice(&bytes[start..cursor]));
    }
    Ok((segments, stored, conflict))
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

    fn key() -> Key {
        Key {
            source: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            destination: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)),
            identification: 7,
            next_header: 17,
        }
    }

    #[test]
    fn out_of_order_fragments_reassemble() {
        let now = Instant::now();
        let mut reassembler = Reassembler::new(Limits::default(), OverlapPolicy::RejectConflicting);
        assert!(reassembler
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
            .is_none());
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
    fn conflicting_overlap_rejects_by_default() {
        let now = Instant::now();
        let mut reassembler = Reassembler::new(Limits::default(), OverlapPolicy::RejectConflicting);
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
    }

    #[test]
    fn expiry_emits_incomplete_event_and_releases_bytes() {
        let now = Instant::now();
        let limits = Limits {
            fragment_expiry: Duration::from_secs(1),
            ..Limits::default()
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
        let mut reassembler = Reassembler::new(Limits::default(), OverlapPolicy::RejectConflicting);
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
        let limits = Limits {
            max_aggregate_bytes: 193,
            ..Limits::default()
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
}
