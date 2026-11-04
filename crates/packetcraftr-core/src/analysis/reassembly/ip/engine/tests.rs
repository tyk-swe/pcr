// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

use bytes::Bytes;

use super::super::{Ipv4DatagramKey, Ipv4Fragment, Ipv6DatagramKey, Ipv6Fragment};
use super::*;
use crate::analysis::scope::Interner;

#[derive(Clone, Copy, Debug)]
enum Version {
    V4,
    V6,
}

fn fragment(version: Version, id: u16, start: usize, payload: &[u8], more: bool) -> Fragment {
    let scope = Interner::default().intern(None, Vec::new()).unwrap();
    match version {
        Version::V4 => {
            let key = Ipv4DatagramKey {
                scope,
                source: Ipv4Addr::new(192, 0, 2, 1),
                destination: Ipv4Addr::new(198, 51, 100, 1),
                identification: id,
                protocol: 17,
            };
            let mut header = vec![0; 20];
            header[0] = 0x45;
            header[2..4].copy_from_slice(&u16::try_from(20 + payload.len()).unwrap().to_be_bytes());
            header[4..6].copy_from_slice(&id.to_be_bytes());
            let flags = u16::try_from(start / 8).unwrap() | if more { 0x2000 } else { 0 };
            header[6..8].copy_from_slice(&flags.to_be_bytes());
            header[8] = 64;
            header[9] = key.protocol;
            header[12..16].copy_from_slice(&key.source.octets());
            header[16..20].copy_from_slice(&key.destination.octets());
            Fragment::Ipv4(Ipv4Fragment {
                key,
                fragment_offset: u16::try_from(start / 8).unwrap(),
                more_fragments: more,
                header: Bytes::from(header),
                payload: Bytes::copy_from_slice(payload),
            })
        }
        Version::V6 => {
            let key = Ipv6DatagramKey {
                scope,
                source: Ipv6Addr::LOCALHOST,
                destination: "2001:db8::1".parse().unwrap(),
                identification: u32::from(id),
            };
            let mut prefix = vec![0; 40];
            prefix[0] = 0x60;
            prefix[4..6].copy_from_slice(&u16::try_from(8 + payload.len()).unwrap().to_be_bytes());
            prefix[6] = 44;
            prefix[7] = 64;
            prefix[8..24].copy_from_slice(&key.source.octets());
            prefix[24..40].copy_from_slice(&key.destination.octets());
            Fragment::Ipv6(Ipv6Fragment {
                key,
                fragment_offset: u16::try_from(start / 8).unwrap(),
                more_fragments: more,
                next_header: 17,
                unfragmentable_prefix: Bytes::from(prefix),
                predecessor_next_header_offset: 6,
                payload: Bytes::copy_from_slice(payload),
            })
        }
    }
}

fn key(version: Version, id: u16) -> DatagramKey {
    match fragment(version, id, 0, &[0; 8], true) {
        Fragment::Ipv4(f) => DatagramKey::Ipv4(f.key),
        Fragment::Ipv6(f) => DatagramKey::Ipv6(f.key),
    }
}

fn expected_wire(version: Version, id: u16, payload: &[u8]) -> Bytes {
    match fragment(version, id, 0, &[0; 8], true) {
        Fragment::Ipv4(f) => {
            let mut bytes = f.header.to_vec();
            bytes[2..4].copy_from_slice(&u16::try_from(20 + payload.len()).unwrap().to_be_bytes());
            bytes[6..8].fill(0);
            let mut sum = bytes
                .as_chunks::<2>()
                .0
                .iter()
                .map(|pair| u32::from(u16::from_be_bytes([pair[0], pair[1]])))
                .sum::<u32>();
            while sum >> 16 != 0 {
                sum = (sum & 0xffff) + (sum >> 16);
            }
            bytes[10..12].copy_from_slice(&(!(sum as u16)).to_be_bytes());
            bytes.extend_from_slice(payload);
            Bytes::from(bytes)
        }
        Fragment::Ipv6(f) => {
            let mut bytes = f.unfragmentable_prefix.to_vec();
            bytes[4..6].copy_from_slice(&u16::try_from(payload.len()).unwrap().to_be_bytes());
            bytes[6] = f.next_header;
            bytes.extend_from_slice(payload);
            Bytes::from(bytes)
        }
    }
}

struct Reference {
    version: Version,
    id: u16,
    policy: OverlapPolicy,
    payload: Vec<Option<u8>>,
    final_length: Option<usize>,
    fragment_count: usize,
    duplicates: usize,
    overlaps: usize,
}

impl Reference {
    fn new(version: Version, id: u16, policy: OverlapPolicy, length: usize) -> Self {
        Self {
            version,
            id,
            policy,
            payload: vec![None; length],
            final_length: None,
            fragment_count: 0,
            duplicates: 0,
            overlaps: 0,
        }
    }

    fn push(&mut self, start: usize, incoming: &[u8], more: bool) -> Result<PushOutcome, Error> {
        let mut added = 0;
        let mut conflicts = 0;
        for (old, new) in self.payload[start..start + incoming.len()]
            .iter()
            .zip(incoming)
        {
            match old {
                None => added += 1,
                Some(value) if value != new => conflicts += 1,
                _ => {}
            }
        }
        if conflicts != 0 && self.policy == OverlapPolicy::Reject {
            return Err(Malformed::ConflictingOverlap { bytes: conflicts }.into());
        }
        for (old, new) in self.payload[start..start + incoming.len()]
            .iter_mut()
            .zip(incoming)
        {
            if old.is_none() || self.policy == OverlapPolicy::Last {
                *old = Some(*new);
            }
        }
        self.fragment_count += 1;
        self.overlaps += conflicts;
        if !more {
            self.final_length = Some(start + incoming.len());
        }
        let disposition = if added == 0 && conflicts == 0 {
            self.duplicates += 1;
            FragmentDisposition::Duplicate {
                bytes: incoming.len(),
            }
        } else if conflicts != 0 {
            FragmentDisposition::OverlapResolved {
                policy: self.policy,
                affected_bytes: conflicts,
                added_bytes: added,
            }
        } else {
            FragmentDisposition::Accepted { added_bytes: added }
        };
        let unique_bytes = self.payload.iter().filter(|byte| byte.is_some()).count();
        let fragment = FragmentOutcome {
            key: key(self.version, self.id),
            disposition,
            fragment_count: self.fragment_count,
            unique_bytes,
            known_final_length: self.final_length,
        };
        if self.final_length == Some(unique_bytes) {
            let payload: Vec<u8> = self.payload.iter().map(|byte| byte.unwrap()).collect();
            let datagram = CompletedDatagram {
                key: key(self.version, self.id),
                bytes: expected_wire(self.version, self.id, &payload),
                fragment_count: self.fragment_count,
                unique_bytes,
                final_payload_length: payload.len(),
                duplicate_fragments: self.duplicates,
                overlap_bytes: self.overlaps,
            };
            Ok(PushOutcome::Completed { fragment, datagram })
        } else {
            Ok(PushOutcome::Accepted(fragment))
        }
    }
}

#[test]
fn fragment_traces_match_byte_reference() {
    let payload: Vec<u8> = (0..128).map(|index| (index * 13) as u8).collect();
    for version in [Version::V4, Version::V6] {
        for policy in [
            OverlapPolicy::Reject,
            OverlapPolicy::First,
            OverlapPolicy::Last,
        ] {
            for order in [
                vec![0, 1, 2, 3, 4, 5, 6, 7],
                vec![7, 6, 5, 4, 3, 2, 1, 0],
                vec![3, 7, 1, 5, 0, 6, 2, 4],
            ] {
                let mut actual = Reassembler::new(Limits::default(), policy).unwrap();
                let mut reference = Reference::new(version, 9, policy, payload.len());
                for (position, chunk) in order.into_iter().enumerate() {
                    let start = chunk * 16;
                    let bytes = &payload[start..start + 16];
                    let more = start + 16 != payload.len();
                    let now = Instant::now();
                    assert_eq!(
                        actual.push(fragment(version, 9, start, bytes, more), now),
                        reference.push(start, bytes, more),
                        "{version:?} {policy:?} chunk {chunk}"
                    );
                    if position == 1 {
                        assert_eq!(
                            actual.push(fragment(version, 9, start, bytes, more), now),
                            reference.push(start, bytes, more)
                        );
                        let mut changed = bytes.to_vec();
                        changed[3] ^= 0xff;
                        assert_eq!(
                            actual.push(fragment(version, 9, start, &changed, more), now),
                            reference.push(start, &changed, more)
                        );
                    }
                }
                assert_eq!(actual.datagram_count(), 0);
                assert_eq!(actual.aggregate_payload_bytes(), 0);
            }
        }
    }
}

#[test]
fn reverse_fragment_payload_copying_scales_linearly() {
    for count in [16usize, 64, 256, 1024] {
        let limits = Limits {
            max_fragments_per_datagram: count,
            ..Limits::default()
        };
        let mut reassembler = Reassembler::new(limits, OverlapPolicy::Reject).unwrap();
        merge::PAYLOAD_COPIED.with(|copied| copied.set(0));
        let mut baseline = None;
        for index in (0..count).rev() {
            let start = index * 8;
            let outcome = reassembler
                .push(
                    fragment(Version::V4, 1, start, &[index as u8; 8], index + 1 != count),
                    Instant::now(),
                )
                .unwrap();
            if let PushOutcome::Accepted(_) = outcome {
                let payload = reassembler.aggregate_payload_bytes();
                let fixed =
                    *baseline.get_or_insert(reassembler.aggregate_memory_charge() - payload);
                assert!(reassembler.aggregate_memory_charge() <= fixed + 2 * payload);
            } else {
                assert_eq!(index, 0);
            }
        }
        let copied = merge::PAYLOAD_COPIED.with(std::cell::Cell::get);
        assert!(
            copied <= 3 * count * 8,
            "{count} fragments copied {copied} bytes"
        );
        assert_eq!(reassembler.aggregate_payload_bytes(), 0);
    }
}

#[test]
fn reverse_fragments_copy_linearly_within_budget() {
    for count in [96usize, 192, 384, 768] {
        let payload_length = count * 8;
        let previous_capacity = payload_length.next_power_of_two() / 2;
        let limit = super::super::DATAGRAM_METADATA_CHARGE
            + 2 * super::super::RANGE_METADATA_CHARGE
            + previous_capacity
            + payload_length
            + 32;
        let limits = Limits {
            max_fragments_per_datagram: count,
            max_aggregate_bytes: limit,
            ..Limits::default()
        };
        let mut r = Reassembler::new(limits, OverlapPolicy::Reject).unwrap();
        merge::PAYLOAD_COPIED.with(|copied| copied.set(0));
        for index in (1..=count).rev() {
            r.push(
                fragment(Version::V4, 1, index * 8, &[index as u8; 8], true),
                Instant::now(),
            )
            .unwrap();
            assert!(r.aggregate_memory_charge() <= limit);
        }
        let copied = merge::PAYLOAD_COPIED.with(std::cell::Cell::get);
        assert!(
            copied <= 3 * payload_length,
            "{count} fragments copied {copied} bytes"
        );
        assert_eq!(r.aggregate_payload_bytes(), payload_length);
    }
}

#[test]
fn overlapping_fragments_respect_byte_precedence() {
    let payload: Vec<u8> = (0..64).map(|index| index as u8).collect();
    for version in [Version::V4, Version::V6] {
        for policy in [
            OverlapPolicy::Reject,
            OverlapPolicy::First,
            OverlapPolicy::Last,
        ] {
            let mut actual = Reassembler::new(Limits::default(), policy).unwrap();
            let mut reference = Reference::new(version, 10, policy, payload.len());
            let now = Instant::now();
            for start in [0, 32] {
                let bytes = &payload[start..start + 16];
                assert_eq!(
                    actual.push(fragment(version, 10, start, bytes, true), now),
                    reference.push(start, bytes, true)
                );
            }
            let mut bridge = payload[8..40].to_vec();
            bridge[0] ^= 0xff;
            bridge[24] ^= 0xff;
            assert_eq!(
                actual.push(fragment(version, 10, 8, &bridge, true), now),
                reference.push(8, &bridge, true)
            );
            if policy == OverlapPolicy::Reject {
                assert_eq!(
                    actual.push(fragment(version, 10, 16, &payload[16..32], true), now),
                    reference.push(16, &payload[16..32], true)
                );
            }
            assert_eq!(
                actual.push(fragment(version, 10, 48, &payload[48..], false), now),
                reference.push(48, &payload[48..], false)
            );
        }
    }
}

#[test]
fn capacity_limits_reject_growth_transactionally() {
    for (limit, succeeds) in [(4263, false), (4268, true)] {
        let limits = Limits {
            max_aggregate_bytes: limit,
            ..Limits::default()
        };
        let mut r = Reassembler::new(limits, OverlapPolicy::Reject).unwrap();
        let now = Instant::now();
        for start in [64, 56] {
            r.push(
                fragment(Version::V4, 2, start, &[start as u8; 8], true),
                now,
            )
            .unwrap();
        }
        let third = r.push(fragment(Version::V4, 2, 48, &[48; 8], true), now);
        assert_eq!(third.is_ok(), succeeds);
        assert!(r.aggregate_memory_charge() <= limit);
        if !succeeds {
            assert!(matches!(
                third,
                Err(Error::Resource(Resource::AggregateMemoryLimit { .. }))
            ));
            let duplicate = r
                .push(fragment(Version::V4, 2, 56, &[56; 8], true), now)
                .unwrap();
            assert!(matches!(
                duplicate,
                PushOutcome::Accepted(FragmentOutcome {
                    disposition: FragmentDisposition::Duplicate { bytes: 8 },
                    fragment_count: 3,
                    unique_bytes: 16,
                    ..
                })
            ));
        }
    }
}

#[test]
fn completion_growth_respects_datagram_peak() {
    let limits = Limits {
        max_aggregate_bytes: 4332,
        ..Limits::default()
    };
    let mut r = Reassembler::new(limits, OverlapPolicy::Reject).unwrap();
    let now = Instant::now();
    r.push(fragment(Version::V4, 2, 16, &[2; 8], false), now)
        .unwrap();
    r.push(fragment(Version::V4, 2, 8, &[1; 8], true), now)
        .unwrap();
    let outcome = r
        .push(fragment(Version::V4, 2, 0, &[0; 8], true), now)
        .unwrap();
    let PushOutcome::Completed { datagram, .. } = outcome else {
        panic!("datagram was not completed")
    };
    assert_eq!(
        &datagram.bytes[20..],
        &[
            0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2
        ]
    );
    assert_eq!(r.aggregate_payload_bytes(), 0);
}

#[test]
fn limits_expiry_and_flush_preserve_outcomes() {
    let limits = Limits {
        max_datagrams: 2,
        max_fragments_per_datagram: 2,
        max_bytes_per_datagram: 64,
        max_retained_outcomes: 1,
        idle_expiry: Duration::from_secs(5),
        ..Limits::default()
    };
    let mut r = Reassembler::new(limits, OverlapPolicy::Reject).unwrap();
    let now = Instant::now();
    r.push(fragment(Version::V4, 1, 8, &[1; 8], true), now)
        .unwrap();
    r.push(
        fragment(Version::V4, 2, 8, &[2; 8], true),
        now + Duration::from_secs(1),
    )
    .unwrap();
    assert!(matches!(
        r.push(fragment(Version::V4, 3, 8, &[3; 8], true), now),
        Err(Error::Resource(Resource::DatagramLimit { .. }))
    ));
    r.push(fragment(Version::V4, 1, 8, &[1; 8], true), now)
        .unwrap();
    assert!(matches!(
        r.push(fragment(Version::V4, 1, 16, &[1; 8], true), now),
        Err(Error::Resource(Resource::FragmentLimit { .. }))
    ));
    assert!(matches!(
        r.push(fragment(Version::V4, 2, 64, &[2; 8], true), now),
        Err(Error::Resource(Resource::DatagramByteLimit { .. }))
    ));
    let expired = r.expire(now + Duration::from_secs(5));
    assert_eq!(
        expired.outcomes,
        vec![IncompleteDatagram {
            key: key(Version::V4, 1),
            reason: IncompleteReason::IdleExpired,
            fragment_count: 2,
            unique_bytes: 8,
            known_final_length: None,
            duplicate_fragments: 1,
            overlap_bytes: 0
        }]
    );
    r.push(
        fragment(Version::V4, 3, 8, &[3; 8], true),
        now + Duration::from_secs(5),
    )
    .unwrap();
    let flushed = r.flush();
    assert_eq!(
        flushed.outcomes,
        vec![IncompleteDatagram {
            key: key(Version::V4, 2),
            reason: IncompleteReason::EndOfCapture,
            fragment_count: 1,
            unique_bytes: 8,
            known_final_length: None,
            duplicate_fragments: 0,
            overlap_bytes: 0
        }]
    );
    assert_eq!(flushed.omitted_ipv4, 1);
    assert_eq!(r.datagram_count(), 0);
    assert_eq!(r.aggregate_payload_bytes(), 0);
}
