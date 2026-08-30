// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use bytes::Bytes;
use packetcraftr_core::analysis::reassembly::Limits;
use packetcraftr_core::analysis::reassembly::ip::{
    DatagramKey, Error, Family, Fragment, FragmentDisposition, IncompleteReason, Ipv4DatagramKey,
    Ipv4Fragment, Ipv6DatagramKey, Ipv6Fragment, MalformedError, OverlapPolicy, PushOutcome,
    Reassembler, ResourceError,
};
use packetcraftr_core::analysis::scope::{Interner, ScopeId};
use proptest::prelude::*;

fn scope() -> ScopeId {
    Interner::new()
        .intern(None, Vec::new())
        .expect("one empty scope fits")
}

fn ipv4_key() -> Ipv4DatagramKey {
    Ipv4DatagramKey {
        scope: scope(),
        source: Ipv4Addr::new(192, 0, 2, 1),
        destination: Ipv4Addr::new(198, 51, 100, 2),
        identification: 0x1234,
        protocol: 17,
    }
}

fn ipv4_header(
    key: &Ipv4DatagramKey,
    offset: u16,
    more_fragments: bool,
    payload_length: usize,
) -> Bytes {
    let total_length = u16::try_from(20 + payload_length).expect("fixture IPv4 length fits");
    let mut header = vec![0_u8; 20];
    header[0] = 0x45;
    header[2..4].copy_from_slice(&total_length.to_be_bytes());
    header[4..6].copy_from_slice(&key.identification.to_be_bytes());
    let flags_offset = offset | if more_fragments { 0x2000 } else { 0 };
    header[6..8].copy_from_slice(&flags_offset.to_be_bytes());
    header[8] = 64;
    header[9] = key.protocol;
    header[12..16].copy_from_slice(&key.source.octets());
    header[16..20].copy_from_slice(&key.destination.octets());
    let checksum = packetcraftr_core::protocol::checksum(&header);
    header[10..12].copy_from_slice(&checksum.to_be_bytes());
    Bytes::from(header)
}

fn ipv4_header_with_options(
    key: &Ipv4DatagramKey,
    offset: u16,
    more_fragments: bool,
    payload_length: usize,
    options: &[u8],
) -> Bytes {
    assert_eq!(options.len() % 4, 0, "fixture options are word aligned");
    let header_length = 20 + options.len();
    let total_length =
        u16::try_from(header_length + payload_length).expect("fixture IPv4 length fits");
    let mut header = vec![0_u8; header_length];
    header[0] = 0x40 | u8::try_from(header_length / 4).expect("fixture IHL fits");
    header[2..4].copy_from_slice(&total_length.to_be_bytes());
    header[4..6].copy_from_slice(&key.identification.to_be_bytes());
    let flags_offset = offset | if more_fragments { 0x2000 } else { 0 };
    header[6..8].copy_from_slice(&flags_offset.to_be_bytes());
    header[8] = 64;
    header[9] = key.protocol;
    header[12..16].copy_from_slice(&key.source.octets());
    header[16..20].copy_from_slice(&key.destination.octets());
    header[20..].copy_from_slice(options);
    let checksum = packetcraftr_core::protocol::checksum(&header);
    header[10..12].copy_from_slice(&checksum.to_be_bytes());
    Bytes::from(header)
}

fn ipv4_fragment(
    key: &Ipv4DatagramKey,
    offset: u16,
    more_fragments: bool,
    payload: impl Into<Bytes>,
) -> Fragment {
    let payload = payload.into();
    Fragment::Ipv4(Ipv4Fragment {
        key: key.clone(),
        fragment_offset: offset,
        more_fragments,
        header: ipv4_header(key, offset, more_fragments, payload.len()),
        payload,
    })
}

fn ipv6_key() -> Ipv6DatagramKey {
    Ipv6DatagramKey {
        scope: scope(),
        source: "2001:db8::1".parse().expect("fixture source"),
        destination: "2001:db8::2".parse().expect("fixture destination"),
        identification: 0x1234_5678,
    }
}

fn ipv6_prefix(key: &Ipv6DatagramKey, fragment_payload_length: usize) -> Bytes {
    let payload_length = u16::try_from(8 + fragment_payload_length).expect("fixture length fits");
    let mut prefix = vec![0_u8; 40];
    prefix[0] = 0x60;
    prefix[4..6].copy_from_slice(&payload_length.to_be_bytes());
    prefix[6] = 44;
    prefix[7] = 64;
    prefix[8..24].copy_from_slice(&key.source.octets());
    prefix[24..40].copy_from_slice(&key.destination.octets());
    Bytes::from(prefix)
}

fn ipv6_prefix_with_destination_options(
    key: &Ipv6DatagramKey,
    fragment_payload_length: usize,
) -> Bytes {
    let payload_length =
        u16::try_from(8 + 8 + fragment_payload_length).expect("fixture length fits");
    let mut prefix = vec![0_u8; 48];
    prefix[0] = 0x60;
    prefix[4..6].copy_from_slice(&payload_length.to_be_bytes());
    prefix[6] = 60;
    prefix[7] = 64;
    prefix[8..24].copy_from_slice(&key.source.octets());
    prefix[24..40].copy_from_slice(&key.destination.octets());
    prefix[40] = 44;
    prefix[41] = 0;
    Bytes::from(prefix)
}

fn ipv6_fragment(
    key: &Ipv6DatagramKey,
    offset: u16,
    more_fragments: bool,
    payload: impl Into<Bytes>,
) -> Fragment {
    let payload = payload.into();
    Fragment::Ipv6(Ipv6Fragment {
        key: key.clone(),
        fragment_offset: offset,
        more_fragments,
        next_header: 17,
        unfragmentable_prefix: ipv6_prefix(key, payload.len()),
        predecessor_next_header_offset: 6,
        payload,
    })
}

fn completed(
    outcome: PushOutcome,
) -> packetcraftr_core::analysis::reassembly::ip::CompletedDatagram {
    match outcome {
        PushOutcome::Completed { datagram, .. } => datagram,
        PushOutcome::Accepted(_) => panic!("fixture expected completion"),
    }
}

#[test]
fn ipv4_out_of_order_completion_reconstructs_a_normalized_datagram() {
    let key = ipv4_key();
    let now = Instant::now();
    let mut reassembler = Reassembler::new(Limits::default(), OverlapPolicy::Reject);
    let tail = reassembler
        .push(ipv4_fragment(&key, 1, false, &b"ijkl"[..]), now)
        .expect("tail is retained with a gap");
    assert!(matches!(tail, PushOutcome::Accepted(_)));

    let datagram = completed(
        reassembler
            .push(ipv4_fragment(&key, 0, true, &b"abcdefgh"[..]), now)
            .expect("first fragment fills the gap"),
    );
    assert_eq!(datagram.key, DatagramKey::Ipv4(key));
    assert_eq!(datagram.fragment_count, 2);
    assert_eq!(datagram.unique_bytes, 12);
    assert_eq!(datagram.final_payload_length, 12);
    assert_eq!(datagram.bytes.len(), 32);
    assert_eq!(&datagram.bytes[2..4], &32_u16.to_be_bytes());
    assert_eq!(&datagram.bytes[6..8], &[0, 0]);
    assert_eq!(
        packetcraftr_core::protocol::checksum(&datagram.bytes[..20]),
        0
    );
    assert_eq!(&datagram.bytes[20..], b"abcdefghijkl");
    assert_eq!(reassembler.datagram_count(), 0);
    assert_eq!(
        reassembler.aggregate_memory_charge(),
        4_096,
        "the reusable hash-table high-water slot remains charged"
    );
}

#[test]
fn separated_out_of_order_ranges_remain_sorted_and_complete() {
    let key = ipv4_key();
    let now = Instant::now();
    let mut reassembler = Reassembler::new(Limits::default(), OverlapPolicy::Reject);
    for (offset, more_fragments, payload) in [
        (3, false, &b"yz12"[..]),
        (0, true, &b"abcdefgh"[..]),
        (1, true, &b"ijklmnop"[..]),
    ] {
        let outcome = reassembler
            .push(ipv4_fragment(&key, offset, more_fragments, payload), now)
            .expect("out-of-order fragment is retained");
        assert!(matches!(outcome, PushOutcome::Accepted(_)));
    }

    let datagram = completed(
        reassembler
            .push(ipv4_fragment(&key, 2, true, &b"qrstuvwx"[..]), now)
            .expect("last gap completes the datagram"),
    );
    assert_eq!(&datagram.bytes[20..], b"abcdefghijklmnopqrstuvwxyz12");
}

#[test]
fn retained_reconstruction_bytes_do_not_pin_capture_storage() {
    let now = Instant::now();

    let ipv4_key = ipv4_key();
    let ipv4_header = ipv4_header(&ipv4_key, 0, true, 8);
    let mut ipv4_frame = vec![0_u8; 4096];
    ipv4_frame[..ipv4_header.len()].copy_from_slice(&ipv4_header);
    let ipv4_frame = Bytes::from(ipv4_frame);
    let mut ipv4 = Reassembler::new(Limits::default(), OverlapPolicy::Reject);
    ipv4.push(
        Fragment::Ipv4(Ipv4Fragment {
            key: ipv4_key,
            fragment_offset: 0,
            more_fragments: true,
            header: ipv4_frame.slice(..ipv4_header.len()),
            payload: Bytes::from_static(b"abcdefgh"),
        }),
        now,
    )
    .expect("IPv4 fragment is retained");
    assert!(ipv4_frame.is_unique());

    let ipv6_key = ipv6_key();
    let ipv6_prefix = ipv6_prefix(&ipv6_key, 8);
    let mut ipv6_frame = vec![0_u8; 4096];
    ipv6_frame[..ipv6_prefix.len()].copy_from_slice(&ipv6_prefix);
    let ipv6_frame = Bytes::from(ipv6_frame);
    let mut ipv6 = Reassembler::new(Limits::default(), OverlapPolicy::Reject);
    ipv6.push(
        Fragment::Ipv6(Ipv6Fragment {
            key: ipv6_key,
            fragment_offset: 0,
            more_fragments: true,
            next_header: 17,
            unfragmentable_prefix: ipv6_frame.slice(..ipv6_prefix.len()),
            predecessor_next_header_offset: 6,
            payload: Bytes::from_static(b"abcdefgh"),
        }),
        now,
    )
    .expect("IPv6 fragment is retained");
    assert!(ipv6_frame.is_unique());
}

#[test]
fn identical_datagram_tuples_never_cross_exact_capture_scopes() {
    let mut interner = Interner::new();
    let first_scope = interner
        .intern(Some(1), Vec::new())
        .expect("first interface scope fits");
    let second_scope = interner
        .intern(Some(2), Vec::new())
        .expect("second interface scope fits");
    let mut first_key = ipv4_key();
    first_key.scope = first_scope;
    let mut second_key = first_key.clone();
    second_key.scope = second_scope;
    let now = Instant::now();
    let mut reassembler = Reassembler::new(Limits::default(), OverlapPolicy::Reject);

    reassembler
        .push(ipv4_fragment(&first_key, 0, true, &b"aaaaaaaa"[..]), now)
        .expect("first scope prefix is retained");
    reassembler
        .push(ipv4_fragment(&second_key, 1, false, &b"bbbb"[..]), now)
        .expect("second scope tail is independently retained");
    assert_eq!(reassembler.datagram_count(), 2);

    let first = completed(
        reassembler
            .push(ipv4_fragment(&first_key, 1, false, &b"cccc"[..]), now)
            .expect("first scope completes only with its own tail"),
    );
    let second = completed(
        reassembler
            .push(ipv4_fragment(&second_key, 0, true, &b"dddddddd"[..]), now)
            .expect("second scope completes only with its own prefix"),
    );
    assert_eq!(&first.bytes[20..], b"aaaaaaaacccc");
    assert_eq!(&second.bytes[20..], b"ddddddddbbbb");
}

#[test]
fn ipv6_completion_removes_fragment_header_and_patches_its_predecessor() {
    let key = ipv6_key();
    let now = Instant::now();
    let mut reassembler = Reassembler::new(Limits::default(), OverlapPolicy::Reject);
    reassembler
        .push(ipv6_fragment(&key, 0, true, &b"abcdefgh"[..]), now)
        .expect("first fragment is retained");
    let datagram = completed(
        reassembler
            .push(ipv6_fragment(&key, 1, false, &b"ijkl"[..]), now)
            .expect("tail completes"),
    );

    assert_eq!(datagram.key, DatagramKey::Ipv6(key));
    assert_eq!(datagram.bytes.len(), 52);
    assert_eq!(&datagram.bytes[4..6], &12_u16.to_be_bytes());
    assert_eq!(datagram.bytes[6], 17);
    assert_eq!(&datagram.bytes[40..], b"abcdefghijkl");
}

#[test]
fn reconstruction_preserves_ipv4_options_and_ipv6_extension_prefixes() {
    let now = Instant::now();
    let ipv4_key = ipv4_key();
    let mut ipv4 = Reassembler::new(Limits::default(), OverlapPolicy::Reject);
    ipv4.push(ipv4_fragment(&ipv4_key, 1, false, &b"ijkl"[..]), now)
        .expect("optionless tail is retained");
    let first_payload = Bytes::from_static(b"abcdefgh");
    let first_header =
        ipv4_header_with_options(&ipv4_key, 0, true, first_payload.len(), &[1, 1, 0, 0]);
    let datagram = completed(
        ipv4.push(
            Fragment::Ipv4(Ipv4Fragment {
                key: ipv4_key,
                fragment_offset: 0,
                more_fragments: true,
                header: first_header,
                payload: first_payload,
            }),
            now,
        )
        .expect("first fragment completes with its options"),
    );
    assert_eq!(datagram.bytes[0] & 0x0f, 6);
    assert_eq!(&datagram.bytes[20..24], &[1, 1, 0, 0]);
    assert_eq!(&datagram.bytes[24..], b"abcdefghijkl");
    assert_eq!(
        packetcraftr_core::protocol::checksum(&datagram.bytes[..24]),
        0
    );

    let ipv6_key = ipv6_key();
    let make_fragment = |offset, more_fragments, payload: Bytes| {
        Fragment::Ipv6(Ipv6Fragment {
            key: ipv6_key.clone(),
            fragment_offset: offset,
            more_fragments,
            next_header: 17,
            unfragmentable_prefix: ipv6_prefix_with_destination_options(&ipv6_key, payload.len()),
            predecessor_next_header_offset: 40,
            payload,
        })
    };
    let mut ipv6 = Reassembler::new(Limits::default(), OverlapPolicy::Reject);
    ipv6.push(make_fragment(0, true, Bytes::from_static(b"abcdefgh")), now)
        .expect("prefixed first fragment is retained");
    let datagram = completed(
        ipv6.push(make_fragment(1, false, Bytes::from_static(b"ijkl")), now)
            .expect("prefixed tail completes"),
    );
    assert_eq!(&datagram.bytes[4..6], &20_u16.to_be_bytes());
    assert_eq!(datagram.bytes[6], 60);
    assert_eq!(datagram.bytes[40], 17);
    assert_eq!(&datagram.bytes[48..], b"abcdefghijkl");
}

#[test]
fn overlap_policies_reject_keep_first_or_keep_last_and_report_changed_bytes() {
    let key = ipv4_key();
    let now = Instant::now();
    for (policy, expected) in [
        (OverlapPolicy::First, &b"abcdefgh"[..]),
        (OverlapPolicy::Last, &b"ABcdefgh"[..]),
    ] {
        let mut reassembler = Reassembler::new(Limits::default(), policy);
        reassembler
            .push(ipv4_fragment(&key, 0, true, &b"abcdefgh"[..]), now)
            .expect("first copy is retained");
        let resolution = reassembler
            .push(ipv4_fragment(&key, 0, true, &b"ABcdefgh"[..]), now)
            .expect("policy resolves conflicting bytes");
        assert!(matches!(
            resolution,
            PushOutcome::Accepted(ref outcome)
                if outcome.disposition == FragmentDisposition::OverlapResolved {
                    policy,
                    affected_bytes: 2,
                    added_bytes: 0,
                }
        ));
        let datagram = completed(
            reassembler
                .push(ipv4_fragment(&key, 1, false, &b"ijkl"[..]), now)
                .expect("tail completes"),
        );
        assert_eq!(&datagram.bytes[20..28], expected);
        assert_eq!(datagram.overlap_bytes, 2);
    }

    let mut reject = Reassembler::new(Limits::default(), OverlapPolicy::Reject);
    reject
        .push(ipv4_fragment(&key, 0, true, &b"abcdefgh"[..]), now)
        .expect("first copy is retained");
    assert_eq!(
        reject.push(ipv4_fragment(&key, 0, true, &b"ABcdefgh"[..]), now),
        Err(Error::Malformed(MalformedError::ConflictingOverlap {
            bytes: 2
        }))
    );
    assert_eq!(reject.datagram_count(), 1, "rejected input is atomic");
}

#[test]
fn ipv4_overlap_ignores_per_fragment_normalized_header_fields() {
    let key = ipv4_key();
    let now = Instant::now();
    let mut reassembler = Reassembler::new(Limits::default(), OverlapPolicy::Last);
    reassembler
        .push(ipv4_fragment(&key, 0, true, &b"abcdefghijklmnop"[..]), now)
        .expect("long first fragment is retained");
    let outcome = reassembler
        .push(ipv4_fragment(&key, 0, true, &b"ABcdefgh"[..]), now)
        .expect("length and checksum differences are reconstruction-normalized");
    assert!(matches!(
        outcome,
        PushOutcome::Accepted(ref outcome)
            if outcome.disposition == FragmentDisposition::OverlapResolved {
                policy: OverlapPolicy::Last,
                affected_bytes: 2,
                added_bytes: 0,
            }
    ));
}

#[test]
fn identical_duplicates_count_without_retaining_payload_twice() {
    let key = ipv4_key();
    let now = Instant::now();
    let mut reassembler = Reassembler::new(Limits::default(), OverlapPolicy::Reject);
    reassembler
        .push(ipv4_fragment(&key, 0, true, &b"abcdefgh"[..]), now)
        .expect("first copy is retained");
    let retained_before = reassembler.aggregate_payload_bytes();
    let duplicate = reassembler
        .push(ipv4_fragment(&key, 0, true, &b"abcdefgh"[..]), now)
        .expect("identical copy is accepted as duplicate");
    assert!(matches!(
        duplicate,
        PushOutcome::Accepted(ref outcome)
            if outcome.fragment_count == 2
                && outcome.disposition == FragmentDisposition::Duplicate { bytes: 8 }
    ));
    assert_eq!(reassembler.aggregate_payload_bytes(), retained_before);
    let datagram = completed(
        reassembler
            .push(ipv4_fragment(&key, 1, false, &b"ijkl"[..]), now)
            .expect("tail completes"),
    );
    assert_eq!(datagram.fragment_count, 3);
    assert_eq!(datagram.duplicate_fragments, 1);
}

#[test]
fn idle_and_eof_retirement_report_bounded_gap_evidence() {
    let key = ipv4_key();
    let now = Instant::now();
    let limits = Limits {
        ip_idle_expiry: Duration::from_secs(2),
        ..Limits::default()
    };
    let mut reassembler = Reassembler::new(limits, OverlapPolicy::Reject);
    reassembler
        .push(ipv4_fragment(&key, 1, false, &b"ijkl"[..]), now)
        .expect("tail with gap is retained");
    assert!(
        reassembler
            .expire(now + Duration::from_secs(1))
            .outcomes
            .is_empty()
    );
    let expired = reassembler.expire(now + Duration::from_secs(2));
    assert_eq!(expired.outcomes.len(), 1);
    assert_eq!(expired.outcomes[0].reason, IncompleteReason::IdleExpired);
    assert_eq!(expired.outcomes[0].fragment_count, 1);
    assert_eq!(expired.outcomes[0].unique_bytes, 4);
    assert_eq!(expired.outcomes[0].known_final_length, Some(12));
    assert!(reassembler.flush().outcomes.is_empty());

    reassembler
        .push(ipv4_fragment(&key, 0, true, &b"abcdefgh"[..]), now)
        .expect("new partial datagram is retained");
    let flushed = reassembler.flush();
    assert_eq!(flushed.outcomes.len(), 1);
    assert_eq!(flushed.outcomes[0].reason, IncompleteReason::EndOfCapture);
    assert_eq!(flushed.outcomes[0].known_final_length, None);
}

#[test]
fn resource_limits_reject_before_retaining_new_payload() {
    let key = ipv4_key();
    let now = Instant::now();
    let mut datagrams = Reassembler::new(
        Limits {
            max_ip_datagrams: 0,
            ..Limits::default()
        },
        OverlapPolicy::Reject,
    );
    assert_eq!(
        datagrams.push(ipv4_fragment(&key, 0, true, &b"abcdefgh"[..]), now),
        Err(Error::Resource(ResourceError::DatagramLimit { limit: 0 }))
    );
    assert_eq!(datagrams.aggregate_payload_bytes(), 0);

    let mut bytes = Reassembler::new(
        Limits {
            max_ip_bytes_per_datagram: 7,
            ..Limits::default()
        },
        OverlapPolicy::Reject,
    );
    assert_eq!(
        bytes.push(ipv4_fragment(&key, 0, true, &b"abcdefgh"[..]), now),
        Err(Error::Resource(ResourceError::DatagramByteLimit {
            limit: 7
        }))
    );
    assert_eq!(bytes.datagram_count(), 0);

    let mut aggregate = Reassembler::new(
        Limits {
            // 4,096 collection metadata + 64 range + 20 header + 8 payload.
            max_ip_aggregate_bytes: 4_187,
            ..Limits::default()
        },
        OverlapPolicy::Reject,
    );
    assert_eq!(
        aggregate.push(ipv4_fragment(&key, 0, true, &b"abcdefgh"[..]), now),
        Err(Error::Resource(ResourceError::AggregateMemoryLimit {
            limit: 4_187
        }))
    );
    assert_eq!(aggregate.datagram_count(), 0);

    let mut fragments = Reassembler::new(
        Limits {
            max_ip_fragments_per_datagram: 1,
            ..Limits::default()
        },
        OverlapPolicy::Reject,
    );
    fragments
        .push(ipv4_fragment(&key, 0, true, &b"abcdefgh"[..]), now)
        .expect("first fragment fits the limit");
    let retained = fragments.aggregate_memory_charge();
    assert_eq!(
        fragments.push(ipv4_fragment(&key, 0, true, &b"abcdefgh"[..]), now),
        Err(Error::Resource(ResourceError::FragmentLimit { limit: 1 }))
    );
    assert_eq!(fragments.datagram_count(), 1);
    assert_eq!(fragments.aggregate_memory_charge(), retained);
}

#[test]
fn aggregate_limit_covers_replacement_and_completion_peak_allocations() {
    let key = ipv4_key();
    let now = Instant::now();
    let limit = 4_295;
    let mut reassembler = Reassembler::new(
        Limits {
            max_ip_aggregate_bytes: limit,
            ..Limits::default()
        },
        OverlapPolicy::Reject,
    );
    reassembler
        .push(ipv4_fragment(&key, 0, true, &b"abcdefgh"[..]), now)
        .expect("the first retained range fits");
    let retained = reassembler.aggregate_memory_charge();

    assert_eq!(
        reassembler.push(ipv4_fragment(&key, 1, false, &b"tail"[..]), now),
        Err(Error::Resource(ResourceError::AggregateMemoryLimit {
            limit
        }))
    );
    assert_eq!(reassembler.datagram_count(), 1);
    assert_eq!(reassembler.aggregate_memory_charge(), retained);
}

#[test]
fn removed_datagrams_keep_hash_table_high_water_memory_charged() {
    let first = ipv4_key();
    let mut second = first.clone();
    second.identification = second.identification.saturating_add(1);
    let mut third = second.clone();
    third.identification = third.identification.saturating_add(1);
    let now = Instant::now();
    let mut reassembler = Reassembler::new(
        Limits {
            max_ip_datagrams: 2,
            max_ip_aggregate_bytes: 8_400,
            ..Limits::default()
        },
        OverlapPolicy::Reject,
    );
    reassembler
        .push(ipv4_fragment(&first, 0, true, &b"abcdefgh"[..]), now)
        .expect("first high-water slot fits");
    reassembler
        .push(ipv4_fragment(&second, 0, true, &b"abcdefgh"[..]), now)
        .expect("second high-water slot fits");
    assert_eq!(reassembler.flush().outcomes.len(), 2);
    assert_eq!(reassembler.datagram_count(), 0);
    assert_eq!(reassembler.aggregate_memory_charge(), 8_192);

    reassembler
        .push(ipv4_fragment(&third, 0, true, &b"abcdefgh"[..]), now)
        .expect("a retained table slot can be reused without another charge");
    assert_eq!(reassembler.aggregate_memory_charge(), 8_284);
}

#[test]
fn malformed_lengths_and_final_offsets_fail_closed_without_destroying_old_state() {
    let key = ipv4_key();
    let now = Instant::now();
    let mut reassembler = Reassembler::new(Limits::default(), OverlapPolicy::Reject);
    assert_eq!(
        reassembler.push(ipv4_fragment(&key, 0, true, Bytes::new()), now),
        Err(Error::Malformed(MalformedError::EmptyPayload))
    );
    assert_eq!(
        reassembler.push(ipv4_fragment(&key, 0, true, &b"seven!!"[..]), now),
        Err(Error::Malformed(MalformedError::UnalignedNonFinal {
            length: 7
        }))
    );

    reassembler
        .push(ipv4_fragment(&key, 2, false, &b"tail"[..]), now)
        .expect("first final length is retained");
    assert_eq!(
        reassembler.push(ipv4_fragment(&key, 1, false, &b"tail"[..]), now),
        Err(Error::Malformed(MalformedError::ConflictingFinalLength {
            existing: 20,
            new: 12
        }))
    );
    assert_eq!(reassembler.flush().outcomes[0].known_final_length, Some(20));

    let mut oversized = Reassembler::new(Limits::default(), OverlapPolicy::Reject);
    assert_eq!(
        oversized.push(ipv4_fragment(&key, 0x1fff, false, &b"1234567"[..]), now),
        Err(Error::Malformed(MalformedError::ReconstructedLength {
            family: packetcraftr_core::analysis::reassembly::ip::Family::Ipv4
        }))
    );
    assert_eq!(oversized.datagram_count(), 0);
}

#[test]
fn first_ipv4_header_revalidates_the_retained_wire_extent() {
    let key = ipv4_key();
    let now = Instant::now();
    let mut reassembler = Reassembler::new(Limits::default(), OverlapPolicy::Reject);
    reassembler
        .push(ipv4_fragment(&key, 8_187, true, &b"abcdefgh"[..]), now)
        .expect("the high range fits with the minimum IPv4 header");
    let retained = reassembler.aggregate_memory_charge();

    let payload = Bytes::from_static(b"abcdefgh");
    let first = Fragment::Ipv4(Ipv4Fragment {
        key: key.clone(),
        fragment_offset: 0,
        more_fragments: true,
        header: ipv4_header_with_options(&key, 0, true, payload.len(), &[0_u8; 40]),
        payload,
    });
    assert_eq!(
        reassembler.push(first, now),
        Err(Error::Malformed(MalformedError::ReconstructedLength {
            family: Family::Ipv4,
        }))
    );
    assert_eq!(reassembler.datagram_count(), 1);
    assert_eq!(reassembler.aggregate_memory_charge(), retained);
}

#[test]
fn repeated_first_ipv4_headers_must_agree_on_preserved_flags() {
    let key = ipv4_key();
    let now = Instant::now();
    let first = ipv4_fragment(&key, 0, true, &b"abcdefgh"[..]);
    let mut conflicting = match ipv4_fragment(&key, 0, true, &b"abcdefgh"[..]) {
        Fragment::Ipv4(fragment) => fragment,
        Fragment::Ipv6(_) => unreachable!(),
    };
    let mut header = conflicting.header.to_vec();
    let flags_offset = u16::from_be_bytes([header[6], header[7]]) | 0x4000;
    header[6..8].copy_from_slice(&flags_offset.to_be_bytes());
    header[10..12].fill(0);
    let checksum = packetcraftr_core::protocol::checksum(&header);
    header[10..12].copy_from_slice(&checksum.to_be_bytes());
    conflicting.header = Bytes::from(header);

    let mut reassembler = Reassembler::new(Limits::default(), OverlapPolicy::Reject);
    reassembler
        .push(first, now)
        .expect("the first offset-zero fragment is retained");
    assert_eq!(
        reassembler.push(Fragment::Ipv4(conflicting), now),
        Err(Error::Malformed(MalformedError::InconsistentIpv4Header))
    );
}

#[test]
fn known_final_length_rejects_beyond_and_nonfinal_data_atomically() {
    let key = ipv4_key();
    let now = Instant::now();
    let mut beyond = Reassembler::new(Limits::default(), OverlapPolicy::Reject);
    beyond
        .push(ipv4_fragment(&key, 1, false, &b"tail"[..]), now)
        .expect("final length twelve is established");
    let retained = beyond.aggregate_memory_charge();
    assert_eq!(
        beyond.push(ipv4_fragment(&key, 1, true, &b"12345678"[..]), now),
        Err(Error::Malformed(MalformedError::BeyondFinalLength {
            final_length: 12,
        }))
    );
    assert_eq!(beyond.aggregate_memory_charge(), retained);

    let mut at_final = Reassembler::new(Limits::default(), OverlapPolicy::Reject);
    at_final
        .push(ipv4_fragment(&key, 1, false, &b"12345678"[..]), now)
        .expect("final length sixteen is established");
    let retained = at_final.aggregate_memory_charge();
    assert_eq!(
        at_final.push(ipv4_fragment(&key, 1, true, &b"abcdefgh"[..]), now),
        Err(Error::Malformed(MalformedError::NonFinalAtFinalLength {
            final_length: 16,
        }))
    );
    assert_eq!(at_final.aggregate_memory_charge(), retained);
}

#[test]
fn final_length_rejects_a_retained_nonfinal_endpoint_regardless_of_arrival_order() {
    let key = ipv4_key();
    let now = Instant::now();
    let non_final = ipv4_fragment(&key, 0, true, &b"abcdefghijklmnop"[..]);
    let final_tail = ipv4_fragment(&key, 1, false, &b"ijklmnop"[..]);

    for fragments in [
        [non_final.clone(), final_tail.clone()],
        [final_tail.clone(), non_final.clone()],
    ] {
        let mut reassembler = Reassembler::new(Limits::default(), OverlapPolicy::Reject);
        reassembler
            .push(fragments[0].clone(), now)
            .expect("the first fragment is individually valid");
        assert_eq!(
            reassembler.push(fragments[1].clone(), now),
            Err(Error::Malformed(MalformedError::NonFinalAtFinalLength {
                final_length: 16,
            }))
        );
    }
}

#[test]
fn wire_offset_guard_rejects_values_before_checked_byte_conversion() {
    // A valid 13-bit wire offset cannot overflow usize after multiplication
    // by eight. The reachable overflow defense is therefore the public input
    // guard that rejects values outside those 13 bits before conversion.
    let key = ipv6_key();
    let mut fragment = match ipv6_fragment(&key, 0, true, &b"abcdefgh"[..]) {
        Fragment::Ipv6(fragment) => fragment,
        Fragment::Ipv4(_) => unreachable!(),
    };
    fragment.fragment_offset = 0x2000;
    let mut reassembler = Reassembler::new(Limits::default(), OverlapPolicy::Reject);
    assert_eq!(
        reassembler.push(Fragment::Ipv6(fragment), Instant::now()),
        Err(Error::Malformed(MalformedError::OffsetOutOfRange {
            offset: 0x2000,
        }))
    );
    assert_eq!(reassembler.datagram_count(), 0);

    let key = ipv4_key();
    let mut fragment = match ipv4_fragment(&key, 0, true, &b"abcdefgh"[..]) {
        Fragment::Ipv4(fragment) => fragment,
        Fragment::Ipv6(_) => unreachable!(),
    };
    fragment.fragment_offset = 0x2000;
    assert_eq!(
        reassembler.push(Fragment::Ipv4(fragment), Instant::now()),
        Err(Error::Malformed(MalformedError::OffsetOutOfRange {
            offset: 0x2000,
        }))
    );
    assert_eq!(reassembler.datagram_count(), 0);
}

#[test]
fn intrinsic_wire_extent_precedes_configurable_byte_limit() {
    let key = ipv6_key();
    let now = Instant::now();
    let mut reassembler = Reassembler::new(Limits::default(), OverlapPolicy::Reject);
    assert_eq!(
        reassembler.push(ipv6_fragment(&key, 0x1fff, false, &b"12345678"[..]), now),
        Err(Error::Malformed(MalformedError::ReconstructedLength {
            family: Family::Ipv6,
        }))
    );
    assert_eq!(reassembler.datagram_count(), 0);
}

#[test]
fn ipv6_predecessor_must_be_on_the_structural_extension_chain() {
    let mut key = ipv6_key();
    let mut source = key.source.octets();
    source[0] = 44;
    key.source = source.into();
    let payload = Bytes::from_static(b"abcdefgh");
    let mut prefix = ipv6_prefix(&key, payload.len()).to_vec();
    prefix[6] = 59;
    let fragment = Fragment::Ipv6(Ipv6Fragment {
        key,
        fragment_offset: 0,
        more_fragments: true,
        next_header: 17,
        unfragmentable_prefix: Bytes::from(prefix),
        predecessor_next_header_offset: 8,
        payload,
    });
    let mut reassembler = Reassembler::new(Limits::default(), OverlapPolicy::Reject);
    assert!(matches!(
        reassembler.push(fragment, Instant::now()),
        Err(Error::Malformed(MalformedError::InvalidIpv6Prefix { .. }))
    ));
    assert_eq!(reassembler.datagram_count(), 0);
}

#[test]
fn ipv6_predecessor_rejects_an_undersized_authentication_header() {
    let key = ipv6_key();
    let payload = Bytes::from_static(b"abcdefgh");
    let mut prefix = vec![0_u8; 48];
    prefix[0] = 0x60;
    prefix[4..6].copy_from_slice(&24_u16.to_be_bytes());
    prefix[6] = 51;
    prefix[7] = 64;
    prefix[8..24].copy_from_slice(&key.source.octets());
    prefix[24..40].copy_from_slice(&key.destination.octets());
    prefix[40] = 44;
    prefix[41] = 0;
    let fragment = Fragment::Ipv6(Ipv6Fragment {
        key,
        fragment_offset: 0,
        more_fragments: true,
        next_header: 17,
        unfragmentable_prefix: Bytes::from(prefix),
        predecessor_next_header_offset: 40,
        payload,
    });
    let mut reassembler = Reassembler::new(Limits::default(), OverlapPolicy::Reject);

    assert!(matches!(
        reassembler.push(fragment, Instant::now()),
        Err(Error::Malformed(MalformedError::InvalidIpv6Prefix { .. }))
    ));
    assert_eq!(reassembler.datagram_count(), 0);
}

#[test]
fn unrepresentable_idle_expiry_fails_before_state_mutation() {
    let key = ipv4_key();
    let limits = Limits {
        ip_idle_expiry: Duration::MAX,
        ..Limits::default()
    };
    let mut reassembler = Reassembler::new(limits, OverlapPolicy::Reject);
    assert_eq!(
        reassembler.push(
            ipv4_fragment(&key, 0, true, &b"abcdefgh"[..]),
            Instant::now()
        ),
        Err(Error::Resource(ResourceError::IdleExpiryRange {
            expiry: Duration::MAX,
        }))
    );
    assert_eq!(reassembler.datagram_count(), 0);
}

#[test]
fn inconsistent_ipv6_prefix_and_next_header_are_typed_errors() {
    let key = ipv6_key();
    let now = Instant::now();
    let first = ipv6_fragment(&key, 0, true, &b"abcdefgh"[..]);
    let mut reassembler = Reassembler::new(Limits::default(), OverlapPolicy::Reject);
    reassembler
        .push(first, now)
        .expect("first prefix is retained");

    let mut different_next = match ipv6_fragment(&key, 1, false, &b"tail"[..]) {
        Fragment::Ipv6(fragment) => fragment,
        Fragment::Ipv4(_) => unreachable!(),
    };
    different_next.next_header = 6;
    assert_eq!(
        reassembler.push(Fragment::Ipv6(different_next), now),
        Err(Error::Malformed(
            MalformedError::InconsistentIpv6NextHeader {
                expected: 17,
                actual: 6
            }
        ))
    );

    let mut different_prefix = match ipv6_fragment(&key, 1, false, &b"tail"[..]) {
        Fragment::Ipv6(fragment) => fragment,
        Fragment::Ipv4(_) => unreachable!(),
    };
    let mut prefix = different_prefix.unfragmentable_prefix.to_vec();
    prefix[3] = 1;
    different_prefix.unfragmentable_prefix = Bytes::from(prefix);
    assert_eq!(
        reassembler.push(Fragment::Ipv6(different_prefix), now),
        Err(Error::Malformed(MalformedError::InconsistentIpv6Prefix))
    );
}

proptest! {
    #[test]
    fn offset_map_completion_is_exact_for_forward_or_reverse_fragment_order(
        blocks in prop::collection::vec(any::<[u8; 8]>(), 2..8),
        reverse in any::<bool>(),
    ) {
        let key = ipv4_key();
        let now = Instant::now();
        let mut order = (0..blocks.len()).collect::<Vec<_>>();
        if reverse {
            order.reverse();
        }
        let mut reassembler = Reassembler::new(Limits::default(), OverlapPolicy::Reject);
        let mut completion = None;
        for index in order {
            let outcome = reassembler
                .push(
                    ipv4_fragment(
                        &key,
                        u16::try_from(index).expect("fixture offset fits"),
                        index + 1 != blocks.len(),
                        Bytes::copy_from_slice(&blocks[index]),
                    ),
                    now,
                )
                .expect("bounded generated fragment is valid");
            if let PushOutcome::Completed { datagram, .. } = outcome {
                completion = Some(datagram);
            }
        }
        let datagram = completion.expect("all generated blocks complete the datagram");
        let expected = blocks.into_iter().flatten().collect::<Vec<_>>();
        prop_assert_eq!(&datagram.bytes[20..], expected.as_slice());
        prop_assert_eq!(datagram.unique_bytes, expected.len());
        prop_assert_eq!(reassembler.datagram_count(), 0);
    }

    #[test]
    fn overlap_policies_are_deterministic_for_arbitrary_conflicting_bytes(
        first in any::<[u8; 8]>(),
        last in any::<[u8; 8]>(),
        tail in any::<[u8; 4]>(),
    ) {
        prop_assume!(first != last);
        let key = ipv4_key();
        let now = Instant::now();
        let conflicts = first
            .iter()
            .zip(last.iter())
            .filter(|(left, right)| left != right)
            .count();

        for (policy, expected) in [
            (OverlapPolicy::First, first),
            (OverlapPolicy::Last, last),
        ] {
            let mut outputs = Vec::new();
            for _ in 0..2 {
                let mut reassembler = Reassembler::new(Limits::default(), policy);
                reassembler
                    .push(
                        ipv4_fragment(&key, 0, true, Bytes::copy_from_slice(&first)),
                        now,
                    )
                    .expect("first overlap input is retained");
                let resolution = reassembler
                    .push(
                        ipv4_fragment(&key, 0, true, Bytes::copy_from_slice(&last)),
                        now,
                    )
                    .expect("explicit policy resolves overlap");
                let disposition = match resolution {
                    PushOutcome::Accepted(outcome) => outcome.disposition,
                    PushOutcome::Completed { .. } => {
                        return Err(TestCaseError::fail("overlap unexpectedly completed"));
                    }
                };
                prop_assert_eq!(
                    disposition,
                    FragmentDisposition::OverlapResolved {
                        policy,
                        affected_bytes: conflicts,
                        added_bytes: 0,
                    }
                );
                outputs.push(completed(
                    reassembler
                        .push(
                            ipv4_fragment(&key, 1, false, Bytes::copy_from_slice(&tail)),
                            now,
                        )
                        .expect("tail completes overlap fixture"),
                ));
            }
            prop_assert_eq!(&outputs[0].bytes[20..28], &expected);
            prop_assert_eq!(outputs[0].bytes.clone(), outputs[1].bytes.clone());
        }

        let mut reject = Reassembler::new(Limits::default(), OverlapPolicy::Reject);
        reject
            .push(
                ipv4_fragment(&key, 0, true, Bytes::copy_from_slice(&first)),
                now,
            )
            .expect("reject fixture retains first input");
        prop_assert_eq!(
            reject.push(
                ipv4_fragment(&key, 0, true, Bytes::copy_from_slice(&last)),
                now,
            ),
            Err(Error::Malformed(MalformedError::ConflictingOverlap {
                bytes: conflicts,
            }))
        );
        prop_assert_eq!(reject.datagram_count(), 1);
        let datagram = completed(
            reject
                .push(
                    ipv4_fragment(&key, 1, false, Bytes::copy_from_slice(&tail)),
                    now,
                )
                .expect("rejected overlap left original state intact"),
        );
        prop_assert_eq!(&datagram.bytes[20..28], &first);
    }

    #[test]
    fn many_fragment_ipv6_completion_is_exact_in_either_direction(
        blocks in prop::collection::vec(any::<[u8; 8]>(), 3..8),
        reverse in any::<bool>(),
    ) {
        let key = ipv6_key();
        let now = Instant::now();
        let mut order = (0..blocks.len()).collect::<Vec<_>>();
        if reverse {
            order.reverse();
        }
        let mut reassembler = Reassembler::new(Limits::default(), OverlapPolicy::Reject);
        let mut completion = None;
        for index in order {
            let outcome = reassembler
                .push(
                    ipv6_fragment(
                        &key,
                        u16::try_from(index).expect("fixture offset fits"),
                        index + 1 != blocks.len(),
                        Bytes::copy_from_slice(&blocks[index]),
                    ),
                    now,
                )
                .expect("bounded generated IPv6 fragment is valid");
            if let PushOutcome::Completed { datagram, .. } = outcome {
                completion = Some(datagram);
            }
        }
        let datagram = completion.expect("all IPv6 blocks complete the datagram");
        let expected = blocks.into_iter().flatten().collect::<Vec<_>>();
        prop_assert_eq!(&datagram.bytes[40..], expected.as_slice());
        prop_assert_eq!(datagram.unique_bytes, expected.len());
        prop_assert_eq!(reassembler.datagram_count(), 0);
    }
}
