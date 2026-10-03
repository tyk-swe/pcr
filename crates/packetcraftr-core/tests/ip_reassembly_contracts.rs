// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use bytes::Bytes;
use packetcraftr_core::analysis::reassembly::ip::Limits;
use packetcraftr_core::analysis::reassembly::ip::{
    Error, Fragment, Ipv4DatagramKey, Ipv4Fragment, Malformed, OverlapPolicy, Reassembler, Resource,
};
use packetcraftr_core::analysis::scope::{Interner, ScopeId};
use packetcraftr_core::analysis::{Constraint, Error as AnalysisError};
use packetcraftr_core::error::Classified;

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

#[test]
fn resource_limits_reject_before_retaining_new_payload() {
    let key = ipv4_key();
    let now = Instant::now();
    let mut datagrams = Reassembler::new(
        Limits {
            max_datagrams: 0,
            ..Limits::default()
        },
        OverlapPolicy::Reject,
    )
    .unwrap();
    assert_eq!(
        datagrams.push(ipv4_fragment(&key, 0, true, &b"abcdefgh"[..]), now),
        Err(Error::Resource(Resource::DatagramLimit { limit: 0 }))
    );
    assert_eq!(datagrams.aggregate_payload_bytes(), 0);

    let mut bytes = Reassembler::new(
        Limits {
            max_bytes_per_datagram: 7,
            ..Limits::default()
        },
        OverlapPolicy::Reject,
    )
    .unwrap();
    assert_eq!(
        bytes.push(ipv4_fragment(&key, 0, true, &b"abcdefgh"[..]), now),
        Err(Error::Resource(Resource::DatagramByteLimit { limit: 7 }))
    );
    assert_eq!(bytes.datagram_count(), 0);

    let mut aggregate = Reassembler::new(
        Limits {
            // 4,096 collection metadata + 64 range + 20 header + 8 payload.
            max_aggregate_bytes: 4_187,
            ..Limits::default()
        },
        OverlapPolicy::Reject,
    )
    .unwrap();
    assert_eq!(
        aggregate.push(ipv4_fragment(&key, 0, true, &b"abcdefgh"[..]), now),
        Err(Error::Resource(Resource::AggregateMemoryLimit {
            limit: 4_187
        }))
    );
    assert_eq!(aggregate.datagram_count(), 0);

    let mut fragments = Reassembler::new(
        Limits {
            max_fragments_per_datagram: 1,
            ..Limits::default()
        },
        OverlapPolicy::Reject,
    )
    .unwrap();
    fragments
        .push(ipv4_fragment(&key, 0, true, &b"abcdefgh"[..]), now)
        .expect("first fragment fits the limit");
    let retained = fragments.aggregate_memory_charge();
    assert_eq!(
        fragments.push(ipv4_fragment(&key, 0, true, &b"abcdefgh"[..]), now),
        Err(Error::Resource(Resource::FragmentLimit { limit: 1 }))
    );
    assert_eq!(fragments.datagram_count(), 1);
    assert_eq!(fragments.aggregate_memory_charge(), retained);
}

#[test]
fn malformed_lengths_and_final_offsets_fail_closed_without_destroying_old_state() {
    let key = ipv4_key();
    let now = Instant::now();
    let mut reassembler = Reassembler::new(Limits::default(), OverlapPolicy::Reject).unwrap();
    assert_eq!(
        reassembler.push(ipv4_fragment(&key, 0, true, Bytes::new()), now),
        Err(Error::Malformed(Malformed::EmptyPayload))
    );
    assert_eq!(
        reassembler.push(ipv4_fragment(&key, 0, true, &b"seven!!"[..]), now),
        Err(Error::Malformed(Malformed::UnalignedNonFinal { length: 7 }))
    );

    reassembler
        .push(ipv4_fragment(&key, 2, false, &b"tail"[..]), now)
        .expect("first final length is retained");
    assert_eq!(
        reassembler.push(ipv4_fragment(&key, 1, false, &b"tail"[..]), now),
        Err(Error::Malformed(Malformed::ConflictingFinalLength {
            existing: 20,
            new: 12
        }))
    );
    assert_eq!(reassembler.flush().outcomes[0].known_final_length, Some(20));

    let mut oversized = Reassembler::new(Limits::default(), OverlapPolicy::Reject).unwrap();
    assert_eq!(
        oversized.push(ipv4_fragment(&key, 0x1fff, false, &b"1234567"[..]), now),
        Err(Error::Malformed(Malformed::ReconstructedLength {
            family: packetcraftr_core::analysis::reassembly::ip::Family::Ipv4
        }))
    );
    assert_eq!(oversized.datagram_count(), 0);
}

#[test]
fn unrepresentable_idle_expiry_is_refused_at_construction() {
    let limits = Limits {
        idle_expiry: Duration::MAX,
        ..Limits::default()
    };
    let error = Reassembler::new(limits.clone(), OverlapPolicy::Reject).unwrap_err();
    assert!(matches!(
        error,
        AnalysisError::InvalidLimit {
            field: "idle_expiry",
            reason: Constraint::WithinClockRange,
            ..
        }
    ));
    assert_eq!(error.classification().code, "cli.analysis_limit");
    assert!(limits.validate().is_err());
}
