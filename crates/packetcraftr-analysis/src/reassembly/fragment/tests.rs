// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

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
    let mut reassembler = Reassembler::new(Limits::default(), OverlapPolicy::RejectConflicting);
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
    let mut reassembler = Reassembler::new(Limits::default(), OverlapPolicy::RejectConflicting);
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
    let mut reassembler = Reassembler::new(Limits::default(), OverlapPolicy::KeepFirst);
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
    let mut reassembler = Reassembler::new(Limits::default(), OverlapPolicy::KeepFirst);
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
    let mut reassembler = Reassembler::new(Limits::default(), OverlapPolicy::RejectConflicting);
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
    let mut reassembler = Reassembler::new(Limits::default(), OverlapPolicy::RejectConflicting);
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
    let limits = Limits {
        max_aggregate_bytes: 200,
        ..Limits::default()
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
    let mut reassembler = Reassembler::new(Limits::default(), OverlapPolicy::RejectConflicting);
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
    let mut reassembler = Reassembler::new(Limits::default(), OverlapPolicy::RejectConflicting);

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
        Limits {
            max_fragments_per_datagram: 0,
            ..Limits::default()
        },
        OverlapPolicy::RejectConflicting,
    );
    assert_eq!(
        denied.push(fragment.clone(), Instant::now()).unwrap_err(),
        Error::FragmentLimit { limit: 0 }
    );

    let limits = Limits {
        max_flows: 0,
        max_aggregate_bytes: 0,
        max_fragments_per_datagram: 1,
        ..Limits::default()
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
    let limits = Limits {
        fragment_expiry: Duration::from_secs(5),
        ..Limits::default()
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
    let mut reassembler = Reassembler::new(Limits::default(), OverlapPolicy::RejectConflicting);

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
