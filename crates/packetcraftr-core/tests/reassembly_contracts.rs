// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
// Test code indexes fixtures and counts by hand; the fail-closed lints are
// for library paths.
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::net::{IpAddr, Ipv4Addr};
use std::time::Instant;

use bytes::Bytes;
use packetcraftr_core::analysis::reassembly::{
    Limits,
    fragment::{self, DatagramKey, Fragment, OverlapPolicy, ScopedDatagramKey},
};
use packetcraftr_core::analysis::scope::EncapsulationIdentifier;

fn scope() -> packetcraftr_core::analysis::scope::ScopeId {
    packetcraftr_core::analysis::scope::Interner::new()
        .intern(None, Vec::new())
        .expect("one scope fits")
}

fn datagram_key() -> ScopedDatagramKey {
    ScopedDatagramKey {
        scope: scope(),
        datagram: DatagramKey {
            source: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            destination: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2)),
            identification: 7,
            next_header: 17,
        },
    }
}

#[test]
fn fragments_complete_in_wire_order_after_out_of_order_arrival() {
    let now = Instant::now();
    let mut reassembler = fragment::Reassembler::new(Limits::default(), OverlapPolicy::default());
    assert!(
        reassembler
            .push(
                Fragment {
                    key: datagram_key(),
                    offset: 8,
                    more_fragments: false,
                    bytes: Bytes::from_static(b"ijk"),
                },
                now,
            )
            .expect("final fragment must be retained")
            .is_none()
    );
    let event = reassembler
        .push(
            Fragment {
                key: datagram_key(),
                offset: 0,
                more_fragments: true,
                bytes: Bytes::from_static(b"abcdefgh"),
            },
            now,
        )
        .expect("leading fragment must complete the datagram")
        .expect("completion event must be emitted");
    let fragment::Event::Complete(datagram) = event else {
        panic!("expected complete datagram");
    };
    assert_eq!(datagram.bytes.as_ref(), b"abcdefghijk");
    assert_eq!(datagram.fragment_count, 2);
    assert_eq!(reassembler.aggregate_bytes(), 0);
}

#[test]
fn fragments_cannot_complete_across_interface_or_tunnel_scopes() {
    let now = Instant::now();
    let mut scopes = packetcraftr_core::analysis::scope::Interner::new();
    let base_scope = scopes.intern(Some(0), Vec::new()).expect("scope fits");
    let other_interface = scopes.intern(Some(1), Vec::new()).expect("scope fits");
    let other_tunnel = scopes
        .intern(Some(0), vec![EncapsulationIdentifier::Vxlan { vni: 20 }])
        .expect("scope fits");
    let tuple = datagram_key().datagram;
    let mut reassembler = fragment::Reassembler::new(Limits::default(), OverlapPolicy::default());

    let leading = Fragment {
        key: ScopedDatagramKey {
            scope: base_scope,
            datagram: tuple.clone(),
        },
        offset: 0,
        more_fragments: true,
        bytes: Bytes::from_static(b"abcdefgh"),
    };
    assert!(
        reassembler
            .push(leading, now)
            .expect("leading fragment is retained")
            .is_none()
    );
    for scope in [other_interface, other_tunnel] {
        let event = reassembler
            .push(
                Fragment {
                    key: ScopedDatagramKey {
                        scope,
                        datagram: tuple.clone(),
                    },
                    offset: 8,
                    more_fragments: false,
                    bytes: Bytes::from_static(b"ijk"),
                },
                now,
            )
            .expect("foreign final fragment is retained separately");
        assert!(event.is_none());
    }
    assert_eq!(reassembler.flow_count(), 3);

    let event = reassembler
        .push(
            Fragment {
                key: ScopedDatagramKey {
                    scope: base_scope,
                    datagram: tuple,
                },
                offset: 8,
                more_fragments: false,
                bytes: Bytes::from_static(b"ijk"),
            },
            now,
        )
        .expect("matching final fragment completes")
        .expect("base datagram completes");
    let fragment::Event::Complete(datagram) = event else {
        panic!("expected complete datagram");
    };
    assert_eq!(datagram.bytes.as_ref(), b"abcdefghijk");
    assert_eq!(reassembler.flow_count(), 2);
}
