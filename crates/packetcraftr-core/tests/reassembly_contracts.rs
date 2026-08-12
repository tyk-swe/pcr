// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

use bytes::Bytes;
use packetcraftr_core::analysis::reassembly::{
    Limits,
    fragment::{self, DatagramKey, Fragment, OverlapPolicy, ScopedDatagramKey},
    tcp::{self, FlowKey, ScopedFlowKey, Segment},
};
use packetcraftr_core::analysis::scope::{EncapsulationIdentifier, ScopeInterner};

fn scope() -> packetcraftr_core::analysis::scope::ScopeId {
    ScopeInterner::new()
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

fn flow_key() -> ScopedFlowKey {
    ScopedFlowKey {
        scope: scope(),
        flow: FlowKey {
            source: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            source_port: 12_345,
            destination: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2)),
            destination_port: 443,
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
    let mut scopes = ScopeInterner::new();
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

#[test]
fn fragment_overlap_and_expiry_are_bounded() {
    let now = Instant::now();
    let limits = Limits {
        fragment_expiry: Duration::from_secs(1),
        ..Limits::default()
    };
    let mut reassembler = fragment::Reassembler::new(limits, OverlapPolicy::RejectConflicting);
    reassembler
        .push(
            Fragment {
                key: datagram_key(),
                offset: 0,
                more_fragments: true,
                bytes: Bytes::from_static(b"abcdefgh"),
            },
            now,
        )
        .expect("first fragment must be retained");
    assert!(matches!(
        reassembler.push(
            Fragment {
                key: datagram_key(),
                offset: 0,
                more_fragments: true,
                bytes: Bytes::from_static(b"ABCDEFGH"),
            },
            now,
        ),
        Err(fragment::Error::ConflictingOverlap { offset: 0 })
    ));
    assert_eq!(reassembler.expire(now + Duration::from_secs(1)).len(), 1);
    assert_eq!(reassembler.flow_count(), 0);
}

#[test]
fn tcp_out_of_order_data_and_retransmission_are_deterministic() {
    let now = Instant::now();
    let flow = flow_key();
    let mut reassembler = tcp::Reassembler::new(Limits::default());
    reassembler
        .open_flow(flow.clone(), 100, now)
        .expect("flow must open");
    assert!(
        reassembler
            .push(
                Segment {
                    flow: flow.clone(),
                    sequence: 108,
                    payload: Bytes::from_static(b"ij"),
                    syn: false,
                    fin: false,
                    rst: false,
                },
                now,
            )
            .expect("out-of-order segment must buffer")
            .is_empty()
    );
    let events = reassembler
        .push(
            Segment {
                flow: flow.clone(),
                sequence: 100,
                payload: Bytes::from_static(b"abcdefgh"),
                syn: false,
                fin: false,
                rst: false,
            },
            now,
        )
        .expect("gap-filling segment must deliver");
    let delivered = events
        .iter()
        .filter_map(|event| match event {
            tcp::Event::Data { bytes, .. } => Some(bytes.as_ref()),
            _ => None,
        })
        .flatten()
        .copied()
        .collect::<Vec<_>>();
    assert_eq!(delivered, b"abcdefghij");

    let retransmission = reassembler
        .push(
            Segment {
                flow,
                sequence: 100,
                payload: Bytes::from_static(b"abcdefgh"),
                syn: false,
                fin: false,
                rst: false,
            },
            now,
        )
        .expect("duplicate must be classified");
    assert!(retransmission.iter().any(|event| matches!(
        event,
        tcp::Event::Retransmission {
            bytes: 8,
            conflicting: false,
            ..
        }
    )));
}
