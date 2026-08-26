// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
// Test code indexes fixtures and counts by hand; the fail-closed lints are
// for library paths.
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use bytes::Bytes;
use packetcraftr_core::field::WireValue;
use packetcraftr_core::layer::{Malformed, Raw};
use packetcraftr_core::protocol::ipv6::{Fragment, SegmentRoutingHeader};
use packetcraftr_core::protocol::link::{Arp, Vlan, Vlan8021ad};
use packetcraftr_core::protocol::network::{Ipv4, Ipv6};
use packetcraftr_core::protocol::transport::{Sctp, Tcp, Udp};
use packetcraftr_core::protocol::tunnel::Vxlan;
use packetcraftr_core::semantics::{
    BuiltinProtocol, VlanKind, VlanMetadata, enclosing_ip_path, live_destinations, outer_ip_path,
    outer_layers, outer_scope_len, transport_key, transport_keys_are_reversed,
    validate_segment_route, vlan_metadata,
};
use packetcraftr_core::{Packet, reflective_layer};

#[derive(Clone, Debug, PartialEq, Eq)]
struct RouteMimic {
    destination: Ipv4Addr,
}

reflective_layer! {
    fn route_mimic_schema() => {
        protocol: packetcraftr_core::layer::Id::new("route_mimic"),
        name: "Untrusted Route Mimic"
    }
    impl RouteMimic {
        "destination" => {
            kind: Ipv4, tier: Required,
            description: "Field that must not opt an unknown protocol into route semantics",
            reflect: destination,
            layout: (0, 4)
        }
    }
    layout pub fn route_mimic_layout();
}

fn ipv6(value: &str) -> Ipv6Addr {
    value.parse().expect("test address must be valid IPv6")
}

#[test]
fn live_destinations_include_ipv4_routes_and_arp_targets_once() {
    let active = Ipv4Addr::new(203, 0, 113, 10);
    let final_destination = Ipv4Addr::new(203, 0, 113, 20);
    let arp_target = Ipv4Addr::new(192, 0, 2, 99);
    let mut packet = Packet::new();
    packet
        .push(Ipv4 {
            source: Ipv4Addr::new(192, 0, 2, 10),
            destination: active,
            // LSRR containing two addresses, with the pointer on the second.
            options: Bytes::from_static(&[131, 11, 8, 203, 0, 113, 10, 203, 0, 113, 20]),
            ..Ipv4::default()
        })
        .push(Arp {
            target_protocol: arp_target,
            ..Arp::default()
        });

    let path = outer_ip_path(&packet)
        .expect("valid source route must be interpreted")
        .expect("packet contains IPv4");
    assert_eq!(path.active_destination, IpAddr::V4(active));
    assert_eq!(path.final_destination, IpAddr::V4(final_destination));
    assert_eq!(
        path.declared_route_destinations,
        [IpAddr::V4(active), IpAddr::V4(final_destination)]
    );
    assert_eq!(
        live_destinations(&packet).expect("route-bearing packet must be valid"),
        [
            IpAddr::V4(active),
            IpAddr::V4(final_destination),
            IpAddr::V4(arp_target),
        ]
    );
}

#[test]
fn ipv6_segment_route_reports_active_final_and_declared_destinations() {
    let segments = [
        ipv6("2001:db8::10"),
        ipv6("2001:db8::20"),
        ipv6("2001:db8::30"),
    ];
    let mut packet = Packet::new();
    packet
        .push(Ipv6 {
            source: ipv6("2001:db8::1"),
            destination: segments[1],
            ..Ipv6::default()
        })
        .push(SegmentRoutingHeader {
            segments_left: WireValue::Exact(1),
            last_entry: WireValue::Exact(2),
            segments: segments.to_vec(),
            ..SegmentRoutingHeader::default()
        });

    let path = outer_ip_path(&packet)
        .expect("valid SRH must be interpreted")
        .expect("packet contains IPv6");
    assert_eq!(path.active_destination, IpAddr::V6(segments[1]));
    assert_eq!(path.final_destination, IpAddr::V6(segments[2]));
    assert_eq!(
        path.visited_destinations,
        [IpAddr::V6(segments[1]), IpAddr::V6(segments[2])]
    );
    assert_eq!(
        live_destinations(&packet).expect("valid SRH must expose every live destination"),
        [
            IpAddr::V6(segments[1]),
            IpAddr::V6(segments[0]),
            IpAddr::V6(segments[2]),
        ]
    );

    let route = validate_segment_route(Ipv6Addr::UNSPECIFIED, segments.to_vec(), 2, 2, 0)
        .expect("an unspecified header destination may be materialized later");
    assert_eq!(route.active_index, 0);
    assert_eq!(route.active_destination, segments[0]);
}

#[test]
fn segment_route_validation_rejects_each_inconsistent_state() {
    let first = ipv6("2001:db8::1");
    let second = ipv6("2001:db8::2");
    let other = ipv6("2001:db8::ffff");
    let cases = [
        ("empty", first, Vec::new(), 0, 0, 0, "requires 1..=127"),
        (
            "too many segments",
            first,
            vec![first; 128],
            0,
            127,
            0,
            "requires 1..=127",
        ),
        (
            "last-entry mismatch",
            first,
            vec![first, second],
            1,
            0,
            0,
            "does not match segment-list index",
        ),
        (
            "segments-left overflow",
            first,
            vec![first, second],
            2,
            1,
            0,
            "exceeds last_entry",
        ),
        (
            "unsupported flags",
            first,
            vec![first, second],
            1,
            1,
            1,
            "flags are non-zero",
        ),
        (
            "destination mismatch",
            other,
            vec![first, second],
            1,
            1,
            0,
            "does not match active SRH segment",
        ),
    ];

    for (name, destination, segments, segments_left, last_entry, flags, message) in cases {
        let error = validate_segment_route(destination, segments, segments_left, last_entry, flags)
            .unwrap_err();
        assert!(error.to_string().contains(message), "{name}: {error}");
    }
}

#[test]
fn malformed_ipv4_source_routes_fail_closed() {
    let cases = [
        (vec![1; 41], "exceed the 40-byte header limit"),
        (vec![7], "missing its length byte"),
        (vec![7, 1], "invalid length 1"),
        (vec![7, 4, 0], "option 7 is truncated"),
        (
            vec![131, 4, 4, 0],
            "source-route option 131 has invalid length 4",
        ),
        (vec![131, 7, 3, 192, 0, 2, 1], "invalid pointer 3"),
    ];

    for (options, message) in cases {
        let packet = [Ipv4 {
            destination: Ipv4Addr::new(192, 0, 2, 1),
            options: options.into(),
            ..Ipv4::default()
        }]
        .into_iter()
        .collect();
        let error = outer_ip_path(&packet).unwrap_err();
        assert!(error.to_string().contains(message), "{error}");
    }
}

#[test]
fn encapsulation_bounds_outer_ip_and_vlan_interpretation() {
    let outer_destination = Ipv4Addr::new(192, 0, 2, 2);
    let inner_destination = ipv6("2001:db8::2");
    let mut packet = Packet::new();
    packet
        .push(Vlan8021ad {
            priority: 5,
            drop_eligible: true,
            vlan_id: 4095,
            ..Vlan8021ad::default()
        })
        .push(Vlan {
            priority: 1,
            vlan_id: 7,
            ..Vlan::default()
        })
        .push(Ipv4 {
            source: Ipv4Addr::new(192, 0, 2, 1),
            destination: outer_destination,
            ..Ipv4::default()
        })
        .push(Vxlan::default())
        // This invalid inner tag must not affect directly transmitted metadata.
        .push(Vlan {
            priority: 8,
            ..Vlan::default()
        })
        .push(Ipv6 {
            source: ipv6("2001:db8::1"),
            destination: inner_destination,
            ..Ipv6::default()
        });

    assert_eq!(outer_scope_len(&packet), 4);
    assert_eq!(
        outer_layers(&packet)
            .map(|layer| layer.protocol_id().as_str())
            .collect::<Vec<_>>(),
        ["vlan8021ad", "vlan", "ipv4", "vxlan"]
    );
    assert_eq!(
        outer_ip_path(&packet)
            .expect("outer header must be valid")
            .expect("packet has an outer IP header")
            .final_destination,
        IpAddr::V4(outer_destination)
    );
    assert_eq!(
        enclosing_ip_path(&packet, packet.len())
            .expect("inner header must be valid")
            .expect("packet has an enclosing IP header")
            .final_destination,
        IpAddr::V6(inner_destination)
    );
    assert_eq!(
        live_destinations(&packet).expect("both encapsulated destinations must be authorized"),
        [IpAddr::V4(outer_destination), IpAddr::V6(inner_destination)]
    );
    assert_eq!(
        vlan_metadata(&packet).expect("only directly transmitted tags are interpreted"),
        [
            VlanMetadata {
                kind: VlanKind::Ieee8021Ad,
                priority: 5,
                drop_eligible: true,
                vlan_id: 4095,
            },
            VlanMetadata {
                kind: VlanKind::Ieee8021Q,
                priority: 1,
                drop_eligible: false,
                vlan_id: 7,
            },
        ]
    );

    for (tag, message) in [
        (
            Vlan {
                priority: 8,
                ..Vlan::default()
            },
            "priority",
        ),
        (
            Vlan {
                vlan_id: 4096,
                ..Vlan::default()
            },
            "vlan_id",
        ),
    ] {
        let packet = [tag].into_iter().collect();
        let error = vlan_metadata(&packet).unwrap_err();
        assert!(error.to_string().contains(message), "{error}");
    }
}

#[test]
fn ambiguous_live_route_state_is_rejected_at_the_trust_boundary() {
    let mut ipv4_fragment = Packet::new();
    ipv4_fragment.push(Ipv4 {
        destination: Ipv4Addr::new(192, 0, 2, 1),
        more_fragments: true,
        ..Ipv4::default()
    });

    let mut ipv6_fragment = Packet::new();
    ipv6_fragment
        .push(Ipv6 {
            destination: ipv6("2001:db8::1"),
            ..Ipv6::default()
        })
        .push(Fragment {
            fragment_offset: 1,
            ..Fragment::default()
        });

    let cases = [
        (ipv4_fragment, "non-atomic ipv4 fragment"),
        (ipv6_fragment, "non-atomic ipv6_fragment fragment"),
        (
            [Malformed::new(
                Some(packetcraftr_core::layer::Id::new("ipv4")),
                Bytes::new(),
                "short header",
            )]
            .into_iter()
            .collect(),
            "malformed ipv4 layer may hide a live destination",
        ),
        (
            [SegmentRoutingHeader::default()].into_iter().collect(),
            "SRH is not in a contiguous typed extension chain",
        ),
        (
            [RouteMimic {
                destination: Ipv4Addr::new(198, 51, 100, 1),
            }]
            .into_iter()
            .collect(),
            "unknown protocol route_mimic exposes route-bearing field destination",
        ),
    ];

    for (packet, message) in cases {
        let error = live_destinations(&packet).unwrap_err();
        assert!(error.to_string().contains(message), "{error}");
    }

    let harmless: Packet = [Malformed::new(
        Some(packetcraftr_core::layer::Id::new("tcp")),
        Bytes::new(),
        "short segment",
    )]
    .into_iter()
    .collect();
    assert!(
        live_destinations(&harmless)
            .expect("malformed transport cannot hide a route")
            .is_empty()
    );
}

#[test]
fn transport_keys_are_all_or_nothing_and_protocol_specific() {
    let tcp_request = Tcp {
        source_port: 40_000,
        destination_port: 443,
        ..Tcp::default()
    };
    let tcp_response = Tcp {
        source_port: 443,
        destination_port: 40_000,
        ..Tcp::default()
    };
    let udp_request = Udp {
        source_port: 40_000,
        destination_port: 53,
        ..Udp::default()
    };
    let udp_response = Udp {
        source_port: 53,
        destination_port: 40_000,
        ..Udp::default()
    };
    let sctp_request = Sctp {
        source_port: 40_000,
        destination_port: 5_000,
        ..Sctp::default()
    };
    let sctp_response = Sctp {
        source_port: 5_000,
        destination_port: 40_000,
        ..Sctp::default()
    };

    let key = transport_key(&tcp_request).expect("TCP exposes a complete transport key");
    assert_eq!(key.protocol, BuiltinProtocol::Tcp);
    assert_eq!((key.source_port, key.destination_port), (40_000, 443));
    assert!(transport_keys_are_reversed(&tcp_request, &tcp_response));
    assert!(transport_keys_are_reversed(&udp_request, &udp_response));
    assert!(transport_keys_are_reversed(&sctp_request, &sctp_response));
    assert!(!transport_keys_are_reversed(&tcp_request, &tcp_request));
    assert!(!transport_keys_are_reversed(&tcp_request, &udp_response));
    assert!(transport_key(&Raw::new(vec![0_u8])).is_none());
}
