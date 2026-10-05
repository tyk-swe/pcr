// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
#![allow(dead_code)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use packetcraftr_core::packet::{VlanKind, VlanTag};
use packetcraftr_core::protocol::link::{Vlan, Vlan8021ad};
use packetcraftr_core::protocol::network::{Ipv4, Ipv6};
use packetcraftr_core::protocol::semantics::{
    enclosing_ip_path, live_destinations, outer_ip_path, outer_layers, outer_scope_len, vlan_tags,
};
use packetcraftr_core::protocol::tunnel::Vxlan;
use packetcraftr_core::{packet::Packet, reflective_layer};

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
            kind: Ipv4, derived: false, required: true,
            description: "Field that must not opt an unknown protocol into route semantics",
            reflect: destination,
            layout: (0, 4)
        }
    }
    layout pub fn route_mimic_layout();
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Ipv4Impostor {
    destination: Ipv4Addr,
}

reflective_layer! {
    fn ipv4_impostor_schema() => {
        protocol: packetcraftr_core::layer::Id::new("ipv4"),
        name: "Custom layer reusing the ipv4 name"
    }
    impl Ipv4Impostor {
        "destination" => {
            kind: Ipv4, derived: false, required: true,
            description: "Field a built-in IPv4 layer would route by",
            reflect: destination,
            layout: (0, 4)
        }
    }
    layout pub fn ipv4_impostor_layout();
}

fn ipv6_addr(value: &str) -> Ipv6Addr {
    value.parse().expect("test address must be valid IPv6")
}

#[test]
fn bad_ipv4_source_routes_fail_closed() {
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
fn encapsulation_bounds_vlan_interpretation() {
    let outer_destination = Ipv4Addr::new(192, 0, 2, 2);
    let inner_destination = ipv6_addr("2001:db8::2");
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
        .push(Vlan {
            priority: 8,
            ..Vlan::default()
        })
        .push(Ipv6 {
            source: ipv6_addr("2001:db8::1"),
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
        vlan_tags(&packet).expect("only directly transmitted tags are interpreted"),
        [
            VlanTag {
                kind: VlanKind::Ieee8021Ad,
                priority: 5,
                drop_eligible: true,
                vlan_id: 4095,
            },
            VlanTag {
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
        let error = vlan_tags(&packet).unwrap_err();
        assert!(error.to_string().contains(message), "{error}");
    }
}
