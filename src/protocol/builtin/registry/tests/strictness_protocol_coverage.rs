// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::*;

#[test]
fn stacked_service_and_customer_vlan_round_trip() {
    let registry = Arc::new(default_registry().unwrap());
    let mut packet = Packet::new();
    packet
        .push(Ethernet::default())
        .push(Vlan8021ad {
            vlan_id: 100,
            ..Vlan8021ad::default()
        })
        .push(Vlan {
            vlan_id: 200,
            ..Vlan::default()
        })
        .push(Ipv6 {
            source: "2001:db8::1".parse::<Ipv6Addr>().unwrap(),
            destination: "2001:db8::2".parse::<Ipv6Addr>().unwrap(),
            ..Ipv6::default()
        })
        .push(Udp {
            source_port: 9,
            destination_port: 9,
            ..Udp::default()
        });
    let builder = Builder::new(Arc::clone(&registry));
    let built = builder
        .build(packet, BuildContext::default(), BuildOptions::default())
        .unwrap();
    let decoded = Dissector::new(Arc::clone(&registry))
        .decode_with_root(
            built.bytes.clone(),
            "ethernet".into(),
            DecodeOptions::default(),
        )
        .unwrap();

    assert_eq!(decoded.packet.get_all::<Vlan8021ad>().count(), 1);
    assert_eq!(decoded.packet.get_all::<Vlan>().count(), 1);
    let rebuilt = builder
        .build(
            decoded.packet,
            BuildContext::default(),
            BuildOptions::default(),
        )
        .unwrap();
    assert_eq!(rebuilt.bytes, built.bytes);
}

#[test]
fn strict_rejects_and_permissive_reports_inconsistent_wire_values() {
    let registry = Arc::new(default_registry().unwrap());
    let builder = Builder::new(registry);
    let mut packet = Packet::new();
    packet.push(Ipv4 {
        total_length: WireValue::Exact(21),
        source: Ipv4Addr::new(192, 0, 2, 1),
        destination: Ipv4Addr::new(198, 51, 100, 2),
        ..Ipv4::default()
    });

    assert!(
        builder
            .build(
                packet.clone(),
                BuildContext::default(),
                BuildOptions::default()
            )
            .is_err()
    );
    let permissive = builder
        .build(
            packet,
            BuildContext::default(),
            BuildOptions {
                mode: BuildMode::Permissive,
                ..BuildOptions::default()
            },
        )
        .unwrap();
    assert!(permissive.requires_live_opt_in);
    assert!(
        permissive
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "build.inconsistent_dependent_field")
    );
}

#[test]
fn strict_rejects_untyped_ipv6_routing_headers() {
    let registry = Arc::new(default_registry().unwrap());
    let builder = Builder::new(registry);
    let mut packet = Packet::new();
    packet
        .push(Ipv6 {
            next_header: WireValue::Exact(43),
            source: "2001:db8::1".parse().unwrap(),
            destination: "2001:db8::2".parse().unwrap(),
            ..Ipv6::default()
        })
        .push(Raw::new(Bytes::from_static(&[59, 0, 0, 0, 0, 0, 0, 0])));

    assert!(
        builder
            .build(
                packet.clone(),
                BuildContext::default(),
                BuildOptions::default(),
            )
            .is_err()
    );
    let built = builder
        .build(
            packet,
            BuildContext::default(),
            BuildOptions {
                mode: BuildMode::Permissive,
                ..BuildOptions::default()
            },
        )
        .unwrap();
    assert!(
        built
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "build.untyped_ipv6_routing_header")
    );
    assert!(built.requires_live_opt_in);
}

#[test]
fn permissive_mode_preserves_ipv4_and_tcp_reserved_bits() {
    let registry = Arc::new(default_registry().unwrap());
    let builder = Builder::new(Arc::clone(&registry));
    let mut packet = Packet::new();
    packet
        .push(Ipv4 {
            reserved_flag: true,
            source: Ipv4Addr::new(192, 0, 2, 1),
            destination: Ipv4Addr::new(198, 51, 100, 2),
            ..Ipv4::default()
        })
        .push(Tcp {
            reserved_bits: 0b101,
            ..Tcp::default()
        });
    assert!(
        builder
            .build(
                packet.clone(),
                BuildContext::default(),
                BuildOptions::default(),
            )
            .is_err()
    );
    let options = BuildOptions {
        mode: BuildMode::Permissive,
        ..BuildOptions::default()
    };
    let built = builder
        .build(packet, BuildContext::default(), options.clone())
        .unwrap();
    let decoded = Dissector::new(registry)
        .decode_with_root(built.bytes.clone(), "ipv4".into(), DecodeOptions::default())
        .unwrap();
    assert!(decoded.packet.get::<Ipv4>().unwrap().reserved_flag);
    assert_eq!(decoded.packet.get::<Tcp>().unwrap().reserved_bits, 0b101);
    let rebuilt = builder
        .build(decoded.packet, BuildContext::default(), options)
        .unwrap();
    assert_eq!(rebuilt.bytes, built.bytes);
}

#[test]
fn all_ip_in_ip_family_combinations_round_trip() {
    let registry = Arc::new(default_registry().unwrap());
    let builder = Builder::new(Arc::clone(&registry));
    for (outer_v6, inner_v6) in [(false, false), (false, true), (true, false), (true, true)] {
        let mut packet = Packet::new();
        if outer_v6 {
            packet.push(Ipv6 {
                source: "2001:db8::1".parse().unwrap(),
                destination: "2001:db8::2".parse().unwrap(),
                ..Ipv6::default()
            });
        } else {
            packet.push(Ipv4 {
                source: Ipv4Addr::new(192, 0, 2, 1),
                destination: Ipv4Addr::new(192, 0, 2, 2),
                ..Ipv4::default()
            });
        }
        if inner_v6 {
            packet.push(Ipv6 {
                source: "2001:db8:1::1".parse().unwrap(),
                destination: "2001:db8:1::2".parse().unwrap(),
                ..Ipv6::default()
            });
        } else {
            packet.push(Ipv4 {
                source: Ipv4Addr::new(198, 51, 100, 1),
                destination: Ipv4Addr::new(198, 51, 100, 2),
                ..Ipv4::default()
            });
        }
        packet.push(Udp::default());

        let built = builder
            .build(packet, BuildContext::default(), BuildOptions::default())
            .unwrap();
        let root = if outer_v6 { "ipv6" } else { "ipv4" };
        let decoded = Dissector::new(Arc::clone(&registry))
            .decode_with_root(built.bytes.clone(), root.into(), DecodeOptions::default())
            .unwrap();
        let protocols = decoded
            .packet
            .iter()
            .map(|layer| layer.protocol_id().as_str().to_owned())
            .collect::<Vec<_>>();
        assert_eq!(
            protocols,
            vec![
                if outer_v6 { "ipv6" } else { "ipv4" },
                if inner_v6 { "ipv6" } else { "ipv4" },
                "udp",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect::<Vec<_>>()
        );
        let rebuilt = builder
            .build(
                decoded.packet,
                BuildContext::default(),
                BuildOptions::default(),
            )
            .unwrap();
        assert_eq!(rebuilt.bytes, built.bytes);
    }
}

#[test]
fn gre_sctp_and_igmp_round_trip_through_the_default_registry() {
    let mut gre_packet = Packet::new();
    gre_packet
        .push(Ipv4 {
            source: Ipv4Addr::new(192, 0, 2, 1),
            destination: Ipv4Addr::new(192, 0, 2, 2),
            ..Ipv4::default()
        })
        .push(Gre {
            checksum: Some(WireValue::Auto),
            key: Some(0x1122_3344),
            sequence: Some(7),
            ..Gre::default()
        })
        .push(Ipv6 {
            source: "2001:db8::1".parse().unwrap(),
            destination: "2001:db8::2".parse().unwrap(),
            ..Ipv6::default()
        })
        .push(Udp::default());

    let mut sctp_packet = Packet::new();
    sctp_packet
        .push(Ipv4 {
            source: Ipv4Addr::new(192, 0, 2, 1),
            destination: Ipv4Addr::new(192, 0, 2, 2),
            ..Ipv4::default()
        })
        .push(Sctp::default())
        .push(Raw::new(vec![
            1, 0, 0, 20, 0x11, 0x22, 0x33, 0x44, 0, 1, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0,
        ]));

    let mut igmp_packet = Packet::new();
    igmp_packet
        .push(Ipv4 {
            source: Ipv4Addr::new(192, 0, 2, 1),
            destination: Ipv4Addr::new(224, 0, 0, 1),
            ..Ipv4::default()
        })
        .push(Igmp {
            code: 100,
            body: Bytes::from_static(&[224, 0, 0, 1]),
            ..Igmp::default()
        });

    let registry = Arc::new(default_registry().unwrap());
    let builder = Builder::new(Arc::clone(&registry));
    for (packet, expected) in [
        (gre_packet, vec!["ipv4", "gre", "ipv6", "udp"]),
        (sctp_packet, vec!["ipv4", "sctp", "raw"]),
        (igmp_packet, vec!["ipv4", "igmp"]),
    ] {
        let built = builder
            .build(packet, BuildContext::default(), BuildOptions::default())
            .unwrap();
        let decoded = Dissector::new(Arc::clone(&registry))
            .decode_with_root(built.bytes.clone(), "ipv4".into(), DecodeOptions::default())
            .unwrap();
        assert_eq!(
            decoded
                .packet
                .iter()
                .map(|layer| layer.protocol_id().as_str().to_owned())
                .collect::<Vec<_>>(),
            expected.into_iter().map(str::to_owned).collect::<Vec<_>>()
        );
        assert!(decoded.diagnostics.is_empty());
        let rebuilt = builder
            .build(
                decoded.packet,
                BuildContext::default(),
                BuildOptions::default(),
            )
            .unwrap();
        assert_eq!(rebuilt.bytes, built.bytes);
    }
}
