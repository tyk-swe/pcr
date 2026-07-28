// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::*;

#[test]
fn ethernet_ipv4_udp_round_trip_rebuilds_identical_bytes() {
    let registry = Arc::new(default_registry().unwrap());
    let mut packet = Packet::new();
    packet
        .push(Ethernet {
            destination: [0, 1, 2, 3, 4, 5],
            source: [6, 7, 8, 9, 10, 11],
            ether_type: WireValue::Auto,
        })
        .push(Ipv4 {
            identification: 0x1234,
            source: Ipv4Addr::new(192, 0, 2, 1),
            destination: Ipv4Addr::new(198, 51, 100, 2),
            ..Ipv4::default()
        })
        .push(Udp {
            source_port: 12345,
            destination_port: 53,
            ..Udp::default()
        })
        .push(Raw::new(Bytes::from_static(b"packet")));
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
    let rebuilt = builder
        .build(
            decoded.packet,
            BuildContext::default(),
            BuildOptions::default(),
        )
        .unwrap();

    assert_eq!(rebuilt.bytes, built.bytes);
    assert!(decoded.diagnostics.is_empty());
}

#[test]
fn ipv4_udp_odd_payload_emits_known_checksum() {
    let registry = Arc::new(default_registry().unwrap());
    let mut packet = Packet::new();
    packet
        .push(Ipv4 {
            source: Ipv4Addr::new(192, 0, 2, 1),
            destination: Ipv4Addr::new(198, 51, 100, 2),
            ..Ipv4::default()
        })
        .push(Udp {
            source_port: 5_000,
            destination_port: 53,
            ..Udp::default()
        })
        .push(Raw::new(Bytes::from_static(&[
            0xde, 0xad, 0xbe, 0xef, 0x01,
        ])));

    let built = Builder::new(Arc::clone(&registry))
        .build(packet, BuildContext::default(), BuildOptions::default())
        .unwrap();
    assert_eq!(&built.bytes[26..28], &[0x61, 0x42]);

    let decoded = Dissector::new(registry)
        .decode_with_root(built.bytes, "ipv4".into(), DecodeOptions::default())
        .unwrap();
    assert!(decoded.diagnostics.is_empty());
}

#[test]
fn icmpv4_and_icmpv6_codec_paths_round_trip_exact_bytes() {
    let registry = Arc::new(default_registry().unwrap());
    let builder = Builder::new(Arc::clone(&registry));

    let mut ipv4 = Packet::new();
    ipv4.push(Ipv4 {
        source: Ipv4Addr::new(192, 0, 2, 1),
        destination: Ipv4Addr::new(198, 51, 100, 2),
        ..Ipv4::default()
    })
    .push(Icmpv4 {
        body: Bytes::from_static(&[0x12, 0x34, 0, 1]),
        ..Icmpv4::default()
    });
    let built4 = builder
        .build(ipv4, BuildContext::default(), BuildOptions::default())
        .unwrap();
    let decoded4 = Dissector::new(Arc::clone(&registry))
        .decode_with_root(
            built4.bytes.clone(),
            "ipv4".into(),
            DecodeOptions::default(),
        )
        .unwrap();
    assert!(decoded4.packet.get::<Icmpv4>().is_some());
    assert!(decoded4.diagnostics.is_empty());
    let rebuilt4 = builder
        .build(
            decoded4.packet,
            BuildContext::default(),
            BuildOptions::default(),
        )
        .unwrap();
    assert_eq!(rebuilt4.bytes, built4.bytes);

    let mut ipv6 = Packet::new();
    ipv6.push(Ipv6 {
        source: "2001:db8::1".parse().unwrap(),
        destination: "2001:db8::2".parse().unwrap(),
        ..Ipv6::default()
    })
    .push(Icmpv6 {
        body: Bytes::from_static(&[0x56, 0x78, 0, 2]),
        ..Icmpv6::default()
    });
    let built6 = builder
        .build(ipv6, BuildContext::default(), BuildOptions::default())
        .unwrap();
    let decoded6 = Dissector::new(Arc::clone(&registry))
        .decode_with_root(
            built6.bytes.clone(),
            "ipv6".into(),
            DecodeOptions::default(),
        )
        .unwrap();
    assert!(decoded6.packet.get::<Icmpv6>().is_some());
    assert!(decoded6.diagnostics.is_empty());
    let rebuilt6 = builder
        .build(
            decoded6.packet,
            BuildContext::default(),
            BuildOptions::default(),
        )
        .unwrap();
    assert_eq!(rebuilt6.bytes, built6.bytes);
}

#[test]
fn ethernet_padding_is_preserved_without_changing_ip_or_udp_lengths() {
    let registry = Arc::new(default_registry().unwrap());
    let mut packet = Packet::new();
    packet
        .push(Ethernet::default())
        .push(Ipv4 {
            source: Ipv4Addr::new(192, 0, 2, 1),
            destination: Ipv4Addr::new(198, 51, 100, 2),
            ..Ipv4::default()
        })
        .push(Udp {
            source_port: 12345,
            destination_port: 9,
            ..Udp::default()
        })
        .push(Raw::new(Bytes::from_static(b"abc")))
        .push(Padding::new(Bytes::from_static(&[0; 15])));
    let builder = Builder::new(Arc::clone(&registry));
    let built = builder
        .build(packet, BuildContext::default(), BuildOptions::default())
        .unwrap();

    assert_eq!(u16::from_be_bytes([built.bytes[16], built.bytes[17]]), 31);
    assert_eq!(u16::from_be_bytes([built.bytes[38], built.bytes[39]]), 11);

    let decoded = Dissector::new(Arc::clone(&registry))
        .decode_with_root(
            built.bytes.clone(),
            "ethernet".into(),
            DecodeOptions::default(),
        )
        .unwrap();
    assert_eq!(
        decoded.packet.get::<Padding>().unwrap().bytes,
        Bytes::from_static(&[0; 15])
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

#[test]
fn udp_trailer_remains_inside_ipv4_length_but_outside_udp_length() {
    let registry = Arc::new(default_registry().unwrap());
    let mut packet = Packet::new();
    packet
        .push(Ethernet::default())
        .push(Ipv4 {
            source: Ipv4Addr::new(192, 0, 2, 1),
            destination: Ipv4Addr::new(198, 51, 100, 2),
            ..Ipv4::default()
        })
        .push(Udp {
            source_port: 12345,
            destination_port: 9,
            ..Udp::default()
        })
        .push(Raw::new(Bytes::from_static(b"abc")))
        .push(Padding::after_layer(Bytes::from_static(b"trail"), 2));
    let builder = Builder::new(Arc::clone(&registry));
    let built = builder
        .build(packet, BuildContext::default(), BuildOptions::default())
        .unwrap();

    assert_eq!(u16::from_be_bytes([built.bytes[16], built.bytes[17]]), 36);
    assert_eq!(u16::from_be_bytes([built.bytes[38], built.bytes[39]]), 11);

    let decoded = Dissector::new(Arc::clone(&registry))
        .decode_with_root(
            built.bytes.clone(),
            "ethernet".into(),
            DecodeOptions::default(),
        )
        .unwrap();
    assert_eq!(
        decoded.packet.get::<Padding>().unwrap().outside_layer,
        Some(2)
    );
    let document = packetcraftr_packet::document::PacketDocument::from_packet(&decoded.packet);
    let reloaded = document.to_packet(&registry, 64).unwrap();
    let rebuilt = builder
        .build(reloaded, BuildContext::default(), BuildOptions::default())
        .unwrap();
    assert_eq!(rebuilt.bytes, built.bytes);
}

#[test]
fn initial_ipv4_fragment_payload_stays_raw_until_reassembly() {
    let registry = Arc::new(default_registry().unwrap());
    let mut packet = Packet::new();
    packet
        .push(Ipv4 {
            more_fragments: true,
            protocol: WireValue::Exact(17),
            source: Ipv4Addr::new(192, 0, 2, 1),
            destination: Ipv4Addr::new(198, 51, 100, 2),
            ..Ipv4::default()
        })
        .push(Raw::new(Bytes::from_static(&[
            0x30, 0x39, 0, 53, 0, 32, 0, 0,
        ])));
    let built = Builder::new(Arc::clone(&registry))
        .build(packet, BuildContext::default(), BuildOptions::default())
        .unwrap();
    let decoded = Dissector::new(registry)
        .decode_with_root(built.bytes, "ipv4".into(), DecodeOptions::default())
        .unwrap();

    assert!(decoded.packet.get::<Raw>().is_some());
    assert!(decoded.packet.get::<Udp>().is_none());
    assert!(
        decoded
            .packet
            .get::<packetcraftr_packet::layer::MalformedLayer>()
            .is_none()
    );
}

#[test]
fn vxlan_tunnel_round_trips_and_selects_the_inner_ethernet() {
    let registry = Arc::new(default_registry().unwrap());
    let mut packet = Packet::new();
    packet
        .push(Ethernet::default())
        .push(Ipv4 {
            source: Ipv4Addr::new(10, 0, 0, 1),
            destination: Ipv4Addr::new(10, 0, 0, 2),
            ..Ipv4::default()
        })
        .push(Udp {
            source_port: 49152,
            destination_port: 4789,
            ..Udp::default()
        })
        .push(Vxlan {
            vni: 5000,
            ..Vxlan::default()
        })
        .push(Ethernet::default())
        .push(Ipv4 {
            source: Ipv4Addr::new(192, 168, 1, 1),
            destination: Ipv4Addr::new(192, 168, 1, 5),
            ..Ipv4::default()
        })
        .push(Icmpv4 {
            body: Bytes::from_static(b"inner"),
            ..Icmpv4::default()
        });
    let built = Builder::new(Arc::clone(&registry))
        .build(packet, BuildContext::default(), BuildOptions::default())
        .unwrap();
    let decoded = Dissector::new(Arc::clone(&registry))
        .decode_with_root(
            built.bytes.clone(),
            "ethernet".into(),
            DecodeOptions::default(),
        )
        .unwrap();

    assert_eq!(decoded.packet.get_all::<Ethernet>().count(), 2);
    assert_eq!(decoded.packet.get_all::<Ipv4>().count(), 2);
    let vxlan = decoded.packet.get::<Vxlan>().unwrap();
    assert_eq!(vxlan.vni, 5000);
    assert!(decoded.diagnostics.is_empty());

    let rebuilt = Builder::new(registry)
        .build(
            decoded.packet,
            BuildContext::default(),
            BuildOptions::default(),
        )
        .unwrap();
    assert_eq!(rebuilt.bytes, built.bytes);
}

#[test]
fn strict_build_requires_the_registered_port_for_a_udp_encapsulation() {
    let registry = Arc::new(default_registry().unwrap());
    let builder = Builder::new(Arc::clone(&registry));
    let vxlan_on = |source_port: u16, destination_port: u16| {
        let mut packet = Packet::new();
        packet
            .push(Ipv4 {
                source: Ipv4Addr::new(10, 0, 0, 1),
                destination: Ipv4Addr::new(10, 0, 0, 2),
                ..Ipv4::default()
            })
            .push(Udp {
                source_port,
                destination_port,
                ..Udp::default()
            })
            .push(Vxlan::default())
            .push(Ethernet::default())
            .push(Ipv4 {
                source: Ipv4Addr::new(192, 168, 1, 1),
                destination: Ipv4Addr::new(192, 168, 1, 5),
                ..Ipv4::default()
            })
            .push(Icmpv4::default());
        packet
    };

    let error = builder
        .build(
            vxlan_on(49152, 9999),
            BuildContext::default(),
            BuildOptions::default(),
        )
        .unwrap_err();
    assert!(error.to_string().contains("UDP port 4789"));

    // Either endpoint may own the registered port: a reply datagram carries
    // it as the source.
    let reply = builder
        .build(
            vxlan_on(4789, 49152),
            BuildContext::default(),
            BuildOptions::default(),
        )
        .unwrap();
    assert!(reply.diagnostics.is_empty());

    let permissive = builder
        .build(
            vxlan_on(49152, 9999),
            BuildContext::default(),
            BuildOptions {
                mode: BuildMode::Permissive,
                ..BuildOptions::default()
            },
        )
        .unwrap();
    assert!(
        permissive
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "build.udp_encapsulation_port")
    );

    // The converse holds too: an opaque payload on the registered port
    // would dissect as VXLAN, so its layers would not round-trip either.
    let mut raw_on_port = Packet::new();
    raw_on_port
        .push(Ipv4 {
            source: Ipv4Addr::new(10, 0, 0, 1),
            destination: Ipv4Addr::new(10, 0, 0, 2),
            ..Ipv4::default()
        })
        .push(Udp {
            source_port: 49152,
            destination_port: 4789,
            ..Udp::default()
        })
        .push(Raw::new(Bytes::from_static(b"opaque")));
    let error = builder
        .build(
            raw_on_port,
            BuildContext::default(),
            BuildOptions::default(),
        )
        .unwrap_err();
    assert!(error.to_string().contains("vxlan"));
}

#[test]
fn geneve_tunnels_round_trip_bridged_ethernet_and_bare_ip_frames() {
    let registry = Arc::new(default_registry().unwrap());
    let builder = Builder::new(Arc::clone(&registry));
    let outer = |geneve: Geneve| {
        let mut packet = Packet::new();
        packet
            .push(Ipv4 {
                source: Ipv4Addr::new(10, 0, 0, 1),
                destination: Ipv4Addr::new(10, 0, 0, 2),
                ..Ipv4::default()
            })
            .push(Udp {
                source_port: 49152,
                destination_port: 6081,
                ..Udp::default()
            })
            .push(geneve);
        packet
    };

    // Transparent Ethernet Bridging: Auto protocol_type resolves to 0x6558
    // from the inner Ethernet frame, and a critical option is carried
    // verbatim.
    let mut bridged = outer(Geneve {
        vni: 5001,
        critical: true,
        options: Bytes::from_static(&[0x01, 0x02, 0x83, 0x00]),
        ..Geneve::default()
    });
    bridged
        .push(Ethernet::default())
        .push(Ipv4 {
            source: Ipv4Addr::new(192, 168, 1, 1),
            destination: Ipv4Addr::new(192, 168, 1, 5),
            ..Ipv4::default()
        })
        .push(Icmpv4::default());
    let built = builder
        .build(bridged, BuildContext::default(), BuildOptions::default())
        .unwrap();
    let decoded = Dissector::new(Arc::clone(&registry))
        .decode_with_root(built.bytes.clone(), "ipv4".into(), DecodeOptions::default())
        .unwrap();
    let geneve = decoded.packet.get::<Geneve>().unwrap();
    assert_eq!(geneve.protocol_type, WireValue::Exact(0x6558));
    assert_eq!(geneve.vni, 5001);
    assert_eq!(geneve.options.as_ref(), &[0x01, 0x02, 0x83, 0x00]);
    assert_eq!(decoded.packet.get_all::<Ethernet>().count(), 1);
    assert!(decoded.diagnostics.is_empty());
    let rebuilt = builder
        .build(
            decoded.packet,
            BuildContext::default(),
            BuildOptions::default(),
        )
        .unwrap();
    assert_eq!(rebuilt.bytes, built.bytes);

    // A bare IPv4 inner frame resolves protocol_type 0x0800 with no
    // Ethernet in between.
    let mut bare = outer(Geneve {
        vni: 7,
        ..Geneve::default()
    });
    bare.push(Ipv4 {
        source: Ipv4Addr::new(192, 168, 2, 1),
        destination: Ipv4Addr::new(192, 168, 2, 9),
        ..Ipv4::default()
    })
    .push(Icmpv4::default());
    let built = builder
        .build(bare, BuildContext::default(), BuildOptions::default())
        .unwrap();
    let decoded = Dissector::new(Arc::clone(&registry))
        .decode_with_root(built.bytes.clone(), "ipv4".into(), DecodeOptions::default())
        .unwrap();
    assert_eq!(
        decoded.packet.get::<Geneve>().unwrap().protocol_type,
        WireValue::Exact(0x0800)
    );
    assert_eq!(decoded.packet.get_all::<Ipv4>().count(), 2);
    assert!(decoded.packet.get_all::<Ethernet>().count() == 0);
    assert!(decoded.diagnostics.is_empty());
    let rebuilt = builder
        .build(
            decoded.packet,
            BuildContext::default(),
            BuildOptions::default(),
        )
        .unwrap();
    assert_eq!(rebuilt.bytes, built.bytes);

    // The generic UDP encapsulation-port rule applies to GENEVE too.
    let mut away = Packet::new();
    away.push(Ipv4 {
        source: Ipv4Addr::new(10, 0, 0, 1),
        destination: Ipv4Addr::new(10, 0, 0, 2),
        ..Ipv4::default()
    })
    .push(Udp {
        source_port: 49152,
        destination_port: 9999,
        ..Udp::default()
    })
    .push(Geneve::default())
    .push(Ipv4 {
        source: Ipv4Addr::new(192, 168, 2, 1),
        destination: Ipv4Addr::new(192, 168, 2, 9),
        ..Ipv4::default()
    })
    .push(Icmpv4::default());
    let error = builder
        .build(away, BuildContext::default(), BuildOptions::default())
        .unwrap_err();
    assert!(error.to_string().contains("UDP port 6081"));
}

#[test]
fn mpls_label_stacks_round_trip_to_ip_and_opaque_bottoms() {
    let registry = Arc::new(default_registry().unwrap());
    let builder = Builder::new(Arc::clone(&registry));

    // A two-entry stack over Ethernet whose bottom carries IPv4.
    let mut stacked = Packet::new();
    stacked
        .push(Ethernet::default())
        .push(Mpls {
            label: 100,
            bottom_of_stack: false,
            ..Mpls::default()
        })
        .push(Mpls {
            label: 200,
            traffic_class: 5,
            ..Mpls::default()
        })
        .push(Ipv4 {
            source: Ipv4Addr::new(10, 0, 0, 1),
            destination: Ipv4Addr::new(10, 0, 0, 2),
            ..Ipv4::default()
        })
        .push(Icmpv4::default());
    let built = builder
        .build(stacked, BuildContext::default(), BuildOptions::default())
        .unwrap();
    assert_eq!(&built.bytes[12..14], &[0x88, 0x47]);
    let decoded = Dissector::new(Arc::clone(&registry))
        .decode_with_root(
            built.bytes.clone(),
            "ethernet".into(),
            DecodeOptions::default(),
        )
        .unwrap();
    let labels = decoded.packet.get_all::<Mpls>().collect::<Vec<_>>();
    assert_eq!(labels.len(), 2);
    assert_eq!(labels[0].label, 100);
    assert!(!labels[0].bottom_of_stack);
    assert_eq!(labels[1].label, 200);
    assert_eq!(labels[1].traffic_class, 5);
    assert!(labels[1].bottom_of_stack);
    assert!(decoded.packet.get::<Ipv4>().is_some());
    assert!(decoded.diagnostics.is_empty());
    let rebuilt = builder
        .build(
            decoded.packet,
            BuildContext::default(),
            BuildOptions::default(),
        )
        .unwrap();
    assert_eq!(rebuilt.bytes, built.bytes);

    // A pseudowire payload with no protocol field stays opaque; its leading
    // control-word nibble must not be mistaken for another label entry.
    let mut pseudowire = Packet::new();
    pseudowire
        .push(Ethernet::default())
        .push(Mpls::default())
        .push(Raw::new(Bytes::from_static(&[0x00, 0x01, 0x02, 0x03])));
    let built = builder
        .build(pseudowire, BuildContext::default(), BuildOptions::default())
        .unwrap();
    let decoded = Dissector::new(Arc::clone(&registry))
        .decode_with_root(
            built.bytes.clone(),
            "ethernet".into(),
            DecodeOptions::default(),
        )
        .unwrap();
    assert_eq!(decoded.packet.get_all::<Mpls>().count(), 1);
    assert_eq!(
        decoded.packet.get::<Raw>().unwrap().bytes.as_ref(),
        &[0x00, 0x01, 0x02, 0x03]
    );
    let rebuilt = builder
        .build(
            decoded.packet,
            BuildContext::default(),
            BuildOptions::default(),
        )
        .unwrap();
    assert_eq!(rebuilt.bytes, built.bytes);

    // The S bit must agree with what actually follows.
    let mut lying = Packet::new();
    lying
        .push(Ethernet::default())
        .push(Mpls {
            bottom_of_stack: true,
            ..Mpls::default()
        })
        .push(Mpls::default())
        .push(Ipv4 {
            source: Ipv4Addr::new(10, 0, 0, 1),
            destination: Ipv4Addr::new(10, 0, 0, 2),
            ..Ipv4::default()
        })
        .push(Icmpv4::default());
    let error = builder
        .build(lying, BuildContext::default(), BuildOptions::default())
        .unwrap_err();
    assert!(error.to_string().contains("S bit"));

    // A terminal entry with the S bit clear is a truncated stack.
    let mut truncated = Packet::new();
    truncated.push(Ethernet::default()).push(Mpls {
        bottom_of_stack: false,
        ..Mpls::default()
    });
    let error = builder
        .build(truncated, BuildContext::default(), BuildOptions::default())
        .unwrap_err();
    assert!(error.to_string().contains("S bit"));
}

#[test]
fn multicast_mpls_frames_round_trip_their_exact_ethertype() {
    let registry = Arc::new(default_registry().unwrap());
    let builder = Builder::new(Arc::clone(&registry));
    let mut packet = Packet::new();
    packet
        .push(Ethernet {
            ether_type: WireValue::Exact(0x8848),
            ..Ethernet::default()
        })
        .push(Mpls::default())
        .push(Ipv4 {
            source: Ipv4Addr::new(10, 0, 0, 1),
            destination: Ipv4Addr::new(224, 0, 0, 5),
            ..Ipv4::default()
        })
        .push(Icmpv4::default());
    let built = builder
        .build(packet, BuildContext::default(), BuildOptions::default())
        .unwrap();
    assert!(built.diagnostics.is_empty());
    assert_eq!(&built.bytes[12..14], &[0x88, 0x48]);

    let decoded = Dissector::new(Arc::clone(&registry))
        .decode_with_root(
            built.bytes.clone(),
            "ethernet".into(),
            DecodeOptions::default(),
        )
        .unwrap();
    assert!(decoded.packet.get::<Mpls>().is_some());
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
fn a_stack_truncated_before_its_bottom_dissects_as_missing_a_label() {
    // An Ethernet frame that ends right after a non-bottom label entry.
    let mut bytes = Vec::<u8>::new();
    bytes.extend_from_slice(&[0; 12]);
    bytes.extend_from_slice(&[0x88, 0x47]);
    bytes.extend_from_slice(&[0x00, 0x01, 0x44, 0x40]);
    let decoded = Dissector::new(Arc::new(default_registry().unwrap()))
        .decode_with_root(
            Bytes::from(bytes),
            "ethernet".into(),
            DecodeOptions::default(),
        )
        .unwrap();

    assert!(
        decoded
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "decode.missing_required_child")
    );
}

#[test]
fn strict_build_requires_the_encapsulated_frame_after_vxlan() {
    let registry = Arc::new(default_registry().unwrap());
    let builder = Builder::new(Arc::clone(&registry));
    let bare_vxlan = || {
        let mut packet = Packet::new();
        packet
            .push(Ipv4 {
                source: Ipv4Addr::new(10, 0, 0, 1),
                destination: Ipv4Addr::new(10, 0, 0, 2),
                ..Ipv4::default()
            })
            .push(Udp {
                source_port: 49152,
                destination_port: 4789,
                ..Udp::default()
            })
            .push(Vxlan::default());
        packet
    };

    let error = builder
        .build(
            bare_vxlan(),
            BuildContext::default(),
            BuildOptions::default(),
        )
        .unwrap_err();
    assert!(error.to_string().contains("ethernet"));

    let permissive = builder
        .build(
            bare_vxlan(),
            BuildContext::default(),
            BuildOptions {
                mode: BuildMode::Permissive,
                ..BuildOptions::default()
            },
        )
        .unwrap();
    assert!(
        permissive
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "build.discriminator_child_mismatch")
    );
}

#[test]
fn a_zero_destination_port_still_selects_the_source_port_encapsulation() {
    let registry = Arc::new(default_registry().unwrap());
    let builder = Builder::new(Arc::clone(&registry));
    let mut packet = Packet::new();
    packet
        .push(Ipv4 {
            source: Ipv4Addr::new(10, 0, 0, 1),
            destination: Ipv4Addr::new(10, 0, 0, 2),
            ..Ipv4::default()
        })
        .push(Udp {
            source_port: 4789,
            destination_port: 0,
            ..Udp::default()
        })
        .push(Vxlan::default())
        .push(Ethernet::default())
        .push(Ipv4 {
            source: Ipv4Addr::new(192, 168, 1, 1),
            destination: Ipv4Addr::new(192, 168, 1, 5),
            ..Ipv4::default()
        })
        .push(Icmpv4::default());
    let built = builder
        .build(packet, BuildContext::default(), BuildOptions::default())
        .unwrap();
    assert!(built.diagnostics.is_empty());

    let decoded = Dissector::new(Arc::clone(&registry))
        .decode_with_root(built.bytes.clone(), "ipv4".into(), DecodeOptions::default())
        .unwrap();
    assert!(decoded.packet.get::<Vxlan>().is_some());

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
fn an_encapsulated_ethernet_frame_keeps_its_own_link_padding_scope() {
    let registry = Arc::new(default_registry().unwrap());
    let builder = Builder::new(Arc::clone(&registry));
    let mut outer = Packet::new();
    outer
        .push(Ethernet::default())
        .push(Ipv4 {
            source: Ipv4Addr::new(10, 0, 0, 1),
            destination: Ipv4Addr::new(10, 0, 0, 2),
            ..Ipv4::default()
        })
        .push(Udp {
            source_port: 49152,
            destination_port: 4789,
            ..Udp::default()
        })
        .push(Vxlan::default())
        .push(Ethernet::default())
        .push(Ipv4 {
            source: Ipv4Addr::new(192, 168, 1, 1),
            destination: Ipv4Addr::new(192, 168, 1, 5),
            ..Ipv4::default()
        })
        .push(Icmpv4 {
            body: Bytes::from_static(b"inner"),
            ..Icmpv4::default()
        });
    // Minimum-frame padding on the tunneled Ethernet frame, outside the
    // inner network length but inside the outer datagram.
    outer.push(Padding::after_layer(vec![0_u8; 6], 5));
    let built = builder
        .build(outer, BuildContext::default(), BuildOptions::default())
        .unwrap();
    let decoded = Dissector::new(Arc::clone(&registry))
        .decode_with_root(
            built.bytes.clone(),
            "ethernet".into(),
            DecodeOptions::default(),
        )
        .unwrap();

    // Minimum-frame padding on the tunneled Ethernet frame is link padding
    // in the frame's own scope, not malformed bytes outside the outer
    // network envelope.
    let codes = decoded
        .diagnostics
        .iter()
        .map(|diagnostic| diagnostic.code.as_str())
        .collect::<Vec<_>>();
    assert_eq!(codes, ["decode.trailing_padding"]);
    assert!(decoded.packet.get::<Padding>().is_some());

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
fn udp_traffic_away_from_registered_ports_still_decodes_as_raw() {
    let registry = Arc::new(default_registry().unwrap());
    let mut packet = Packet::new();
    packet
        .push(Ipv4 {
            source: Ipv4Addr::new(10, 0, 0, 1),
            destination: Ipv4Addr::new(10, 0, 0, 2),
            ..Ipv4::default()
        })
        .push(Udp {
            source_port: 40000,
            destination_port: 40001,
            ..Udp::default()
        })
        .push(Raw::new(Bytes::from_static(b"opaque")));
    let built = Builder::new(Arc::clone(&registry))
        .build(packet, BuildContext::default(), BuildOptions::default())
        .unwrap();
    let decoded = Dissector::new(registry)
        .decode_with_root(built.bytes, "ipv4".into(), DecodeOptions::default())
        .unwrap();

    let raw = decoded.packet.get::<Raw>().unwrap();
    assert_eq!(raw.bytes.as_ref(), b"opaque");
    assert!(decoded.packet.get::<Vxlan>().is_none());
}
