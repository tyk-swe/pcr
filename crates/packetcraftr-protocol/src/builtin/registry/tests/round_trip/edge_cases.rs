// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::*;

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
