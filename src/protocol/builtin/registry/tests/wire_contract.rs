// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::*;

#[test]
fn unknown_exact_ether_type_with_raw_rebuilds_strictly() {
    let registry = Arc::new(default_registry().unwrap());
    let builder = Builder::new(Arc::clone(&registry));
    let mut packet = Packet::new();
    packet
        .push(Ethernet {
            ether_type: WireValue::Exact(0x1234),
            ..Ethernet::default()
        })
        .push(Raw::new(Bytes::from_static(b"opaque")));
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
}

#[test]
fn strict_fragment_building_enforces_flag_and_alignment_rules() {
    let registry = Arc::new(default_registry().unwrap());
    let builder = Builder::new(registry);
    let mut packet = Packet::new();
    packet
        .push(Ipv4 {
            dont_fragment: true,
            more_fragments: true,
            protocol: WireValue::Exact(253),
            source: Ipv4Addr::new(192, 0, 2, 1),
            destination: Ipv4Addr::new(198, 51, 100, 2),
            ..Ipv4::default()
        })
        .push(Raw::new(Bytes::from_static(b"odd")));
    assert!(
        builder
            .build(packet, BuildContext::default(), BuildOptions::default())
            .is_err()
    );
}

#[test]
fn hop_by_hop_cannot_follow_another_ipv6_extension() {
    let registry = Arc::new(default_registry().unwrap());
    let mut packet = Packet::new();
    packet
        .push(Ipv6 {
            source: "2001:db8::1".parse().unwrap(),
            destination: "2001:db8::2".parse().unwrap(),
            ..Ipv6::default()
        })
        .push(DestinationOptions::default())
        .push(HopByHop::default())
        .push(Udp::default());
    assert!(
        Builder::new(registry)
            .build(packet, BuildContext::default(), BuildOptions::default())
            .is_err()
    );
}

#[test]
fn strict_srh_requires_outer_destination_to_match_active_segment() {
    let registry = Arc::new(default_registry().unwrap());
    let mut packet = Packet::new();
    packet
        .push(Ipv6 {
            source: "2001:db8::1".parse().unwrap(),
            destination: "2001:db8::99".parse().unwrap(),
            ..Ipv6::default()
        })
        .push(SegmentRoutingHeader {
            segments: vec![
                "2001:db8::10".parse().unwrap(),
                "2001:db8::20".parse().unwrap(),
            ],
            ..SegmentRoutingHeader::default()
        })
        .push(Udp::default());
    assert!(
        Builder::new(registry)
            .build(packet, BuildContext::default(), BuildOptions::default())
            .is_err()
    );
}

#[test]
fn no_next_header_with_bytes_is_explicitly_malformed() {
    let registry = Arc::new(default_registry().unwrap());
    let mut bytes = vec![0_u8; 43];
    bytes[0] = 0x60;
    bytes[5] = 3;
    bytes[6] = 59;
    bytes[7] = 64;
    bytes[40..].copy_from_slice(b"bad");
    let decoded = Dissector::new(Arc::clone(&registry))
        .decode_with_root(bytes.clone(), "ipv6".into(), DecodeOptions::default())
        .unwrap();
    assert!(
        decoded
            .packet
            .get::<crate::packet::layer::MalformedLayer>()
            .is_some()
    );
    let rebuilt = Builder::new(registry)
        .build(
            decoded.packet,
            BuildContext::default(),
            BuildOptions::default(),
        )
        .unwrap();
    assert_eq!(rebuilt.bytes.as_ref(), bytes);
    assert!(rebuilt.requires_live_opt_in);
}

#[test]
fn empty_ipv6_ethernet_payload_preserves_link_padding() {
    let registry = Arc::new(default_registry().unwrap());
    let mut packet = Packet::new();
    packet
        .push(Ethernet::default())
        .push(Ipv6 {
            source: "2001:db8::1".parse().unwrap(),
            destination: "2001:db8::2".parse().unwrap(),
            ..Ipv6::default()
        })
        .push(Padding::new(Bytes::from_static(&[0; 6])));
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

    assert_eq!(
        decoded.packet.get::<Padding>().unwrap().bytes,
        Bytes::from_static(&[0; 6])
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
fn missing_ipv6_child_with_link_padding_is_not_a_jumbogram() {
    let registry = Arc::new(default_registry().unwrap());
    let mut bytes = vec![0_u8; 14 + 40 + 6];
    bytes[12..14].copy_from_slice(&0x86dd_u16.to_be_bytes());
    bytes[14] = 0x60;
    bytes[20] = 17;
    bytes[21] = 64;

    let decoded = Dissector::new(Arc::clone(&registry))
        .decode_with_root(bytes.clone(), "ethernet".into(), DecodeOptions::default())
        .unwrap();
    assert!(decoded.packet.get::<Ipv6>().is_some());
    assert!(
        decoded
            .packet
            .get::<crate::packet::layer::MalformedLayer>()
            .is_some()
    );
    assert_eq!(
        decoded.packet.get::<Padding>().unwrap().bytes,
        Bytes::from_static(&[0; 6])
    );

    let rebuilt = Builder::new(registry)
        .build(
            decoded.packet,
            BuildContext::default(),
            BuildOptions::default(),
        )
        .unwrap();
    assert_eq!(rebuilt.bytes.as_ref(), bytes);
}

#[test]
fn zero_length_raw_ipv6_trailer_is_not_a_jumbogram_without_hop_by_hop() {
    let registry = Arc::new(default_registry().unwrap());
    let mut bytes = vec![0_u8; 43];
    bytes[0] = 0x60;
    bytes[6] = 59;
    bytes[7] = 64;
    bytes[40..].copy_from_slice(b"bad");

    let decoded = Dissector::new(Arc::clone(&registry))
        .decode_with_root(bytes.clone(), "ipv6".into(), DecodeOptions::default())
        .unwrap();
    assert!(decoded.packet.get::<Ipv6>().is_some());
    assert_eq!(
        decoded.packet.get::<Padding>().unwrap().outside_layer,
        Some(0)
    );
    assert!(
        decoded
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "decode.trailing_malformed")
    );

    let rebuilt = Builder::new(registry)
        .build(
            decoded.packet,
            BuildContext::default(),
            BuildOptions::default(),
        )
        .unwrap();
    assert_eq!(rebuilt.bytes.as_ref(), bytes);
    assert!(rebuilt.requires_live_opt_in);
}

#[test]
fn ipv4_known_answer_emits_rfc_checksum_vector() {
    let registry = Arc::new(default_registry().unwrap());
    let mut packet = Packet::new();
    packet
        .push(Ipv4 {
            dont_fragment: true,
            ttl: 64,
            protocol: WireValue::Exact(17),
            source: Ipv4Addr::new(192, 168, 0, 1),
            destination: Ipv4Addr::new(192, 168, 0, 199),
            ..Ipv4::default()
        })
        .push(Raw::new(Bytes::from(vec![0; 95])));

    let built = Builder::new(registry)
        .build(
            packet,
            BuildContext::default(),
            BuildOptions {
                mode: BuildMode::Permissive,
                ..BuildOptions::default()
            },
        )
        .unwrap();

    assert_eq!(
        &built.bytes[..20],
        &[
            0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0xb8, 0x61, 0xc0, 0xa8,
            0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7,
        ]
    );
}

#[test]
fn build_context_materializes_unspecified_ip_addresses_before_checksums() {
    let registry = Arc::new(default_registry().unwrap());
    let mut packet = Packet::new();
    packet.push(Ipv4::default()).push(Udp::default());
    let built = Builder::new(Arc::clone(&registry))
        .build(
            packet,
            BuildContext {
                source: Some("192.0.2.1".parse().unwrap()),
                destination: Some("198.51.100.2".parse().unwrap()),
                ..BuildContext::default()
            },
            BuildOptions::default(),
        )
        .unwrap();

    assert_eq!(
        built.packet.get::<Ipv4>().unwrap().source,
        Ipv4Addr::new(192, 0, 2, 1)
    );
    assert_eq!(&built.bytes[12..16], &[192, 0, 2, 1]);
    assert_eq!(&built.bytes[16..20], &[198, 51, 100, 2]);
    let decoded = Dissector::new(registry)
        .decode_with_root(built.bytes, "ipv4".into(), DecodeOptions::default())
        .unwrap();
    assert!(decoded.diagnostics.is_empty());
}

#[test]
fn typed_arp_rejects_non_ethernet_ipv4_address_families() {
    let registry = Arc::new(default_registry().unwrap());
    let builder = Builder::new(Arc::clone(&registry));
    let mut packet = Packet::new();
    packet.push(Arp {
        hardware_type: 2,
        ..Arp::default()
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
    assert!(
        permissive
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "build.arp_address_types")
    );

    let decoded = Dissector::new(registry)
        .decode_with_root(permissive.bytes, "arp".into(), DecodeOptions::default())
        .unwrap();
    assert!(
        decoded
            .packet
            .get::<crate::packet::layer::MalformedLayer>()
            .is_some()
    );
}
