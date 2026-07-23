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
    let document = crate::packet::document::PacketDocument::from_packet(&decoded.packet);
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
            .get::<crate::packet::layer::MalformedLayer>()
            .is_none()
    );
}
