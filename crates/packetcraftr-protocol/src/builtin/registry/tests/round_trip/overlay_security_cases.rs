// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::*;

#[test]
fn l2tpv3_session_headers_round_trip_with_an_opaque_cookie_payload() {
    let registry = Arc::new(default_registry().unwrap());
    let builder = Builder::new(Arc::clone(&registry));
    let mut packet = Packet::new();
    packet
        .push(Ipv4 {
            source: Ipv4Addr::new(10, 0, 0, 1),
            destination: Ipv4Addr::new(10, 0, 0, 2),
            ..Ipv4::default()
        })
        .push(L2tpv3 { session_id: 0x5eed })
        .push(Raw::new(Bytes::from_static(&[1, 2, 3, 4, 0x45, 0, 0, 20])));
    let built = builder
        .build(packet, BuildContext::default(), BuildOptions::default())
        .unwrap();
    assert!(built.diagnostics.is_empty());
    assert_eq!(built.bytes[9], 115);
    let decoded = Dissector::new(Arc::clone(&registry))
        .decode_with_root(built.bytes.clone(), "ipv4".into(), DecodeOptions::default())
        .unwrap();
    assert_eq!(decoded.packet.get::<L2tpv3>().unwrap().session_id, 0x5eed);
    // The cookie and tunneled frame stay opaque even when the bytes after
    // the cookie imitate an IPv4 header.
    assert_eq!(decoded.packet.get_all::<Ipv4>().count(), 1);
    assert!(decoded.packet.get::<Raw>().is_some());
    assert!(decoded.diagnostics.is_empty());
    let rebuilt = builder
        .build(
            decoded.packet,
            BuildContext::default(),
            BuildOptions::default(),
        )
        .unwrap();
    assert_eq!(rebuilt.bytes, built.bytes);

    // A typed child would serialize structure the dissector never
    // recovers from behind the cookie.
    let mut typed = Packet::new();
    typed
        .push(Ipv4 {
            source: Ipv4Addr::new(10, 0, 0, 1),
            destination: Ipv4Addr::new(10, 0, 0, 2),
            ..Ipv4::default()
        })
        .push(L2tpv3::default())
        .push(Icmpv4::default());
    let permissive = builder
        .build(
            typed,
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
            .any(|diagnostic| diagnostic.code == "build.l2tpv3_cookie")
    );
}

#[test]
fn erspan_mirrored_frames_round_trip_both_header_types() {
    let registry = Arc::new(default_registry().unwrap());
    let builder = Builder::new(Arc::clone(&registry));
    let mirrored = |erspan: Erspan, gre: Gre| {
        let mut packet = Packet::new();
        packet
            .push(Ipv4 {
                source: Ipv4Addr::new(10, 0, 0, 1),
                destination: Ipv4Addr::new(10, 0, 0, 2),
                ..Ipv4::default()
            })
            .push(gre)
            .push(erspan)
            .push(Ethernet::default())
            .push(Ipv4 {
                source: Ipv4Addr::new(192, 168, 1, 1),
                destination: Ipv4Addr::new(192, 168, 1, 5),
                ..Ipv4::default()
            })
            .push(Icmpv4::default());
        packet
    };

    // Type II with a GRE sequence number, as the ERSPAN drafts prescribe.
    let built = builder
        .build(
            mirrored(
                Erspan {
                    vlan: 100,
                    session_id: 42,
                    index_word: 0x102,
                    ..Erspan::default()
                },
                Gre {
                    sequence: Some(7),
                    ..Gre::default()
                },
            ),
            BuildContext::default(),
            BuildOptions::default(),
        )
        .unwrap();
    assert!(built.diagnostics.is_empty());
    let decoded = Dissector::new(Arc::clone(&registry))
        .decode_with_root(built.bytes.clone(), "ipv4".into(), DecodeOptions::default())
        .unwrap();
    let erspan = decoded.packet.get::<Erspan>().unwrap();
    assert_eq!(erspan.session_id, 42);
    assert_eq!(erspan.index_word, 0x102);
    assert_eq!(decoded.packet.get_all::<Ipv4>().count(), 2);
    assert!(decoded.diagnostics.is_empty());
    let rebuilt = builder
        .build(
            decoded.packet,
            BuildContext::default(),
            BuildOptions::default(),
        )
        .unwrap();
    assert_eq!(rebuilt.bytes, built.bytes);

    // Type III on its own GRE protocol type.
    let built = builder
        .build(
            mirrored(
                Erspan {
                    version: 2,
                    session_id: 9,
                    type3: Some(ErspanType3 {
                        timestamp: 0x1122_3344,
                        sgt: 7,
                        flags: 0x8001,
                        subheader: Some(Bytes::from_static(&[9, 8, 7, 6, 5, 4, 3, 2])),
                    }),
                    ..Erspan::default()
                },
                Gre {
                    protocol_type: WireValue::Exact(0x22eb),
                    ..Gre::default()
                },
            ),
            BuildContext::default(),
            BuildOptions::default(),
        )
        .unwrap();
    assert!(built.diagnostics.is_empty());
    let decoded = Dissector::new(Arc::clone(&registry))
        .decode_with_root(built.bytes.clone(), "ipv4".into(), DecodeOptions::default())
        .unwrap();
    let erspan = decoded.packet.get::<Erspan>().unwrap();
    assert_eq!(erspan.version, 2);
    let type3 = erspan.type3.as_ref().unwrap();
    assert_eq!(type3.timestamp, 0x1122_3344);
    assert_eq!(
        type3.subheader.as_deref(),
        Some(&[9, 8, 7, 6, 5, 4, 3, 2][..])
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

    // A version that disagrees with the GRE protocol type does not build
    // strictly.
    let error = builder
        .build(
            mirrored(
                Erspan::default(),
                Gre {
                    protocol_type: WireValue::Exact(0x22eb),
                    ..Gre::default()
                },
            ),
            BuildContext::default(),
            BuildOptions::default(),
        )
        .unwrap_err();
    assert!(error.to_string().contains("0x88be"));

    // Type II requires the GRE sequence number.
    let error = builder
        .build(
            mirrored(Erspan::default(), Gre::default()),
            BuildContext::default(),
            BuildOptions::default(),
        )
        .unwrap_err();
    assert!(error.to_string().contains("sequence"));

    // An Auto GRE protocol type materializes the Type II value, so a
    // Type III header requires an explicit 0x22eb.
    let error = builder
        .build(
            mirrored(
                Erspan {
                    version: 2,
                    type3: Some(ErspanType3::default()),
                    ..Erspan::default()
                },
                Gre::default(),
            ),
            BuildContext::default(),
            BuildOptions::default(),
        )
        .unwrap_err();
    assert!(error.to_string().contains("0x22eb"));
}

#[test]
fn ipsec_esp_and_ah_round_trip_with_the_chain_continuing_through_ah() {
    let registry = Arc::new(default_registry().unwrap());
    let builder = Builder::new(Arc::clone(&registry));

    // AH authenticates a TCP-free ICMP payload: the chain continues.
    let mut authenticated = Packet::new();
    authenticated
        .push(Ipv4 {
            source: Ipv4Addr::new(10, 0, 0, 1),
            destination: Ipv4Addr::new(10, 0, 0, 2),
            ..Ipv4::default()
        })
        .push(Ah {
            spi: 0x100,
            sequence: 5,
            ..Ah::default()
        })
        .push(Icmpv4::default());
    let built = builder
        .build(
            authenticated,
            BuildContext::default(),
            BuildOptions::default(),
        )
        .unwrap();
    assert!(built.diagnostics.is_empty());
    assert_eq!(built.bytes[9], 51);
    assert_eq!(built.bytes[20], 1);
    let decoded = Dissector::new(Arc::clone(&registry))
        .decode_with_root(built.bytes.clone(), "ipv4".into(), DecodeOptions::default())
        .unwrap();
    let ah = decoded.packet.get::<Ah>().unwrap();
    assert_eq!(ah.spi, 0x100);
    assert_eq!(ah.icv.len(), 12);
    assert!(decoded.packet.get::<Icmpv4>().is_some());
    assert!(decoded.diagnostics.is_empty());
    let rebuilt = builder
        .build(
            decoded.packet,
            BuildContext::default(),
            BuildOptions::default(),
        )
        .unwrap();
    assert_eq!(rebuilt.bytes, built.bytes);

    // ESP ciphertext stays opaque.
    let mut encrypted = Packet::new();
    encrypted
        .push(Ipv4 {
            source: Ipv4Addr::new(10, 0, 0, 1),
            destination: Ipv4Addr::new(10, 0, 0, 2),
            ..Ipv4::default()
        })
        .push(Esp {
            spi: 0x200,
            sequence: 9,
        })
        .push(Raw::new(Bytes::from_static(&[0x45, 0x00, 0x00, 0x14])));
    let built = builder
        .build(encrypted, BuildContext::default(), BuildOptions::default())
        .unwrap();
    assert_eq!(built.bytes[9], 50);
    let decoded = Dissector::new(Arc::clone(&registry))
        .decode_with_root(built.bytes.clone(), "ipv4".into(), DecodeOptions::default())
        .unwrap();
    assert_eq!(decoded.packet.get::<Esp>().unwrap().spi, 0x200);
    // The ciphertext imitating an IPv4 header is not dissected.
    assert!(decoded.packet.get_all::<Ipv4>().count() == 1);
    assert!(decoded.packet.get::<Raw>().is_some());
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
fn ah_keeps_the_other_address_familys_children_out() {
    let registry = Arc::new(default_registry().unwrap());
    let builder = Builder::new(Arc::clone(&registry));

    // Building ICMPv4 behind an IPv6 AH does not pass strictly.
    let mut cross = Packet::new();
    cross
        .push(Ipv6 {
            source: "2001:db8::1".parse().unwrap(),
            destination: "2001:db8::2".parse().unwrap(),
            ..Ipv6::default()
        })
        .push(Ah::default())
        .push(Icmpv4::default());
    let error = builder
        .build(cross, BuildContext::default(), BuildOptions::default())
        .unwrap_err();
    assert!(error.to_string().contains("address family"));

    // Dissecting IPv6/AH with next_header 1 keeps the payload opaque
    // instead of inventing an ICMPv4 layer.
    let mut inner = Vec::<u8>::new();
    inner.push(1);
    inner.push(4);
    inner.extend_from_slice(&[0, 0, 0, 0, 0, 9, 0, 0, 0, 1]);
    inner.extend_from_slice(&[0; 12]);
    inner.extend_from_slice(&[8, 0, 0, 0]);
    let mut bytes = Vec::<u8>::new();
    bytes.extend_from_slice(&[0x60, 0, 0, 0]);
    bytes.extend_from_slice(&u16::try_from(inner.len()).unwrap().to_be_bytes());
    bytes.push(51);
    bytes.push(64);
    bytes.extend_from_slice(
        &"2001:db8::1"
            .parse::<std::net::Ipv6Addr>()
            .unwrap()
            .octets(),
    );
    bytes.extend_from_slice(
        &"2001:db8::2"
            .parse::<std::net::Ipv6Addr>()
            .unwrap()
            .octets(),
    );
    bytes.extend_from_slice(&inner);
    let decoded = Dissector::new(registry)
        .decode_with_root(Bytes::from(bytes), "ipv6".into(), DecodeOptions::default())
        .unwrap();

    assert!(decoded.packet.get::<Icmpv4>().is_none());
    assert!(
        decoded
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "decode.ah_family")
    );

    // The preserved cross-family capture still rebuilds byte-for-byte: the
    // discriminator selects nothing in this family, so its opaque payload
    // is the faithful child.
    let original = decoded.original.clone();
    let rebuilt = builder
        .build(
            decoded.packet,
            BuildContext::default(),
            BuildOptions::default(),
        )
        .unwrap();
    assert_eq!(rebuilt.bytes, original);
}

#[test]
fn esp_builds_refuse_typed_plaintext_children() {
    let registry = Arc::new(default_registry().unwrap());
    let builder = Builder::new(Arc::clone(&registry));
    let plaintext = || {
        let mut packet = Packet::new();
        packet
            .push(Ipv4 {
                source: Ipv4Addr::new(10, 0, 0, 1),
                destination: Ipv4Addr::new(10, 0, 0, 2),
                ..Ipv4::default()
            })
            .push(Esp::default())
            .push(Icmpv4::default());
        packet
    };

    // Strict construction fails on the missing binding before the codec
    // even runs; permissive still flags the ciphertext violation.
    assert!(
        builder
            .build(
                plaintext(),
                BuildContext::default(),
                BuildOptions::default()
            )
            .is_err()
    );
    let permissive = builder
        .build(
            plaintext(),
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
            .any(|diagnostic| diagnostic.code == "build.esp_ciphertext")
    );
}

#[test]
fn transport_checksums_reach_the_srh_final_destination_through_ah() {
    let registry = Arc::new(default_registry().unwrap());
    let builder = Builder::new(Arc::clone(&registry));
    let mut packet = Packet::new();
    packet
        .push(Ipv6 {
            source: "2001:db8::1".parse().unwrap(),
            // The header names the active segment; the transport checksum
            // must still be computed against the final one.
            destination: "2001:db8::10".parse().unwrap(),
            ..Ipv6::default()
        })
        .push(Ah::default())
        .push(SegmentRoutingHeader {
            segments: vec![
                "2001:db8::10".parse().unwrap(),
                "2001:db8::20".parse().unwrap(),
            ],
            ..SegmentRoutingHeader::default()
        })
        .push(Tcp::default())
        .push(Raw::new(Bytes::from_static(b"data")));
    let built = builder
        .build(packet, BuildContext::default(), BuildOptions::default())
        .unwrap();

    let decoded = Dissector::new(Arc::clone(&registry))
        .decode_with_root(
            built.bytes.clone(),
            "ipv6".into(),
            DecodeOptions {
                verify_checksums: true,
                ..DecodeOptions::default()
            },
        )
        .unwrap();
    // A checksum built against the header destination instead of the SRH
    // final segment would be flagged here.
    assert!(decoded.diagnostics.is_empty(), "{:?}", decoded.diagnostics);
    assert!(decoded.packet.get::<Tcp>().is_some());
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
fn an_ipv6_ah_header_must_align_to_eight_octets() {
    let registry = Arc::new(default_registry().unwrap());
    let builder = Builder::new(Arc::clone(&registry));
    let ipv6_ah = |icv: &'static [u8]| {
        let mut packet = Packet::new();
        packet
            .push(Ipv6 {
                source: "2001:db8::1".parse().unwrap(),
                destination: "2001:db8::2".parse().unwrap(),
                ..Ipv6::default()
            })
            .push(Ah {
                icv: Bytes::from_static(icv),
                ..Ah::default()
            })
            .push(Icmpv6::default());
        packet
    };

    // A 20-byte header breaks the 8-octet extension unit under IPv6.
    let error = builder
        .build(
            ipv6_ah(&[0; 8]),
            BuildContext::default(),
            BuildOptions::default(),
        )
        .unwrap_err();
    assert!(error.to_string().contains("8 octets"));

    // The default 96-bit ICV yields an aligned 24-byte header.
    let built = builder
        .build(
            ipv6_ah(&[0; 12]),
            BuildContext::default(),
            BuildOptions::default(),
        )
        .unwrap();
    assert!(built.diagnostics.is_empty());
    let decoded = Dissector::new(Arc::clone(&registry))
        .decode_with_root(built.bytes.clone(), "ipv6".into(), DecodeOptions::default())
        .unwrap();
    assert!(decoded.packet.get::<Icmpv6>().is_some());
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
