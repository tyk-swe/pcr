// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::*;

#[test]
fn an_802_3_frame_round_trips_llc_snap_and_the_ethertype_space() {
    let registry = Arc::new(default_registry().unwrap());
    let builder = Builder::new(Arc::clone(&registry));
    let mut packet = Packet::new();
    packet
        .push(Ethernet::default())
        .push(Llc::default())
        .push(Snap::default())
        .push(Ipv4 {
            source: Ipv4Addr::new(10, 0, 0, 1),
            destination: Ipv4Addr::new(10, 0, 0, 2),
            ..Ipv4::default()
        })
        .push(Icmpv4 {
            body: Bytes::from_static(b"llc!"),
            ..Icmpv4::default()
        });
    let built = builder
        .build(packet, BuildContext::default(), BuildOptions::default())
        .unwrap();
    assert!(built.diagnostics.is_empty());
    // The EtherType slot carries the 802.3 payload length: LLC (3) + SNAP
    // (5) + IPv4 (20) + ICMP (8).
    assert_eq!(u16::from_be_bytes([built.bytes[12], built.bytes[13]]), 36);
    let decoded = Dissector::new(Arc::clone(&registry))
        .decode_with_root(
            built.bytes.clone(),
            "ethernet".into(),
            DecodeOptions::default(),
        )
        .unwrap();
    assert!(decoded.packet.get::<Llc>().is_some());
    assert_eq!(decoded.packet.get::<Snap>().unwrap().oui, 0);
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
}

#[test]
fn a_padded_802_3_frame_keeps_its_length_and_link_padding() {
    let registry = Arc::new(default_registry().unwrap());
    let builder = Builder::new(Arc::clone(&registry));
    let mut packet = Packet::new();
    packet
        .push(Ethernet::default())
        .push(Llc {
            dsap: 0x42,
            ssap: 0x42,
            control: Bytes::from_static(&[0x03]),
        })
        .push(Raw::new(Bytes::from_static(&[1, 2, 3, 4, 5])))
        .push(Padding::new(Bytes::from_static(&[0; 38])));
    let built = builder
        .build(packet, BuildContext::default(), BuildOptions::default())
        .unwrap();
    // The declared length covers LLC and its payload, not the padding.
    assert_eq!(u16::from_be_bytes([built.bytes[12], built.bytes[13]]), 8);
    assert_eq!(built.bytes.len(), 60);

    let decoded = Dissector::new(Arc::clone(&registry))
        .decode_with_root(
            built.bytes.clone(),
            "ethernet".into(),
            DecodeOptions::default(),
        )
        .unwrap();
    let codes = decoded
        .diagnostics
        .iter()
        .map(|diagnostic| diagnostic.code.as_str())
        .collect::<Vec<_>>();
    assert_eq!(codes, ["decode.trailing_padding"]);
    // The unregistered SAP pair keeps its payload as typed raw bytes.
    assert!(decoded.packet.get::<Llc>().is_some());
    assert_eq!(
        decoded.packet.get::<Raw>().unwrap().bytes.as_ref(),
        &[1, 2, 3, 4, 5]
    );
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
fn direct_vlan_roots_classify_802_3_trailers_as_link_padding() {
    let registry = Arc::new(default_registry().unwrap());
    for root in ["vlan", "vlan8021ad"] {
        let bytes = Bytes::from_static(&[
            0x00, 0x01, 0x00, 0x03, 0x42, 0x42, 0x03, 0x00, 0x00, 0x00, 0x00,
        ]);
        let decoded = Dissector::new(Arc::clone(&registry))
            .decode_with_root(bytes, root.into(), DecodeOptions::default())
            .unwrap();

        assert!(decoded.packet.get::<Padding>().is_some());
        assert!(
            decoded
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "decode.trailing_padding")
        );
        assert!(
            decoded
                .diagnostics
                .iter()
                .all(|diagnostic| diagnostic.code != "decode.trailing_malformed")
        );
    }
}

#[test]
fn a_length_form_ether_type_requires_llc_framing() {
    let registry = Arc::new(default_registry().unwrap());
    let builder = Builder::new(Arc::clone(&registry));
    // An ether_type at or below 1500 dissects as an 802.3 payload length
    // selecting LLC, so opaque bytes there would come back as a different
    // layer stack.
    let length_form = || {
        let mut packet = Packet::new();
        packet
            .push(Ethernet {
                ether_type: WireValue::Exact(5),
                ..Ethernet::default()
            })
            .push(Raw::new(Bytes::from_static(&[1, 2, 3, 4, 5])));
        packet
    };
    let error = builder
        .build(
            length_form(),
            BuildContext::default(),
            BuildOptions::default(),
        )
        .unwrap_err();
    assert!(error.to_string().contains("802.3 payload length"));

    // The VLAN tags share the 802.3 framing rule.
    let mut tagged = Packet::new();
    tagged
        .push(Ethernet::default())
        .push(Vlan {
            vlan_id: 7,
            ether_type: WireValue::Exact(5),
            ..Vlan::default()
        })
        .push(Raw::new(Bytes::from_static(&[1, 2, 3, 4, 5])));
    let error = builder
        .build(tagged, BuildContext::default(), BuildOptions::default())
        .unwrap_err();
    assert!(error.to_string().contains("802.3 payload length"));

    let permissive = builder
        .build(
            length_form(),
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
            .any(|diagnostic| diagnostic.code == "build.link_length_form")
    );
}

#[test]
fn auto_raw_link_payloads_use_an_unknown_non_length_discriminator() {
    let registry = Arc::new(default_registry().unwrap());
    let builder = Builder::new(Arc::clone(&registry));
    let permissive = BuildOptions {
        mode: BuildMode::Permissive,
        ..BuildOptions::default()
    };

    let mut ethernet_raw = Packet::new();
    ethernet_raw
        .push(Ethernet::default())
        .push(Raw::new(Bytes::from_static(b"opaque")));
    let built = builder
        .build(ethernet_raw, BuildContext::default(), permissive.clone())
        .unwrap();
    assert_eq!(u16::from_be_bytes([built.bytes[12], built.bytes[13]]), 1501);
    assert!(
        built
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "build.auto_raw_discriminator")
    );

    let decoded = Dissector::new(Arc::clone(&registry))
        .decode_with_root(
            built.bytes.clone(),
            "ethernet".into(),
            DecodeOptions::default(),
        )
        .unwrap();
    assert_eq!(
        decoded.packet.get::<Raw>().unwrap().bytes.as_ref(),
        b"opaque"
    );
    assert!(decoded.packet.get::<Padding>().is_none());
    let rebuilt = builder
        .build(
            decoded.packet,
            BuildContext::default(),
            BuildOptions::default(),
        )
        .unwrap();
    assert_eq!(rebuilt.bytes, built.bytes);

    let mut vlan_raw = Packet::new();
    vlan_raw
        .push(Ethernet::default())
        .push(Vlan::default())
        .push(Raw::new(Bytes::from_static(b"opaque")));
    let built = builder
        .build(vlan_raw, BuildContext::default(), permissive)
        .unwrap();
    assert_eq!(u16::from_be_bytes([built.bytes[16], built.bytes[17]]), 1501);

    let decoded = Dissector::new(Arc::clone(&registry))
        .decode_with_root(
            built.bytes.clone(),
            "ethernet".into(),
            DecodeOptions::default(),
        )
        .unwrap();
    assert!(decoded.packet.get::<Vlan>().is_some());
    assert_eq!(
        decoded.packet.get::<Raw>().unwrap().bytes.as_ref(),
        b"opaque"
    );
    assert!(decoded.packet.get::<Padding>().is_none());
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
fn a_snap_child_requires_the_snap_sap_pair() {
    let registry = Arc::new(default_registry().unwrap());
    let builder = Builder::new(Arc::clone(&registry));
    // A SAP pair other than 0xAA/0xAA never announces SNAP, so dissection
    // would keep the header bytes as typed raw payload.
    let mislabeled = || {
        let mut packet = Packet::new();
        packet
            .push(Ethernet::default())
            .push(Llc {
                dsap: 0x42,
                ssap: 0x42,
                control: Bytes::from_static(&[0x03]),
            })
            .push(Snap::default())
            .push(Ipv4 {
                source: Ipv4Addr::new(10, 0, 0, 1),
                destination: Ipv4Addr::new(10, 0, 0, 2),
                ..Ipv4::default()
            })
            .push(Icmpv4::default());
        packet
    };
    let error = builder
        .build(
            mislabeled(),
            BuildContext::default(),
            BuildOptions::default(),
        )
        .unwrap_err();
    assert!(error.to_string().contains("does not select snap"));

    let permissive = builder
        .build(
            mislabeled(),
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
fn a_vendor_snap_numbering_restricts_typed_children_to_registered_bindings() {
    let registry = Arc::new(default_registry().unwrap());
    let builder = Builder::new(Arc::clone(&registry));
    // Cisco's OUI with an unregistered protocol identifier has no vendor
    // binding, so a typed child would dissect back as raw bytes.
    let vendor_typed = || {
        let mut packet = Packet::new();
        packet
            .push(Ethernet::default())
            .push(Llc::default())
            .push(Snap {
                oui: 0x0000_000c,
                protocol_id: WireValue::Exact(0x2003),
            })
            .push(Ipv4 {
                source: Ipv4Addr::new(10, 0, 0, 1),
                destination: Ipv4Addr::new(10, 0, 0, 2),
                ..Ipv4::default()
            })
            .push(Icmpv4::default());
        packet
    };
    let error = builder
        .build(
            vendor_typed(),
            BuildContext::default(),
            BuildOptions::default(),
        )
        .unwrap_err();
    assert!(error.to_string().contains("does not select ipv4"));

    let permissive = builder
        .build(
            vendor_typed(),
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

    // An opaque vendor payload builds cleanly and round-trips; the unknown
    // packed discriminator surfaces as the usual unknown-binding warning.
    let mut opaque = Packet::new();
    opaque
        .push(Ethernet::default())
        .push(Llc::default())
        .push(Snap {
            oui: 0x0000_000c,
            protocol_id: WireValue::Exact(0x2003),
        })
        .push(Raw::new(Bytes::from_static(&[0xca, 0xfe])));
    let built = builder
        .build(opaque, BuildContext::default(), BuildOptions::default())
        .unwrap();
    assert!(built.diagnostics.is_empty());
    let decoded = Dissector::new(Arc::clone(&registry))
        .decode_with_root(
            built.bytes.clone(),
            "ethernet".into(),
            DecodeOptions::default(),
        )
        .unwrap();
    let codes = decoded
        .diagnostics
        .iter()
        .map(|diagnostic| diagnostic.code.as_str())
        .collect::<Vec<_>>();
    assert_eq!(codes, ["decode.unknown_binding"]);
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
fn an_empty_802_3_length_frame_stops_cleanly_without_a_missing_llc_child() {
    let registry = Arc::new(default_registry().unwrap());
    let builder = Builder::new(Arc::clone(&registry));
    let mut packet = Packet::new();
    packet.push(Ethernet::default());
    let built = builder
        .build(packet, BuildContext::default(), BuildOptions::default())
        .unwrap();
    assert!(built.diagnostics.is_empty());
    assert_eq!(u16::from_be_bytes([built.bytes[12], built.bytes[13]]), 0);

    // A zero 802.3 length declares an empty frame, not a truncated LLC
    // header: dissection stops cleanly instead of reporting a missing child.
    let decoded = Dissector::new(Arc::clone(&registry))
        .decode_with_root(
            built.bytes.clone(),
            "ethernet".into(),
            DecodeOptions::default(),
        )
        .unwrap();
    assert!(decoded.diagnostics.is_empty());
    assert_eq!(decoded.packet.len(), 1);
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
fn an_ethertype_form_link_header_is_not_a_padding_boundary() {
    let registry = Arc::new(default_registry().unwrap());
    let builder = Builder::new(Arc::clone(&registry));
    // An EtherType-form header declares no payload length, so padding bound
    // outside it would fold back into the raw payload on dissection.
    let unbounded = || {
        let mut packet = Packet::new();
        packet
            .push(Ethernet {
                ether_type: WireValue::Exact(0x9999),
                ..Ethernet::default()
            })
            .push(Raw::new(Bytes::from_static(&[1, 2, 3])))
            .push(Padding::after_layer(vec![0; 4], 0));
        packet
    };
    let error = builder
        .build(
            unbounded(),
            BuildContext::default(),
            BuildOptions::default(),
        )
        .unwrap_err();
    assert!(error.to_string().contains("outside-layer boundary"));

    let permissive = builder
        .build(
            unbounded(),
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
            .any(|diagnostic| diagnostic.code == "build.unsupported_padding_boundary")
    );

    let mut raw_undefined = Packet::new();
    raw_undefined
        .push(Ethernet {
            ether_type: WireValue::Raw(Bytes::from_static(&[0x05, 0xdd])),
            ..Ethernet::default()
        })
        .push(Padding::after_layer(vec![0; 4], 0));
    let built = builder
        .build(
            raw_undefined,
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
            .any(|diagnostic| diagnostic.code == "build.unsupported_padding_boundary")
    );
    let decoded = Dissector::new(Arc::clone(&registry))
        .decode_with_root(
            built.bytes.clone(),
            "ethernet".into(),
            DecodeOptions::default(),
        )
        .unwrap();
    assert!(decoded.packet.get::<Padding>().is_none());
    assert_eq!(
        decoded.packet.get::<Raw>().unwrap().bytes.as_ref(),
        &[0, 0, 0, 0]
    );

    let mut raw_length = Packet::new();
    raw_length
        .push(Ethernet {
            ether_type: WireValue::Raw(Bytes::from_static(&[0, 0])),
            ..Ethernet::default()
        })
        .push(Padding::after_layer(vec![0; 4], 0));
    let built = builder
        .build(
            raw_length,
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
            .all(|diagnostic| diagnostic.code != "build.unsupported_padding_boundary")
    );
    let decoded = Dissector::new(Arc::clone(&registry))
        .decode_with_root(
            built.bytes.clone(),
            "ethernet".into(),
            DecodeOptions::default(),
        )
        .unwrap();
    assert_eq!(
        decoded.packet.get::<Padding>().unwrap().bytes,
        Bytes::from_static(&[0; 4])
    );

    // A length-framed header is a real boundary: the declared length ends
    // the covered payload before the padding.
    let mut framed = Packet::new();
    framed
        .push(Ethernet::default())
        .push(Llc {
            dsap: 0x42,
            ssap: 0x42,
            control: Bytes::from_static(&[0x03]),
        })
        .push(Raw::new(Bytes::from_static(&[1, 2, 3, 4, 5])))
        .push(Padding::after_layer(vec![0; 4], 0));
    let built = builder
        .build(framed, BuildContext::default(), BuildOptions::default())
        .unwrap();
    assert_eq!(u16::from_be_bytes([built.bytes[12], built.bytes[13]]), 8);
}

#[test]
fn llc_control_traffic_keeps_its_payload_opaque() {
    let registry = Arc::new(default_registry().unwrap());
    let builder = Builder::new(Arc::clone(&registry));
    // Only unnumbered-information frames carry an upper protocol's payload;
    // a typed child under any other control format would dissect as raw.
    let mislabeled = || {
        let mut packet = Packet::new();
        packet
            .push(Ethernet::default())
            .push(Llc {
                dsap: 0xaa,
                ssap: 0xaa,
                control: Bytes::from_static(&[0xe3]),
            })
            .push(Snap::default())
            .push(Ipv4 {
                source: Ipv4Addr::new(10, 0, 0, 1),
                destination: Ipv4Addr::new(10, 0, 0, 2),
                ..Ipv4::default()
            })
            .push(Icmpv4::default());
        packet
    };
    let error = builder
        .build(
            mislabeled(),
            BuildContext::default(),
            BuildOptions::default(),
        )
        .unwrap_err();
    assert!(error.to_string().contains("unnumbered-information"));

    let permissive = builder
        .build(
            mislabeled(),
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
            .any(|diagnostic| diagnostic.code == "build.llc_control")
    );

    // A TEST frame on the SNAP SAPs keeps its payload as raw bytes and
    // round-trips exactly, in both directions.
    let mut opaque = Packet::new();
    opaque
        .push(Ethernet::default())
        .push(Llc {
            dsap: 0xaa,
            ssap: 0xaa,
            control: Bytes::from_static(&[0xe3]),
        })
        .push(Raw::new(Bytes::from_static(&[1, 2, 3, 4, 5])));
    let built = builder
        .build(opaque, BuildContext::default(), BuildOptions::default())
        .unwrap();
    assert!(built.diagnostics.is_empty());
    let decoded = Dissector::new(Arc::clone(&registry))
        .decode_with_root(
            built.bytes.clone(),
            "ethernet".into(),
            DecodeOptions::default(),
        )
        .unwrap();
    assert!(decoded.diagnostics.is_empty());
    assert!(decoded.packet.get::<Snap>().is_none());
    assert_eq!(
        decoded.packet.get::<Raw>().unwrap().bytes.as_ref(),
        &[1, 2, 3, 4, 5]
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
fn a_truncated_llc_payload_rebuilds_exactly_as_a_malformed_layer() {
    let registry = Arc::new(default_registry().unwrap());
    let builder = Builder::new(Arc::clone(&registry));
    // A declared 802.3 length of 2 cannot hold the 3-byte LLC minimum, so
    // the payload survives as a malformed layer intending llc — and that
    // capture must still rebuild to the exact bytes in strict mode.
    let mut frame = vec![0_u8; 12];
    frame.extend_from_slice(&[0x00, 0x02, 0xaa, 0xaa, 0x00, 0x00, 0x00, 0x00]);
    let frame = Bytes::from(frame);
    let mut decoded = Dissector::new(Arc::clone(&registry))
        .decode_with_root(frame.clone(), "ethernet".into(), DecodeOptions::default())
        .unwrap();
    assert!(decoded.packet.get::<Llc>().is_none());
    let malformed = decoded.packet.get::<MalformedLayer>().unwrap();
    assert_eq!(
        malformed.intended_protocol.as_ref().map(|id| id.as_str()),
        Some("llc")
    );
    assert_eq!(
        decoded.packet.get::<Padding>().unwrap().bytes,
        Bytes::from_static(&[0; 4])
    );
    assert!(!decoded.diagnostics.is_empty());
    decoded.packet.get_mut::<Ethernet>().unwrap().ether_type = WireValue::Auto;
    let rebuilt = builder
        .build(
            decoded.packet,
            BuildContext::default(),
            BuildOptions::default(),
        )
        .unwrap();
    assert_eq!(rebuilt.bytes, frame);
}

#[test]
fn an_empty_snap_llc_header_dissects_as_missing_its_snap_child() {
    // The SNAP SAP pair on a UI frame announces a SNAP header; a frame
    // ending right after the LLC header reports it missing, exactly as
    // strict build rejects the childless layer.
    let mut bytes = Vec::<u8>::new();
    bytes.extend_from_slice(&[0; 12]);
    bytes.extend_from_slice(&[0x00, 0x03]);
    bytes.extend_from_slice(&[0xaa, 0xaa, 0x03]);
    let decoded = Dissector::new(Arc::new(default_registry().unwrap()))
        .decode_with_root(
            Bytes::from(bytes),
            "ethernet".into(),
            DecodeOptions::default(),
        )
        .unwrap();

    assert!(decoded.packet.get::<Llc>().is_some());
    assert!(
        decoded
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "decode.missing_required_child")
    );
}

#[test]
fn a_zero_oui_snap_layer_rejects_typed_children_without_an_ethertype_binding() {
    let registry = Arc::new(default_registry().unwrap());
    let builder = Builder::new(Arc::clone(&registry));
    // ICMPv4 has no EtherType, so nothing the protocol_id can resolve to
    // would select it on dissection; the payload would come back as raw.
    let unbound = || {
        let mut packet = Packet::new();
        packet
            .push(Ethernet::default())
            .push(Llc::default())
            .push(Snap::default())
            .push(Icmpv4::default());
        packet
    };
    let error = builder
        .build(unbound(), BuildContext::default(), BuildOptions::default())
        .unwrap_err();
    assert!(error.to_string().contains("cannot contain adjacent layer"));

    let permissive = builder
        .build(
            unbound(),
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
