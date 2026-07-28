// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::*;

#[test]
fn pppoe_session_and_discovery_round_trip_their_stages() {
    let registry = Arc::new(default_registry().unwrap());
    let builder = Builder::new(Arc::clone(&registry));

    // Session data: eth 0x8864 / pppoe(code 0) / ppp 0x0021 / ipv4, with
    // the EtherType and PPP protocol resolving from their children.
    let mut session = Packet::new();
    session
        .push(Ethernet::default())
        .push(Pppoe {
            session_id: 0x1234,
            ..Pppoe::default()
        })
        .push(Ppp::default())
        .push(Ipv4 {
            source: Ipv4Addr::new(10, 0, 0, 1),
            destination: Ipv4Addr::new(10, 0, 0, 2),
            ..Ipv4::default()
        })
        .push(Icmpv4::default());
    let built = builder
        .build(session, BuildContext::default(), BuildOptions::default())
        .unwrap();
    assert_eq!(&built.bytes[12..14], &[0x88, 0x64]);
    assert_eq!(&built.bytes[20..22], &[0x00, 0x21]);
    let decoded = Dissector::new(Arc::clone(&registry))
        .decode_with_root(
            built.bytes.clone(),
            "ethernet".into(),
            DecodeOptions::default(),
        )
        .unwrap();
    assert_eq!(decoded.packet.get::<Pppoe>().unwrap().session_id, 0x1234);
    assert!(decoded.packet.get::<Ppp>().is_some());
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

    // An LCP frame keeps its unregistered protocol and opaque payload.
    let mut lcp = Packet::new();
    lcp.push(Ethernet::default())
        .push(Pppoe::default())
        .push(Ppp {
            protocol: WireValue::Exact(0xc021),
        })
        .push(Raw::new(Bytes::from_static(&[0x01, 0x01, 0x00, 0x04])));
    let built = builder
        .build(lcp, BuildContext::default(), BuildOptions::default())
        .unwrap();
    let decoded = Dissector::new(Arc::clone(&registry))
        .decode_with_root(
            built.bytes.clone(),
            "ethernet".into(),
            DecodeOptions::default(),
        )
        .unwrap();
    assert_eq!(
        decoded.packet.get::<Ppp>().unwrap().protocol,
        WireValue::Exact(0xc021)
    );
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

    // Discovery: eth 0x8863 / pppoe(PADI) / opaque tag bytes.
    let mut discovery = Packet::new();
    discovery
        .push(Ethernet {
            ether_type: WireValue::Exact(0x8863),
            ..Ethernet::default()
        })
        .push(Pppoe {
            code: 0x09,
            ..Pppoe::default()
        })
        .push(Raw::new(Bytes::from_static(&[0x01, 0x01, 0x00, 0x00])));
    let built = builder
        .build(discovery, BuildContext::default(), BuildOptions::default())
        .unwrap();
    assert_eq!(&built.bytes[12..14], &[0x88, 0x63]);
    let decoded = Dissector::new(Arc::clone(&registry))
        .decode_with_root(
            built.bytes.clone(),
            "ethernet".into(),
            DecodeOptions::default(),
        )
        .unwrap();
    assert_eq!(decoded.packet.get::<Pppoe>().unwrap().code, 0x09);
    assert!(decoded.packet.get::<Ppp>().is_none());
    assert!(decoded.diagnostics.is_empty());
    let rebuilt = builder
        .build(
            decoded.packet,
            BuildContext::default(),
            BuildOptions::default(),
        )
        .unwrap();
    assert_eq!(rebuilt.bytes, built.bytes);

    // A stage code that disagrees with the payload does not build strictly.
    let mut lying = Packet::new();
    lying
        .push(Ethernet::default())
        .push(Pppoe {
            code: 0x09,
            ..Pppoe::default()
        })
        .push(Ppp::default())
        .push(Ipv4 {
            source: Ipv4Addr::new(10, 0, 0, 1),
            destination: Ipv4Addr::new(10, 0, 0, 2),
            ..Ipv4::default()
        })
        .push(Icmpv4::default());
    let error = builder
        .build(lying, BuildContext::default(), BuildOptions::default())
        .unwrap_err();
    assert!(error.to_string().contains("session-stage"));

    // An Auto EtherType materializes the session value, so a discovery
    // frame must name 0x8863 explicitly — whatever the enclosing link
    // header calls its discriminator field.
    for auto_parent in [
        {
            let mut packet = Packet::new();
            packet.push(Ethernet::default());
            packet
        },
        {
            let mut packet = Packet::new();
            packet.push(crate::capture::LinuxSll::default());
            packet
        },
    ] {
        let mut auto_discovery = auto_parent;
        auto_discovery
            .push(Pppoe {
                code: 0x09,
                ..Pppoe::default()
            })
            .push(Raw::new(Bytes::from_static(&[0x01, 0x01, 0x00, 0x00])));
        let error = builder
            .build(
                auto_discovery,
                BuildContext::default(),
                BuildOptions::default(),
            )
            .unwrap_err();
        assert!(error.to_string().contains("0x8863"));
    }
}

#[test]
fn a_terminal_session_header_does_not_build_strictly() {
    let registry = Arc::new(default_registry().unwrap());
    let builder = Builder::new(Arc::clone(&registry));
    let mut terminal = Packet::new();
    terminal.push(Ethernet::default()).push(Pppoe::default());
    let error = builder
        .build(terminal, BuildContext::default(), BuildOptions::default())
        .unwrap_err();
    assert!(error.to_string().contains("PPP frame"));

    // A tag-free discovery PADT is complete.
    let mut padt = Packet::new();
    padt.push(Ethernet {
        ether_type: WireValue::Exact(0x8863),
        ..Ethernet::default()
    })
    .push(Pppoe {
        code: 0xa7,
        ..Pppoe::default()
    });
    let built = builder
        .build(padt, BuildContext::default(), BuildOptions::default())
        .unwrap();
    assert!(built.diagnostics.is_empty());
}

#[test]
fn an_empty_session_frame_dissects_as_missing_its_ppp_header() {
    let registry = Arc::new(default_registry().unwrap());
    let mut bytes = Vec::<u8>::new();
    bytes.extend_from_slice(&[0; 12]);
    bytes.extend_from_slice(&[0x88, 0x64]);
    bytes.extend_from_slice(&[0x11, 0x00, 0x00, 0x07, 0x00, 0x00]);
    let decoded = Dissector::new(registry)
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
fn a_discovery_frame_imitating_ppp_stays_opaque() {
    let registry = Arc::new(default_registry().unwrap());
    // eth 0x8863 / pppoe(code 0, RFC-invalid for discovery) / bytes that
    // imitate PPP protocol 0x0021.
    let mut bytes = Vec::<u8>::new();
    bytes.extend_from_slice(&[0; 12]);
    bytes.extend_from_slice(&[0x88, 0x63]);
    bytes.extend_from_slice(&[0x11, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x21]);
    let decoded = Dissector::new(registry)
        .decode_with_root(
            Bytes::from(bytes),
            "ethernet".into(),
            DecodeOptions::default(),
        )
        .unwrap();

    assert!(decoded.packet.get::<Ppp>().is_none());
    assert_eq!(
        decoded.packet.get::<Raw>().unwrap().bytes.as_ref(),
        &[0x00, 0x21]
    );
    assert!(
        decoded
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "decode.pppoe_stage")
    );
}

#[test]
fn a_padded_pppoe_discovery_frame_round_trips_its_declared_length() {
    let registry = Arc::new(default_registry().unwrap());
    let builder = Builder::new(Arc::clone(&registry));
    let mut padded = Packet::new();
    padded
        .push(Ethernet {
            ether_type: WireValue::Exact(0x8863),
            ..Ethernet::default()
        })
        .push(Pppoe {
            code: 0x09,
            ..Pppoe::default()
        })
        .push(Raw::new(Bytes::from_static(&[0x01, 0x01, 0x00, 0x00])));
    // Minimum-frame padding outside the declared PPPoE length.
    padded.push(Padding::after_layer(vec![0_u8; 8], 1));
    let built = builder
        .build(padded, BuildContext::default(), BuildOptions::default())
        .unwrap();
    // The declared length covers the tags, not the padding.
    assert_eq!(u16::from_be_bytes([built.bytes[18], built.bytes[19]]), 4);

    let decoded = Dissector::new(Arc::clone(&registry))
        .decode_with_root(
            built.bytes.clone(),
            "ethernet".into(),
            DecodeOptions::default(),
        )
        .unwrap();
    assert_eq!(
        decoded.packet.get::<Padding>().unwrap().outside_layer,
        Some(1)
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
