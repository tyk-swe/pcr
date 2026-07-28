// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::*;

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
