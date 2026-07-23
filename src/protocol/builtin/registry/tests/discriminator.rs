// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::*;

#[test]
fn raw_child_cannot_claim_a_registered_typed_discriminator_in_strict_mode() {
    let registry = Arc::new(default_registry().unwrap());
    let builder = Builder::new(Arc::clone(&registry));
    let mut packet = Packet::new();
    packet
        .push(Ethernet {
            ether_type: WireValue::Exact(0x0800),
            ..Ethernet::default()
        })
        .push(Raw::new(Bytes::from_static(b"not-ip")));

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
    assert!(permissive.requires_live_opt_in);
    assert!(
        permissive
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "build.raw_typed_discriminator")
    );
}

fn ipv4_with_raw_protocol(protocol: u8) -> Packet {
    let mut packet = Packet::new();
    packet
        .push(Ipv4 {
            protocol: WireValue::Exact(protocol),
            source: Ipv4Addr::new(192, 0, 2, 1),
            destination: Ipv4Addr::new(198, 51, 100, 2),
            ..Ipv4::default()
        })
        .push(Raw::new(Bytes::from_static(b"opaque")));
    packet
}

fn ipv6_with_raw_next_header(next_header: u8) -> Packet {
    let mut packet = Packet::new();
    packet
        .push(Ipv6 {
            next_header: WireValue::Exact(next_header),
            source: "2001:db8::1".parse().unwrap(),
            destination: "2001:db8::2".parse().unwrap(),
            ..Ipv6::default()
        })
        .push(Raw::new(Bytes::from_static(b"opaque")));
    packet
}

#[test]
fn typed_ip_discriminators_are_derived_and_decode_to_typed_children() {
    let registry = Arc::new(default_registry().unwrap());
    let builder = Builder::new(Arc::clone(&registry));

    let mut igmp = Packet::new();
    igmp.push(Ipv4 {
        source: Ipv4Addr::new(192, 0, 2, 1),
        destination: Ipv4Addr::new(224, 0, 0, 1),
        ..Ipv4::default()
    })
    .push(Igmp::default());
    let built = builder
        .build(igmp, BuildContext::default(), BuildOptions::default())
        .unwrap();
    assert_eq!(
        built.packet.get::<Ipv4>().unwrap().protocol,
        WireValue::Exact(2)
    );
    let decoded = Dissector::new(Arc::clone(&registry))
        .decode_with_root(built.bytes, "ipv4".into(), DecodeOptions::default())
        .unwrap();
    assert!(decoded.packet.get::<Igmp>().is_some());

    let mut ipv4_in_ipv4 = Packet::new();
    ipv4_in_ipv4
        .push(Ipv4 {
            source: Ipv4Addr::new(192, 0, 2, 1),
            destination: Ipv4Addr::new(198, 51, 100, 2),
            ..Ipv4::default()
        })
        .push(Ipv4 {
            source: Ipv4Addr::new(10, 0, 0, 1),
            destination: Ipv4Addr::new(10, 0, 0, 2),
            ..Ipv4::default()
        });
    let built = builder
        .build(
            ipv4_in_ipv4,
            BuildContext::default(),
            BuildOptions::default(),
        )
        .unwrap();
    assert_eq!(
        built.packet.get::<Ipv4>().unwrap().protocol,
        WireValue::Exact(4)
    );
    let decoded = Dissector::new(Arc::clone(&registry))
        .decode_with_root(built.bytes, "ipv4".into(), DecodeOptions::default())
        .unwrap();
    assert_eq!(
        decoded
            .packet
            .iter()
            .map(|layer| layer.protocol_id().as_str().to_owned())
            .collect::<Vec<_>>(),
        ["ipv4", "ipv4"].map(str::to_owned)
    );

    let mut ipv6_in_ipv4 = Packet::new();
    ipv6_in_ipv4
        .push(Ipv4 {
            source: Ipv4Addr::new(192, 0, 2, 1),
            destination: Ipv4Addr::new(198, 51, 100, 2),
            ..Ipv4::default()
        })
        .push(Ipv6 {
            source: "2001:db8::1".parse().unwrap(),
            destination: "2001:db8::2".parse().unwrap(),
            ..Ipv6::default()
        });
    let built = builder
        .build(
            ipv6_in_ipv4,
            BuildContext::default(),
            BuildOptions::default(),
        )
        .unwrap();
    assert_eq!(
        built.packet.get::<Ipv4>().unwrap().protocol,
        WireValue::Exact(41)
    );

    let mut gre_ipv6_sctp = Packet::new();
    gre_ipv6_sctp
        .push(Ipv6 {
            source: "2001:db8::1".parse().unwrap(),
            destination: "2001:db8::2".parse().unwrap(),
            ..Ipv6::default()
        })
        .push(Gre::default())
        .push(Ipv6 {
            source: "2001:db8:1::1".parse().unwrap(),
            destination: "2001:db8:1::2".parse().unwrap(),
            ..Ipv6::default()
        })
        .push(Sctp::default())
        .push(Raw::new(Bytes::from_static(&[
            1, 0, 0, 20, 0x11, 0x22, 0x33, 0x44, 0, 1, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0,
        ])));
    let built = builder
        .build(
            gre_ipv6_sctp,
            BuildContext::default(),
            BuildOptions::default(),
        )
        .unwrap();
    assert_eq!(
        built.packet.get::<Ipv6>().unwrap().next_header,
        WireValue::Exact(47)
    );
    assert_eq!(
        built.packet.get::<Gre>().unwrap().protocol_type,
        WireValue::Exact(0x86dd)
    );
    assert_eq!(
        built.packet.layer(2).unwrap().field("next_header"),
        Some(crate::packet::field::FieldValue::Unsigned(132))
    );
    let decoded = Dissector::new(Arc::clone(&registry))
        .decode_with_root(built.bytes, "ipv6".into(), DecodeOptions::default())
        .unwrap();
    assert_eq!(
        decoded
            .packet
            .iter()
            .map(|layer| layer.protocol_id().as_str().to_owned())
            .collect::<Vec<_>>(),
        ["ipv6", "gre", "ipv6", "sctp", "raw"].map(str::to_owned)
    );
}

#[test]
fn typed_ip_discriminators_reject_raw_or_mismatched_children() {
    let registry = Arc::new(default_registry().unwrap());
    let builder = Builder::new(Arc::clone(&registry));
    let cases = [
        ("ipv4 igmp", ipv4_with_raw_protocol(2)),
        ("ipv4 in ipv4", ipv4_with_raw_protocol(4)),
        ("ipv6 in ipv4", ipv4_with_raw_protocol(41)),
        ("gre in ipv4", ipv4_with_raw_protocol(47)),
        ("sctp in ipv4", ipv4_with_raw_protocol(132)),
        ("ipv4 in ipv6", ipv6_with_raw_next_header(4)),
        ("ipv6 in ipv6", ipv6_with_raw_next_header(41)),
        ("gre in ipv6", ipv6_with_raw_next_header(47)),
        ("sctp in ipv6", ipv6_with_raw_next_header(132)),
    ];
    for (label, packet) in cases {
        assert!(
            builder
                .build(
                    packet.clone(),
                    BuildContext::default(),
                    BuildOptions::default(),
                )
                .is_err(),
            "{label} accepted a raw typed child in strict mode"
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
        assert!(permissive.requires_live_opt_in, "{label}");
        assert!(
            permissive
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "build.raw_typed_discriminator"),
            "{label} did not warn about a raw typed discriminator"
        );
    }

    let mut mismatch = Packet::new();
    mismatch
        .push(Ipv4 {
            protocol: WireValue::Exact(132),
            source: Ipv4Addr::new(192, 0, 2, 1),
            destination: Ipv4Addr::new(198, 51, 100, 2),
            ..Ipv4::default()
        })
        .push(Udp::default());
    assert!(
        builder
            .build(
                mismatch.clone(),
                BuildContext::default(),
                BuildOptions::default(),
            )
            .is_err()
    );
    let permissive = builder
        .build(
            mismatch,
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
            .any(|diagnostic| { diagnostic.code == "build.discriminator_child_mismatch" })
    );
}

#[test]
fn missing_ip_typed_child_decodes_as_preserved_malformed_payload() {
    let registry = Arc::new(default_registry().unwrap());
    let builder = Builder::new(Arc::clone(&registry));
    let mut bytes = vec![0_u8; 20];
    bytes[0] = 0x45;
    bytes[2..4].copy_from_slice(&20_u16.to_be_bytes());
    bytes[8] = 64;
    bytes[9] = 132;
    bytes[10..12].copy_from_slice(&36399_u16.to_be_bytes());
    bytes[12..16].copy_from_slice(&[192, 0, 2, 1]);
    bytes[16..20].copy_from_slice(&[198, 51, 100, 2]);

    let decoded = Dissector::new(Arc::clone(&registry))
        .decode_with_root(bytes.clone(), "ipv4".into(), DecodeOptions::default())
        .unwrap();
    assert!(
        decoded
            .packet
            .get::<crate::packet::layer::MalformedLayer>()
            .is_some()
    );
    assert!(
        decoded
            .diagnostics
            .iter()
            .any(|diagnostic| { diagnostic.code == "decode.missing_required_child" })
    );
    let rebuilt = builder
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
fn auto_discriminator_cannot_invent_wire_intent_for_raw() {
    let registry = Arc::new(default_registry().unwrap());
    let mut packet = Packet::new();
    packet
        .push(Ethernet::default())
        .push(Raw::new(Bytes::from_static(b"opaque")));
    assert!(
        Builder::new(registry)
            .build(packet, BuildContext::default(), BuildOptions::default())
            .is_err()
    );
}

#[test]
fn known_discriminator_requires_present_typed_child() {
    let registry = Arc::new(default_registry().unwrap());
    let builder = Builder::new(Arc::clone(&registry));
    let mut packet = Packet::new();
    packet.push(Ethernet {
        ether_type: WireValue::Exact(0x0800),
        ..Ethernet::default()
    });
    assert!(
        builder
            .build(packet, BuildContext::default(), BuildOptions::default())
            .is_err()
    );

    let mut bytes = vec![0_u8; 14];
    bytes[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
    let decoded = Dissector::new(Arc::clone(&registry))
        .decode_with_root(bytes.clone(), "ethernet".into(), DecodeOptions::default())
        .unwrap();
    assert!(
        decoded
            .packet
            .get::<crate::packet::layer::MalformedLayer>()
            .is_some()
    );
    assert!(
        decoded
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "decode.missing_required_child")
    );
    let rebuilt = builder
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
fn no_next_header_bytes_require_malformed_representation() {
    let registry = Arc::new(default_registry().unwrap());
    let mut packet = Packet::new();
    packet
        .push(Ipv6 {
            next_header: WireValue::Exact(59),
            source: "2001:db8::1".parse().unwrap(),
            destination: "2001:db8::2".parse().unwrap(),
            ..Ipv6::default()
        })
        .push(Raw::new(Bytes::from_static(b"bad")));
    assert!(
        Builder::new(registry)
            .build(packet, BuildContext::default(), BuildOptions::default())
            .is_err()
    );
}

#[test]
fn fragmented_packets_require_raw_fragment_payloads() {
    let registry = Arc::new(default_registry().unwrap());
    let mut packet = Packet::new();
    packet
        .push(Ipv4 {
            more_fragments: true,
            source: Ipv4Addr::new(192, 0, 2, 1),
            destination: Ipv4Addr::new(198, 51, 100, 2),
            ..Ipv4::default()
        })
        .push(Udp::default());
    assert!(
        Builder::new(registry)
            .build(packet, BuildContext::default(), BuildOptions::default())
            .is_err()
    );
}
