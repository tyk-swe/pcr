// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::*;

#[test]
fn builtin_registration_is_deterministic_and_has_portable_roots() {
    let first = default_registry().unwrap();
    let second = default_registry().unwrap();
    let first_ids = first
        .protocols()
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    let second_ids = second
        .protocols()
        .map(ToString::to_string)
        .collect::<Vec<_>>();

    assert_eq!(first_ids, second_ids);
    assert_eq!(
        first
            .root_for_link_type(packetcraftr_capture::LinkType::ETHERNET.0)
            .unwrap()
            .as_str(),
        "ethernet"
    );
    assert_eq!(
        first
            .root_for_link_type(packetcraftr_capture::LinkType::RAW.0)
            .unwrap()
            .as_str(),
        "raw_ip"
    );
    assert!(first.protocol_named("dot1q").is_some());
}

#[test]
fn every_constructible_builtin_publishes_its_schema_through_the_registry() {
    let registry = default_registry().unwrap();
    let defaults = std::collections::BTreeMap::new();
    for protocol in registry.protocols() {
        let schema = registry.schema(protocol);
        let codec = registry.codec(protocol).expect("registered codec");
        let constructible = codec.make_layer(&defaults).is_ok();
        assert_eq!(
            schema.is_some(),
            constructible,
            "{protocol} schema availability must track constructibility"
        );
        if let Some(schema) = schema {
            assert_eq!(&schema.protocol, protocol);
        }
    }
    // `raw_ip` is the one decode-only built-in, so it anchors the negative case
    // and keeps this test honest if the catalog ever loses its only such entry.
    assert!(registry.schema("raw_ip").is_none());
    assert_eq!(
        registry.schema("ipv4").expect("ipv4 schema").protocol,
        packetcraftr_packet::layer::Id::new("ipv4")
    );
}

#[test]
fn a_filter_alias_may_not_shadow_a_canonical_schema_path() {
    use packetcraftr_packet::registry::FilterFieldBinding;

    // `ipv4.source` already resolves through the cached schema, so rebinding
    // that exact spelling would give one path two meanings.
    let mut builder = ProtocolRegistry::builder();
    builder.module(&BuiltinProtocols).unwrap();
    builder
        .bind_filter_field(
            "ipv4.source",
            FilterFieldBinding::Direct {
                protocol: packetcraftr_packet::layer::Id::new("ipv4"),
                field: "destination",
            },
        )
        .unwrap();
    assert!(matches!(
        builder.build(),
        Err(RegistryError::DuplicateFilterField { .. })
    ));

    // The same holds through a registered protocol alias, since `ip` and
    // `ipv4` name the same schema.
    let mut builder = ProtocolRegistry::builder();
    builder.module(&BuiltinProtocols).unwrap();
    builder
        .bind_filter_field(
            "ip.ttl",
            FilterFieldBinding::Direct {
                protocol: packetcraftr_packet::layer::Id::new("ipv4"),
                field: "ttl",
            },
        )
        .unwrap();
    assert!(matches!(
        builder.build(),
        Err(RegistryError::DuplicateFilterField { .. })
    ));

    // A conventional spelling that is not itself a schema field is fine, and
    // so is a nested flag path whose prefix is not an alias.
    let mut builder = ProtocolRegistry::builder();
    builder.module(&BuiltinProtocols).unwrap();
    builder
        .bind_filter_field(
            "ip.src",
            FilterFieldBinding::Direct {
                protocol: packetcraftr_packet::layer::Id::new("ipv4"),
                field: "source",
            },
        )
        .unwrap();
    builder
        .bind_filter_field(
            "tcp.flags.syn",
            FilterFieldBinding::Bits {
                protocol: packetcraftr_packet::layer::Id::new("tcp"),
                field: "flags",
                mask: 0x02,
                shift: 1,
            },
        )
        .unwrap();
    builder.build().unwrap();
}

#[test]
fn generic_raw_link_root_selects_the_ip_version() {
    let registry = Arc::new(default_registry().unwrap());
    let mut packet = Packet::new();
    packet.push(Ipv4 {
        source: Ipv4Addr::new(192, 0, 2, 1),
        destination: Ipv4Addr::new(198, 51, 100, 2),
        ..Ipv4::default()
    });
    let bytes = Builder::new(Arc::clone(&registry))
        .build(packet, BuildContext::default(), BuildOptions::default())
        .unwrap()
        .bytes;
    let frame = packetcraftr_capture::Frame::new(
        std::time::SystemTime::UNIX_EPOCH,
        packetcraftr_capture::LinkType::RAW,
        bytes,
    )
    .unwrap();
    let decoded = Dissector::new(registry)
        .decode(frame, DecodeOptions::default())
        .unwrap();
    assert!(decoded.packet.get::<Ipv4>().is_some());
}

#[test]
fn generic_raw_ipv6_root_continues_through_extensions() {
    let registry = Arc::new(default_registry().unwrap());
    let mut packet = Packet::new();
    packet
        .push(Ipv6 {
            source: "2001:db8::1".parse().unwrap(),
            destination: "2001:db8::2".parse().unwrap(),
            ..Ipv6::default()
        })
        .push(HopByHop::default())
        .push(Udp::default());
    let bytes = Builder::new(Arc::clone(&registry))
        .build(packet, BuildContext::default(), BuildOptions::default())
        .unwrap()
        .bytes;
    let frame = packetcraftr_capture::Frame::new(
        std::time::SystemTime::UNIX_EPOCH,
        packetcraftr_capture::LinkType::RAW,
        bytes,
    )
    .unwrap();
    let decoded = Dissector::new(registry)
        .decode(frame, DecodeOptions::default())
        .unwrap();
    assert!(decoded.packet.get::<Ipv6>().is_some());
    assert!(decoded.packet.get::<HopByHop>().is_some());
    assert!(decoded.packet.get::<Udp>().is_some());
}

#[test]
fn expression_factories_accept_roadmap_aliases() {
    let registry = default_registry().unwrap();
    let packet = parse_packet_expression(
        "eth(src=00:11:22:33:44:55,dst=66:77:88:99:aa:bb)/vlan(vid=42,pcp=3,dei=true)/ipv4(src=192.0.2.1,dst=198.51.100.2)/tcp(sport=12345,dport=443)/raw(hex=\"deadbeef\")",
        &registry,
        ExpressionOptions::default(),
    )
    .unwrap();

    assert_eq!(packet.get::<Vlan>().unwrap().vlan_id, 42);
    assert_eq!(packet.get::<Tcp>().unwrap().destination_port, 443);
    assert_eq!(
        packet.get::<Raw>().unwrap().bytes,
        Bytes::from_static(&[0xde, 0xad, 0xbe, 0xef])
    );

    let text = parse_packet_expression(
        "raw(text=\"hello\")",
        &registry,
        ExpressionOptions::default(),
    )
    .unwrap();
    assert_eq!(
        text.get::<Raw>().unwrap().bytes,
        Bytes::from_static(b"hello")
    );
}
