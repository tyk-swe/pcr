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
            .root_for_link_type(crate::capture::LinkType::ETHERNET.0)
            .unwrap()
            .as_str(),
        "ethernet"
    );
    assert_eq!(
        first
            .root_for_link_type(crate::capture::LinkType::RAW.0)
            .unwrap()
            .as_str(),
        "raw_ip"
    );
    assert!(first.protocol_named("dot1q").is_some());
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
    let frame = crate::capture::Frame::new(
        std::time::SystemTime::UNIX_EPOCH,
        crate::capture::LinkType::RAW,
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
    let frame = crate::capture::Frame::new(
        std::time::SystemTime::UNIX_EPOCH,
        crate::capture::LinkType::RAW,
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
