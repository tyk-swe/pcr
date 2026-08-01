// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use super::*;
use crate::common::network_from_addresses;
use crate::{builtin::Module as BuiltinProtocols, ipv6::SegmentRoutingHeader, transport::Udp};
use packetcraftr_packet::field::WireValue;
use packetcraftr_packet::{
    Packet,
    build::{BuildContext, BuildOptions, Builder},
    registry::ProtocolRegistry,
};

fn address(value: &str) -> Ipv6Addr {
    value.parse().unwrap()
}

fn tunnel_registry() -> Arc<ProtocolRegistry> {
    let mut builder = ProtocolRegistry::builder();
    builder.module(&BuiltinProtocols).unwrap();
    builder.bind("ipv6", 41, "ipv6", 100).unwrap();
    builder.bind("ipv6_srh", 41, "ipv6", 100).unwrap();
    Arc::new(builder.build().unwrap())
}

#[test]
fn outer_srh_does_not_change_inner_ipv6_udp_checksum() {
    let inner_source = address("2001:db8:1::1");
    let inner_destination = address("2001:db8:1::2");
    let mut packet = Packet::new();
    packet
        .push(Ipv6 {
            next_header: WireValue::Exact(43),
            source: address("2001:db8::1"),
            destination: address("2001:db8::10"),
            ..Ipv6::default()
        })
        .push(SegmentRoutingHeader {
            next_header: WireValue::Exact(41),
            segments: vec![address("2001:db8::10")],
            ..SegmentRoutingHeader::default()
        })
        .push(Ipv6 {
            source: inner_source,
            destination: inner_destination,
            ..Ipv6::default()
        })
        .push(Udp::default());

    let built = Builder::new(tunnel_registry())
        .build(packet, BuildContext::default(), BuildOptions::default())
        .unwrap();
    let udp_offset = 40 + 24 + 40;
    assert_eq!(
        crate::common::transport_checksum(
            network_from_addresses(inner_source.into(), inner_destination.into()),
            17,
            &built.bytes[udp_offset..],
        )
        .unwrap(),
        0
    );
}

#[test]
fn inner_srh_does_not_override_outer_ipv6_destination() {
    let mut packet = Packet::new();
    packet
        .push(Ipv6 {
            next_header: WireValue::Exact(41),
            source: address("2001:db8::1"),
            destination: address("2001:db8::2"),
            ..Ipv6::default()
        })
        .push(Ipv6 {
            source: address("2001:db8:1::1"),
            destination: address("2001:db8:1::10"),
            ..Ipv6::default()
        })
        .push(SegmentRoutingHeader {
            segments: vec![address("2001:db8:1::10")],
            ..SegmentRoutingHeader::default()
        })
        .push(Udp::default());

    Builder::new(tunnel_registry())
        .build(packet, BuildContext::default(), BuildOptions::default())
        .unwrap();
}

#[test]
fn build_context_materializes_only_the_outer_network_envelope() {
    let source = Ipv4Addr::new(192, 0, 2, 1);
    let destination = Ipv4Addr::new(192, 0, 2, 2);
    let mut packet = Packet::new();
    packet
        .push(Ipv4::default())
        .push(Ipv4::default())
        .push(Udp::default());

    let built = Builder::new(Arc::new(crate::builtin::registry().unwrap()))
        .build(
            packet,
            BuildContext {
                source: Some(source.into()),
                destination: Some(destination.into()),
            },
            BuildOptions::default(),
        )
        .unwrap();

    assert_eq!(&built.bytes[12..16], &source.octets());
    assert_eq!(&built.bytes[16..20], &destination.octets());
    assert_eq!(&built.bytes[32..40], &[0; 8]);
    assert_eq!(
        crate::common::transport_checksum(
            network_from_addresses(Ipv4Addr::UNSPECIFIED.into(), Ipv4Addr::UNSPECIFIED.into(),),
            17,
            &built.bytes[40..],
        )
        .unwrap(),
        0
    );
}
