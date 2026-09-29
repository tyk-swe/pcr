// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::UNIX_EPOCH;

use bytes::Bytes;
use packetcraftr_core::build::{Builder, BuiltPacket};
use packetcraftr_core::decode::{DecodedPacket, Dissector};
use packetcraftr_core::expression;
use packetcraftr_core::frame::{Frame, LinkType};
use packetcraftr_core::layer::{Layer, Raw};
use packetcraftr_core::packet::Packet;
use packetcraftr_core::protocol::builtin;
use packetcraftr_core::protocol::link::{Ethernet, Vlan};
use packetcraftr_core::protocol::network::{Ipv4, Ipv6};
use packetcraftr_core::registry::Registry;

pub(crate) const ROOT_LINK_TYPE: LinkType = LinkType(u32::MAX);

pub(crate) fn rooted_registry(root: &'static str) -> Arc<Registry> {
    Arc::new(
        builtin::registry_with(|builder| {
            builder.bind_link_type(ROOT_LINK_TYPE, root)?;
            Ok(())
        })
        .unwrap_or_else(|error| panic!("{root} root binding: {error}")),
    )
}

pub(crate) fn ipv4(source: [u8; 4], destination: [u8; 4]) -> Ipv4 {
    Ipv4 {
        source: Ipv4Addr::from(source),
        destination: Ipv4Addr::from(destination),
        ..Ipv4::default()
    }
}

pub(crate) fn ipv6(source: &str, destination: &str) -> Ipv6 {
    Ipv6 {
        source: source.parse().expect("source address"),
        destination: destination.parse().expect("destination address"),
        ..Ipv6::default()
    }
}

pub(crate) fn build(recipe: &str) -> BuiltPacket {
    let registry = builtin::registry();
    let packet = expression::parse(recipe, &registry, Default::default()).unwrap();
    Builder::new(registry)
        .build(packet, Default::default(), Default::default())
        .unwrap()
}

pub(crate) fn dissect(bytes: Bytes) -> DecodedPacket {
    Dissector::new(builtin::registry())
        .decode(
            Frame::new(UNIX_EPOCH, LinkType::IPV4, bytes).unwrap(),
            Default::default(),
        )
        .unwrap()
}

/// A transport packet on bare IP or an Ethernet carrier with one VLAN tag.
pub(crate) fn transport_frame(
    is_ipv6: bool,
    ethernet: bool,
    transport: impl Layer,
    payload: &[u8],
) -> Frame {
    let mut packet = Packet::new();
    if ethernet {
        packet.push(Ethernet::default());
        packet.push(Vlan::default());
    }
    if is_ipv6 {
        packet.push(ipv6("2001:db8::1", "2001:db8::2"));
    } else {
        packet.push(ipv4([192, 0, 2, 1], [198, 51, 100, 2]));
    }
    packet.push(transport);
    packet.push(Raw::new(payload.to_vec()));
    let built = Builder::new(builtin::registry())
        .build(packet, Default::default(), Default::default())
        .expect("transport fixture must build");
    let link_type = if ethernet {
        LinkType::ETHERNET
    } else if is_ipv6 {
        LinkType::IPV6
    } else {
        LinkType::IPV4
    };
    Frame::new(UNIX_EPOCH, link_type, built.bytes).expect("transport fixture frame must be valid")
}
