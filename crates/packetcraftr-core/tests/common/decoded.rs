// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Decoded-packet fixtures shared by the filter contract tests.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use packetcraftr_core::decode;
use packetcraftr_core::filter::Context;
use packetcraftr_core::frame::{Frame, LinkType};
use packetcraftr_core::layer::Raw;
use packetcraftr_core::packet::Packet;
use packetcraftr_core::protocol::link::Ethernet;
use packetcraftr_core::protocol::network::{Ipv4, Ipv6};
use packetcraftr_core::protocol::transport::{Tcp, Udp};
use packetcraftr_core::protocol::tunnel::Vxlan;
use packetcraftr_core::{build, codec};

use super::registry;

const PAYLOAD: &[u8] = b"GET /index HTTP/1.1";

/// Builds one Ethernet-rooted packet and dissects the exact bytes back.
pub(crate) fn decoded(packet: Packet) -> decode::DecodedPacket {
    let registry = registry();
    let built = build::Builder::new(Arc::clone(&registry))
        .build(packet, codec::Context::default(), build::Options::default())
        .unwrap_or_else(|error| panic!("fixture build: {error}"));
    let frame = Frame::new(
        SystemTime::UNIX_EPOCH + Duration::from_secs(123),
        LinkType::ETHERNET,
        built.bytes,
    )
    .expect("fixture frame");
    let mut decoded = decode::Dissector::new(registry)
        .decode(frame, decode::Options::default())
        .unwrap_or_else(|error| panic!("fixture decode: {error}"));
    decoded.frame.interface = Some(4);
    decoded
}

/// Outer `ethernet/ipv4/udp`, a VXLAN tunnel, then an inner
/// `ethernet/ipv4/udp/raw`: every protocol this file filters appears twice.
pub(crate) fn tunnelled() -> decode::DecodedPacket {
    let mut packet = Packet::new();
    packet.push(Ethernet {
        destination: [0x00, 0x01, 0x02, 0x03, 0x04, 0x05],
        source: [0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b],
        ..Ethernet::default()
    });
    packet.push(Ipv4 {
        source: "192.0.2.1".parse().expect("outer source"),
        destination: "198.51.100.2".parse().expect("outer destination"),
        ..Ipv4::default()
    });
    packet.push(Udp {
        source_port: 12_345,
        destination_port: 4_789,
        ..Udp::default()
    });
    packet.push(Vxlan {
        vni: 0x12345,
        ..Vxlan::default()
    });
    packet.push(Ethernet {
        destination: [0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f],
        source: [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        ..Ethernet::default()
    });
    packet.push(Ipv4 {
        source: "10.0.0.1".parse().expect("inner source"),
        destination: "10.0.0.2".parse().expect("inner destination"),
        ..Ipv4::default()
    });
    packet.push(Udp {
        source_port: 40_000,
        destination_port: 9_999,
        ..Udp::default()
    });
    packet.push(Raw::new(PAYLOAD.to_vec()));
    decoded(packet)
}

pub(crate) fn ipv6_tcp() -> decode::DecodedPacket {
    let mut packet = Packet::new();
    packet.push(Ethernet::default());
    packet.push(Ipv6 {
        source: "2001:db8::1".parse().expect("source"),
        destination: "2001:db8:1::2".parse().expect("destination"),
        ..Ipv6::default()
    });
    packet.push(Tcp {
        source_port: 44_000,
        destination_port: 443,
        flags: Tcp::SYN | Tcp::ACK,
        ..Tcp::default()
    });
    packet.push(Raw::new(PAYLOAD.to_vec()));
    decoded(packet)
}

pub(crate) fn context(decoded: &decode::DecodedPacket) -> Context<'_> {
    Context {
        decoded,
        derived: &[],
        number: 7,
        tcp_stream: Some(2),
        udp_stream: Some(3),
    }
}
