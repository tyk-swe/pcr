// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod common;

use std::net::{IpAddr, Ipv4Addr};
use std::time::SystemTime;

use bytes::Bytes;
use common::packets::ipv4;
use common::registry;
use packetcraftr_core::frame::{Frame, LinkType};
use packetcraftr_core::layer::{Malformed, Raw};
use packetcraftr_core::packet::Packet;
use packetcraftr_core::protocol::BuiltinProtocol;
use packetcraftr_core::protocol::link::Ethernet;
use packetcraftr_core::protocol::network::{Icmpv4, Ipv4};
use packetcraftr_core::protocol::semantics::{live_destinations, outer_scope_len};
use packetcraftr_core::protocol::tunnel::Etherip;
use packetcraftr_core::{build, codec, decode};

fn outer_ipv4() -> Ipv4 {
    ipv4([192, 0, 2, 1], [198, 51, 100, 2])
}

fn etherip_packet(etherip: Etherip) -> Packet {
    let mut packet = Packet::new();
    packet.push(outer_ipv4());
    packet.push(etherip);
    packet.push(Ethernet::default());
    packet.push(ipv4([10, 0, 0, 1], [10, 0, 0, 2]));
    packet.push(Icmpv4::default());
    packet
}

fn permissive() -> build::Options {
    build::Options {
        mode: codec::Mode::Permissive,
        ..build::Options::default()
    }
}

fn build_with(packet: Packet, options: build::Options) -> build::BuiltPacket {
    build::Builder::new(registry())
        .build(packet, codec::Context::default(), options)
        .expect("fixture builds")
}

fn dissect(bytes: impl Into<Bytes>) -> decode::DecodedPacket {
    let frame = Frame::new(SystemTime::UNIX_EPOCH, LinkType::IPV4, bytes).unwrap();
    decode::Dissector::new(registry())
        .decode(frame, decode::Options::default())
        .unwrap()
}

fn protocols(decoded: &decode::DecodedPacket) -> Vec<&str> {
    decoded
        .packet
        .iter()
        .map(|layer| layer.protocol_id().as_str())
        .collect()
}

#[test]
fn etherip_is_an_encapsulation_boundary_and_a_malformed_header_hides_the_destination() {
    assert!(BuiltinProtocol::Etherip.is_encapsulation_boundary());
    let packet = etherip_packet(Etherip::default());
    // the outer IPv4 header and the EtherIP header are the transmitted path
    assert_eq!(outer_scope_len(&packet), 2);
    assert_eq!(
        live_destinations(&packet).unwrap(),
        [
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        ]
    );

    // one byte cannot hold an EtherIP header
    let mut truncated = Packet::new();
    truncated.push(outer_ipv4());
    truncated.push(Raw::new(vec![0x30]));
    let mut wire = build_with(truncated, permissive()).bytes.to_vec();
    wire[9] = 97;
    let decoded = dissect(wire);
    assert_eq!(protocols(&decoded), ["ipv4", "malformed"]);
    let malformed = decoded.packet.get::<Malformed>().unwrap();
    assert_eq!(malformed.intended_protocol.as_deref(), Some("etherip"));
    assert_eq!(malformed.bytes.as_ref(), [0x30]);
    let error = live_destinations(&decoded.packet).unwrap_err();
    assert!(error.to_string().contains("etherip"), "{error}");
}
