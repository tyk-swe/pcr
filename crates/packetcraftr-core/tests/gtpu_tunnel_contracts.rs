// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
#![allow(dead_code)]

mod common;

use std::net::{IpAddr, Ipv4Addr};
use std::time::SystemTime;

use bytes::Bytes;
use common::packets::ipv4;
use common::registry;
use packetcraftr_core::frame::{Frame, LinkType};
use packetcraftr_core::layer::Malformed;
use packetcraftr_core::packet::Packet;
use packetcraftr_core::protocol::link::Ethernet;
use packetcraftr_core::protocol::network::Ipv4;
use packetcraftr_core::protocol::semantics::{live_destinations, outer_scope_len};
use packetcraftr_core::protocol::transport::Udp;
use packetcraftr_core::protocol::tunnel::Gtpu;
use packetcraftr_core::{build, codec, decode};

/// Ethernet, IPv4 and UDP headers precede the GTP-U header.
const GTPU_OFFSET: usize = 14 + 20 + 8;

fn outer() -> Packet {
    let mut packet = Packet::new();
    packet.push(Ethernet::default());
    packet.push(ipv4([192, 0, 2, 1], [198, 51, 100, 2]));
    packet.push(Udp {
        source_port: 50_000,
        destination_port: 2_152,
        ..Udp::default()
    });
    packet
}

fn inner_udp() -> (Ipv4, Udp) {
    (
        ipv4([10, 0, 0, 1], [10, 0, 0, 2]),
        Udp {
            source_port: 40_000,
            destination_port: 40_001,
            ..Udp::default()
        },
    )
}

fn tunnel(gtpu: Gtpu) -> Packet {
    let mut packet = outer();
    packet.push(gtpu);
    let (ip, udp) = inner_udp();
    packet.push(ip);
    packet.push(udp);
    packet
}

fn dissect(bytes: impl Into<Bytes>) -> decode::DecodedPacket {
    let frame = Frame::new(SystemTime::UNIX_EPOCH, LinkType::ETHERNET, bytes).unwrap();
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

/// Builds strictly, dissects the bytes and requires a strict rebuild of the
/// dissected packet to reproduce them.
fn round_trip(packet: Packet) -> (Bytes, decode::DecodedPacket) {
    let builder = build::Builder::new(registry());
    let built = builder
        .build(packet, codec::Context::default(), build::Options::default())
        .expect("fixture builds strictly");
    let decoded = dissect(built.bytes.clone());
    let rebuilt = builder
        .build(
            decoded.packet.clone(),
            codec::Context::default(),
            build::Options::default(),
        )
        .expect("dissected fixture rebuilds strictly");
    assert_eq!(rebuilt.bytes, built.bytes);
    (built.bytes, decoded)
}

#[test]
fn declared_length_beyond_the_datagram_is_malformed_with_the_bytes_kept() {
    let built = build::Builder::new(registry())
        .build(
            tunnel(Gtpu::default()),
            codec::Context::default(),
            build::Options::default(),
        )
        .unwrap();
    let mut wire = built.bytes.to_vec();
    wire[GTPU_OFFSET + 3] += 10;
    let decoded = dissect(wire.clone());

    assert_eq!(
        protocols(&decoded),
        ["ethernet", "ipv4", "udp", "malformed"]
    );
    let malformed = decoded.packet.get::<Malformed>().unwrap();
    assert_eq!(malformed.intended_protocol.as_deref(), Some("gtpu"));
    assert_eq!(malformed.bytes.as_ref(), &wire[GTPU_OFFSET..]);
    assert!(
        decoded
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "decode.malformed_layer")
    );
    // a header that cannot be read may hide the tunnelled destination
    let error = live_destinations(&decoded.packet).unwrap_err();
    assert!(error.to_string().contains("gtpu"), "{error}");
}

#[test]
fn gtpu_is_an_encapsulation_boundary_and_a_malformed_header_hides_the_destination() {
    let packet = tunnel(Gtpu::default());
    // ethernet, outer ipv4, udp and the GTP-U header are the transmitted path
    assert_eq!(outer_scope_len(&packet), 4);
    assert_eq!(
        live_destinations(&packet).unwrap(),
        [
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        ]
    );

    let mut hidden = outer();
    hidden.push(Malformed::new(
        Some("gtpu".to_owned()),
        vec![0x30, 0xff],
        "truncated",
    ));
    let error = live_destinations(&hidden).unwrap_err();
    assert!(error.to_string().contains("gtpu"), "{error}");
}
