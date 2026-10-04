// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
#![allow(dead_code)]

mod common;

use std::time::SystemTime;

use bytes::Bytes;
use common::packets::ipv4;
use common::registry;
use packetcraftr_core::frame::{Frame, LinkType};
use packetcraftr_core::layer::{Layer, Malformed, Raw};
use packetcraftr_core::packet::Packet;
use packetcraftr_core::protocol::application::dns::Dns;
use packetcraftr_core::protocol::transport::Udp;
use packetcraftr_core::{build, codec, decode};

const MDNS_PORT: u16 = 5_353;
const LLMNR_PORT: u16 = 5_355;
const CLIENT: [u8; 4] = [192, 0, 2, 10];
const RESPONDER: [u8; 4] = [192, 0, 2, 80];
const MDNS_GROUP: [u8; 4] = [224, 0, 0, 251];

/// `host.local A` with the unicast-response (QU) bit set in the class.
const MDNS_QU_QUERY: &[u8] =
    b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x04host\x05local\x00\x00\x01\x80\x01";
/// The matching response: id 0, no question section, cache-flush bit in the
/// answer's class.
const MDNS_RESPONSE: &[u8] = b"\x00\x00\x84\x00\x00\x00\x00\x01\x00\x00\x00\x00\x04host\x05local\x00\x00\x01\x80\x01\x00\x00\x00\x78\x00\x04\xc0\x00\x02\x50";
/// A response whose answer owner is a compression pointer to the question's
/// `host.local` name; its class also carries the cache-flush bit.
const MDNS_COMPRESSED_RESPONSE: &[u8] = b"\x00\x00\x84\x00\x00\x01\x00\x01\x00\x00\x00\x00\x04host\x05local\x00\x00\x01\x80\x01\xc0\x0c\x00\x01\x80\x01\x00\x00\x00\x78\x00\x04\xc0\x00\x02\x50";
const LLMNR_QUERY: &[u8] =
    b"\x12\x34\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x04host\x00\x00\x01\x00\x01";

fn udp_packet(
    source: [u8; 4],
    destination: [u8; 4],
    source_port: u16,
    destination_port: u16,
    payload: impl Layer,
) -> Packet {
    let mut packet = Packet::new();
    packet.push(ipv4(source, destination));
    packet.push(Udp {
        source_port,
        destination_port,
        ..Udp::default()
    });
    packet.push(payload);
    packet
}

fn dns(wire: &[u8]) -> Dns {
    Dns::try_from(wire.to_vec()).expect("fixture DNS message")
}

fn build_with(packet: Packet, mode: codec::Mode) -> build::BuiltPacket {
    build::Builder::new(registry())
        .build(
            packet,
            codec::Context::default(),
            build::Options {
                mode,
                ..build::Options::default()
            },
        )
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

/// Builds `packet` strictly, dissects it and requires a strict rebuild of the
/// dissected packet to match, also after dropping the retained wire image so
/// the typed fields alone must reproduce every bit.
fn round_trip(packet: Packet) -> decode::DecodedPacket {
    let built = build_with(packet, codec::Mode::Strict);
    let decoded = dissect(built.bytes.clone());
    assert_eq!(protocols(&decoded), ["ipv4", "udp", "dns"]);
    assert_eq!(
        build_with(decoded.packet.clone(), codec::Mode::Strict).bytes,
        built.bytes
    );
    let mut retyped = decoded.packet.clone();
    retyped.get_mut::<Dns>().unwrap().edit(|_| {});
    assert_eq!(build_with(retyped, codec::Mode::Strict).bytes, built.bytes);
    decoded
}

#[test]
fn bad_dns_multicast_ports_keeps_bytes() {
    for port in [MDNS_PORT, LLMNR_PORT] {
        let wire = build_with(
            udp_packet(
                CLIENT,
                MDNS_GROUP,
                50_000,
                port,
                Raw::new(vec![0x12, 0x34, 0x81]),
            ),
            codec::Mode::Permissive,
        )
        .bytes;
        let decoded = dissect(wire.clone());
        assert_eq!(protocols(&decoded), ["ipv4", "udp", "malformed"], "{port}");
        let malformed = decoded.packet.get::<Malformed>().unwrap();
        assert_eq!(malformed.intended_protocol.as_deref(), Some("dns"));
        assert_eq!(malformed.bytes.as_ref(), [0x12, 0x34, 0x81]);
    }
}

fn decoded_packet(
    source: [u8; 4],
    destination: [u8; 4],
    source_port: u16,
    destination_port: u16,
    wire: &[u8],
) -> Packet {
    dissect(
        build_with(
            udp_packet(
                source,
                destination,
                source_port,
                destination_port,
                dns(wire),
            ),
            codec::Mode::Strict,
        )
        .bytes,
    )
    .packet
}
