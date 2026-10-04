// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod common;

use common::decoded::protocols;
use common::registry;
use std::sync::Arc;
use std::time::SystemTime;

use bytes::Bytes;
use packetcraftr_core::document;
use packetcraftr_core::field::FieldValue;
use packetcraftr_core::frame::{Frame, LinkType};
use packetcraftr_core::layer::Raw;
use packetcraftr_core::protocol::link::Ethernet;
use packetcraftr_core::protocol::network::Ipv4;
use packetcraftr_core::protocol::transport::Tcp;
use packetcraftr_core::{build, codec, decode, packet::Packet};

use common::tls_vectors::{CLIENT_HELLO_VECTORS, decode_hex};

const CLIENT_PORT: u16 = 40_000;

fn client_hello_record() -> Vec<u8> {
    decode_hex(CLIENT_HELLO_VECTORS[1].record_hex)
}

fn dissect(source_port: u16, destination_port: u16, payload: &[u8]) -> decode::DecodedPacket {
    let registry = registry();
    let mut packet = Packet::new();
    packet.push(Ethernet::default());
    packet.push(Ipv4 {
        source: "192.0.2.1".parse().expect("source address"),
        destination: "198.51.100.2".parse().expect("destination address"),
        ..Ipv4::default()
    });
    packet.push(Tcp {
        source_port,
        destination_port,
        sequence: 1,
        flags: Tcp::ACK,
        ..Tcp::default()
    });
    packet.push(Raw::new(Bytes::copy_from_slice(payload)));
    let builder = build::Builder::new(Arc::clone(&registry));
    let built = builder
        .build(packet, codec::Context::default(), build::Options::default())
        .expect("segment builds");
    let frame = Frame::new(
        SystemTime::UNIX_EPOCH,
        LinkType::ETHERNET,
        built.bytes.clone(),
    )
    .expect("segment frame");
    let decoded = decode::Dissector::new(Arc::clone(&registry))
        .decode(frame, decode::Options::default())
        .expect("segment dissects");
    let rebuilt = builder
        .build(
            decoded.packet.clone(),
            codec::Context::default(),
            build::Options::default(),
        )
        .expect("dissected segment rebuilds");
    assert_eq!(
        rebuilt.bytes, built.bytes,
        "build(dissect(x)) must equal x on port {destination_port}"
    );
    decoded
}

#[test]
fn an_unbound_port_never_dissects_tls() {
    let decoded = dissect(CLIENT_PORT, 80, &client_hello_record());
    assert_eq!(protocols(&decoded), vec!["ethernet", "ipv4", "tcp", "raw"]);
    assert!(decoded.diagnostics.is_empty());
}

#[test]
fn pkt_reject_non_boolean_partial_flag() {
    let decoded = dissect(CLIENT_PORT, 443, &client_hello_record());
    let mut document = document::Packet::from_packet(&decoded.packet);
    document
        .layers
        .iter_mut()
        .find(|layer| layer.protocol == "tls")
        .expect("a tls layer")
        .fields
        .insert("incomplete".to_owned(), FieldValue::from("yes"));
    assert!(matches!(
        document.to_packet(&registry(), 8),
        Err(document::Error::Layer {
            source: codec::Error::Field(packetcraftr_core::field::Error::WrongType {
                expected: "bool",
                ..
            }),
            ..
        })
    ));
}
