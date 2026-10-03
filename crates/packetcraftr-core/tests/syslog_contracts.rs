// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod common;

use std::time::SystemTime;

use bytes::Bytes;
use common::packets::ipv4;
use packetcraftr_core::frame::{Frame, LinkType};
use packetcraftr_core::layer::{Layer, Raw};
use packetcraftr_core::packet::Packet;
use packetcraftr_core::protocol::application::syslog::{
    MAX_MESSAGE_BYTES, MAX_STRUCTURED_DATA_ELEMENTS, Syslog, SyslogFormat,
};
use packetcraftr_core::protocol::builtin;
use packetcraftr_core::protocol::transport::Udp;
use packetcraftr_core::{build, codec, decode};

fn packet(payload: impl Layer) -> Packet {
    let mut packet = Packet::new();
    packet.push(ipv4([192, 0, 2, 1], [192, 0, 2, 2]));
    packet.push(Udp {
        source_port: 40_000,
        destination_port: 514,
        ..Udp::default()
    });
    packet.push(payload);
    packet
}

fn build_with(packet: Packet, mode: codec::Mode) -> Result<build::BuiltPacket, build::Error> {
    build::Builder::new(builtin::registry()).build(
        packet,
        codec::Context::default(),
        build::Options {
            mode,
            ..build::Options::default()
        },
    )
}

fn dissect(bytes: impl Into<Bytes>) -> decode::DecodedPacket {
    let frame = Frame::new(SystemTime::UNIX_EPOCH, LinkType::IPV4, bytes).unwrap();
    decode::Dissector::new(builtin::registry())
        .decode(frame, decode::Options::default())
        .unwrap()
}

/// A datagram to UDP 514 holding exactly `message`.
fn datagram(message: &[u8]) -> Bytes {
    build_with(packet(Raw::new(message.to_vec())), codec::Mode::Permissive)
        .unwrap()
        .bytes
}

fn protocols(decoded: &decode::DecodedPacket) -> Vec<&str> {
    decoded
        .packet
        .iter()
        .map(|layer| layer.protocol_id().as_str())
        .collect()
}

/// Dissects `message` and requires a strict rebuild to reproduce the datagram.
fn typed(message: &[u8]) -> Syslog {
    let wire = datagram(message);
    let decoded = dissect(wire.clone());
    assert_eq!(protocols(&decoded), ["ipv4", "udp", "syslog"]);
    assert!(decoded.diagnostics.is_empty(), "{:?}", decoded.diagnostics);
    let rebuilt = build_with(decoded.packet.clone(), codec::Mode::Strict).unwrap();
    assert_eq!(rebuilt.bytes, wire);
    decoded.packet.get::<Syslog>().unwrap().clone()
}

fn is_raw(message: &[u8]) -> bool {
    let decoded = dissect(datagram(message));
    let raw = protocols(&decoded) == ["ipv4", "udp", "raw"];
    if raw {
        assert_eq!(decoded.packet.get::<Raw>().unwrap().bytes.as_ref(), message);
    }
    raw
}

#[test]
fn invalid_priorities_and_oversized_messages_decode_as_raw() {
    for message in [
        &b"<192>1 - - - - - -"[..],
        b"<999>hello",
        b"<34 missing close",
        b"<34",
        b"<>1 - - - - - -",
        b"<a>hello",
        b"<-1>hello",
        b"<1234>hello",
        b"<034>hello",
        b"<00>hello",
        b"34>hello",
        b" <34>hello",
        b"hello",
    ] {
        assert!(is_raw(message), "{message:?}");
    }

    let mut oversized = b"<14>".to_vec();
    oversized.resize(MAX_MESSAGE_BYTES + 1, b'x');
    assert!(is_raw(&oversized));
    oversized.pop();
    assert!(!is_raw(&oversized), "exactly at the cap is typed");
}

#[test]
fn structured_data_element_count_is_bounded() {
    let message = |elements: usize| {
        let mut message = b"<14>1 - - - - - ".to_vec();
        for _ in 0..elements {
            message.extend_from_slice(b"[a@1 k=\"v\"]");
        }
        message.extend_from_slice(b" text");
        message
    };
    let at_limit = typed(&message(MAX_STRUCTURED_DATA_ELEMENTS));
    assert_eq!(at_limit.format, SyslogFormat::Rfc5424);
    assert_eq!(
        at_limit.structured_data.len(),
        MAX_STRUCTURED_DATA_ELEMENTS * 11
    );
    assert!(is_raw(&message(MAX_STRUCTURED_DATA_ELEMENTS + 1)));
}
