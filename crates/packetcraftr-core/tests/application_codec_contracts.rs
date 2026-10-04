// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod common;

use common::decoded::protocols;
use common::length_prefixed;
use packetcraftr_core::{
    build::{Builder, Options},
    codec::Mode,
    decode::{DecodedPacket, Dissector},
    diagnostic::Severity,
    frame::{Frame, LinkType},
    layer::Raw,
    packet::Packet,
    protocol::{
        builtin,
        network::Ipv4,
        transport::{Tcp, Udp},
    },
};
use std::time::UNIX_EPOCH;

fn dns_response_with_answers(count: u16) -> Vec<u8> {
    let mut wire = vec![0x12, 0x34, 0x81, 0x80, 0, 0];
    wire.extend_from_slice(&count.to_be_bytes());
    wire.extend_from_slice(&[0; 4]);
    for _ in 0..count {
        wire.extend_from_slice(&[0, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 1]);
    }
    wire
}

fn dissect_dns(udp: bool, payload: &[u8]) -> (DecodedPacket, Frame) {
    let mut packet = Packet::new();
    packet.push(Ipv4 {
        source: "192.0.2.1".parse().unwrap(),
        destination: "198.51.100.2".parse().unwrap(),
        ..Default::default()
    });
    if udp {
        packet.push(Udp {
            source_port: 40000,
            destination_port: 53,
            ..Default::default()
        });
    } else {
        packet.push(Tcp {
            source_port: 40000,
            destination_port: 53,
            ..Default::default()
        });
    }
    packet.push(Raw::new(payload.to_vec()));
    let built = Builder::new(builtin::registry())
        .build(
            packet,
            Default::default(),
            Options {
                mode: Mode::Permissive,
                ..Default::default()
            },
        )
        .unwrap();
    let frame = Frame::new(UNIX_EPOCH, LinkType::IPV4, built.bytes).unwrap();
    let decoded = Dissector::new(builtin::registry())
        .decode(frame.clone(), Default::default())
        .unwrap();
    (decoded, frame)
}

#[test]
fn tcp_dns_says_why() {
    let over = dns_response_with_answers(513);
    let (decoded, frame) = dissect_dns(false, &length_prefixed(&over));
    assert_eq!(protocols(&decoded), vec!["ipv4", "tcp", "raw"]);
    assert_eq!(
        decoded
            .diagnostics
            .iter()
            .map(|diagnostic| (diagnostic.code, diagnostic.severity, diagnostic.layer))
            .collect::<Vec<_>>(),
        vec![("dns.message_unparsed", Severity::Info, Some(2))]
    );
    assert!(
        decoded.diagnostics[0]
            .message
            .contains("DNS record count 513 exceeds limit 512"),
        "{}",
        decoded.diagnostics[0].message
    );
    let rebuilt = Builder::new(builtin::registry())
        .build(decoded.packet, Default::default(), Default::default())
        .unwrap();
    assert_eq!(&rebuilt.bytes, frame.bytes());

    let (decoded, _) = dissect_dns(true, &over);
    assert!(
        decoded
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "decode.malformed_layer"
                && diagnostic.severity == Severity::Error),
        "{:?}",
        decoded.diagnostics
    );

    let (decoded, _) = dissect_dns(false, &length_prefixed(&dns_response_with_answers(512)));
    assert_eq!(protocols(&decoded), vec!["ipv4", "tcp", "dns"]);
    assert!(decoded.diagnostics.is_empty());
}
