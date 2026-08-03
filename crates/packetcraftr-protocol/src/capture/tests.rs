// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;
use std::time::SystemTime;

use super::bsd::{CaptureByteOrder, FamilyHeader, decode_family};
use super::*;
use crate::{
    builtin::registry as default_registry,
    common::protocol,
    network::{Ipv4, Ipv6},
};
use packetcraftr_core::frame::{Frame, LinkType};
use packetcraftr_packet::layer::Raw;
use packetcraftr_packet::{
    Packet,
    build::{BuildContext, BuildOptions, Builder},
    codec::CodecError,
    decode::{DecodeOptions, Dissector},
    document::PacketDocument,
};

fn ipv4_bytes() -> Vec<u8> {
    let registry = Arc::new(default_registry().unwrap());
    let mut packet = Packet::new();
    packet.push(Ipv4 {
        source: "192.0.2.1".parse().unwrap(),
        destination: "198.51.100.2".parse().unwrap(),
        ..Ipv4::default()
    });
    Builder::new(registry)
        .build(packet, BuildContext::default(), BuildOptions::default())
        .unwrap()
        .bytes
        .to_vec()
}

#[test]
fn truncated_loopback_header_reports_the_selected_protocol() {
    assert!(matches!(
        decode_family(&[0, 0, 0], FamilyHeader::Loop),
        Err(CodecError::Truncated {
            protocol: actual,
            needed: 4,
            available: 3,
        }) if actual == protocol("bsd_loop")
    ));
}

#[test]
fn cooked_link_build_rejects_address_length_beyond_wire_slot() {
    let registry = Arc::new(default_registry().unwrap());
    let builder = Builder::new(registry);

    let mut sll = Packet::new();
    sll.push(LinuxSll {
        address_length: 9,
        ..LinuxSll::default()
    });
    assert!(
        builder
            .build(sll, BuildContext::default(), BuildOptions::default())
            .is_err()
    );

    let mut sll2 = Packet::new();
    sll2.push(LinuxSll2 {
        address_length: 9,
        ..LinuxSll2::default()
    });
    assert!(
        builder
            .build(sll2, BuildContext::default(), BuildOptions::default())
            .is_err()
    );
}

#[test]
fn null_and_loop_endianness_decode_to_ipv4() {
    let registry = Arc::new(default_registry().unwrap());
    for (link_type, family) in [
        (LinkType::NULL, 2u32.to_le_bytes()),
        (LinkType::NULL, 2u32.to_be_bytes()),
        (LinkType::LOOP, 2u32.to_be_bytes()),
    ] {
        let mut frame = family.to_vec();
        frame.extend_from_slice(&ipv4_bytes());
        let decoded = Dissector::new(Arc::clone(&registry))
            .decode(
                Frame::new(SystemTime::UNIX_EPOCH, link_type, frame).unwrap(),
                DecodeOptions::default(),
            )
            .unwrap();
        assert!(decoded.packet.get::<Ipv4>().is_some());
    }
}

#[test]
fn sll_and_sll2_use_their_protocol_offsets() {
    let registry = Arc::new(default_registry().unwrap());
    let ip = ipv4_bytes();
    let mut sll = vec![0, 0, 0, 1, 0, 6, 0, 1, 2, 3, 4, 5, 0, 0, 0x08, 0x00];
    sll.extend_from_slice(&ip);
    let mut sll2 = vec![
        0x08, 0x00, 0, 0, 0, 0, 0, 7, 0, 1, 0, 6, 0, 1, 2, 3, 4, 5, 0, 0,
    ];
    sll2.extend_from_slice(&ip);

    let first = Dissector::new(Arc::clone(&registry))
        .decode(
            Frame::new(SystemTime::UNIX_EPOCH, LinkType::LINUX_SLL, sll).unwrap(),
            DecodeOptions::default(),
        )
        .unwrap();
    let second = Dissector::new(registry)
        .decode(
            Frame::new(SystemTime::UNIX_EPOCH, LinkType::LINUX_SLL2, sll2).unwrap(),
            DecodeOptions::default(),
        )
        .unwrap();
    assert!(first.packet.get::<LinuxSll>().is_some());
    assert!(first.packet.get::<Ipv4>().is_some());
    assert_eq!(second.packet.get::<LinuxSll2>().unwrap().interface_index, 7);
    assert!(second.packet.get::<Ipv4>().is_some());
}

#[test]
fn unknown_sll_protocols_rebuild_exactly_as_raw() {
    let registry = Arc::new(default_registry().unwrap());
    let builder = Builder::new(Arc::clone(&registry));
    for (root, mut frame) in [
        (
            "linux_sll",
            vec![0, 0, 0, 1, 0, 6, 0, 1, 2, 3, 4, 5, 0, 0, 0x12, 0x34],
        ),
        (
            "linux_sll2",
            vec![
                0x12, 0x34, 0, 0, 0, 0, 0, 7, 0, 1, 0, 6, 0, 1, 2, 3, 4, 5, 0, 0,
            ],
        ),
    ] {
        frame.extend_from_slice(&[0xaa, 0xbb]);
        let decoded = Dissector::new(Arc::clone(&registry))
            .decode_with_root(frame.clone(), root.into(), DecodeOptions::default())
            .unwrap();
        assert!(decoded.packet.get::<Raw>().is_some());
        let document = PacketDocument::from_packet(&decoded.packet);
        let reloaded = document.to_packet(&registry, 64).unwrap();
        let rebuilt = builder
            .build(reloaded, BuildContext::default(), BuildOptions::default())
            .unwrap();
        assert_eq!(rebuilt.bytes.as_ref(), frame);
    }
}

#[test]
fn strict_capture_family_must_match_typed_child() {
    let registry = Arc::new(default_registry().unwrap());
    let mut packet = Packet::new();
    packet.push(BsdLoop { family: 2 }).push(Ipv6 {
        source: "2001:db8::1".parse().unwrap(),
        destination: "2001:db8::2".parse().unwrap(),
        ..Ipv6::default()
    });

    assert!(
        Builder::new(registry)
            .build(packet, BuildContext::default(), BuildOptions::default())
            .is_err()
    );
}

#[test]
fn big_endian_null_byte_order_survives_packet_documents() {
    let registry = Arc::new(default_registry().unwrap());
    let mut bytes = 2_u32.to_be_bytes().to_vec();
    bytes.extend_from_slice(&ipv4_bytes());
    let decoded = Dissector::new(Arc::clone(&registry))
        .decode_with_root(
            bytes.clone(),
            protocol("bsd_null"),
            DecodeOptions::default(),
        )
        .unwrap();
    assert_eq!(
        decoded.packet.get::<BsdNull>().unwrap().byte_order,
        CaptureByteOrder::Big
    );

    let document = PacketDocument::from_packet(&decoded.packet);
    let reloaded = document.to_packet(&registry, 64).unwrap();
    let rebuilt = Builder::new(registry)
        .build(reloaded, BuildContext::default(), BuildOptions::default())
        .unwrap();
    assert_eq!(rebuilt.bytes.as_ref(), bytes);
}
