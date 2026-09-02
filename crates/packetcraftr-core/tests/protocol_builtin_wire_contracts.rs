// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
// Test code indexes fixtures and counts by hand; the fail-closed lints are
// for library paths.
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::net::Ipv4Addr;
use std::sync::Arc;

use packetcraftr_core::frame::{Frame, LinkType};
use packetcraftr_core::protocol::{
    BuiltinProtocol, builtin, capture::BUILTIN_CAPTURE_ROOTS, network::Ipv4, transport::Udp,
};
use packetcraftr_core::{Packet, build, decode, layer::Raw};

fn representative_packet() -> Packet {
    let mut packet = Packet::new();
    packet.push(Ipv4 {
        source: Ipv4Addr::new(192, 0, 2, 1),
        destination: Ipv4Addr::new(198, 51, 100, 2),
        ..Ipv4::default()
    });
    packet.push(Udp {
        source_port: 12_345,
        destination_port: 9_999,
        ..Udp::default()
    });
    packet.push(Raw::new(b"abc".to_vec()));
    packet
}

#[test]
fn ipv4_udp_build_dissect_rebuild_is_exact() {
    let registry = builtin::registry();
    let builder = build::Builder::new(Arc::clone(&registry));
    let built = builder
        .build(
            representative_packet(),
            build::Context::default(),
            build::Options::default(),
        )
        .expect("representative packet must build");

    assert_eq!(built.bytes.len(), 31);
    assert_eq!(&built.bytes[..10], &[0x45, 0, 0, 31, 0, 0, 0, 0, 64, 17]);
    assert_eq!(
        &built.bytes[20..28],
        &[0x30, 0x39, 0x27, 0x0f, 0, 11, 0xf7, 0xf5]
    );
    assert_eq!(&built.bytes[28..], b"abc");

    let frame = Frame::new(
        std::time::SystemTime::UNIX_EPOCH,
        LinkType::IPV4,
        built.bytes.clone(),
    )
    .expect("frame must be valid");
    let decoded = decode::Dissector::new(Arc::clone(&registry))
        .decode(frame, decode::Options::default())
        .expect("wire vector must dissect");
    let rebuilt = builder
        .build(
            decoded.packet,
            build::Context::default(),
            build::Options::default(),
        )
        .expect("decoded packet must rebuild");
    assert_eq!(rebuilt.bytes, built.bytes);
}

#[test]
fn advertised_protocols_and_capture_roots_are_registered() {
    let registry = builtin::registry();

    for &protocol in BuiltinProtocol::ALL {
        assert!(registry.codec(protocol.as_str()).is_some());
        assert_eq!(
            registry.matcher(protocol.as_str()).is_some(),
            protocol.has_matcher(),
            "{}",
            protocol.as_str()
        );
        for alias in protocol.aliases() {
            assert_eq!(
                registry.protocol_named(alias).map(|value| value.as_str()),
                Some(protocol.as_str())
            );
        }
    }
    // The one advertised non-round-tripping codec is the one that cannot
    // encode at all, and it says so instead of failing silently.
    let not_round_tripping: Vec<&str> = BuiltinProtocol::ALL
        .iter()
        .filter(|protocol| !protocol.exact_round_trip())
        .map(|protocol| protocol.as_str())
        .collect();
    assert_eq!(not_round_tripping, ["raw_ip"]);
    let error = registry
        .codec("raw_ip")
        .expect("raw_ip codec")
        .encode(
            &Raw::new(vec![0x45]),
            &[],
            &packetcraftr_core::codec::LayerEncodeContext {
                packet: &Packet::new(),
                index: 0,
                build_context: &build::Context::default(),
                mode: build::Mode::Strict,
                registry: &registry,
                child: None,
                remaining_packet_bytes: usize::MAX,
            },
        )
        .err()
        .expect("raw_ip cannot encode");
    assert!(
        matches!(error, packetcraftr_core::codec::Error::Unsupported { .. }),
        "{error}"
    );
    for root in BUILTIN_CAPTURE_ROOTS {
        assert_eq!(
            registry
                .root_for_link_type(root.link_type.0)
                .map(|value| value.as_str()),
            Some(root.protocol.as_str())
        );
    }
}

#[test]
fn dissection_limits_reject_before_parsing() {
    let registry = builtin::registry();
    let frame = Frame::new(
        std::time::SystemTime::UNIX_EPOCH,
        LinkType::IPV4,
        vec![0_u8; 20],
    )
    .expect("frame must be valid");
    let error = decode::Dissector::new(registry)
        .decode(
            frame,
            decode::Options {
                max_packet_size: 19,
                ..decode::Options::default()
            },
        )
        .expect_err("oversized input must be rejected before codec traversal");
    assert!(error.to_string().contains("packet size"));
}
