// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::Ipv4Addr;
use std::sync::Arc;

use packetcraftr_core::frame::{Frame, LinkType};
use packetcraftr_core::protocol::{BuiltinProtocol, builtin, network::Ipv4, transport::Udp};
use packetcraftr_core::{build, codec, decode, layer::Raw, packet::Packet};

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
            codec::Context::default(),
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
            codec::Context::default(),
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
                registry
                    .protocol_named(alias)
                    .map(packetcraftr_core::layer::Id::as_str),
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
                build_context: &codec::Context::default(),
                mode: codec::Mode::Strict,
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
}

#[test]
fn every_mapped_link_type_maps_to_its_root_protocol_and_back() {
    use BuiltinProtocol::{BsdLoop, BsdNull, Ethernet, Ipv4, Ipv6, LinuxSll, LinuxSll2, RawIp};
    // (link type, root protocol, link type written for that root protocol)
    let matrix = [
        (0, BsdNull, 0),
        (1, Ethernet, 1),
        (12, RawIp, 101),
        (101, RawIp, 101),
        (108, BsdLoop, 108),
        (113, LinuxSll, 113),
        (228, Ipv4, 228),
        (229, Ipv6, 229),
        (276, LinuxSll2, 276),
    ];
    let registry = builtin::registry();

    let mut mapped = LinkType::BUILTIN_ROOTS.to_vec();
    mapped.sort();
    let expected: Vec<_> = matrix
        .iter()
        .map(|&(number, protocol, _)| (LinkType(number), protocol))
        .collect();
    assert_eq!(mapped, expected);

    for (number, protocol, written) in matrix {
        let link_type = LinkType(number);
        assert_eq!(link_type.root_protocol(), Some(protocol), "{link_type}");
        assert_eq!(
            registry
                .root_for_link_type(link_type)
                .map(packetcraftr_core::layer::Id::as_str),
            Some(protocol.as_str()),
            "{link_type}"
        );
        assert_eq!(
            LinkType::for_root_protocol(protocol),
            Some(LinkType(written)),
            "{}",
            protocol.as_str()
        );
        assert_eq!(
            link_type.is_raw_ip(),
            matches!(protocol, RawIp | Ipv4 | Ipv6),
            "{link_type}"
        );
    }
    for &protocol in BuiltinProtocol::ALL {
        if !matrix.iter().any(|&(_, root, _)| root == protocol) {
            assert_eq!(
                LinkType::for_root_protocol(protocol),
                None,
                "{}",
                protocol.as_str()
            );
        }
    }
    let unmapped = LinkType(147);
    assert_eq!(unmapped.root_protocol(), None);
    assert!(!unmapped.is_raw_ip());
    assert!(registry.root_for_link_type(unmapped).is_none());
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
                limits: packetcraftr_core::packet::Limits {
                    max_packet_size: 19,
                    ..packetcraftr_core::packet::Limits::default()
                },
            },
        )
        .expect_err("oversized input must be rejected before codec traversal");
    assert!(error.to_string().contains("packet size"));
}
