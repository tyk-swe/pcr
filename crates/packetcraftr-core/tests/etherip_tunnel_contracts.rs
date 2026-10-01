// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod common;

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use common::packets::ipv4;
use common::{TcpSpec, client_tcp, reader, registry};
use packetcraftr_core::analysis::{Options, run};
use packetcraftr_core::frame::{Frame, LinkType};
use packetcraftr_core::layer::{Malformed, Raw};
use packetcraftr_core::packet::Packet;
use packetcraftr_core::protocol::BuiltinProtocol;
use packetcraftr_core::protocol::link::Ethernet;
use packetcraftr_core::protocol::network::{Icmpv4, Ipv4};
use packetcraftr_core::protocol::semantics::{live_destinations, outer_scope_len};
use packetcraftr_core::protocol::transport::{Tcp, Udp};
use packetcraftr_core::protocol::tunnel::{Etherip, Mpls};
use packetcraftr_core::{build, codec, decode};

const OUTER_IPV4_LEN: usize = 20;

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

fn codes(decoded: &decode::DecodedPacket, fragment: &str) -> Vec<&'static str> {
    decoded
        .diagnostics
        .iter()
        .map(|diagnostic| diagnostic.code)
        .filter(|code| code.contains(fragment))
        .collect()
}

#[test]
fn etherip_carries_an_ethernet_frame_and_round_trips_exactly() {
    let built = build_with(
        etherip_packet(Etherip::default()),
        build::Options::default(),
    );
    // the outer protocol number is derived from the EtherIP child
    assert_eq!(built.bytes[9], 97);
    assert_eq!(
        &built.bytes[OUTER_IPV4_LEN..OUTER_IPV4_LEN + 2],
        [0x30, 0x00]
    );

    let decoded = dissect(built.bytes.clone());
    assert_eq!(
        protocols(&decoded),
        ["ipv4", "etherip", "ethernet", "ipv4", "icmpv4"]
    );
    assert!(codes(&decoded, "etherip").is_empty());
    let etherip = decoded.packet.get::<Etherip>().unwrap();
    assert_eq!((etherip.version, etherip.reserved), (3, 0));
    let rebuilt = build_with(decoded.packet, build::Options::default());
    assert_eq!(rebuilt.bytes, built.bytes);
}

#[test]
fn a_wrong_version_and_reserved_bits_are_diagnosed_and_kept_exactly() {
    let packet = || {
        etherip_packet(Etherip {
            version: 2,
            reserved: 0x123,
        })
    };
    let strict = build::Builder::new(registry()).build(
        packet(),
        codec::Context::default(),
        build::Options::default(),
    );
    assert!(strict.is_err());

    let built = build_with(packet(), permissive());
    assert_eq!(
        built
            .diagnostics
            .iter()
            .map(|diagnostic| diagnostic.code)
            .filter(|code| code.contains("etherip"))
            .collect::<Vec<_>>(),
        ["build.etherip_version", "build.etherip_reserved"]
    );
    assert_eq!(
        &built.bytes[OUTER_IPV4_LEN..OUTER_IPV4_LEN + 2],
        [0x21, 0x23]
    );

    let decoded = dissect(built.bytes.clone());
    assert_eq!(
        codes(&decoded, "etherip"),
        ["decode.etherip_version", "decode.etherip_reserved"]
    );
    let etherip = decoded.packet.get::<Etherip>().unwrap();
    assert_eq!((etherip.version, etherip.reserved), (2, 0x123));
    assert_eq!(
        protocols(&decoded),
        ["ipv4", "etherip", "ethernet", "ipv4", "icmpv4"]
    );
    assert_eq!(build_with(decoded.packet, permissive()).bytes, built.bytes);
}

#[test]
fn etherip_requires_an_ethernet_child() {
    let mut packet = Packet::new();
    packet.push(outer_ipv4());
    packet.push(Etherip::default());
    packet.push(Raw::new(vec![1, 2, 3]));
    let strict = build::Builder::new(registry()).build(
        packet.clone(),
        codec::Context::default(),
        build::Options::default(),
    );
    assert!(strict.is_err());
    let built = build_with(packet, permissive());
    assert!(
        built
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "build.raw_typed_discriminator")
    );
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

#[test]
fn ip_protocols_137_and_143_and_udp_6635_select_mpls_and_ethernet() {
    let mut mpls = Packet::new();
    mpls.push(outer_ipv4());
    mpls.push(Mpls::default());
    mpls.push(ipv4([10, 0, 0, 1], [10, 0, 0, 2]));
    mpls.push(Icmpv4::default());
    let built = build_with(mpls, build::Options::default());
    assert_eq!(built.bytes[9], 137);
    assert_eq!(
        protocols(&dissect(built.bytes)),
        ["ipv4", "mpls", "ipv4", "icmpv4"]
    );

    let mut ethernet = Packet::new();
    ethernet.push(outer_ipv4());
    ethernet.push(Ethernet::default());
    ethernet.push(ipv4([10, 0, 0, 1], [10, 0, 0, 2]));
    ethernet.push(Icmpv4::default());
    let built = build_with(ethernet, build::Options::default());
    assert_eq!(built.bytes[9], 143);
    let decoded = dissect(built.bytes.clone());
    assert_eq!(protocols(&decoded), ["ipv4", "ethernet", "ipv4", "icmpv4"]);
    assert_eq!(
        build_with(decoded.packet, build::Options::default()).bytes,
        built.bytes
    );

    let mut udp = Packet::new();
    udp.push(outer_ipv4());
    udp.push(Udp {
        source_port: 50_000,
        destination_port: 6_635,
        ..Udp::default()
    });
    udp.push(Mpls::default());
    udp.push(ipv4([10, 0, 0, 1], [10, 0, 0, 2]));
    udp.push(Icmpv4::default());
    let built = build_with(udp, build::Options::default());
    assert_eq!(
        protocols(&dissect(built.bytes)),
        ["ipv4", "udp", "mpls", "ipv4", "icmpv4"]
    );
}

/// IP protocol 143 follows the IPIP precedent: the carrier is not an
/// encapsulation boundary, so the outer scope spans the inner headers and
/// every IP destination stays visible to authorization.
#[test]
fn ethernet_over_ip_143_has_no_boundary_like_ipip() {
    assert!(!BuiltinProtocol::Ethernet.is_encapsulation_boundary());
    assert!(!BuiltinProtocol::Ipv4.is_encapsulation_boundary());

    let mut ipip = Packet::new();
    ipip.push(outer_ipv4());
    ipip.push(ipv4([10, 0, 0, 1], [10, 0, 0, 2]));
    ipip.push(Icmpv4::default());
    let mut ethernet = Packet::new();
    ethernet.push(outer_ipv4());
    ethernet.push(Ethernet::default());
    ethernet.push(ipv4([10, 0, 0, 1], [10, 0, 0, 2]));
    ethernet.push(Icmpv4::default());

    for packet in [&ipip, &ethernet] {
        assert_eq!(outer_scope_len(packet), packet.len());
        assert_eq!(
            live_destinations(packet).unwrap(),
            [
                IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2)),
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            ]
        );
    }
}

fn etherip_tcp_frame(
    registry: &Arc<packetcraftr_core::registry::Registry>,
    timestamp: SystemTime,
    inner_source_mac: [u8; 6],
    spec: &TcpSpec,
) -> Frame {
    let mut packet = Packet::new();
    packet.push(outer_ipv4());
    packet.push(Etherip::default());
    packet.push(Ethernet {
        source: inner_source_mac,
        ..Ethernet::default()
    });
    packet.push(Ipv4 {
        source: spec.source,
        destination: spec.destination,
        ..Ipv4::default()
    });
    packet.push(Tcp {
        source_port: spec.source_port,
        destination_port: spec.destination_port,
        sequence: spec.sequence,
        acknowledgment: spec.acknowledgment,
        flags: spec.flags,
        window: spec.window,
        ..Tcp::default()
    });
    let built = build::Builder::new(Arc::clone(registry))
        .build(packet, codec::Context::default(), build::Options::default())
        .expect("EtherIP fixture builds");
    Frame::new(timestamp, LinkType::IPV4, built.bytes).expect("EtherIP fixture frame")
}

/// Analysis has no EtherIP encapsulation identifier (adding one would change
/// the versioned output schema), so inner flows that differ only below the
/// outer IP pair share a scope and a stream. This pins that known limitation.
/// Flip this test when an identifier lands with the schema that adds it.
#[test]
fn inner_ethernet_segments_do_not_scope_identical_inner_tcp_tuples() {
    let registry = registry();
    let epoch = SystemTime::UNIX_EPOCH;
    let flow = client_tcp(100, 0, Tcp::SYN, 1_000);
    let frames = [
        etherip_tcp_frame(&registry, epoch, [2, 0, 0, 0, 0, 1], &flow),
        etherip_tcp_frame(
            &registry,
            epoch + Duration::from_secs(1),
            [2, 0, 0, 0, 0, 2],
            &flow,
        ),
    ];
    let mut capture = reader(&frames);
    let mut streams = Vec::new();
    run(&mut capture, registry, &Options::default(), |record| {
        streams.push(
            record
                .tcp
                .and_then(|view| view.conversation)
                .map(|stream| stream.index),
        );
        Ok(())
    })
    .expect("EtherIP analysis succeeds");
    assert_eq!(streams, vec![Some(0), Some(0)]);
}
