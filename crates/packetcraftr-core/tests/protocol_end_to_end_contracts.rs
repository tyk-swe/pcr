// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod common;

use common::packets::{ROOT_LINK_TYPE, ipv4, ipv6, rooted_registry};
use common::registry;
use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::SystemTime;

use bytes::Bytes;
use packetcraftr_core::diagnostic::{
    CHECKSUM_FAILURE_CODES, GRE_CHECKSUM, ICMPV4_CHECKSUM, ICMPV6_CHECKSUM, IGMP_CHECKSUM,
    IPV4_CHECKSUM, SCTP_CHECKSUM, TCP_CHECKSUM, UDP_CHECKSUM, VRRP_CHECKSUM,
};
use packetcraftr_core::frame::Frame;
use packetcraftr_core::layer::{Layer, Malformed, Raw};
use packetcraftr_core::protocol::application::dns::Dns;
use packetcraftr_core::protocol::link::{Arp, Ethernet};
use packetcraftr_core::protocol::network::{Icmpv4, Icmpv6, Igmp, Ipv4, Ipv6, Vrrp};
use packetcraftr_core::protocol::transport::{Sctp, Tcp, Udp};
use packetcraftr_core::protocol::tunnel::Gre;
use packetcraftr_core::registry::Registry;
use packetcraftr_core::{build, codec, decode, packet::Packet};

fn decode_from_root(
    registry: &Arc<Registry>,
    bytes: impl Into<Bytes>,
    options: decode::Options,
) -> Result<decode::DecodedPacket, decode::Error> {
    let frame = Frame::new(SystemTime::UNIX_EPOCH, ROOT_LINK_TYPE, bytes)?;
    decode::Dissector::new(Arc::clone(registry)).decode(frame, options)
}

fn round_trip(packet: Packet, root: &'static str) -> (build::BuiltPacket, decode::DecodedPacket) {
    let registry = rooted_registry(root);
    let builder = build::Builder::new(Arc::clone(&registry));
    let built = builder
        .build(packet, codec::Context::default(), build::Options::default())
        .unwrap_or_else(|error| panic!("{root} build: {error}"));
    let decoded = decode_from_root(&registry, built.bytes.clone(), decode::Options::default())
        .unwrap_or_else(|error| panic!("{root} decode: {error}"));
    let rebuilt = builder
        .build(
            decoded.packet.clone(),
            codec::Context::default(),
            build::Options::default(),
        )
        .unwrap_or_else(|error| panic!("{root} rebuild: {error}"));
    assert_eq!(rebuilt.bytes, built.bytes, "{root} exact round trip");
    (built, decoded)
}

fn known_tcp() -> Tcp {
    Tcp {
        source_port: 12_345,
        destination_port: 80,
        sequence: 1,
        window: 0xfaf0,
        ..Tcp::default()
    }
}

#[test]
fn sctp_dns_bad_inputs_cover_bounded_parsers() {
    let init_chunk = vec![
        1, 0, 0, 20, 0, 0, 0, 7, 0, 0, 4, 0, 0, 10, 0, 10, 0, 1, 0, 1,
    ];
    let mut sctp = Packet::new();
    sctp.push(ipv4([192, 0, 2, 1], [192, 0, 2, 2]));
    sctp.push(Sctp::default());
    sctp.push(Raw::new(init_chunk));
    let (_, decoded) = round_trip(sctp, "ipv4");
    assert!(decoded.packet.get::<Sctp>().is_some());

    let query = vec![
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 3, b'w', b'w',
        b'w', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0, 0, 1, 0, 1,
    ];
    let dns = Dns::try_from(query.clone()).expect("valid DNS query");
    assert_eq!(dns.id, 0x1234);
    assert_eq!(dns.questions[0].name.to_string(), "www.example.com.");
    assert_eq!(dns.questions[0].query_type, 1);
    assert_eq!(dns.wire().as_ref(), query);
    let mut packet = Packet::new();
    packet.push(ipv4([192, 0, 2, 1], [8, 8, 8, 8]));
    packet.push(Udp::default());
    packet.push(dns.clone());
    let (_, decoded) = round_trip(packet, "ipv4");
    assert_eq!(decoded.packet.get::<Dns>().map(|dns| dns.id), Some(0x1234));

    for (root, bytes) in [
        ("ethernet", vec![0; 13]),
        ("ipv4", vec![0; 19]),
        ("ipv6", vec![0; 39]),
        ("udp", vec![0; 7]),
        ("tcp", vec![0; 19]),
        ("sctp", vec![0; 11]),
        ("dns", vec![0; 11]),
        ("geneve", vec![0; 7]),
        ("vxlan", vec![0; 7]),
        ("gre", vec![0; 3]),
        ("etherip", vec![0; 1]),
        ("gtpu", vec![0; 7]),
    ] {
        let decoded = decode_from_root(&rooted_registry(root), bytes, decode::Options::default())
            .unwrap_or_else(|error| panic!("{root} malformed preservation failed: {error}"));
        assert!(decoded.packet.get::<Malformed>().is_some(), "{root}");
        assert_eq!(
            decoded.diagnostics[0].code, "decode.malformed_layer",
            "{root}"
        );
    }
}

#[test]
fn typed_child_no_payload_kept_bad() {
    let mut bytes = vec![0; 14];
    bytes[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());

    let decoded = decode_from_root(
        &rooted_registry("ethernet"),
        bytes,
        decode::Options::default(),
    )
    .expect("empty typed child should be preserved");

    assert_eq!(decoded.packet.len(), 2);
    let malformed = decoded
        .packet
        .get::<Malformed>()
        .expect("missing IPv4 header should be materialized as malformed");
    assert_eq!(malformed.intended_protocol.as_deref(), Some("ipv4"));
    assert!(malformed.bytes.is_empty());
    assert_eq!(malformed.reason, "required child header is absent");
    assert_eq!(
        decoded.diagnostics.last().map(|diagnostic| diagnostic.code),
        Some("decode.missing_required_child")
    );
}

#[test]
fn corrupted_builtin_integrity_fails() {
    let mut ipv4_header = Packet::new();
    ipv4_header.push(ipv4([192, 0, 2, 1], [192, 0, 2, 2]));
    ipv4_header.push(Icmpv4::default());

    let mut tcp = Packet::new();
    tcp.push(ipv4([192, 0, 2, 1], [192, 0, 2, 2]));
    tcp.push(known_tcp());

    let mut udp = Packet::new();
    udp.push(ipv4([192, 0, 2, 1], [192, 0, 2, 2]));
    udp.push(Udp {
        source_port: 12_345,
        destination_port: 40_000,
        ..Udp::default()
    });
    udp.push(Raw::new(b"PCR!".to_vec()));

    let mut sctp = Packet::new();
    sctp.push(ipv4([192, 0, 2, 1], [192, 0, 2, 2]));
    sctp.push(Sctp::default());
    sctp.push(Raw::new(vec![11, 0, 0, 4]));

    let mut icmpv4 = Packet::new();
    icmpv4.push(ipv4([192, 0, 2, 1], [192, 0, 2, 2]));
    icmpv4.push(Icmpv4::default());

    let mut icmpv6 = Packet::new();
    icmpv6.push(ipv6("2001:db8::1", "2001:db8::2"));
    icmpv6.push(Icmpv6::default());

    let mut igmp = Packet::new();
    igmp.push(ipv4([192, 0, 2, 1], [224, 0, 0, 1]));
    igmp.push(Igmp::default());

    let mut vrrp = Packet::new();
    vrrp.push(Ipv4 {
        ttl: 255,
        ..ipv4([192, 0, 2, 1], [224, 0, 0, 18])
    });
    vrrp.push(Vrrp {
        version: 2,
        addresses: vec!["192.0.2.100".parse().unwrap()],
        ..Vrrp::default()
    });

    let vrrp_v3_ipv4 = vrrp_packet(vrrp_ipv4_envelope(), vrrp_v3(&["192.0.2.100"]));
    let vrrp_v3_ipv6 = vrrp_packet(vrrp_ipv6_envelope(), vrrp_v3(&["2001:db8::1"]));

    let mut gre = Packet::new();
    gre.push(ipv4([192, 0, 2, 1], [192, 0, 2, 2]));
    gre.push(Gre {
        checksum: Some(Default::default()),
        key: Some(7),
        ..Gre::default()
    });
    gre.push(Ethernet::default());
    gre.push(Arp::default());

    let cases = [
        (IPV4_CHECKSUM, "ipv4", ipv4_header, 8),
        (TCP_CHECKSUM, "ipv4", tcp, 38),
        (UDP_CHECKSUM, "ipv4", udp, 31),
        (SCTP_CHECKSUM, "ipv4", sctp, 24),
        (ICMPV4_CHECKSUM, "ipv4", icmpv4, 27),
        (ICMPV6_CHECKSUM, "ipv6", icmpv6, 47),
        (IGMP_CHECKSUM, "ipv4", igmp, 27),
        (VRRP_CHECKSUM, "ipv4", vrrp, 26),
        (VRRP_CHECKSUM, "ipv4", vrrp_v3_ipv4, 26),
        (VRRP_CHECKSUM, "ipv6", vrrp_v3_ipv6, 46),
        (GRE_CHECKSUM, "ipv4", gre, 28),
    ];

    let registry = registry();
    let builder = build::Builder::new(Arc::clone(&registry));
    let mut observed = BTreeSet::new();

    for (code, root, packet, corrupted_offset) in cases {
        let built = builder
            .build(packet, codec::Context::default(), build::Options::default())
            .unwrap_or_else(|error| panic!("{code} build: {error}"));
        let mut bytes = built.bytes.to_vec();
        bytes[corrupted_offset] ^= 0xff;
        let decoded = decode_from_root(
            &rooted_registry(root),
            Bytes::from(bytes),
            decode::Options::default(),
        )
        .unwrap_or_else(|error| panic!("{code} decode: {error}"));
        let failures: Vec<&str> = decoded
            .diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.is_checksum_failure())
            .map(|diagnostic| diagnostic.code)
            .collect();
        assert_eq!(
            failures,
            [code],
            "{code} diagnostics: {:?}",
            decoded.diagnostics
        );
        observed.insert(code);
    }

    assert_eq!(
        observed,
        CHECKSUM_FAILURE_CODES
            .iter()
            .copied()
            .collect::<BTreeSet<_>>()
    );
}

fn vrrp_ipv4_envelope() -> Ipv4 {
    Ipv4 {
        ttl: 255,
        ..ipv4([192, 0, 2, 1], [224, 0, 0, 18])
    }
}

fn vrrp_ipv6_envelope() -> Ipv6 {
    Ipv6 {
        hop_limit: 255,
        ..ipv6("fe80::1", "ff02::12")
    }
}

fn vrrp_v3(addresses: &[&str]) -> Vrrp {
    Vrrp {
        version: 3,
        vrid: 7,
        priority: 120,
        max_advert_interval: 100,
        addresses: addresses.iter().map(|text| text.parse().unwrap()).collect(),
        ..Vrrp::default()
    }
}

fn vrrp_packet(envelope: impl Layer, vrrp: Vrrp) -> Packet {
    let mut packet = Packet::new();
    packet.push(envelope);
    packet.push(vrrp);
    packet
}
