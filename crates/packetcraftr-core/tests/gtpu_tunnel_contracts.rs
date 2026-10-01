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
use packetcraftr_core::field::WireValue;
use packetcraftr_core::frame::{Frame, LinkType};
use packetcraftr_core::layer::{Id, Malformed, Raw};
use packetcraftr_core::packet::Packet;
use packetcraftr_core::protocol::link::Ethernet;
use packetcraftr_core::protocol::network::Ipv4;
use packetcraftr_core::protocol::semantics::{live_destinations, outer_scope_len};
use packetcraftr_core::protocol::transport::{Tcp, Udp};
use packetcraftr_core::protocol::tunnel::Gtpu;
use packetcraftr_core::registry::Discriminator;
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

fn permissive() -> build::Options {
    build::Options {
        mode: codec::Mode::Permissive,
        ..build::Options::default()
    }
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

fn gtpu_codes(decoded: &decode::DecodedPacket) -> Vec<&'static str> {
    decoded
        .diagnostics
        .iter()
        .map(|diagnostic| diagnostic.code)
        .filter(|code| code.contains("gtpu"))
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
fn g_pdu_without_optional_fields_round_trips_and_selects_the_inner_ip_version() {
    let (bytes, decoded) = round_trip(tunnel(Gtpu {
        teid: 0x1122_3344,
        ..Gtpu::default()
    }));
    assert_eq!(
        protocols(&decoded),
        ["ethernet", "ipv4", "udp", "gtpu", "ipv4", "udp"]
    );
    // flags 0x30 (version 1, PT), G-PDU, length of the inner IPv4 and UDP headers, TEID
    assert_eq!(
        &bytes[GTPU_OFFSET..GTPU_OFFSET + 8],
        [0x30, 0xff, 0, 28, 0x11, 0x22, 0x33, 0x44]
    );
    let gtpu = decoded.packet.get::<Gtpu>().unwrap();
    assert_eq!(gtpu.teid, 0x1122_3344);
    assert_eq!(gtpu.length, WireValue::Exact(28));
    assert_eq!(gtpu.sequence_number, 0);
    assert!(gtpu.extensions.is_empty());
    assert!(gtpu_codes(&decoded).is_empty());

    let mut ipv6 = outer();
    ipv6.push(Gtpu::default());
    ipv6.push(common::packets::ipv6("2001:db8::1", "2001:db8::2"));
    let (_, decoded) = round_trip(ipv6);
    assert_eq!(
        protocols(&decoded),
        ["ethernet", "ipv4", "udp", "gtpu", "ipv6"]
    );
}

#[test]
fn sequence_number_and_extension_headers_round_trip_and_expose_their_fields() {
    let (bytes, decoded) = round_trip(tunnel(Gtpu {
        sequence_flag: true,
        sequence_number: 0xbeef,
        ..Gtpu::default()
    }));
    assert_eq!(bytes[GTPU_OFFSET], 0x32);
    // the optional block adds four bytes to the length
    assert_eq!(&bytes[GTPU_OFFSET + 2..GTPU_OFFSET + 4], [0, 32]);
    assert_eq!(
        &bytes[GTPU_OFFSET + 8..GTPU_OFFSET + 12],
        [0xbe, 0xef, 0, 0]
    );
    let gtpu = decoded.packet.get::<Gtpu>().unwrap();
    assert!(gtpu.sequence_flag && !gtpu.extension_flag && !gtpu.npdu_flag);
    assert_eq!(gtpu.sequence_number, 0xbeef);

    // two chained headers: the first announces the second (0xc0), which ends the chain
    let chain = Bytes::from_static(&[1, 0x10, 0x20, 0xc0, 1, 0x30, 0x40, 0x00]);
    let (bytes, decoded) = round_trip(tunnel(Gtpu {
        extension_flag: true,
        sequence_flag: true,
        npdu_flag: true,
        sequence_number: 7,
        npdu_number: 9,
        next_extension_type: 0x85,
        extensions: chain.clone(),
        ..Gtpu::default()
    }));
    assert_eq!(bytes[GTPU_OFFSET], 0x37);
    assert_eq!(&bytes[GTPU_OFFSET + 2..GTPU_OFFSET + 4], [0, 40]);
    assert_eq!(
        protocols(&decoded),
        ["ethernet", "ipv4", "udp", "gtpu", "ipv4", "udp"]
    );
    let gtpu = decoded.packet.get::<Gtpu>().unwrap();
    assert_eq!(
        (
            gtpu.sequence_number,
            gtpu.npdu_number,
            gtpu.next_extension_type
        ),
        (7, 9, 0x85)
    );
    assert_eq!(gtpu.extensions, chain);
    assert_eq!(&bytes[GTPU_OFFSET + 12..GTPU_OFFSET + 20], chain.as_ref());
}

#[test]
fn echo_messages_and_non_ip_payloads_keep_a_raw_child() {
    for message_type in [1_u8, 2] {
        let mut packet = outer();
        packet.push(Gtpu {
            message_type,
            sequence_flag: true,
            sequence_number: 3,
            ..Gtpu::default()
        });
        // a Recovery information element
        packet.push(Raw::new(vec![0x0e, 0x00]));
        let (_, decoded) = round_trip(packet);
        assert_eq!(
            protocols(&decoded),
            ["ethernet", "ipv4", "udp", "gtpu", "raw"],
            "message type {message_type}"
        );
        let raw = decoded.packet.get::<Raw>().unwrap();
        assert_eq!(raw.bytes.as_ref(), [0x0e, 0x00]);
    }

    let mut packet = outer();
    packet.push(Gtpu::default());
    packet.push(Raw::new(vec![0x50, 1, 2]));
    let (_, decoded) = round_trip(packet);
    assert_eq!(
        protocols(&decoded),
        ["ethernet", "ipv4", "udp", "gtpu", "raw"],
        "a payload that is neither IPv4 nor IPv6 stays opaque"
    );
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
fn bytes_after_the_declared_length_are_padding_that_rebuilds_strictly() {
    let mut packet = outer();
    packet.push(Gtpu {
        teid: 1,
        length: WireValue::Exact(0),
        ..Gtpu::default()
    });
    packet.push(Raw::new(vec![0xaa, 0xbb]));
    let built = build::Builder::new(registry())
        .build(packet, codec::Context::default(), permissive())
        .unwrap();

    let decoded = dissect(built.bytes.clone());
    assert_eq!(
        protocols(&decoded),
        ["ethernet", "ipv4", "udp", "gtpu", "padding"]
    );
    assert!(
        decoded
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "decode.trailing_malformed")
    );
    let rebuilt = build::Builder::new(registry())
        .build(
            decoded.packet,
            codec::Context::default(),
            build::Options::default(),
        )
        .expect("padding outside the GTP-U length rebuilds strictly");
    assert_eq!(rebuilt.bytes, built.bytes);
}

#[test]
fn a_zero_length_extension_header_is_rejected_without_walking_on() {
    let packet = || {
        tunnel(Gtpu {
            extension_flag: true,
            next_extension_type: 0x85,
            extensions: Bytes::from_static(&[0, 0, 0, 0]),
            ..Gtpu::default()
        })
    };
    let strict = build::Builder::new(registry()).build(
        packet(),
        codec::Context::default(),
        build::Options::default(),
    );
    assert!(strict.is_err(), "a chain that cannot be walked is refused");

    let built = build::Builder::new(registry())
        .build(packet(), codec::Context::default(), permissive())
        .unwrap();
    assert!(
        built
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "build.gtpu_extension")
    );
    let decoded = dissect(built.bytes.clone());
    assert_eq!(
        protocols(&decoded),
        ["ethernet", "ipv4", "udp", "malformed"]
    );
    let malformed = decoded.packet.get::<Malformed>().unwrap();
    assert_eq!(malformed.intended_protocol.as_deref(), Some("gtpu"));
    assert!(malformed.reason.contains("zero length"), "{malformed:?}");
    assert_eq!(malformed.bytes.as_ref(), &built.bytes[GTPU_OFFSET..]);
}

#[test]
fn extension_chains_that_overrun_or_never_end_are_malformed() {
    // the extension claims 8 bytes but the declared length leaves 4
    let mut packet = outer();
    packet.push(Gtpu {
        extension_flag: true,
        next_extension_type: 0x85,
        extensions: Bytes::from_static(&[2, 0, 0, 0]),
        ..Gtpu::default()
    });
    let built = build::Builder::new(registry())
        .build(packet, codec::Context::default(), permissive())
        .unwrap();
    let decoded = dissect(built.bytes);
    assert_eq!(
        protocols(&decoded),
        ["ethernet", "ipv4", "udp", "malformed"]
    );

    // a chain longer than the header cap whose headers never announce an end
    let mut packet = outer();
    packet.push(Gtpu {
        extension_flag: true,
        next_extension_type: 0x85,
        extensions: Bytes::from([1_u8, 0, 0, 0xc0].repeat(40)),
        ..Gtpu::default()
    });
    let built = build::Builder::new(registry())
        .build(packet, codec::Context::default(), permissive())
        .unwrap();
    let decoded = dissect(built.bytes);
    let malformed = decoded.packet.get::<Malformed>().unwrap();
    assert!(malformed.reason.contains("header count"), "{malformed:?}");
}

#[test]
fn other_versions_and_gtp_prime_are_diagnosed_and_kept_opaque() {
    let mut packet = outer();
    packet.push(Gtpu {
        version: 2,
        protocol_type: false,
        ..Gtpu::default()
    });
    packet.push(Raw::new(vec![0x45, 0, 0, 20]));
    let strict = build::Builder::new(registry()).build(
        packet.clone(),
        codec::Context::default(),
        build::Options::default(),
    );
    assert!(strict.is_err());

    let built = build::Builder::new(registry())
        .build(packet, codec::Context::default(), permissive())
        .unwrap();
    let decoded = dissect(built.bytes.clone());
    // an IPv4-looking payload is not dissected under a header this codec does not define
    assert_eq!(
        protocols(&decoded),
        ["ethernet", "ipv4", "udp", "gtpu", "raw"]
    );
    assert_eq!(
        gtpu_codes(&decoded),
        ["decode.gtpu_version", "decode.gtpu_protocol_type"]
    );
    let rebuilt = build::Builder::new(registry())
        .build(decoded.packet, codec::Context::default(), permissive())
        .unwrap();
    assert_eq!(rebuilt.bytes, built.bytes);
}

#[test]
fn flags_that_disagree_with_the_optional_fields_are_diagnosed() {
    let built = build::Builder::new(registry())
        .build(
            tunnel(Gtpu {
                sequence_flag: true,
                npdu_number: 4,
                ..Gtpu::default()
            }),
            codec::Context::default(),
            permissive(),
        )
        .unwrap();
    assert!(
        built
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "build.gtpu_flags"),
        "{:?}",
        built.diagnostics
    );
    let decoded = dissect(built.bytes);
    assert_eq!(gtpu_codes(&decoded), ["decode.gtpu_flags"]);
    // the wire bytes survive untouched
    assert_eq!(decoded.packet.get::<Gtpu>().unwrap().npdu_number, 4);

    // optional fields need a flag to be on the wire at all
    let mut declared = outer();
    declared.push(Gtpu {
        length: WireValue::Exact(2),
        sequence_flag: true,
        ..Gtpu::default()
    });
    let built = build::Builder::new(registry())
        .build(declared, codec::Context::default(), permissive())
        .unwrap();
    let decoded = dissect(built.bytes);
    assert_eq!(
        protocols(&decoded),
        ["ethernet", "ipv4", "udp", "malformed"]
    );
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

#[test]
fn udp_2152_binds_gtpu_and_the_payload_nibble_selects_the_ip_version() {
    let registry = registry();
    let child = |parent: &str, discriminator: u64| {
        registry
            .child_for(parent, Discriminator(discriminator))
            .map(|id: Id| id.as_str())
    };
    assert_eq!(child("udp", 2152), Some("gtpu"));
    assert_eq!(child("gtpu", 0x104), Some("ipv4"));
    assert_eq!(child("gtpu", 0x106), Some("ipv6"));
    assert_eq!(child("gtpu", 0), Some("raw"));
}

fn gtpu_tcp_frame(
    registry: &Arc<packetcraftr_core::registry::Registry>,
    timestamp: SystemTime,
    teid: u32,
    spec: &TcpSpec,
) -> Frame {
    let mut packet = Packet::new();
    packet.push(ipv4([203, 0, 113, 1], [203, 0, 113, 2]));
    packet.push(Udp {
        source_port: 50_000,
        destination_port: 2_152,
        ..Udp::default()
    });
    packet.push(Gtpu {
        teid,
        ..Gtpu::default()
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
        .expect("GTP-U fixture builds");
    Frame::new(timestamp, LinkType::IPV4, built.bytes).expect("GTP-U fixture frame")
}

/// Analysis has no GTP-U encapsulation identifier (adding one would change
/// the versioned output schema), so inner flows that differ only by TEID
/// share a scope and a stream. This pins that known limitation.
/// Flip this test when an identifier lands with the schema that adds it.
#[test]
fn teids_do_not_scope_identical_inner_tcp_tuples() {
    let registry = registry();
    let epoch = SystemTime::UNIX_EPOCH;
    let flow = client_tcp(100, 0, Tcp::SYN, 1_000);
    let frames = [
        gtpu_tcp_frame(&registry, epoch, 1, &flow),
        gtpu_tcp_frame(&registry, epoch + Duration::from_secs(1), 2, &flow),
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
    .expect("GTP-U analysis succeeds");
    assert_eq!(streams, vec![Some(0), Some(0)]);
}
