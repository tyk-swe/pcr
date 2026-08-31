// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
// Test code indexes fixtures and counts by hand; the fail-closed lints are
// for library paths.
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

//! Contracts of the display-filter language: what a path resolves to, what a
//! comparison means at run time, and which mistakes are compile errors.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use packetcraftr_core::filter::{Context, Error, Filter, Options};
use packetcraftr_core::frame::{Frame, LinkType};
use packetcraftr_core::layer::Raw;
use packetcraftr_core::protocol::builtin;
use packetcraftr_core::protocol::link::Ethernet;
use packetcraftr_core::protocol::network::{Ipv4, Ipv6};
use packetcraftr_core::protocol::transport::{Tcp, Udp};
use packetcraftr_core::protocol::tunnel::Vxlan;
use packetcraftr_core::registry::Registry;
use packetcraftr_core::{Packet, build, decode};

const PAYLOAD: &[u8] = b"GET /index HTTP/1.1";

fn registry() -> Arc<Registry> {
    builtin::registry()
}

/// Builds one Ethernet-rooted packet and dissects the exact bytes back.
fn decoded(packet: Packet) -> decode::DecodedPacket {
    let registry = registry();
    let built = build::Builder::new(Arc::clone(&registry))
        .build(packet, build::Context::default(), build::Options::default())
        .unwrap_or_else(|error| panic!("fixture build: {error}"));
    let frame = Frame::new(
        SystemTime::UNIX_EPOCH + Duration::from_secs(123),
        LinkType::ETHERNET,
        built.bytes,
    )
    .expect("fixture frame");
    let mut decoded = decode::Dissector::new(registry)
        .decode(frame, decode::Options::default())
        .unwrap_or_else(|error| panic!("fixture decode: {error}"));
    decoded.frame.interface = Some(4);
    decoded
}

/// Outer `ethernet/ipv4/udp`, a VXLAN tunnel, then an inner
/// `ethernet/ipv4/udp/raw`: every protocol this file filters appears twice.
fn tunnelled() -> decode::DecodedPacket {
    let mut packet = Packet::new();
    packet.push(Ethernet {
        destination: [0x00, 0x01, 0x02, 0x03, 0x04, 0x05],
        source: [0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b],
        ..Ethernet::default()
    });
    packet.push(Ipv4 {
        source: "192.0.2.1".parse().expect("outer source"),
        destination: "198.51.100.2".parse().expect("outer destination"),
        ..Ipv4::default()
    });
    packet.push(Udp {
        source_port: 12_345,
        destination_port: 4_789,
        ..Udp::default()
    });
    packet.push(Vxlan {
        vni: 0x12345,
        ..Vxlan::default()
    });
    packet.push(Ethernet {
        destination: [0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f],
        source: [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        ..Ethernet::default()
    });
    packet.push(Ipv4 {
        source: "10.0.0.1".parse().expect("inner source"),
        destination: "10.0.0.2".parse().expect("inner destination"),
        ..Ipv4::default()
    });
    packet.push(Udp {
        source_port: 40_000,
        destination_port: 9_999,
        ..Udp::default()
    });
    packet.push(Raw::new(PAYLOAD.to_vec()));
    decoded(packet)
}

fn ipv6_tcp() -> decode::DecodedPacket {
    let mut packet = Packet::new();
    packet.push(Ethernet::default());
    packet.push(Ipv6 {
        source: "2001:db8::1".parse().expect("source"),
        destination: "2001:db8:1::2".parse().expect("destination"),
        ..Ipv6::default()
    });
    packet.push(Tcp {
        source_port: 44_000,
        destination_port: 443,
        flags: Tcp::SYN | Tcp::ACK,
        ..Tcp::default()
    });
    packet.push(Raw::new(PAYLOAD.to_vec()));
    decoded(packet)
}

fn context(decoded: &decode::DecodedPacket) -> Context<'_> {
    Context {
        decoded,
        derived: &[],
        number: 7,
        tcp_stream: Some(2),
        udp_stream: Some(3),
    }
}

/// Compiles each source against the built-in registry and asserts whether it
/// matches the fixture.
fn assert_filters(decoded: &decode::DecodedPacket, cases: &[(&str, bool)]) {
    let registry = registry();
    for (source, expected) in cases {
        let filter = Filter::compile(source, &registry, Options::default())
            .unwrap_or_else(|error| panic!("{source} must compile: {error}"));
        let matched = filter
            .matches(&context(decoded))
            .unwrap_or_else(|error| panic!("{source} must evaluate: {error}"));
        assert_eq!(matched, *expected, "{source}");
    }
}

fn assert_rejected(cases: &[(&str, &str)]) {
    let registry = registry();
    for (source, expected) in cases {
        let error = match Filter::compile(source, &registry, Options::default()) {
            Ok(_) => panic!("{source} must not compile"),
            Err(error) => error,
        };
        assert!(
            error.to_string().contains(expected),
            "{source}: {error} does not mention {expected}"
        );
    }
}

#[test]
fn numeric_comparisons_order_values_and_cross_the_signed_boundary() {
    assert_filters(
        &tunnelled(),
        &[
            ("udp.dstport == 9999", true),
            ("udp.dstport != 9999", true),
            ("udp.srcport > 12345", true),
            ("udp.srcport >= 40000", true),
            ("udp.srcport < 12346", true),
            ("udp.srcport <= 12345", true),
            ("udp.dstport > 65535", false),
            ("udp.dstport < 0", false),
            // A negative literal is representable and simply orders below every
            // unsigned port rather than failing to compare.
            ("udp.dstport > -1", true),
            ("udp.dstport == -1", false),
            ("vxlan.vni == 74565", true),
            ("vxlan.vni == 0x12345", true),
        ],
    );
}

#[test]
fn address_comparisons_test_equality_and_prefix_membership() {
    assert_filters(
        &tunnelled(),
        &[
            ("ip.src == 192.0.2.1", true),
            ("ip.src in 192.0.2.0/24", true),
            ("ip.src in 198.51.100.0/24", false),
            ("ip.src in 0.0.0.0/0", true),
            // A prefix describes a set, so `!=` asks for exclusion from it.
            ("ip.src != 192.0.2.0/24", true),
            ("ip.addr in {10.0.0.2, 203.0.113.9}", true),
            ("ip.addr in {203.0.113.9}", false),
        ],
    );
    assert_filters(
        &ipv6_tcp(),
        &[
            ("ipv6.src == 2001:db8::1", true),
            ("ipv6.src in 2001:db8::/32", true),
            ("ipv6.src in 2001:db8:1::/48", false),
            ("ipv6.dst in 2001:db8:1::/48", true),
            ("ipv6.addr in 2001:db8::/32", true),
        ],
    );
}

#[test]
fn byte_and_mac_comparisons_accept_every_spelling_of_a_byte_run() {
    assert_filters(
        &tunnelled(),
        &[
            ("eth.src == 06:07:08:09:0a:0b", true),
            ("eth.addr == 00:01:02:03:04:05", true),
            ("eth.addr == 0a:0b:0c:0d:0e:0f", true),
            ("eth.src == 06:07:08:09:0a:0c", false),
            ("raw.bytes == \"GET /index HTTP/1.1\"", true),
            ("raw.bytes > \"GET\"", true),
            ("ethernet.source[0:2] == 06:07", true),
            ("ethernet.source[1] == 7", true),
            ("ethernet.source[1] == 8", false),
            ("ipv4.source[0:2] == c0:00", true),
        ],
    );
}

#[test]
fn contains_searches_byte_text_and_mac_haystacks() {
    assert_filters(
        &tunnelled(),
        &[
            ("raw.bytes contains \"index\"", true),
            ("raw.bytes contains \"INDEX\"", false),
            ("raw.bytes contains 47:45:54", true),
            ("raw.bytes contains 47:45:55", false),
            // An empty needle is contained by every haystack the path can read,
            // and by nothing the path cannot.
            ("raw.bytes contains \"\"", true),
            ("eth.src contains 07:08", true),
            ("eth.src contains 08:07", false),
        ],
    );
}

#[test]
fn layer_occurrences_select_one_layer_of_a_tunnelled_stack() {
    assert_filters(
        &tunnelled(),
        &[
            ("ipv4#1.source == 192.0.2.1", true),
            ("ipv4#2.source == 10.0.0.1", true),
            ("ipv4#1.source == 10.0.0.1", false),
            ("ipv4#2.source == 192.0.2.1", false),
            // An unqualified path matches any occurrence.
            ("ipv4.source == 10.0.0.1", true),
            ("ip.src == 192.0.2.1", true),
            ("udp#1.dstport == 4789", true),
            ("udp#2.dstport == 9999", true),
            ("ipv4#3", false),
            ("ethernet#2", true),
            ("ipv4#2", true),
        ],
    );
}

#[test]
fn occurrence_selectors_reject_every_malformed_spelling() {
    assert_rejected(&[
        ("ipv4.source#2 == 192.0.2.1", "must follow the protocol"),
        ("ipv4#x.source == 192.0.2.1", "is not a number"),
        ("ipv4#0.source == 192.0.2.1", "occurrences start at 1"),
        ("frame#1.len > 0", "not a protocol layer"),
        ("tcp#1.stream == 2", "not a protocol layer"),
    ]);
}

#[test]
fn flag_paths_read_the_bit_and_bare_field_paths_read_presence() {
    assert_filters(
        &ipv6_tcp(),
        &[
            ("tcp.flags.syn", true),
            ("tcp.flags.ack", true),
            ("tcp.flags.fin", false),
            ("!tcp.flags.fin", true),
            ("tcp.flags.syn == 1", true),
            ("tcp.flags.fin == 0", true),
            // A non-flag bare path asks whether the packet exposes a value.
            ("tcp.options", true),
            ("raw.bytes", true),
            ("udp.dstport", false),
        ],
    );
}

#[test]
fn frame_and_stream_facts_are_reserved_and_read_from_the_caller() {
    let decoded = tunnelled();
    assert_filters(
        &decoded,
        &[
            ("frame.number == 7", true),
            ("frame.time_epoch == 123", true),
            ("frame.interface_id == 4", true),
            ("frame.interface_id == 5", false),
            ("frame.link_type == 1", true),
            ("frame.len > 0", true),
            ("frame.cap_len > 0", true),
            ("tcp.stream == 2", true),
            ("udp.stream == 3", true),
            ("udp.stream == 2", false),
        ],
    );

    let udp_only = Filter::compile("udp.stream == 3", &registry(), Options::default())
        .expect("stream filter compiles");
    let requirements = udp_only.requirements();
    assert!(requirements.stream_index);
    // The aggregate says a conversation index is needed; the per-transport
    // flags say which one, so a caller that indexes one transport at a time
    // prepares only that half.
    assert!(requirements.udp_stream);
    assert!(!requirements.tcp_stream);

    let filter = Filter::compile("frame.time_epoch >= 0", &registry(), Options::default())
        .expect("timestamp filter compiles");
    assert!(filter.requirements().timestamp);
    assert!(!filter.requirements().stream_index);
    let mut undated = decoded;
    undated.frame.timestamp = None;
    assert!(matches!(
        filter.matches(&context(&undated)),
        Err(Error::TimestampUnavailable)
    ));
}

#[test]
fn impossible_paths_slices_and_literals_are_compile_errors() {
    assert_rejected(&[
        ("ipv4.unknown == 1", "unknown"),
        ("nosuchproto", "unknown"),
        ("ipv4.source == 7", "cannot be compared"),
        ("ipv4.source > 192.0.2.0/24", "prefix"),
        ("tcp.srcport contains \"x\"", "cannot be compared"),
        ("udp.dstport[0] == 1", "cannot be sliced"),
        ("frame.len[0] == 1", "cannot be sliced"),
        ("ethernet.source[3:1] == 00", "precedes start"),
    ]);
}
