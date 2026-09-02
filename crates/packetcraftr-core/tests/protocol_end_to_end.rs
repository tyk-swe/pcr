// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
// Test code indexes fixtures and counts by hand; the fail-closed lints are
// for library paths.
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::collections::BTreeSet;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use packetcraftr_core::diagnostic::{
    CHECKSUM_FAILURE_CODES, GRE_CHECKSUM, ICMPV4_CHECKSUM, ICMPV6_CHECKSUM, IGMP_CHECKSUM,
    IPV4_CHECKSUM, SCTP_CHECKSUM, TCP_CHECKSUM, UDP_CHECKSUM,
};
use packetcraftr_core::filter::{Context as FilterContext, Filter};
use packetcraftr_core::frame::{Frame, LinkType};
use packetcraftr_core::layer::{Layer, Malformed, Raw};
use packetcraftr_core::protocol::application::Dns;
use packetcraftr_core::protocol::builtin;
use packetcraftr_core::protocol::capture::{BsdLoop, BsdNull, LinuxSll, LinuxSll2};
use packetcraftr_core::protocol::gre::Gre;
use packetcraftr_core::protocol::icmp::{Icmpv4, Icmpv6};
use packetcraftr_core::protocol::ipv6::{
    DestinationOptions, Fragment, HopByHop, SegmentRoutingHeader,
};
use packetcraftr_core::protocol::link::{Arp, Ethernet, Llc, Snap, Vlan};
use packetcraftr_core::protocol::network::{Igmp, Ipv4, Ipv6};
use packetcraftr_core::protocol::transport::{Sctp, Tcp, Udp};
use packetcraftr_core::protocol::tunnel::{
    Ah, Erspan, Esp, Geneve, L2tpv3, Mpls, Ppp, Pppoe, Vxlan,
};
use packetcraftr_core::registry::Registry;
use packetcraftr_core::{Packet, build, decode};

fn registry() -> Arc<Registry> {
    builtin::registry()
}

/// A spare link type these tests bind to an explicit root protocol so a
/// dissection can start below the capture layer.
const ROOT_LINK_TYPE: LinkType = LinkType(u32::MAX);

fn rooted_registry(root: &'static str) -> Arc<Registry> {
    Arc::new(
        builtin::registry_with(|builder| {
            builder.bind_link_type(ROOT_LINK_TYPE.0, root)?;
            Ok(())
        })
        .unwrap_or_else(|error| panic!("{root} root binding: {error}")),
    )
}

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
        .build(packet, build::Context::default(), build::Options::default())
        .unwrap_or_else(|error| panic!("{root} build: {error}"));
    let decoded = decode_from_root(&registry, built.bytes.clone(), decode::Options::default())
        .unwrap_or_else(|error| panic!("{root} decode: {error}"));
    let rebuilt = builder
        .build(
            decoded.packet.clone(),
            build::Context::default(),
            build::Options::default(),
        )
        .unwrap_or_else(|error| panic!("{root} rebuild: {error}"));
    assert_eq!(rebuilt.bytes, built.bytes, "{root} exact round trip");
    (built, decoded)
}

fn ipv4(source: [u8; 4], destination: [u8; 4]) -> Ipv4 {
    Ipv4 {
        source: Ipv4Addr::from(source),
        destination: Ipv4Addr::from(destination),
        ..Ipv4::default()
    }
}

fn ipv6(source: &str, destination: &str) -> Ipv6 {
    Ipv6 {
        source: source.parse().expect("source address"),
        destination: destination.parse().expect("destination address"),
        ..Ipv6::default()
    }
}

fn ipv4_source_route(option: u8, pointer: u8, addresses: &[Ipv4Addr]) -> Bytes {
    let length = 3usize
        .checked_add(addresses.len().checked_mul(4).expect("route length fits"))
        .expect("route length fits");
    let mut bytes = Vec::with_capacity(length);
    bytes.push(option);
    bytes.push(u8::try_from(length).expect("IPv4 option length fits u8"));
    bytes.push(pointer);
    for address in addresses {
        bytes.extend_from_slice(&address.octets());
    }
    Bytes::from(bytes)
}

fn source_routed_ipv4(option: u8, pointer: u8, addresses: &[Ipv4Addr]) -> Ipv4 {
    Ipv4 {
        source: Ipv4Addr::new(192, 0, 2, 10),
        destination: Ipv4Addr::new(203, 0, 113, 10),
        options: ipv4_source_route(option, pointer, addresses),
        ..Ipv4::default()
    }
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

fn known_udp() -> Udp {
    Udp {
        source_port: 12_345,
        destination_port: 53,
        ..Udp::default()
    }
}

#[test]
fn ipv4_source_route_decode_accepts_known_transport_checksums() {
    let vectors = [
        (
            "tcp",
            "decode.tcp_checksum",
            "47000030123400004006cc3bc000020acb00710a830704cb007114003039005000000001000000005002faf086480000",
        ),
        (
            "udp",
            "decode.udp_checksum",
            "4700002c123500004011cc33c000020acb00710a830704cb00711400303900350010902a5043522d4c535252",
        ),
    ];

    for (transport, checksum_code, vector) in vectors {
        let bytes =
            packetcraftr_core::protocol::raw::parse_hex(vector).expect("known vector is valid hex");
        let frame = Frame::new(SystemTime::UNIX_EPOCH, LinkType::RAW, bytes)
            .expect("known DLT_RAW vector is a valid frame");
        let decoded = decode::Dissector::new(registry())
            .decode(frame, decode::Options::default())
            .expect("known DLT_RAW vector decodes");

        assert!(
            !decoded
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == checksum_code),
            "{transport} checksum diagnostics: {:?}",
            decoded.diagnostics
        );
    }
}

#[test]
fn ipv4_source_route_encode_matches_known_transport_checksums() {
    let registry = registry();
    let builder = build::Builder::new(Arc::clone(&registry));
    let final_destination = Ipv4Addr::new(203, 0, 113, 20);

    let mut tcp_packet = Packet::new();
    tcp_packet.push(Ipv4 {
        identification: 0x1234,
        ..source_routed_ipv4(131, 4, &[final_destination])
    });
    tcp_packet.push(known_tcp());
    let tcp = builder
        .build(
            tcp_packet,
            build::Context::default(),
            build::Options::default(),
        )
        .expect("known TCP source-route packet builds");
    assert_eq!(
        tcp.packet
            .get::<Tcp>()
            .and_then(|tcp| tcp.checksum.exact())
            .copied(),
        Some(0x8648)
    );

    let mut udp_packet = Packet::new();
    udp_packet.push(Ipv4 {
        identification: 0x1235,
        ..source_routed_ipv4(131, 4, &[final_destination])
    });
    udp_packet.push(known_udp());
    udp_packet.push(Raw::new(b"PCR-LSRR".to_vec()));
    let udp = builder
        .build(
            udp_packet,
            build::Context::default(),
            build::Options {
                mode: build::Mode::Permissive,
                ..build::Options::default()
            },
        )
        .expect("known UDP source-route packet builds");
    assert_eq!(
        udp.packet
            .get::<Udp>()
            .and_then(|udp| udp.checksum.exact())
            .copied(),
        Some(0x902a)
    );
}

fn assert_remaining_source_route_checksums(
    builder: &build::Builder,
    first_remaining: Ipv4Addr,
    final_destination: Ipv4Addr,
) {
    let mut tcp_multiple_lsrr = Packet::new();
    tcp_multiple_lsrr.push(source_routed_ipv4(
        131,
        4,
        &[first_remaining, final_destination],
    ));
    tcp_multiple_lsrr.push(known_tcp());
    let tcp_multiple_lsrr = builder
        .build(
            tcp_multiple_lsrr,
            build::Context::default(),
            build::Options::default(),
        )
        .expect("TCP LSRR with multiple remaining addresses builds");
    assert_eq!(
        tcp_multiple_lsrr
            .packet
            .get::<Tcp>()
            .and_then(|tcp| tcp.checksum.exact())
            .copied(),
        Some(0x863e)
    );

    let mut udp_multiple_ssrr = Packet::new();
    udp_multiple_ssrr.push(source_routed_ipv4(
        137,
        4,
        &[first_remaining, final_destination],
    ));
    udp_multiple_ssrr.push(known_udp());
    udp_multiple_ssrr.push(Raw::new(b"PCR-LSRR".to_vec()));
    let udp_multiple_ssrr = builder
        .build(
            udp_multiple_ssrr,
            build::Context::default(),
            build::Options {
                mode: build::Mode::Permissive,
                ..build::Options::default()
            },
        )
        .expect("UDP SSRR with multiple remaining addresses builds");
    assert_eq!(
        udp_multiple_ssrr
            .packet
            .get::<Udp>()
            .and_then(|udp| udp.checksum.exact())
            .copied(),
        Some(0x9020)
    );
}

fn assert_completed_source_route_checksums(builder: &build::Builder, first_remaining: Ipv4Addr) {
    let mut tcp_completed_ssrr = Packet::new();
    tcp_completed_ssrr.push(source_routed_ipv4(137, 8, &[first_remaining]));
    tcp_completed_ssrr.push(known_tcp());
    let tcp_completed_ssrr = builder
        .build(
            tcp_completed_ssrr,
            build::Context::default(),
            build::Options::default(),
        )
        .expect("TCP completed SSRR builds");
    assert_eq!(
        tcp_completed_ssrr
            .packet
            .get::<Tcp>()
            .and_then(|tcp| tcp.checksum.exact())
            .copied(),
        Some(0x8652)
    );

    let mut udp_completed_lsrr = Packet::new();
    udp_completed_lsrr.push(source_routed_ipv4(131, 8, &[first_remaining]));
    udp_completed_lsrr.push(known_udp());
    udp_completed_lsrr.push(Raw::new(b"PCR-LSRR".to_vec()));
    let udp_completed_lsrr = builder
        .build(
            udp_completed_lsrr,
            build::Context::default(),
            build::Options {
                mode: build::Mode::Permissive,
                ..build::Options::default()
            },
        )
        .expect("UDP completed LSRR builds");
    assert_eq!(
        udp_completed_lsrr
            .packet
            .get::<Udp>()
            .and_then(|udp| udp.checksum.exact())
            .copied(),
        Some(0x9034)
    );
}

#[test]
fn ipv4_source_route_transport_checksums_cover_route_states_and_nearest_envelope() {
    let registry = registry();
    let builder = build::Builder::new(Arc::clone(&registry));
    let first_remaining = Ipv4Addr::new(203, 0, 113, 20);
    let final_destination = Ipv4Addr::new(203, 0, 113, 30);
    assert_remaining_source_route_checksums(&builder, first_remaining, final_destination);
    assert_completed_source_route_checksums(&builder, first_remaining);

    let mut nested = Packet::new();
    nested.push(Ipv4 {
        source: Ipv4Addr::new(10, 0, 0, 1),
        destination: Ipv4Addr::new(10, 0, 0, 2),
        options: ipv4_source_route(131, 4, &[Ipv4Addr::new(10, 0, 0, 9)]),
        ..Ipv4::default()
    });
    nested.push(source_routed_ipv4(137, 8, &[first_remaining]));
    nested.push(known_tcp());
    let nested = builder
        .build(nested, build::Context::default(), build::Options::default())
        .expect("nested IPv4 source-route packet builds");
    assert_eq!(
        nested
            .packet
            .get::<Tcp>()
            .and_then(|tcp| tcp.checksum.exact())
            .copied(),
        Some(0x8652),
        "the completed nearest IPv4 route must beat the outer remaining route"
    );
    let decoded = decode_from_root(
        &rooted_registry("ipv4"),
        nested.bytes,
        decode::Options::default(),
    )
    .expect("nested IPv4 source-route packet decodes");
    assert!(
        !decoded
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "decode.tcp_checksum"),
        "nested TCP checksum diagnostics: {:?}",
        decoded.diagnostics
    );
}

fn filter_fixture() -> (Arc<Registry>, decode::DecodedPacket) {
    let mut packet = Packet::new();
    packet.push(Ethernet {
        destination: [0, 1, 2, 3, 4, 5],
        source: [6, 7, 8, 9, 10, 11],
        ..Ethernet::default()
    });
    packet.push(Ipv4 {
        options: Bytes::from_static(&[1, 1, 0]),
        ..ipv4([192, 0, 2, 1], [198, 51, 100, 2])
    });
    packet.push(Udp {
        source_port: 12_345,
        destination_port: 9_999,
        ..Udp::default()
    });
    packet.push(Raw::new(b"hello-filter".to_vec()));

    let (built, mut decoded) = round_trip(packet, "ethernet");
    assert_eq!(decoded.packet.len(), 4);
    assert!(
        built
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "build.ipv4_options_padded")
    );
    decoded.frame.timestamp = Some(SystemTime::UNIX_EPOCH + Duration::from_secs(123));
    decoded.frame.interface = Some(4);
    (registry(), decoded)
}

fn assert_negative_filters(registry: &Registry, decoded: &decode::DecodedPacket) {
    for source in [
        "tcp.dstport == 80",
        "tcp.flags.syn",
        "ipv4#2",
        "ipv4.destination == 203.0.113.1",
        "raw.bytes contains \"absent\"",
        "frame.interface_id == 5",
        "udp.stream == 4",
    ] {
        let filter = Filter::compile(
            source,
            registry,
            packetcraftr_core::filter::Options::default(),
        )
        .expect("valid negative filter");
        assert!(
            !filter
                .matches(&FilterContext {
                    decoded,
                    derived: &[],
                    number: 7,
                    tcp_stream: None,
                    udp_stream: Some(3),
                })
                .expect("timestamp is available"),
            "{source}"
        );
    }
}

fn assert_invalid_filters(registry: &Registry) {
    assert!(
        Filter::compile(
            "ipv4.unknown == 1",
            registry,
            packetcraftr_core::filter::Options::default(),
        )
        .is_err()
    );

    let overflowed_index = format!("ethernet.source[{}] == 00", usize::MAX);
    let error = Filter::compile(
        &overflowed_index,
        registry,
        packetcraftr_core::filter::Options::default(),
    )
    .expect_err("a single-byte slice must have a representable exclusive end");
    assert!(
        error
            .to_string()
            .contains("has no representable exclusive end")
    );
}

#[test]
fn ethernet_ipv4_udp_raw_round_trip_exercises_filter_language() {
    let (registry, mut decoded) = filter_fixture();
    let source = concat!(
        "ethernet && ipv4.source in 192.0.2.0/24 && ",
        "udp.dstport in {53, 9999} && raw.bytes contains \"filter\" && ",
        "ethernet.source[0:3] == 06:07:08 && frame.number == 7 && ",
        "frame.time_epoch == 123 && frame.interface_id == 4 && udp.stream == 3"
    );
    let filter = Filter::compile(
        source,
        &registry,
        packetcraftr_core::filter::Options::default(),
    )
    .expect("valid filter");
    let requirements = filter.requirements();
    assert!(requirements.stream_index);
    assert!(!requirements.tcp_stream);
    assert!(requirements.udp_stream);
    assert!(
        filter
            .matches(&FilterContext {
                decoded: &decoded,
                derived: &[],
                number: 7,
                tcp_stream: None,
                udp_stream: Some(3),
            })
            .expect("timestamp is available")
    );

    decoded.frame.timestamp = None;
    assert!(matches!(
        filter.matches(&FilterContext {
            decoded: &decoded,
            derived: &[],
            number: 9,
            tcp_stream: None,
            udp_stream: Some(3),
        }),
        Err(packetcraftr_core::filter::Error::TimestampUnavailable)
    ));

    assert_negative_filters(&registry, &decoded);
    assert_invalid_filters(&registry);
}

#[test]
fn ipv6_extensions_tcp_and_segment_routing_round_trip() {
    let mut extension_packet = Packet::new();
    extension_packet.push(ipv6("2001:db8::1", "2001:db8::2"));
    extension_packet.push(HopByHop {
        options: Bytes::from_static(&[0, 0, 1]),
        ..HopByHop::default()
    });
    extension_packet.push(DestinationOptions {
        options: Bytes::from_static(&[1, 0]),
        ..DestinationOptions::default()
    });
    extension_packet.push(Fragment::default());
    extension_packet.push(Tcp {
        source_port: 40_000,
        destination_port: 443,
        sequence: 99,
        flags: Tcp::SYN | Tcp::ACK,
        options: Bytes::from_static(&[1, 1, 1]),
        ..Tcp::default()
    });
    extension_packet.push(Raw::new(b"tls".to_vec()));
    let (built, decoded) = round_trip(extension_packet, "ipv6");
    assert_eq!(decoded.packet.len(), 6);
    assert!(
        built
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "build.tcp_options_padded")
    );

    let final_destination: Ipv6Addr = "2001:db8::99".parse().expect("segment");
    let active: Ipv6Addr = "2001:db8::2".parse().expect("segment");
    let mut srh_packet = Packet::new();
    srh_packet.push(ipv6("2001:db8::1", "2001:db8::2"));
    srh_packet.push(SegmentRoutingHeader {
        segments: vec![active, final_destination],
        ..SegmentRoutingHeader::default()
    });
    srh_packet.push(Udp {
        source_port: 5_000,
        destination_port: 5_001,
        ..Udp::default()
    });
    srh_packet.push(Raw::new(vec![1, 2, 3, 4]));
    let (_, decoded) = round_trip(srh_packet, "ipv6");
    assert_eq!(
        decoded
            .packet
            .get::<SegmentRoutingHeader>()
            .expect("SRH")
            .segments
            .len(),
        2
    );
}

#[test]
fn link_capture_and_raw_ip_roots_round_trip() {
    let mut llc = Packet::new();
    llc.push(Ethernet::default());
    llc.push(Llc::default());
    llc.push(Snap::default());
    llc.push(ipv4([10, 0, 0, 1], [10, 0, 0, 2]));
    llc.push(Icmpv4::default());
    let (_, decoded) = round_trip(llc, "ethernet");
    assert!(decoded.packet.get::<Llc>().is_some());
    assert!(decoded.packet.get::<Snap>().is_some());

    let mut vlan = Packet::new();
    vlan.push(Ethernet::default());
    vlan.push(Vlan {
        priority: 7,
        drop_eligible: true,
        vlan_id: 4094,
        ..Vlan::default()
    });
    vlan.push(Arp {
        sender_protocol: Ipv4Addr::new(192, 0, 2, 10),
        target_protocol: Ipv4Addr::new(192, 0, 2, 1),
        ..Arp::default()
    });
    let (_, decoded) = round_trip(vlan, "ethernet");
    assert_eq!(
        decoded.packet.get::<Vlan>().map(|tag| tag.vlan_id),
        Some(4094)
    );

    let roots: Vec<(Box<dyn Layer>, &str)> = vec![
        (Box::new(BsdNull::default()), "bsd_null"),
        (Box::new(BsdLoop::default()), "bsd_loop"),
        (Box::new(LinuxSll::default()), "linux_sll"),
        (Box::new(LinuxSll2::default()), "linux_sll2"),
    ];
    for (root, name) in roots {
        let mut packet = Packet::new();
        packet.push_boxed(root);
        packet.push(ipv4([203, 0, 113, 1], [203, 0, 113, 2]));
        packet.push(Icmpv4::default());
        let (_, decoded) = round_trip(packet, name);
        assert_eq!(decoded.packet.len(), 3, "{name}");
    }

    let mut ip = Packet::new();
    ip.push(ipv4([192, 0, 2, 1], [198, 51, 100, 1]));
    ip.push(Icmpv4::default());
    let (built, _) = round_trip(ip, "ipv4");
    for link_type in [LinkType::RAW, LinkType::BSD_RAW] {
        let frame =
            Frame::new(SystemTime::UNIX_EPOCH, link_type, built.bytes.clone()).expect("frame");
        let decoded = decode::Dissector::new(registry())
            .decode(frame, decode::Options::default())
            .expect("raw-IP root should sniff version");
        assert!(decoded.packet.get::<Ipv4>().is_some());
    }
}

fn assert_overlay_tunnels_round_trip() {
    let mut vxlan = Packet::new();
    vxlan.push(ipv4([192, 0, 2, 1], [192, 0, 2, 2]));
    vxlan.push(Udp {
        source_port: 50_000,
        destination_port: 4_789,
        ..Udp::default()
    });
    vxlan.push(Vxlan {
        vni: 0x12345,
        ..Vxlan::default()
    });
    vxlan.push(Ethernet::default());
    vxlan.push(ipv4([10, 0, 0, 1], [10, 0, 0, 2]));
    vxlan.push(Icmpv4::default());
    let (_, decoded) = round_trip(vxlan, "ipv4");
    assert_eq!(
        decoded.packet.get::<Vxlan>().map(|header| header.vni),
        Some(0x12345)
    );

    let mut geneve = Packet::new();
    geneve.push(ipv6("2001:db8::1", "2001:db8::2"));
    geneve.push(Udp {
        source_port: 50_000,
        destination_port: 6_081,
        ..Udp::default()
    });
    geneve.push(Geneve {
        vni: 77,
        ..Geneve::default()
    });
    geneve.push(ipv4([172, 16, 0, 1], [172, 16, 0, 2]));
    geneve.push(Icmpv4::default());
    let (_, decoded) = round_trip(geneve, "ipv6");
    assert_eq!(
        decoded.packet.get::<Geneve>().map(|header| header.vni),
        Some(77)
    );

    let mut gre = Packet::new();
    gre.push(ipv4([198, 51, 100, 1], [198, 51, 100, 2]));
    gre.push(Gre {
        checksum: Some(Default::default()),
        key: Some(7),
        sequence: Some(9),
        ..Gre::default()
    });
    gre.push(Erspan::default());
    gre.push(Ethernet::default());
    gre.push(Arp::default());
    let (_, decoded) = round_trip(gre, "ipv4");
    assert_eq!(
        decoded.packet.get::<Gre>().and_then(|header| header.key),
        Some(7)
    );
    assert!(decoded.packet.get::<Erspan>().is_some());
}

#[test]
fn overlay_and_security_tunnel_stacks_round_trip() {
    assert_overlay_tunnels_round_trip();
    let mut mpls = Packet::new();
    mpls.push(Ethernet::default());
    mpls.push(Mpls {
        label: 16,
        bottom_of_stack: false,
        ..Mpls::default()
    });
    mpls.push(Mpls {
        label: 32,
        ..Mpls::default()
    });
    mpls.push(ipv4([10, 1, 0, 1], [10, 1, 0, 2]));
    mpls.push(Icmpv4::default());
    let (_, decoded) = round_trip(mpls, "ethernet");
    assert_eq!(
        decoded
            .packet
            .iter()
            .filter(|layer| layer.as_any().is::<Mpls>())
            .count(),
        2
    );

    let mut pppoe = Packet::new();
    pppoe.push(Ethernet::default());
    pppoe.push(Pppoe {
        session_id: 4,
        ..Pppoe::default()
    });
    pppoe.push(Ppp::default());
    pppoe.push(ipv6("2001:db8:1::1", "2001:db8:1::2"));
    pppoe.push(Icmpv6::default());
    let (_, decoded) = round_trip(pppoe, "ethernet");
    assert!(decoded.packet.get::<Ppp>().is_some());

    let mut ah = Packet::new();
    ah.push(ipv4([192, 0, 2, 1], [192, 0, 2, 2]));
    ah.push(Ah::default());
    ah.push(Udp {
        source_port: 10,
        destination_port: 11,
        ..Udp::default()
    });
    ah.push(Raw::new(vec![1, 2, 3]));
    let (_, decoded) = round_trip(ah, "ipv4");
    assert!(decoded.packet.get::<Ah>().is_some());

    let mut esp = Packet::new();
    esp.push(ipv4([192, 0, 2, 1], [192, 0, 2, 2]));
    esp.push(Esp::default());
    esp.push(Raw::new(vec![0xaa, 0xbb, 0, 59]));
    let (_, decoded) = round_trip(esp, "ipv4");
    assert!(decoded.packet.get::<Esp>().is_some());

    let mut l2tp = Packet::new();
    l2tp.push(ipv4([192, 0, 2, 1], [192, 0, 2, 2]));
    l2tp.push(L2tpv3 { session_id: 42 });
    l2tp.push(Raw::new(vec![1, 2, 3, 4]));
    let (_, decoded) = round_trip(l2tp, "ipv4");
    assert_eq!(
        decoded
            .packet
            .get::<L2tpv3>()
            .map(|header| header.session_id),
        Some(42)
    );
}

#[test]
fn sctp_dns_and_malformed_inputs_cover_bounded_parsers() {
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
    let dns = Dns::from_wire(query.clone()).expect("valid DNS query");
    assert_eq!(dns.id, 0x1234);
    assert_eq!(dns.qnames, ["www.example.com."]);
    assert_eq!(dns.qtypes, [1]);
    assert_eq!(dns.wire().as_ref(), query);
    let mut packet = Packet::new();
    packet.push(ipv4([192, 0, 2, 1], [8, 8, 8, 8]));
    packet.push(Udp::default());
    packet.push(dns.clone());
    let (_, decoded) = round_trip(packet, "ipv4");
    assert_eq!(decoded.packet.get::<Dns>().map(|dns| dns.id), Some(0x1234));

    assert!(Dns::from_wire(vec![0; 11]).is_err());
    let mut too_many = vec![0; 12];
    too_many[4..6].copy_from_slice(&65_u16.to_be_bytes());
    assert!(Dns::from_wire(too_many).is_err());
    let mut pointer_loop = vec![0; 18];
    pointer_loop[4..6].copy_from_slice(&1_u16.to_be_bytes());
    pointer_loop[12] = 0xc0;
    pointer_loop[13] = 12;
    assert!(Dns::from_wire(pointer_loop).is_err());

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
fn typed_child_without_payload_is_preserved_as_malformed() {
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

fn assert_ipv4_strict_and_permissive_modes(builder: &build::Builder) {
    let mut invalid = Packet::new();
    invalid.push(Ipv4 {
        reserved_flag: true,
        ..ipv4([192, 0, 2, 1], [192, 0, 2, 2])
    });
    invalid.push(Icmpv4::default());
    assert!(
        builder
            .build(
                invalid.clone(),
                build::Context::default(),
                build::Options::default()
            )
            .is_err()
    );
    let permissive = builder
        .build(
            invalid,
            build::Context::default(),
            build::Options {
                mode: build::Mode::Permissive,
                ..build::Options::default()
            },
        )
        .expect("permissive build preserves reserved bit with warning");
    assert!(permissive.requires_live_opt_in);
    assert!(
        permissive
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "build.ipv4_reserved_flag")
    );
}

#[test]
fn strict_and_permissive_modes_distinguish_noncanonical_wire_requests() {
    let registry = registry();
    let builder = build::Builder::new(registry);
    assert_ipv4_strict_and_permissive_modes(&builder);
    let mut bad_vxlan = Packet::new();
    bad_vxlan.push(Vxlan {
        flags: 0,
        ..Vxlan::default()
    });
    bad_vxlan.push(Ethernet::default());
    assert!(
        builder
            .build(
                bad_vxlan.clone(),
                build::Context::default(),
                build::Options::default()
            )
            .is_err()
    );
    assert!(
        builder
            .build(
                bad_vxlan,
                build::Context::default(),
                build::Options {
                    mode: build::Mode::Permissive,
                    ..build::Options::default()
                },
            )
            .is_ok()
    );

    let mut bad_geneve = Packet::new();
    bad_geneve.push(Geneve {
        options: Bytes::from_static(&[1, 2, 3]),
        ..Geneve::default()
    });
    bad_geneve.push(Raw::new(vec![1]));
    assert!(
        builder
            .build(
                bad_geneve,
                build::Context::default(),
                build::Options::default()
            )
            .is_err()
    );

    let mut bad_arp = Packet::new();
    bad_arp.push(Arp {
        hardware_type: 2,
        ..Arp::default()
    });
    assert!(
        builder
            .build(
                bad_arp.clone(),
                build::Context::default(),
                build::Options::default()
            )
            .is_err()
    );
    assert!(
        builder
            .build(
                bad_arp,
                build::Context::default(),
                build::Options {
                    mode: build::Mode::Permissive,
                    ..build::Options::default()
                },
            )
            .is_ok()
    );
}

#[test]
fn corrupted_builtin_checksums_report_integrity_failures() {
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
        (GRE_CHECKSUM, "ipv4", gre, 28),
    ];

    let registry = registry();
    let builder = build::Builder::new(Arc::clone(&registry));
    let mut observed = BTreeSet::new();

    for (code, root, packet, corrupted_offset) in cases {
        let built = builder
            .build(packet, build::Context::default(), build::Options::default())
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

#[test]
fn field_aliases_resolve_through_reflection_construction_and_filters_alike() {
    use std::collections::BTreeMap;

    use packetcraftr_core::field::FieldValue;

    let registry = registry();

    // Reflection accepts an alias wherever it accepts the canonical name, so a
    // template axis or fuzz target may name `dst`.
    let mut ipv4 = Ipv4 {
        source: Ipv4Addr::new(192, 0, 2, 1),
        destination: Ipv4Addr::new(198, 51, 100, 2),
        ..Ipv4::default()
    };
    assert_eq!(ipv4.field("dst"), ipv4.field("destination"));
    ipv4.set_field("dst", FieldValue::Ipv4(Ipv4Addr::new(203, 0, 113, 9)))
        .expect("an alias is settable");
    assert_eq!(ipv4.destination, Ipv4Addr::new(203, 0, 113, 9));

    // Construction accepts the alias too, and refuses both spellings at once
    // rather than silently dropping one value.
    let codec = registry.codec_named("ipv4").expect("IPv4 codec");
    let mut fields = BTreeMap::new();
    fields.insert(
        "dst".to_owned(),
        FieldValue::Ipv4(Ipv4Addr::new(198, 51, 100, 7)),
    );
    let built = codec.make_layer(&fields).expect("alias-only construction");
    assert_eq!(
        built.field("destination"),
        Some(FieldValue::Ipv4(Ipv4Addr::new(198, 51, 100, 7)))
    );
    fields.insert(
        "destination".to_owned(),
        FieldValue::Ipv4(Ipv4Addr::new(198, 51, 100, 8)),
    );
    let conflict = codec
        .make_layer(&fields)
        .expect_err("both spellings of one field are refused");
    assert!(
        conflict.to_string().contains("both dst and destination"),
        "{conflict}"
    );

    // Aliases stay out of the published field list and the canonical filter
    // namespace: `ip.src` keeps resolving through its registered binding.
    let schema = registry.schema("ipv4").expect("IPv4 schema");
    assert!(
        schema.fields.iter().all(|field| field.name != "dst"),
        "aliases must not appear as published fields"
    );
    for path in ["ip.src", "ipv4.source"] {
        Filter::compile(
            &format!("{path} == 192.0.2.1"),
            &registry,
            packetcraftr_core::filter::Options::default(),
        )
        .unwrap_or_else(|error| panic!("{path}: {error}"));
    }
}

#[test]
fn pseudo_header_failures_name_the_calling_protocol() {
    let registry = registry();
    let builder = build::Builder::new(Arc::clone(&registry));
    for (protocol, layer) in [
        ("tcp", Box::new(Tcp::default()) as Box<dyn Layer>),
        ("udp", Box::new(Udp::default())),
        ("icmpv6", Box::new(Icmpv6::default())),
    ] {
        let mut packet = Packet::new();
        packet.push_boxed(layer);
        let error = builder
            .clone()
            .build(packet, build::Context::default(), build::Options::default())
            .err()
            .unwrap_or_else(|| panic!("{protocol} without an IP envelope must not build"));
        let message = error.to_string();
        assert!(
            message.contains(&format!("invalid {protocol} layer")),
            "{protocol}: {message}"
        );
    }
}
