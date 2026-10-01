// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod common;

use common::packets::{ROOT_LINK_TYPE, ipv4, ipv6, rooted_registry};
use common::registry;
use std::collections::BTreeSet;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use packetcraftr_core::diagnostic::{
    CHECKSUM_FAILURE_CODES, Diagnostic, GRE_CHECKSUM, ICMPV4_CHECKSUM, ICMPV6_CHECKSUM,
    IGMP_CHECKSUM, IPV4_CHECKSUM, SCTP_CHECKSUM, Severity, TCP_CHECKSUM, UDP_CHECKSUM,
    VRRP_CHECKSUM,
};
use packetcraftr_core::filter::{Context as FilterContext, Filter};
use packetcraftr_core::frame::{Frame, LinkType};
use packetcraftr_core::layer::{Layer, Malformed, Padding, Raw};
use packetcraftr_core::protocol::application::dns::Dns;
use packetcraftr_core::protocol::capture::{BsdLoop, BsdNull, LinuxSll, LinuxSll2};
use packetcraftr_core::protocol::link::{Arp, Ethernet, Llc, Snap, Vlan};
use packetcraftr_core::protocol::network::{
    DestinationOptions, Fragment, HopByHop, Icmpv4, Icmpv6, Igmp, Ipv4, Ipv6, SegmentRoutingHeader,
    Vrrp,
};
use packetcraftr_core::protocol::transport::{Sctp, Tcp, TcpOption, Udp};
use packetcraftr_core::protocol::tunnel::{
    Ah, Erspan, Esp, Geneve, Gre, L2tpv3, Mpls, Ppp, Pppoe, Vxlan,
};
use packetcraftr_core::registry::Registry;
use packetcraftr_core::{build, codec, decode, field::WireValue, packet::Packet};

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
        let bytes = packetcraftr_core::layer::parse_hex(vector).expect("known vector is valid hex");
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
            codec::Context::default(),
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
            codec::Context::default(),
            build::Options {
                mode: codec::Mode::Permissive,
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
            codec::Context::default(),
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
            codec::Context::default(),
            build::Options {
                mode: codec::Mode::Permissive,
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
            codec::Context::default(),
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
            codec::Context::default(),
            build::Options {
                mode: codec::Mode::Permissive,
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
        .build(nested, codec::Context::default(), build::Options::default())
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
            packetcraftr_core::filter::Limits::default(),
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
            packetcraftr_core::filter::Limits::default(),
        )
        .is_err()
    );

    let overflowed_index = format!("ethernet.source[{}] == 00", usize::MAX);
    let error = Filter::compile(
        &overflowed_index,
        registry,
        packetcraftr_core::filter::Limits::default(),
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
        packetcraftr_core::filter::Limits::default(),
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
        options: vec![TcpOption::Nop; 3],
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

#[test]
fn ipv6_option_headers_keep_a_raw_next_header_raw() {
    for raw_first in [true, false] {
        let mut packet = Packet::new();
        packet.push(ipv6("2001:db8::1", "2001:db8::2"));
        let raw = WireValue::Raw(Bytes::from_static(&[59]));
        if raw_first {
            packet.push(HopByHop {
                next_header: raw.clone(),
                ..HopByHop::default()
            });
        } else {
            packet.push(DestinationOptions {
                next_header: raw.clone(),
                ..DestinationOptions::default()
            });
        }
        let built = build::Builder::new(rooted_registry("ipv6"))
            .build(
                packet,
                codec::Context::default(),
                build::Options {
                    mode: codec::Mode::Permissive,
                    ..build::Options::default()
                },
            )
            .expect("a raw Next Header builds permissively");
        let next_header = built
            .packet
            .iter()
            .nth(1)
            .and_then(|layer| layer.field("next_header"));
        assert_eq!(
            next_header,
            Some(packetcraftr_core::field::FieldValue::Bytes(
                Bytes::from_static(&[59])
            )),
            "raw_first={raw_first}"
        );
        assert_eq!(built.bytes[40], 59);
    }
}

#[test]
fn ipv6_option_headers_build_up_to_the_extension_length_field_limit() {
    let build = |options: usize, hop_by_hop: bool| {
        let mut packet = Packet::new();
        packet.push(ipv6("2001:db8::1", "2001:db8::2"));
        let options = Bytes::from(vec![1_u8; options]);
        if hop_by_hop {
            packet.push(HopByHop {
                options,
                ..HopByHop::default()
            });
        } else {
            packet.push(DestinationOptions {
                options,
                ..DestinationOptions::default()
            });
        }
        build::Builder::new(rooted_registry("ipv6")).build(
            packet,
            codec::Context::default(),
            build::Options::default(),
        )
    };

    for hop_by_hop in [true, false] {
        let built = build(2_046, hop_by_hop).expect("the largest header fits Hdr Ext Len");
        assert_eq!(built.bytes[41], u8::MAX, "hop_by_hop={hop_by_hop}");
        assert_eq!(built.bytes.len(), 40 + 2_048, "hop_by_hop={hop_by_hop}");

        let refused = build(2_047, hop_by_hop).expect_err("padding past 2048 bytes is refused");
        assert!(
            packetcraftr_core::error::source_chain(&refused)
                .iter()
                .any(|cause| cause.contains("options header exceeds 2048-byte secure default")),
            "hop_by_hop={hop_by_hop}: {refused:?}"
        );

        let padded = build(3, hop_by_hop).expect("a short header pads to eight bytes");
        assert_eq!(
            padded
                .packet
                .iter()
                .nth(1)
                .and_then(|layer| layer.field("options")),
            Some(packetcraftr_core::field::FieldValue::Bytes(
                Bytes::from_static(&[1, 1, 1, 0, 0, 0])
            )),
            "hop_by_hop={hop_by_hop}"
        );
    }
}

#[test]
fn coverage_paddings_build_only_in_innermost_first_order() {
    let packet = |paddings: [Padding; 2]| {
        let mut packet = Packet::new();
        packet.push(Ethernet::default());
        packet.push(ipv4([192, 0, 2, 1], [192, 0, 2, 2]));
        packet.push(Udp {
            source_port: 40_000,
            destination_port: 9,
            ..Udp::default()
        });
        packet.push(Raw::new(Bytes::from_static(&[1, 2, 3, 4])));
        for padding in paddings {
            packet.push(padding);
        }
        packet
    };
    let outside_udp = || Padding::after_layer(vec![0xbb; 3], 2);
    let outside_ipv4 = || Padding::after_layer(vec![0xaa; 2], 1);

    let (_, decoded) = round_trip(packet([outside_udp(), outside_ipv4()]), "ethernet");
    let paddings = decoded
        .packet
        .iter()
        .filter_map(|layer| layer.downcast_ref::<Padding>())
        .map(|padding| (padding.outside_layer, padding.bytes.len()))
        .collect::<Vec<_>>();
    assert_eq!(paddings, [(Some(2), 3), (Some(1), 2)]);

    let error = build::Builder::new(rooted_registry("ethernet"))
        .build(
            packet([outside_ipv4(), outside_udp()]),
            codec::Context::default(),
            build::Options::default(),
        )
        .expect_err("an outer boundary listed first is refused");
    assert!(
        matches!(
            error,
            build::Error::InvalidPaddingBoundary {
                index: 5,
                outside_layer: 2
            }
        ),
        "{error}"
    );
}

/// Option bytes the IPv4 decoder cannot walk would dissect the whole header as
/// malformed, so strict builds refuse them and permissive builds say so.
#[test]
fn ipv4_options_the_decoder_refuses_are_not_built_strictly() {
    for options in [&[0x44, 0x01, 0x00, 0x00][..], &[0x07]] {
        let packet = || {
            let mut packet = Packet::new();
            packet.push(Ipv4 {
                options: Bytes::copy_from_slice(options),
                ..ipv4([192, 0, 2, 1], [192, 0, 2, 2])
            });
            packet
        };
        let builder = build::Builder::new(rooted_registry("ipv4"));
        assert!(
            builder
                .build(
                    packet(),
                    codec::Context::default(),
                    build::Options::default()
                )
                .is_err(),
            "{options:02x?}"
        );
        let built = builder
            .build(
                packet(),
                codec::Context::default(),
                build::Options {
                    mode: codec::Mode::Permissive,
                    ..build::Options::default()
                },
            )
            .expect("permissive builds keep the requested bytes");
        assert!(
            built
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "build.ipv4_options"),
            "{options:02x?}: {:?}",
            built.diagnostics
        );
    }

    let mut routed = Packet::new();
    routed.push(source_routed_ipv4(
        0x83,
        4,
        &[Ipv4Addr::new(198, 51, 100, 1)],
    ));
    build::Builder::new(rooted_registry("ipv4"))
        .build(routed, codec::Context::default(), build::Options::default())
        .expect("a walkable source route still builds strictly");
}

fn ipv4_options_under_transport(protocol: &str, options: &[u8]) -> Packet {
    let mut packet = Packet::new();
    packet.push(Ipv4 {
        options: Bytes::copy_from_slice(options),
        ..ipv4([192, 0, 2, 1], [192, 0, 2, 2])
    });
    if protocol == "udp" {
        packet.push(Udp {
            destination_port: 4000,
            ..known_udp()
        });
        packet.push(Raw::new(b"PCR".to_vec()));
    } else {
        packet.push(known_tcp());
    }
    packet
}

fn transport_checksum(built: &build::BuiltPacket, protocol: &str) -> Option<u16> {
    let checksum = if protocol == "udp" {
        &built.packet.get::<Udp>()?.checksum
    } else {
        &built.packet.get::<Tcp>()?.checksum
    };
    checksum.exact().copied()
}

fn permissive_options() -> build::Options {
    build::Options {
        mode: codec::Mode::Permissive,
        ..build::Options::default()
    }
}

/// The transport checksum of a permissive build falls back to the IPv4 header
/// destination when the options cannot be walked for a source route.
#[test]
fn ipv4_options_the_decoder_refuses_still_build_permissively_under_transports() {
    let builder = build::Builder::new(registry());
    for protocol in ["udp", "tcp"] {
        let plain = builder
            .build(
                ipv4_options_under_transport(protocol, &[]),
                codec::Context::default(),
                build::Options::default(),
            )
            .expect("the same packet without options builds");
        for options in [
            &[0x44, 0x01, 0x00, 0x00][..],
            &[0x07],
            &[0x83, 0x07, 0x04, 0xc6],
            &[0x89, 0x07, 0x04, 0xc6],
        ] {
            assert!(
                builder
                    .build(
                        ipv4_options_under_transport(protocol, options),
                        codec::Context::default(),
                        build::Options::default()
                    )
                    .is_err(),
                "{protocol} {options:02x?} strict"
            );
            let built = builder
                .build(
                    ipv4_options_under_transport(protocol, options),
                    codec::Context::default(),
                    permissive_options(),
                )
                .unwrap_or_else(|error| panic!("{protocol} {options:02x?} permissive: {error}"));
            assert!(
                built
                    .diagnostics
                    .iter()
                    .any(|diagnostic| diagnostic.code == "build.ipv4_options"),
                "{protocol} {options:02x?}: {:?}",
                built.diagnostics
            );
            assert!(transport_checksum(&plain, protocol).is_some());
            assert_eq!(
                transport_checksum(&built, protocol),
                transport_checksum(&plain, protocol),
                "{protocol} {options:02x?} pseudo-header uses the header destination"
            );
        }
    }
}

/// The encoder writes zero-padded options, so the transport checksum follows
/// the source route those padded bytes name, as a decoder reads it back, in
/// both modes.
#[test]
fn truncated_ipv4_source_routes_are_checksummed_from_their_padded_options() {
    let builder = build::Builder::new(registry());
    for protocol in ["udp", "tcp"] {
        for option in [0x83, 0x89] {
            for present in [5, 6] {
                let route = [option, 7, 4, 198, 51, 100, 1];
                let truncated = &route[..present];
                let mut padded = truncated.to_vec();
                padded.resize(8, 0);
                let explicit = builder
                    .build(
                        ipv4_options_under_transport(protocol, &padded),
                        codec::Context::default(),
                        build::Options::default(),
                    )
                    .unwrap_or_else(|error| {
                        panic!("{protocol} {truncated:02x?} padded strict: {error}")
                    });

                for (mode, options) in [
                    ("strict", build::Options::default()),
                    ("permissive", permissive_options()),
                ] {
                    let label = format!("{protocol} {truncated:02x?} {mode}");
                    let built = builder
                        .build(
                            ipv4_options_under_transport(protocol, truncated),
                            codec::Context::default(),
                            options,
                        )
                        .unwrap_or_else(|error| panic!("{label}: {error}"));

                    assert_eq!(built.bytes, explicit.bytes, "{label}");
                    assert!(transport_checksum(&built, protocol).is_some(), "{label}");
                    let codes = built
                        .diagnostics
                        .iter()
                        .map(|diagnostic| diagnostic.code)
                        .collect::<Vec<_>>();
                    assert!(codes.contains(&"build.ipv4_options_padded"), "{label}");
                    assert!(!codes.contains(&"build.ipv4_options"), "{label}: {codes:?}");
                }
            }
        }
    }
}

/// Options past the header limit cannot be built in either mode, so both
/// report the same failure.
#[test]
fn over_long_ipv4_options_fail_alike_in_both_modes_under_transports() {
    fn failure(
        protocol: &str,
        length: usize,
        options: build::Options,
    ) -> (usize, String, Vec<String>) {
        let error = build::Builder::new(registry())
            .build(
                ipv4_options_under_transport(protocol, &vec![1; length]),
                codec::Context::default(),
                options,
            )
            .expect_err("options past 40 bytes cannot be built");
        let build::Error::Codec {
            index,
            protocol,
            source,
        } = &error
        else {
            panic!("{protocol}: {error}");
        };
        let mut chain = Vec::new();
        let mut cause: Option<&dyn std::error::Error> = Some(source);
        while let Some(error) = cause {
            chain.push(error.to_string());
            cause = error.source();
        }
        (*index, protocol.as_str().to_owned(), chain)
    }

    for protocol in ["udp", "tcp"] {
        for length in [41, 44] {
            let strict = failure(protocol, length, build::Options::default());
            assert!(
                strict.2.last().is_some_and(|last| last.contains("40-byte")),
                "{protocol} {length}: {strict:?}"
            );
            assert_eq!(
                strict,
                failure(protocol, length, permissive_options()),
                "{protocol} {length}"
            );
        }
    }
}

#[test]
fn pppoe_stage_is_checked_against_every_ethertype_parent() {
    let parents: Vec<(&str, Vec<Box<dyn Layer>>)> = vec![
        ("ethernet", vec![Box::new(Ethernet::default())]),
        (
            "ipv4",
            vec![
                Box::new(ipv4([192, 0, 2, 1], [192, 0, 2, 2])),
                Box::new(Gre::default()),
            ],
        ),
        (
            "ethernet",
            vec![
                Box::new(Ethernet::default()),
                Box::new(Llc::default()),
                Box::new(Snap::default()),
            ],
        ),
    ];
    for (root, layers) in parents {
        let mut packet = Packet::new();
        let parent = layers
            .last()
            .map(|layer| layer.protocol_id().as_str())
            .expect("a parent layer");
        for layer in layers {
            packet.push_boxed(layer);
        }
        // PADI, a discovery stage, under a parent left to choose its EtherType.
        packet.push(Pppoe {
            code: 0x09,
            ..Pppoe::default()
        });
        packet.push(Raw::new(Bytes::from_static(&[0x01, 0x01, 0x00, 0x00])));
        let error = build::Builder::new(rooted_registry(root))
            .build(packet, codec::Context::default(), build::Options::default())
            .expect_err("a discovery code under the session EtherType is refused");
        let causes = packetcraftr_core::error::source_chain(&error);
        assert!(
            causes
                .iter()
                .any(|cause| cause.contains("requires the enclosing EtherType 0x8863")),
            "{parent}: {error}: {causes:?}"
        );
    }
}

#[test]
fn cooked_capture_link_addresses_longer_than_the_slot_round_trip() {
    const ARPHRD_INFINIBAND: u16 = 32;
    let address = [0x80, 0, 0x02, 0x48, 0xfe, 0x80, 0, 0];

    let mut sll = Packet::new();
    sll.push(LinuxSll {
        arp_hardware_type: ARPHRD_INFINIBAND,
        address_length: 20,
        address,
        ..LinuxSll::default()
    });
    sll.push(ipv4([203, 0, 113, 1], [203, 0, 113, 2]));
    sll.push(Icmpv4::default());
    let (_, decoded) = round_trip(sll, "linux_sll");
    let header = decoded.packet.get::<LinuxSll>().expect("cooked header");
    assert_eq!((header.address_length, header.address), (20, address));
    assert!(decoded.packet.get::<Ipv4>().is_some());

    let mut sll2 = Packet::new();
    sll2.push(LinuxSll2 {
        arp_hardware_type: ARPHRD_INFINIBAND,
        address_length: 20,
        address,
        ..LinuxSll2::default()
    });
    sll2.push(ipv4([203, 0, 113, 1], [203, 0, 113, 2]));
    sll2.push(Icmpv4::default());
    let (_, decoded) = round_trip(sll2, "linux_sll2");
    let header = decoded.packet.get::<LinuxSll2>().expect("cooked header");
    assert_eq!((header.address_length, header.address), (20, address));
    assert!(decoded.packet.get::<Ipv4>().is_some());
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
            .filter(|layer| layer.is::<Mpls>())
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
                codec::Context::default(),
                build::Options::default()
            )
            .is_err()
    );
    let permissive = builder
        .build(
            invalid,
            codec::Context::default(),
            build::Options {
                mode: codec::Mode::Permissive,
                ..build::Options::default()
            },
        )
        .expect("permissive build preserves reserved bit with warning");
    assert_eq!(permissive.mode, codec::Mode::Permissive);
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
                codec::Context::default(),
                build::Options::default()
            )
            .is_err()
    );
    assert!(
        builder
            .build(
                bad_vxlan,
                codec::Context::default(),
                build::Options {
                    mode: codec::Mode::Permissive,
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
                codec::Context::default(),
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
                codec::Context::default(),
                build::Options::default()
            )
            .is_err()
    );
    assert!(
        builder
            .build(
                bad_arp,
                codec::Context::default(),
                build::Options {
                    mode: codec::Mode::Permissive,
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

#[test]
fn field_aliases_resolve_through_reflection_construction_and_filters_alike() {
    use std::collections::BTreeMap;

    use packetcraftr_core::field::FieldValue;

    let registry = registry();

    let mut ipv4 = Ipv4 {
        source: Ipv4Addr::new(192, 0, 2, 1),
        destination: Ipv4Addr::new(198, 51, 100, 2),
        ..Ipv4::default()
    };
    assert_eq!(ipv4.field("dst"), ipv4.field("destination"));
    ipv4.set_field("dst", FieldValue::Ipv4(Ipv4Addr::new(203, 0, 113, 9)))
        .expect("an alias is settable");
    assert_eq!(ipv4.destination, Ipv4Addr::new(203, 0, 113, 9));

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

    let schema = registry.schema("ipv4").expect("IPv4 schema");
    assert!(
        schema.fields.iter().all(|field| field.name != "dst"),
        "aliases must not appear as published fields"
    );
    for path in ["ip.src", "ipv4.source"] {
        Filter::compile(
            &format!("{path} == 192.0.2.1"),
            &registry,
            packetcraftr_core::filter::Limits::default(),
        )
        .unwrap_or_else(|error| panic!("{path}: {error}"));
    }
}

#[test]
fn icmp_body_views_construct_and_decode_verbatim() {
    use packetcraftr_core::field::FieldValue;

    let registry = registry();
    let codec = registry.codec_named("icmpv4").expect("ICMPv4 codec");

    let mut fields = std::collections::BTreeMap::new();
    fields.insert("identifier".to_owned(), FieldValue::Unsigned(0xbeef));
    fields.insert("sequence".to_owned(), FieldValue::Unsigned(7));
    fields.insert(
        "rest".to_owned(),
        FieldValue::Bytes(Bytes::from_static(b"PCR!")),
    );
    let layer = codec.make_layer(&fields).expect("echo construction");
    assert_eq!(
        layer.field("body"),
        Some(FieldValue::Bytes(Bytes::from_static(&[
            0xbe, 0xef, 0, 7, b'P', b'C', b'R', b'!'
        ])))
    );

    let mut packet = Packet::new();
    packet.push(ipv4([192, 0, 2, 1], [192, 0, 2, 2]));
    packet.push_boxed(layer);
    let (_, decoded) = round_trip(packet, "ipv4");
    let echo = decoded
        .packet
        .iter()
        .find(|layer| layer.protocol_id().as_str() == "icmpv4")
        .expect("decoded ICMPv4 layer");
    assert_eq!(echo.field("identifier"), Some(FieldValue::Unsigned(0xbeef)));
    assert_eq!(echo.field("sequence"), Some(FieldValue::Unsigned(7)));
    assert_eq!(
        echo.field("rest"),
        Some(FieldValue::Bytes(Bytes::from_static(b"PCR!")))
    );

    let mut fields = std::collections::BTreeMap::new();
    fields.insert("type".to_owned(), FieldValue::Unsigned(3));
    fields.insert("code".to_owned(), FieldValue::Unsigned(4));
    fields.insert("mtu".to_owned(), FieldValue::Unsigned(1400));
    let layer = codec.make_layer(&fields).expect("error construction");
    assert_eq!(layer.field("mtu"), Some(FieldValue::Unsigned(1400)));

    let mut packet = Packet::new();
    packet.push(ipv4([192, 0, 2, 1], [192, 0, 2, 2]));
    packet.push_boxed(layer);
    let (_, decoded) = round_trip(packet, "ipv4");
    let unreachable = decoded
        .packet
        .iter()
        .find(|layer| layer.protocol_id().as_str() == "icmpv4")
        .expect("decoded ICMPv4 layer");
    assert_eq!(unreachable.field("mtu"), Some(FieldValue::Unsigned(1400)));

    let icmpv6 = registry.codec_named("icmpv6").expect("ICMPv6 codec");
    let mut fields = std::collections::BTreeMap::new();
    fields.insert("type".to_owned(), FieldValue::Unsigned(2));
    fields.insert("mtu".to_owned(), FieldValue::Unsigned(1280));
    let layer = icmpv6.make_layer(&fields).expect("ICMPv6 construction");
    assert_eq!(
        layer.field("body"),
        Some(FieldValue::Bytes(Bytes::from_static(&[0, 0, 0x05, 0x00])))
    );

    let mut packet = Packet::new();
    packet.push(ipv6("2001:db8::1", "2001:db8::2"));
    packet.push_boxed(layer);
    let (_, decoded) = round_trip(packet, "ipv6");
    let too_big = decoded
        .packet
        .iter()
        .find(|layer| layer.protocol_id().as_str() == "icmpv6")
        .expect("decoded ICMPv6 layer");
    assert_eq!(too_big.field("mtu"), Some(FieldValue::Unsigned(1280)));
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
            .build(packet, codec::Context::default(), build::Options::default())
            .err()
            .unwrap_or_else(|| panic!("{protocol} without an IP envelope must not build"));
        let causes = packetcraftr_core::error::source_chain(&error);
        assert!(
            causes
                .iter()
                .any(|cause| cause.contains(&format!("invalid {protocol} layer"))),
            "{protocol}: {error}: {causes:?}"
        );
    }
}

fn build_in_context(
    root: &'static str,
    packet: Packet,
    context: codec::Context,
) -> (build::BuiltPacket, decode::DecodedPacket) {
    let registry = rooted_registry(root);
    let built = build::Builder::new(Arc::clone(&registry))
        .build(packet, context, build::Options::default())
        .unwrap_or_else(|error| panic!("{root} build: {error}"));
    let decoded = decode_from_root(&registry, built.bytes.clone(), decode::Options::default())
        .unwrap_or_else(|error| panic!("{root} decode: {error}"));
    (built, decoded)
}

fn has_valid_udp_checksum(decoded: &decode::DecodedPacket) -> bool {
    decoded.packet.get::<Udp>().is_some()
        && decoded
            .diagnostics
            .iter()
            .all(|diagnostic| diagnostic.code != UDP_CHECKSUM)
}

#[test]
fn only_the_outermost_ip_layer_takes_unspecified_addresses_from_the_build_context() {
    let source4 = Ipv4Addr::new(192, 0, 2, 1);
    let destination4 = Ipv4Addr::new(192, 0, 2, 2);
    let context4 = codec::Context {
        source: Some(source4.into()),
        destination: Some(destination4.into()),
    };
    let source6: Ipv6Addr = "2001:db8::a".parse().unwrap();
    let destination6: Ipv6Addr = "2001:db8::b".parse().unwrap();
    let context6 = codec::Context {
        source: Some(source6.into()),
        destination: Some(destination6.into()),
    };
    let udp = || Udp {
        source_port: 5000,
        destination_port: 5001,
        ..Udp::default()
    };
    let ipv4_addresses = |built: &build::BuiltPacket| -> Vec<(Ipv4Addr, Ipv4Addr)> {
        built
            .packet
            .iter()
            .filter_map(|layer| layer.downcast_ref::<Ipv4>())
            .map(|layer| (layer.source, layer.destination))
            .collect()
    };
    let ipv6_addresses = |built: &build::BuiltPacket| -> Vec<(Ipv6Addr, Ipv6Addr)> {
        built
            .packet
            .iter()
            .filter_map(|layer| layer.downcast_ref::<Ipv6>())
            .map(|layer| (layer.source, layer.destination))
            .collect()
    };

    let mut packet = Packet::new();
    packet.push(Ipv4::default());
    packet.push(udp());
    packet.push(Raw::new(vec![1, 2, 3, 4]));
    let (built, decoded) = build_in_context("ipv4", packet, context4.clone());
    assert_eq!(ipv4_addresses(&built), [(source4, destination4)]);
    assert!(has_valid_udp_checksum(&decoded));

    let mut packet = Packet::new();
    packet.push(Ipv4::default());
    packet.push(Ipv4::default());
    packet.push(udp());
    packet.push(Raw::new(vec![1, 2, 3, 4]));
    let (built, decoded) = build_in_context("ipv4", packet, context4.clone());
    assert_eq!(
        ipv4_addresses(&built),
        [
            (source4, destination4),
            (Ipv4Addr::UNSPECIFIED, Ipv4Addr::UNSPECIFIED)
        ]
    );
    assert!(has_valid_udp_checksum(&decoded));

    let mut packet = Packet::new();
    packet.push(Ipv6::default());
    packet.push(udp());
    packet.push(Raw::new(vec![1, 2, 3, 4]));
    let (built, decoded) = build_in_context("ipv6", packet, context6.clone());
    assert_eq!(ipv6_addresses(&built), [(source6, destination6)]);
    assert!(has_valid_udp_checksum(&decoded));

    let mut packet = Packet::new();
    packet.push(Ipv6::default());
    packet.push(Ipv6::default());
    packet.push(udp());
    packet.push(Raw::new(vec![1, 2, 3, 4]));
    let (built, decoded) = build_in_context("ipv6", packet, context6.clone());
    assert_eq!(
        ipv6_addresses(&built),
        [
            (source6, destination6),
            (Ipv6Addr::UNSPECIFIED, Ipv6Addr::UNSPECIFIED)
        ]
    );
    assert!(has_valid_udp_checksum(&decoded));

    let mut packet = Packet::new();
    packet.push(Ipv6::default());
    packet.push(udp());
    packet.push(Raw::new(vec![1, 2, 3, 4]));
    let (built, decoded) = build_in_context("ipv6", packet, context4);
    assert_eq!(
        ipv6_addresses(&built),
        [(Ipv6Addr::UNSPECIFIED, Ipv6Addr::UNSPECIFIED)],
        "an IPv4 build context is not inherited by an IPv6 layer"
    );
    assert!(has_valid_udp_checksum(&decoded));

    let mut packet = Packet::new();
    packet.push(Ipv6::default());
    packet.push(SegmentRoutingHeader {
        segments: vec!["2001:db8::2".parse().unwrap(), destination6],
        ..SegmentRoutingHeader::default()
    });
    packet.push(udp());
    packet.push(Raw::new(vec![1, 2, 3, 4]));
    let (built, decoded) = build_in_context("ipv6", packet, context6);
    assert_eq!(
        ipv6_addresses(&built),
        [(source6, "2001:db8::2".parse().unwrap())],
        "the active SRH segment takes precedence over the inherited destination"
    );
    assert!(has_valid_udp_checksum(&decoded));
}

#[test]
fn reduced_srh_round_trips_with_explicit_outer_destination_and_valid_checksum() {
    let mut packet = Packet::new();
    packet.push(ipv6("2001:db8::1", "2001:db8::10"));
    packet.push(SegmentRoutingHeader {
        segments_left: WireValue::Exact(2),
        segments: vec![
            "2001:db8::20".parse().unwrap(),
            "2001:db8::30".parse().unwrap(),
        ],
        ..SegmentRoutingHeader::default()
    });
    packet.push(Udp {
        source_port: 5000,
        destination_port: 5001,
        ..Udp::default()
    });
    packet.push(Raw::new(vec![1, 2, 3, 4]));
    let mut missing_destination = packet.clone();
    missing_destination
        .get_mut::<packetcraftr_core::protocol::network::Ipv6>()
        .unwrap()
        .destination = Ipv6Addr::UNSPECIFIED;
    assert!(
        build::Builder::new(rooted_registry("ipv6"))
            .build(
                missing_destination,
                codec::Context::default(),
                build::Options::default()
            )
            .is_err()
    );
    let (_, decoded) = round_trip(packet, "ipv6");
    assert!(has_valid_udp_checksum(&decoded));
    let path = packetcraftr_core::protocol::semantics::outer_ip_path(&decoded.packet)
        .unwrap()
        .unwrap();
    assert_eq!(
        path.active_destination,
        "2001:db8::10".parse::<std::net::IpAddr>().unwrap()
    );
    assert_eq!(
        path.final_destination,
        "2001:db8::30".parse::<std::net::IpAddr>().unwrap()
    );
}

fn ipv6_bytes(registry: &Arc<Registry>, packet: Packet) -> Vec<u8> {
    rebuild(registry, packet, codec::Mode::Strict)
        .expect("IPv6 fixture builds")
        .bytes
        .to_vec()
}

fn rebuild(
    registry: &Arc<Registry>,
    packet: Packet,
    mode: codec::Mode,
) -> Result<build::BuiltPacket, build::Error> {
    build::Builder::new(Arc::clone(registry)).build(
        packet,
        codec::Context::default(),
        build::Options {
            mode,
            ..build::Options::default()
        },
    )
}

fn warning_fields(diagnostics: &[Diagnostic], code: &str) -> Vec<Option<&'static str>> {
    diagnostics
        .iter()
        .filter(|diagnostic| diagnostic.code == code)
        .map(|diagnostic| diagnostic.field)
        .collect()
}

#[test]
fn ipv6_fragment_bits_ignored_on_receipt_decode_with_a_warning() {
    let registry = rooted_registry("ipv6");
    let mut packet = Packet::new();
    packet.push(ipv6("2001:db8::1", "2001:db8::2"));
    packet.push(Fragment {
        next_header: WireValue::Exact(17),
        more_fragments: true,
        identification: 7,
        ..Fragment::default()
    });
    packet.push(Raw::new(vec![0; 8]));
    let mut bytes = ipv6_bytes(&registry, packet);
    bytes[41] = 0x5a;
    bytes[43] |= 0b100;

    let decoded = decode_from_root(&registry, bytes.clone(), decode::Options::default())
        .expect("a fragment with ignored bits set decodes");

    assert!(decoded.packet.get::<Malformed>().is_none());
    let fragment = decoded.packet.get::<Fragment>().expect("fragment layer");
    assert_eq!(fragment.reserved, 0x5a);
    assert_eq!(fragment.reserved_bits, 0b10);
    assert!(fragment.more_fragments);
    assert_eq!(fragment.identification, 7);
    assert_eq!(
        warning_fields(&decoded.diagnostics, "decode.ipv6_fragment_reserved"),
        [Some("reserved"), Some("reserved_bits")]
    );

    assert!(rebuild(&registry, decoded.packet.clone(), codec::Mode::Strict).is_err());
    let rebuilt = rebuild(&registry, decoded.packet, codec::Mode::Permissive)
        .expect("permissive mode keeps the ignored bits");
    assert_eq!(rebuilt.bytes.as_ref(), bytes);
    assert_eq!(
        warning_fields(&rebuilt.diagnostics, "build.ipv6_fragment_reserved"),
        [Some("reserved"), Some("reserved_bits")]
    );
}

#[test]
fn srh_flags_ignored_on_receipt_decode_with_a_warning() {
    let registry = rooted_registry("ipv6");
    let mut packet = Packet::new();
    packet.push(ipv6("2001:db8::1", "2001:db8::2"));
    packet.push(SegmentRoutingHeader {
        segments: vec![
            "2001:db8::2".parse().expect("segment"),
            "2001:db8::99".parse().expect("segment"),
        ],
        ..SegmentRoutingHeader::default()
    });
    packet.push(Udp {
        source_port: 5_000,
        destination_port: 5_001,
        ..Udp::default()
    });
    packet.push(Raw::new(vec![1, 2, 3, 4]));
    let mut bytes = ipv6_bytes(&registry, packet);
    bytes[45] = 0x80;

    let decoded = decode_from_root(&registry, bytes.clone(), decode::Options::default())
        .expect("an SRH with flags set decodes");

    assert!(decoded.packet.get::<Malformed>().is_none());
    let srh = decoded.packet.get::<SegmentRoutingHeader>().expect("SRH");
    assert_eq!(srh.flags, 0x80);
    assert_eq!(
        warning_fields(&decoded.diagnostics, "decode.srh_flags"),
        [Some("flags")]
    );

    assert!(rebuild(&registry, decoded.packet.clone(), codec::Mode::Strict).is_err());
    let rebuilt = rebuild(&registry, decoded.packet, codec::Mode::Permissive)
        .expect("permissive mode keeps the SRH flags");
    assert_eq!(rebuilt.bytes.as_ref(), bytes);
    assert_eq!(
        warning_fields(&rebuilt.diagnostics, "build.srh_flags"),
        [Some("flags")]
    );
}

#[test]
fn ipv6_fragment_reserved_bits_beyond_two_bits_never_build() {
    let registry = rooted_registry("ipv6");
    let packet = |reserved_bits| {
        let mut packet = Packet::new();
        packet.push(ipv6("2001:db8::1", "2001:db8::2"));
        packet.push(Fragment {
            next_header: WireValue::Exact(17),
            reserved_bits,
            more_fragments: true,
            ..Fragment::default()
        });
        packet.push(Raw::new(vec![0; 8]));
        packet
    };

    rebuild(&registry, packet(3), codec::Mode::Permissive).expect("two bits fit");
    for mode in [codec::Mode::Strict, codec::Mode::Permissive] {
        assert!(rebuild(&registry, packet(4), mode).is_err(), "{mode:?}");
    }
}

fn sctp_packet(sctp: Sctp, chunks: &[u8]) -> Packet {
    let mut packet = Packet::new();
    packet.push(ipv4([192, 0, 2, 1], [192, 0, 2, 2]));
    packet.push(sctp);
    packet.push(Raw::new(chunks.to_vec()));
    packet
}

#[test]
fn strict_build_rejects_and_permissive_build_warns_with_the_same_message() {
    struct Case {
        label: &'static str,
        packet: Packet,
        protocol: &'static str,
        code: &'static str,
        field: Option<&'static str>,
        message: &'static str,
    }

    let addresses = || ipv4([192, 0, 2, 1], [192, 0, 2, 2]);
    let mut cases = Vec::new();

    let mut packet = Packet::new();
    packet.push(Ipv4 {
        reserved_flag: true,
        ..addresses()
    });
    packet.push(Icmpv4::default());
    cases.push(Case {
        label: "IPv4 reserved flag",
        packet,
        protocol: "ipv4",
        code: "build.ipv4_reserved_flag",
        field: Some("reserved_flag"),
        message: "reserved IPv4 flag bit is set",
    });

    let mut packet = Packet::new();
    packet.push(ipv6("2001:db8::1", "2001:db8::2"));
    packet.push(SegmentRoutingHeader {
        segments: vec!["2001:db8::2".parse().unwrap()],
        segments_left: WireValue::Exact(3),
        ..SegmentRoutingHeader::default()
    });
    packet.push(Icmpv6::default());
    cases.push(Case {
        label: "SRH segments left",
        packet,
        protocol: "ipv6_srh",
        code: "build.srh_segments_left",
        field: Some("segments_left"),
        message: "segments_left is 3, exceeding last_entry 0 plus one",
    });

    let mut packet = Packet::new();
    packet.push(addresses());
    packet.push(Tcp {
        reserved_bits: 1,
        ..known_tcp()
    });
    cases.push(Case {
        label: "TCP reserved bits",
        packet,
        protocol: "tcp",
        code: "build.tcp_reserved_bits",
        field: Some("reserved_bits"),
        message: "reserved TCP header bits are non-zero",
    });

    let init = [1, 0, 0, 4];
    cases.push(Case {
        label: "SCTP zero source port",
        packet: sctp_packet(
            Sctp {
                source_port: 0,
                ..Sctp::default()
            },
            &init,
        ),
        protocol: "sctp",
        code: "build.sctp_zero_port",
        field: Some("source_port"),
        message: "source port must not be zero",
    });
    cases.push(Case {
        label: "SCTP zero destination port",
        packet: sctp_packet(
            Sctp {
                destination_port: 0,
                ..Sctp::default()
            },
            &init,
        ),
        protocol: "sctp",
        code: "build.sctp_zero_port",
        field: Some("destination_port"),
        message: "destination port must not be zero",
    });

    for (label, chunks, message) in [
        (
            "INIT bundled after DATA",
            [0, 0, 0, 4, 1, 0, 0, 4],
            "INIT chunk must not be bundled with other chunks",
        ),
        (
            "INIT ACK bundled before DATA",
            [2, 0, 0, 4, 0, 0, 0, 4],
            "INIT ACK chunk must not be bundled with other chunks",
        ),
        (
            "the last unbundleable chunk names the error",
            [1, 0, 0, 4, 14, 0, 0, 4],
            "SHUTDOWN COMPLETE chunk must not be bundled with other chunks",
        ),
    ] {
        cases.push(Case {
            label,
            packet: sctp_packet(Sctp::default(), &chunks),
            protocol: "sctp",
            code: "build.sctp_chunks",
            field: None,
            message,
        });
    }

    let mut packet = Packet::new();
    packet.push(Ipv4 {
        protocol: WireValue::Auto,
        ..addresses()
    });
    packet.push(Raw::new(vec![1, 2, 3, 4]));
    cases.push(Case {
        label: "Auto discriminator over Raw",
        packet,
        protocol: "ipv4",
        code: "build.auto_raw_discriminator",
        field: Some("protocol"),
        message: "Auto protocol cannot infer wire intent from Raw; supply an explicit unknown discriminator",
    });

    for (label, protocol, field, message, parent) in [
        (
            "GRE Auto discriminator over Raw",
            "gre",
            "protocol_type",
            "Auto protocol_type cannot infer wire intent from Raw; supply an explicit unknown discriminator",
            Box::new(Gre::default()) as Box<dyn Layer>,
        ),
        (
            "PPP Auto discriminator over Raw",
            "ppp",
            "protocol",
            "Auto protocol cannot infer wire intent from Raw; supply an explicit unknown discriminator",
            Box::new(Ppp::default()),
        ),
        (
            "Linux cooked v1 Auto discriminator over Raw",
            "linux_sll",
            "protocol",
            "Auto protocol cannot infer wire intent from Raw; supply an explicit unknown discriminator",
            Box::new(LinuxSll::default()),
        ),
        (
            "Linux cooked v2 Auto discriminator over Raw",
            "linux_sll2",
            "protocol",
            "Auto protocol cannot infer wire intent from Raw; supply an explicit unknown discriminator",
            Box::new(LinuxSll2::default()),
        ),
    ] {
        let mut packet = Packet::new();
        packet.push_boxed(parent);
        packet.push(Raw::new(vec![1, 2, 3, 4]));
        cases.push(Case {
            label,
            packet,
            protocol,
            code: "build.auto_raw_discriminator",
            field: Some(field),
            message,
        });
    }

    for (label, protocol, message, parent) in [
        (
            "GRE Raw child for a registered discriminator",
            "gre",
            "discriminator 2048 selects registered layer ipv4, but that layer is absent",
            Box::new(Gre {
                protocol_type: WireValue::Exact(0x0800),
                ..Gre::default()
            }) as Box<dyn Layer>,
        ),
        (
            "PPP Raw child for a registered discriminator",
            "ppp",
            "discriminator 33 selects registered layer ipv4, but that layer is absent",
            Box::new(Ppp {
                protocol: WireValue::Exact(0x0021),
            }),
        ),
        (
            "Linux cooked v1 Raw child for a registered discriminator",
            "linux_sll",
            "discriminator 2048 selects registered layer ipv4, but that layer is absent",
            Box::new(LinuxSll {
                protocol: WireValue::Exact(0x0800),
                ..LinuxSll::default()
            }),
        ),
        (
            "Linux cooked v2 Raw child for a registered discriminator",
            "linux_sll2",
            "discriminator 2048 selects registered layer ipv4, but that layer is absent",
            Box::new(LinuxSll2 {
                protocol: WireValue::Exact(0x0800),
                ..LinuxSll2::default()
            }),
        ),
    ] {
        let mut packet = Packet::new();
        packet.push_boxed(parent);
        packet.push(Raw::new(vec![1, 2, 3, 4]));
        cases.push(Case {
            label,
            packet,
            protocol,
            code: "build.raw_typed_discriminator",
            field: Some("discriminator"),
            message,
        });
    }

    let mut packet = Packet::new();
    packet.push(Ipv4 {
        protocol: WireValue::Exact(6),
        ..addresses()
    });
    packet.push(Raw::new(vec![1, 2, 3, 4]));
    cases.push(Case {
        label: "Raw child for a registered discriminator",
        packet,
        protocol: "ipv4",
        code: "build.raw_typed_discriminator",
        field: Some("discriminator"),
        message: "discriminator 6 selects registered layer tcp, but that layer is absent",
    });

    let mut packet = Packet::new();
    packet.push(Ipv4 {
        protocol: WireValue::Exact(6),
        ..addresses()
    });
    cases.push(Case {
        label: "missing child for a registered discriminator",
        packet,
        protocol: "ipv4",
        code: "build.discriminator_child_mismatch",
        field: Some("discriminator"),
        message: "discriminator 6 selects registered layer tcp, but that layer is absent",
    });

    let mut packet = Packet::new();
    packet.push(BsdNull {
        family: 99,
        ..BsdNull::default()
    });
    packet.push(addresses());
    packet.push(Icmpv4::default());
    cases.push(Case {
        label: "BSD family that does not select the child",
        packet,
        protocol: "bsd_null",
        code: "build.capture_family_binding",
        field: Some("family"),
        message: "address family 99 does not select child ipv4",
    });

    let mut packet = Packet::new();
    packet.push(vrrp_ipv4_envelope());
    packet.push(Vrrp {
        version: 2,
        count_ip: WireValue::Exact(3),
        addresses: vec!["192.0.2.100".parse().unwrap()],
        ..Vrrp::default()
    });
    cases.push(Case {
        label: "VRRP count_ip",
        packet,
        protocol: "vrrp",
        code: "build.inconsistent_dependent_field",
        field: Some("count_ip"),
        message: "count_ip is 3, expected 1",
    });

    let mut packet = Packet::new();
    packet.push(vrrp_ipv4_envelope());
    packet.push(Vrrp {
        version: 2,
        auth_data: Some(Bytes::from_static(&[0; 4])),
        ..Vrrp::default()
    });
    cases.push(Case {
        label: "VRRP authentication data",
        packet,
        protocol: "vrrp",
        code: "build.vrrp_auth_data",
        field: Some("auth_data"),
        message: "VRRP version 2 carries 8 bytes after the addresses, not 4",
    });

    cases.push(Case {
        label: "VRRP version 2 over IPv6",
        packet: vrrp_packet(vrrp_ipv6_envelope(), vrrp_v2()),
        protocol: "vrrp",
        code: "build.vrrp_version",
        field: Some("version"),
        message: "VRRP version 2 is IPv4-only",
    });

    let registry = registry();
    for case in cases {
        let label = case.label;
        match rebuild(&registry, case.packet.clone(), codec::Mode::Strict) {
            Err(build::Error::Codec {
                source: codec::Error::Invalid { protocol, message },
                ..
            }) => {
                assert_eq!(protocol.as_str(), case.protocol, "{label}");
                assert_eq!(message, case.message, "{label}");
            }
            other => panic!("{label}: strict build should reject, got {other:?}"),
        }

        let built = rebuild(&registry, case.packet, codec::Mode::Permissive)
            .unwrap_or_else(|error| panic!("{label}: permissive build failed: {error}"));
        let diagnostic = built
            .diagnostics
            .iter()
            .find(|diagnostic| diagnostic.code == case.code)
            .unwrap_or_else(|| panic!("{label}: missing {} in {:?}", case.code, built.diagnostics));
        assert_eq!(diagnostic.severity, Severity::Warning, "{label}");
        assert_eq!(diagnostic.field, case.field, "{label}");
        assert_eq!(diagnostic.message, case.message, "{label}");
    }
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

fn vrrp_v2() -> Vrrp {
    Vrrp {
        version: 2,
        vrid: 7,
        priority: 120,
        addresses: vec!["192.0.2.100".parse().unwrap()],
        ..Vrrp::default()
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

fn vrrp_layer(decoded: &decode::DecodedPacket) -> &Vrrp {
    decoded
        .packet
        .layer(1)
        .and_then(|layer| layer.downcast_ref::<Vrrp>())
        .expect("a VRRP layer follows the IP header")
}

fn vrrp_message(built: &build::BuiltPacket, header_len: usize) -> String {
    built.bytes[header_len..]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[test]
fn vrrp_advertisements_round_trip_and_verify_their_checksums() {
    // The messages and checksums below were computed independently of the codec.
    let v2 = round_trip(vrrp_packet(vrrp_ipv4_envelope(), vrrp_v2()), "ipv4");
    assert_eq!(
        vrrp_message(&v2.0, 20),
        "210778010001a491c00002640000000000000000"
    );
    assert!(v2.1.diagnostics.is_empty(), "{:?}", v2.1.diagnostics);
    let layer = vrrp_layer(&v2.1);
    assert_eq!((layer.version, layer.vrrp_type, layer.vrid), (2, 1, 7));
    assert_eq!(layer.advert_interval, 1);
    assert_eq!(layer.count_ip, WireValue::Exact(1));
    assert_eq!(
        layer.addresses,
        vec!["192.0.2.100".parse::<std::net::IpAddr>().unwrap()]
    );
    assert_eq!(layer.auth_data.as_ref().map(Bytes::len), Some(8));

    let v3_ipv6 = round_trip(
        vrrp_packet(vrrp_ipv6_envelope(), vrrp_v3(&["2001:db8::1"])),
        "ipv6",
    );
    assert_eq!(
        vrrp_message(&v3_ipv6.0, 40),
        "3107780100642aba20010db8000000000000000000000001"
    );
    assert!(
        v3_ipv6.1.diagnostics.is_empty(),
        "{:?}",
        v3_ipv6.1.diagnostics
    );

    let mut v3 = vrrp_v3(&["192.0.2.100", "192.0.2.101"]);
    v3.vrid = 9;
    v3.priority = 100;
    v3.reserved = 0b0101;
    v3.max_advert_interval = 0x123;
    let v3_ipv4 = round_trip(vrrp_packet(vrrp_ipv4_envelope(), v3), "ipv4");
    assert_eq!(
        vrrp_message(&v3_ipv4.0, 20),
        "310964025123f271c0000264c0000265"
    );
    assert!(
        v3_ipv4.1.diagnostics.is_empty(),
        "{:?}",
        v3_ipv4.1.diagnostics
    );
    let layer = vrrp_layer(&v3_ipv4.1);
    assert_eq!((layer.reserved, layer.max_advert_interval), (0b0101, 0x123));
    assert_eq!(layer.addresses.len(), 2);
}

#[test]
fn vrrp_decode_reports_each_departure_from_the_protocol() {
    let registry = rooted_registry("ipv4");
    let builder = build::Builder::new(Arc::clone(&registry));
    let diagnostics = |packet: Packet, edit: &dyn Fn(&mut Vec<u8>)| {
        let built = builder
            .build(
                packet,
                codec::Context::default(),
                build::Options {
                    mode: codec::Mode::Permissive,
                    ..build::Options::default()
                },
            )
            .expect("permissive build");
        let mut bytes = built.bytes.to_vec();
        edit(&mut bytes);
        let decoded =
            decode_from_root(&registry, bytes, decode::Options::default()).expect("VRRP decodes");
        decoded
            .diagnostics
            .iter()
            .map(|diagnostic| diagnostic.code)
            .collect::<Vec<_>>()
    };

    assert_eq!(
        diagnostics(vrrp_packet(vrrp_ipv4_envelope(), vrrp_v2()), &|_| ()),
        Vec::<&str>::new()
    );
    assert_eq!(
        diagnostics(vrrp_packet(vrrp_ipv4_envelope(), vrrp_v2()), &|bytes| {
            bytes[27] ^= 0xff;
        }),
        ["decode.vrrp_checksum"]
    );
    let hop_limit_64 = Ipv4 {
        ttl: 64,
        ..vrrp_ipv4_envelope()
    };
    assert_eq!(
        diagnostics(vrrp_packet(hop_limit_64, vrrp_v2()), &|_| ()),
        ["decode.vrrp_ttl"]
    );
    let unicast = Ipv4 {
        destination: "192.0.2.2".parse().unwrap(),
        ..vrrp_ipv4_envelope()
    };
    assert_eq!(
        diagnostics(vrrp_packet(unicast, vrrp_v2()), &|_| ()),
        ["decode.vrrp_destination"]
    );
    let miscounted = Vrrp {
        count_ip: WireValue::Exact(2),
        ..vrrp_v3(&["192.0.2.100"])
    };
    assert_eq!(
        diagnostics(vrrp_packet(vrrp_ipv4_envelope(), miscounted), &|_| ()),
        ["decode.vrrp_count"]
    );
    let long_auth = Vrrp {
        auth_data: Some(Bytes::from_static(&[1; 12])),
        ..vrrp_v2()
    };
    assert_eq!(
        diagnostics(vrrp_packet(vrrp_ipv4_envelope(), long_auth), &|_| ()),
        ["decode.vrrp_length"]
    );
}

#[test]
fn vrrp_v3_over_ipv6_reports_each_departure_from_the_protocol() {
    let registry = rooted_registry("ipv6");
    let codes = |envelope: Ipv6, edit: &dyn Fn(&mut Vec<u8>)| {
        let built = rebuild(
            &registry,
            vrrp_packet(envelope, vrrp_v3(&["2001:db8::1"])),
            codec::Mode::Permissive,
        )
        .expect("permissive build");
        let mut bytes = built.bytes.to_vec();
        edit(&mut bytes);
        decode_from_root(&registry, bytes, decode::Options::default())
            .expect("VRRP decodes")
            .diagnostics
            .iter()
            .map(|diagnostic| diagnostic.code)
            .collect::<Vec<_>>()
    };

    assert_eq!(
        codes(vrrp_ipv6_envelope(), &|_| ()),
        Vec::<&str>::new(),
        "a well-formed advertisement is clean"
    );
    assert_eq!(
        codes(vrrp_ipv6_envelope(), &|bytes| bytes[47] ^= 0xff),
        ["decode.vrrp_checksum"]
    );
    let hop_limit_64 = Ipv6 {
        hop_limit: 64,
        ..vrrp_ipv6_envelope()
    };
    assert_eq!(codes(hop_limit_64, &|_| ()), ["decode.vrrp_ttl"]);
    let other_group = Ipv6 {
        destination: "ff02::13".parse().unwrap(),
        ..vrrp_ipv6_envelope()
    };
    assert_eq!(codes(other_group, &|_| ()), ["decode.vrrp_destination"]);
}

#[test]
fn vrrp_malformed_shapes_decode_and_rebuild_to_the_same_bytes() {
    let permissive = build::Options {
        mode: codec::Mode::Permissive,
        ..build::Options::default()
    };
    let cases: [(&str, &'static str, Packet, &[&str]); 4] = [
        (
            "version 2 without authentication data",
            "ipv4",
            vrrp_packet(
                vrrp_ipv4_envelope(),
                Vrrp {
                    addresses: Vec::new(),
                    auth_data: Some(Bytes::new()),
                    ..vrrp_v2()
                },
            ),
            &["decode.vrrp_length"],
        ),
        (
            "version 2 with an address and no authentication data",
            "ipv4",
            vrrp_packet(
                vrrp_ipv4_envelope(),
                Vrrp {
                    auth_data: Some(Bytes::new()),
                    ..vrrp_v2()
                },
            ),
            &["decode.vrrp_length"],
        ),
        (
            "version 2 with a short count",
            "ipv4",
            vrrp_packet(
                vrrp_ipv4_envelope(),
                Vrrp {
                    count_ip: WireValue::Exact(0),
                    ..vrrp_v2()
                },
            ),
            &["decode.vrrp_length"],
        ),
        (
            "version 2 over IPv6",
            "ipv6",
            vrrp_packet(vrrp_ipv6_envelope(), vrrp_v2()),
            &["decode.vrrp_version"],
        ),
    ];

    for (label, root, packet, expected) in cases {
        let registry = rooted_registry(root);
        let builder = build::Builder::new(Arc::clone(&registry));
        let built = builder
            .build(packet, codec::Context::default(), permissive.clone())
            .unwrap_or_else(|error| panic!("{label}: build failed: {error}"));
        let decoded = decode_from_root(&registry, built.bytes.clone(), decode::Options::default())
            .unwrap_or_else(|error| panic!("{label}: decode failed: {error}"));
        let codes: Vec<_> = decoded
            .diagnostics
            .iter()
            .map(|diagnostic| diagnostic.code)
            .collect();
        assert_eq!(codes, expected, "{label}");
        let rebuilt = builder
            .build(
                decoded.packet,
                codec::Context::default(),
                permissive.clone(),
            )
            .unwrap_or_else(|error| panic!("{label}: rebuild failed: {error}"));
        assert_eq!(rebuilt.bytes, built.bytes, "{label}");
    }
}

#[test]
fn vrrp_decode_and_rebuild_keep_inconsistent_counts() {
    let registry = rooted_registry("ipv4");
    let builder = build::Builder::new(Arc::clone(&registry));
    let permissive = build::Options {
        mode: codec::Mode::Permissive,
        ..build::Options::default()
    };
    // count_ip says 255: the 12-byte body reads as 3 complete declared
    // addresses and the version 2 trailer is missing entirely
    let packet = vrrp_packet(
        vrrp_ipv4_envelope(),
        Vrrp {
            count_ip: WireValue::Exact(255),
            ..vrrp_v2()
        },
    );
    let built = builder
        .build(packet, codec::Context::default(), permissive.clone())
        .expect("permissive build");
    let decoded = decode_from_root(&registry, built.bytes.clone(), decode::Options::default())
        .expect("decodes");
    let layer = vrrp_layer(&decoded);
    assert_eq!(layer.count_ip, WireValue::Exact(255));
    assert_eq!(layer.addresses.len(), 3);
    assert_eq!(layer.auth_data.as_ref().map(Bytes::len), Some(0));
    let codes: Vec<_> = decoded
        .diagnostics
        .iter()
        .map(|diagnostic| diagnostic.code)
        .collect();
    assert_eq!(codes, ["decode.vrrp_count", "decode.vrrp_length"]);
    let rebuilt = builder
        .build(decoded.packet, codec::Context::default(), permissive)
        .expect("permissive rebuild");
    assert_eq!(rebuilt.bytes, built.bytes);
}

#[test]
fn vrrp_unknown_version_decodes_as_raw_with_its_bytes_intact() {
    let registry = rooted_registry("ipv4");
    let builder = build::Builder::new(Arc::clone(&registry));
    let built = builder
        .build(
            vrrp_packet(vrrp_ipv4_envelope(), vrrp_v2()),
            codec::Context::default(),
            build::Options::default(),
        )
        .expect("build");
    let mut bytes = built.bytes.to_vec();
    bytes[20] = 0x41;
    let decoded =
        decode_from_root(&registry, bytes.clone(), decode::Options::default()).expect("decodes");
    let raw = decoded
        .packet
        .layer(1)
        .and_then(|layer| layer.downcast_ref::<Raw>())
        .expect("an unknown version stays raw");
    assert_eq!(raw.bytes.as_ref(), &bytes[20..]);
}

#[test]
fn vrrp_needs_an_ip_parent_or_build_addresses() {
    let builder = build::Builder::new(registry());
    let standalone = |layer: Box<dyn Layer>| {
        let mut packet = Packet::new();
        packet.push_boxed(layer);
        builder
            .build(packet, codec::Context::default(), build::Options::default())
            .expect_err("a checksum over a pseudo-header needs addresses")
    };
    let vrrp_error = standalone(Box::<Vrrp>::default());
    let icmpv6_error = standalone(Box::<Icmpv6>::default());
    let (
        build::Error::Codec {
            source: codec::Error::Invalid { message, .. },
            ..
        },
        build::Error::Codec {
            source:
                codec::Error::Invalid {
                    message: icmpv6_message,
                    ..
                },
            ..
        },
    ) = (&vrrp_error, &icmpv6_error)
    else {
        panic!("unexpected errors {vrrp_error:?} and {icmpv6_error:?}");
    };
    assert_eq!(message, icmpv6_message);

    let context = codec::Context {
        source: Some("fe80::1".parse().unwrap()),
        destination: Some("ff02::12".parse().unwrap()),
    };
    let mut packet = Packet::new();
    packet.push(vrrp_v3(&["2001:db8::1"]));
    let built = builder
        .build(packet, context, build::Options::default())
        .expect("build addresses stand in for the IP header");
    assert_eq!(
        vrrp_message(&built, 0),
        "3107780100642aba20010db8000000000000000000000001"
    );
}

#[test]
fn vrrp_builds_refuse_what_the_wire_cannot_carry() {
    let builder = build::Builder::new(registry());
    let invalid = |envelope: Box<dyn Layer>, vrrp: Vrrp| {
        let mut packet = Packet::new();
        packet.push_boxed(envelope);
        packet.push(vrrp);
        for mode in [codec::Mode::Strict, codec::Mode::Permissive] {
            let result = builder.build(
                packet.clone(),
                codec::Context::default(),
                build::Options {
                    mode,
                    ..build::Options::default()
                },
            );
            assert!(
                matches!(
                    result,
                    Err(build::Error::Codec {
                        source: codec::Error::Invalid { .. },
                        ..
                    })
                ),
                "{mode:?}: {result:?}"
            );
        }
    };
    let ipv4 = || Box::new(vrrp_ipv4_envelope()) as Box<dyn Layer>;
    // the address family must follow the version and the header
    invalid(
        Box::new(vrrp_ipv6_envelope()),
        Vrrp {
            addresses: vec!["2001:db8::1".parse().unwrap()],
            ..vrrp_v2()
        },
    );
    invalid(ipv4(), vrrp_v3(&["2001:db8::1"]));
    invalid(
        ipv4(),
        Vrrp {
            version: 4,
            ..vrrp_v2()
        },
    );
    invalid(
        ipv4(),
        Vrrp {
            vrrp_type: 16,
            ..vrrp_v2()
        },
    );
    invalid(
        ipv4(),
        Vrrp {
            max_advert_interval: 0x1000,
            ..vrrp_v3(&[])
        },
    );
    invalid(
        ipv4(),
        Vrrp {
            reserved: 16,
            ..vrrp_v3(&[])
        },
    );
    invalid(
        ipv4(),
        Vrrp {
            addresses: vec!["192.0.2.1".parse().unwrap(); 256],
            ..vrrp_v3(&[])
        },
    );
}

#[test]
fn vrrp_fields_are_reflective_and_bound_the_address_list() {
    use packetcraftr_core::field::FieldValue;

    let mut layer = Vrrp::default();
    layer
        .set_field(
            "addresses",
            FieldValue::List(vec![
                FieldValue::Ipv4(Ipv4Addr::new(192, 0, 2, 1)),
                FieldValue::Text("192.0.2.2".to_owned()),
            ]),
        )
        .expect("addresses are settable");
    assert_eq!(layer.addresses.len(), 2);
    assert_eq!(
        layer.field("addresses"),
        Some(FieldValue::List(vec![
            FieldValue::Ipv4(Ipv4Addr::new(192, 0, 2, 1)),
            FieldValue::Ipv4(Ipv4Addr::new(192, 0, 2, 2)),
        ]))
    );
    layer.set_field("type", FieldValue::Unsigned(1)).unwrap();
    assert_eq!(layer.vrrp_type, 1);

    let too_many = FieldValue::List(vec![FieldValue::Ipv4(Ipv4Addr::LOCALHOST); 256]);
    assert!(layer.set_field("addresses", too_many).is_err());
    assert!(
        layer
            .set_field("addresses", FieldValue::List(vec![FieldValue::Unsigned(1)]))
            .is_err()
    );
    assert_eq!(
        layer.addresses.len(),
        2,
        "refused edits leave the list alone"
    );

    let registry = registry();
    let codec = registry.codec_named("vrrp").expect("VRRP codec");
    let made = codec
        .make_layer(&std::collections::BTreeMap::from([(
            "vrid".to_owned(),
            FieldValue::Unsigned(42),
        )]))
        .expect("construction by field name");
    assert_eq!(made.field("vrid"), Some(FieldValue::Unsigned(42)));
}
