// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use packetcraftr_packet::field::Value as FieldValue;
use packetcraftr_packet::filter::{Context as FilterContext, Filter, Options as FilterOptions};
use packetcraftr_packet::frame::{Frame, LinkType};
use packetcraftr_packet::layer::{Layer, Malformed, Padding, Raw};
use packetcraftr_packet::protocol::application::Dns;
use packetcraftr_packet::protocol::capture::{BsdLoop, BsdNull, LinuxSll, LinuxSll2};
use packetcraftr_packet::protocol::gre::Gre;
use packetcraftr_packet::protocol::icmp::{Icmpv4, Icmpv6};
use packetcraftr_packet::protocol::ipv6::{
    DestinationOptions, Fragment, HopByHop, SegmentRoutingHeader,
};
use packetcraftr_packet::protocol::link::{Arp, Ethernet, Llc, Snap, Vlan};
use packetcraftr_packet::protocol::network::{Ipv4, Ipv6};
use packetcraftr_packet::protocol::transport::{Sctp, Tcp, Udp};
use packetcraftr_packet::protocol::tunnel::{
    Ah, Erspan, Esp, Geneve, L2tpv3, Mpls, Ppp, Pppoe, Vxlan,
};
use packetcraftr_packet::protocol::{builtin, quoted_icmp_error_kind};
use packetcraftr_packet::{Packet, build, decode};

fn registry() -> Arc<packetcraftr_packet::registry::Registry> {
    Arc::new(builtin::registry().expect("built-in registry should be valid"))
}

fn round_trip(packet: Packet, root: &str) -> (build::Result, decode::Result) {
    let registry = registry();
    let builder = build::Builder::new(Arc::clone(&registry));
    let built = builder
        .build(packet, build::Context::default(), build::Options::default())
        .unwrap_or_else(|error| panic!("{root} packet should build: {error}"));
    let decoded = decode::Decoder::new(Arc::clone(&registry))
        .decode_with_root(built.bytes.clone(), root.into(), decode::Options::default())
        .unwrap_or_else(|error| panic!("{root} packet should decode: {error}"));
    let rebuilt = builder
        .build(
            decoded.packet.clone(),
            build::Context::default(),
            build::Options::default(),
        )
        .unwrap_or_else(|error| panic!("{root} decoded packet should rebuild: {error}"));
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

#[test]
fn ethernet_ipv4_udp_raw_round_trip_exercises_filter_language() {
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

    let registry = registry();
    let source = concat!(
        "ethernet && ipv4.source in 192.0.2.0/24 && ",
        "udp.destination_port in {53, 9999} && raw.bytes contains \"filter\" && ",
        "ethernet.source[0:3] == 06:07:08 && frame.number == 7 && ",
        "frame.time_epoch == 123 && frame.interface_id == 4 && udp.stream == 3"
    );
    let filter =
        Filter::compile(source, &registry, FilterOptions::default()).expect("valid filter");
    let requirements = filter.requirements();
    assert!(requirements.stream_index);
    assert!(!requirements.tcp_stream);
    assert!(requirements.udp_stream);
    assert!(
        filter
            .matches(&FilterContext {
                decoded: &decoded,
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
            number: 9,
            tcp_stream: None,
            udp_stream: Some(3),
        }),
        Err(packetcraftr_packet::filter::Error::TimestampUnavailable)
    ));

    for source in [
        "tcp",
        "ipv4#2",
        "ipv4.destination == 203.0.113.1",
        "raw.bytes contains \"absent\"",
        "frame.interface_id == 5",
        "udp.stream == 4",
    ] {
        let filter = Filter::compile(source, &registry, FilterOptions::default())
            .expect("valid negative filter");
        assert!(
            !filter
                .matches(&FilterContext {
                    decoded: &decoded,
                    number: 7,
                    tcp_stream: None,
                    udp_stream: Some(3),
                })
                .expect("timestamp is available"),
            "{source}"
        );
    }

    for invalid in [
        "",
        "unknown",
        "ipv4.unknown == 1",
        "frame.len[0] == 1",
        "udp.destination_port contains \"53\"",
        "udp.destination_port == 192.0.2.1",
        "ipv4.source > 192.0.2.0/24",
        "(ethernet",
        "ethernet &&",
        "ethernet.source[4:2] == 00:00",
        "udp.destination_port in {}",
    ] {
        assert!(
            Filter::compile(invalid, &registry, FilterOptions::default()).is_err(),
            "{invalid}"
        );
    }
    assert!(
        Filter::compile(
            "ethernet",
            &registry,
            FilterOptions {
                max_bytes: 2,
                ..FilterOptions::default()
            },
        )
        .is_err()
    );

    let tcp_requirements = Filter::compile("tcp.stream == 1", &registry, FilterOptions::default())
        .expect("valid TCP stream filter")
        .requirements();
    assert!(tcp_requirements.stream_index);
    assert!(tcp_requirements.tcp_stream);
    assert!(!tcp_requirements.udp_stream);

    let both_requirements = Filter::compile(
        "tcp.stream == 1 || udp.stream == 2",
        &registry,
        FilterOptions::default(),
    )
    .expect("valid mixed stream filter")
    .requirements();
    assert!(both_requirements.stream_index);
    assert!(both_requirements.tcp_stream);
    assert!(both_requirements.udp_stream);

    let overflowed_index = format!("ethernet.source[{}] == 00", usize::MAX);
    let error = Filter::compile(&overflowed_index, &registry, FilterOptions::default())
        .expect_err("a single-byte slice must have a representable exclusive end");
    assert!(
        error
            .to_string()
            .contains("has no representable exclusive end")
    );
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
        let decoded = decode::Decoder::new(registry())
            .decode(frame, decode::Options::default())
            .expect("raw-IP root should sniff version");
        assert!(decoded.packet.get::<Ipv4>().is_some());
    }
}

#[test]
fn overlay_and_security_tunnel_stacks_round_trip() {
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
    assert_eq!(decoded.packet.get_all::<Mpls>().count(), 2);

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

    let decoder = decode::Decoder::new(registry());
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
        let decoded = decoder
            .decode_with_root(bytes, root.into(), decode::Options::default())
            .unwrap_or_else(|error| panic!("{root} malformed preservation failed: {error}"));
        assert!(decoded.packet.get::<Malformed>().is_some(), "{root}");
        assert_eq!(
            decoded.diagnostics[0].code, "decode.malformed_layer",
            "{root}"
        );
    }
}

#[test]
fn strict_and_permissive_modes_distinguish_noncanonical_wire_requests() {
    let registry = registry();
    let builder = build::Builder::new(registry);

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
fn response_matchers_correlate_reverse_udp_and_icmp_echo_flows() {
    let registry = registry();
    let udp_matcher = registry.matcher("udp").expect("UDP matcher");
    let mut request = Packet::new();
    request.push(ipv4([192, 0, 2, 1], [198, 51, 100, 2]));
    request.push(Udp {
        source_port: 40_000,
        destination_port: 33434,
        ..Udp::default()
    });
    request.push(Raw::new(vec![1]));
    let mut response = Packet::new();
    response.push(ipv4([198, 51, 100, 2], [192, 0, 2, 1]));
    response.push(Udp {
        source_port: 33434,
        destination_port: 40_000,
        ..Udp::default()
    });
    response.push(Raw::new(vec![2]));
    let matched = udp_matcher.matches(&request, &response);
    assert!(matched.matched);
    assert_eq!(matched.confidence, 100);
    assert_eq!(
        udp_matcher.responder(&request, &response),
        Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2)))
    );
    response.get_mut::<Udp>().expect("UDP").destination_port = 40_001;
    assert!(!udp_matcher.matches(&request, &response).matched);

    let echo_matcher = registry.matcher("icmpv4").expect("ICMPv4 matcher");
    let mut echo_request = Packet::new();
    echo_request.push(ipv4([192, 0, 2, 1], [198, 51, 100, 2]));
    echo_request.push(Icmpv4 {
        body: Bytes::from_static(&[0x12, 0x34, 0, 1, 9]),
        ..Icmpv4::default()
    });
    let mut echo_response = Packet::new();
    echo_response.push(ipv4([198, 51, 100, 2], [192, 0, 2, 1]));
    echo_response.push(Icmpv4 {
        icmp_type: 0,
        body: Bytes::from_static(&[0x12, 0x34, 0, 1, 7]),
        ..Icmpv4::default()
    });
    assert!(echo_matcher.matches(&echo_request, &echo_response).matched);
    echo_response.get_mut::<Icmpv4>().expect("ICMP").code = 1;
    assert!(!echo_matcher.matches(&echo_request, &echo_response).matched);

    assert!(
        quoted_icmp_error_kind(
            &request,
            &response,
            packetcraftr_packet::protocol::QuotedProbeTransport::Udp,
        )
        .is_none()
    );
}

#[test]
fn tcp_response_correlation_uses_decoded_payload_after_every_mutation_api() {
    let registry = registry();
    let tcp_matcher = registry.matcher("tcp").expect("TCP matcher");
    let mut response = Packet::new();
    response.push(ipv4([198, 51, 100, 2], [192, 0, 2, 1]));
    response.push(Tcp {
        source_port: 80,
        destination_port: 40_000,
        acknowledgment: 104,
        flags: Tcp::ACK,
        ..Tcp::default()
    });

    type Mutator = fn(&mut Packet);
    let mutators: [(&str, Mutator); 6] = [
        ("get_mut", |packet| {
            packet.get_mut::<Raw>().expect("Raw").bytes = Bytes::from_static(&[2, 3, 4]);
        }),
        ("by_protocol_mut", |packet| {
            packet
                .by_protocol_mut(&"raw".into())
                .expect("Raw protocol")
                .set_field("bytes", FieldValue::Bytes(Bytes::from_static(&[2, 3, 4])))
                .expect("Raw bytes field");
        }),
        ("layer_mut", |packet| {
            packet
                .layer_mut(2)
                .expect("Raw layer")
                .as_any_mut()
                .downcast_mut::<Raw>()
                .expect("Raw type")
                .bytes = Bytes::from_static(&[2, 3, 4]);
        }),
        ("edit", |packet| {
            packet
                .edit(
                    &"raw".into(),
                    "bytes",
                    FieldValue::Bytes(Bytes::from_static(&[2, 3, 4])),
                )
                .expect("Raw edit");
        }),
        ("replace", |packet| {
            packet
                .replace(2, Raw::new(Bytes::from_static(&[2, 3, 4])))
                .expect("Raw replacement");
        }),
        ("replace_boxed", |packet| {
            packet
                .replace_boxed(2, Box::new(Raw::new(Bytes::from_static(&[2, 3, 4]))))
                .expect("boxed Raw replacement");
        }),
    ];

    for (name, mutate) in mutators {
        let mut request = Packet::new();
        request.push(ipv4([192, 0, 2, 1], [198, 51, 100, 2]));
        request.push(Tcp {
            source_port: 40_000,
            destination_port: 80,
            sequence: 100,
            ..Tcp::default()
        });
        request.push(Raw::new(Bytes::from_static(&[1])));
        let builder = build::Builder::new(Arc::clone(&registry));
        let built = builder
            .build(
                request,
                build::Context::default(),
                build::Options::default(),
            )
            .expect("TCP request builds");
        let mut request = decode::Decoder::new(Arc::clone(&registry))
            .decode_with_root(built.bytes, "ipv4".into(), decode::Options::default())
            .expect("TCP request decodes")
            .packet;

        assert_eq!(request.encoded_payload_length(1), Some(1), "{name} setup");
        mutate(&mut request);
        assert_eq!(
            request.encoded_payload_length(1),
            None,
            "{name} invalidates"
        );
        assert!(
            tcp_matcher.matches(&request, &response).matched,
            "{name} must use the new TCP payload length"
        );
    }
}

#[test]
fn tcp_response_correlation_preserves_syn_fin_and_trailing_padding_rules() {
    let registry = registry();
    let matcher = registry.matcher("tcp").expect("TCP matcher");
    let mut request = Packet::new();
    request.push(ipv4([192, 0, 2, 1], [198, 51, 100, 2]));
    request.push(Tcp {
        source_port: 40_000,
        destination_port: 80,
        sequence: 100,
        flags: Tcp::SYN | Tcp::FIN,
        ..Tcp::default()
    });
    request.push(Raw::new(Bytes::from_static(&[1])));
    request.push(Padding::after_layer(Bytes::from_static(&[0xaa, 0xbb]), 0));

    let built = build::Builder::new(Arc::clone(&registry))
        .build(
            request,
            build::Context::default(),
            build::Options::default(),
        )
        .expect("padded TCP request builds");
    assert_eq!(built.packet.encoded_payload_length(1), Some(3));

    let mut response = Packet::new();
    response.push(ipv4([198, 51, 100, 2], [192, 0, 2, 1]));
    response.push(Tcp {
        source_port: 80,
        destination_port: 40_000,
        acknowledgment: 103,
        flags: Tcp::ACK,
        ..Tcp::default()
    });
    assert!(matcher.matches(&built.packet, &response).matched);
}
