// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use super::builder::{Ipv4PacketBuilder, Ipv6PacketBuilder, PacketBuilder};
use super::executor::{send_loop, send_via_transport};
use super::interface::{desired_ipv6, resolve_ip_addresses};
use super::ipv4::{build_ipv4_packets, IPV4_HEADER_LEN};
use super::ipv6::{
    build_ipv6_packets, routing_initial_destination, IPV6_FRAGMENT_HEADER_LEN, IPV6_HEADER_LEN,
};
use super::layer2::Layer2Resolved;
use super::metrics::emit_metrics_snapshot;
use super::plan_transmission_with_interface;
use super::transport::{
    build_icmpv6_segment, build_tcp_segment, build_transport_segment, build_udp_segment,
    TransportBuild, TCP_HEADER_LEN, UDP_HEADER_LEN,
};
use super::types::{LinkType, NetworkTarget, PlanningMode, TransmissionPlan, TransmissionSummary};
use super::{SendControlError, TransmissionPolicy};
use crate::engine::spec::{
    DestinationSpec, FragmentSpec, IcmpSpec, IpSpec, Ipv6ExtHeader, Ipv6Spec, Layer2Spec,
    ListenerSpec, LoggingSpec, PacketSpec, PayloadSource, PayloadSpec, TargetAddress, TcpFlagSet,
    TcpSpec, TransmissionSpec, TransportSpec, UdpSpec,
};
use pnet::datalink::{self, MacAddr, NetworkInterface};
use pnet::ipnetwork::{IpNetwork, Ipv4Network, Ipv6Network};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::icmpv6::{checksum as icmpv6_checksum, Icmpv6Packet, Icmpv6Types};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::{ipv6_checksum as tcp_ipv6_checksum, MutableTcpPacket};
use pnet::packet::udp::{ipv6_checksum as udp_ipv6_checksum, MutableUdpPacket};
use pnet::packet::Packet;
use std::fs;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use tempfile::tempdir;

fn make_interface(name: &str, ips: Vec<IpNetwork>) -> NetworkInterface {
    NetworkInterface {
        name: name.to_string(),
        description: String::new(),
        index: 0,
        mac: None,
        ips,
        flags: 0,
    }
}

#[test]
fn ipv4_packet_builder_respects_layer2_configuration() {
    let spec = PacketSpec {
        target: DestinationSpec::default(),
        layer2: Layer2Spec::default(),
        ip: Some(IpSpec::default()),
        ipv6: Ipv6Spec::default(),
        transport: TransportSpec::Auto,
        payload: PayloadSpec {
            source: PayloadSource::Empty,
        },
        transmit: TransmissionSpec::default(),
        listener: ListenerSpec::default(),
        rules_file: None,
        logging: LoggingSpec::default(),
    };

    let builder = Ipv4PacketBuilder {
        source: Ipv4Addr::new(192, 0, 2, 1),
        destination: Ipv4Addr::new(192, 0, 2, 2),
    };

    let transport = TransportBuild {
        bytes: vec![0xde, 0xad, 0xbe, 0xef],
        protocol: IpNextHeaderProtocols::Udp,
        label: "UDP",
    };

    let layer2 = Layer2Resolved {
        source: MacAddr::new(0, 1, 2, 3, 4, 5),
        destination: MacAddr::new(0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff),
        ethertype: EtherTypes::Ipv4,
        vlan: None,
    };

    let result = builder
        .build(&spec, &transport, Some(&layer2))
        .expect("ipv4 builder succeeds");

    assert!(matches!(result.link_type, LinkType::Ethernet));
    assert!(matches!(
        result.target,
        NetworkTarget::Ipv4(addr) if addr == builder.destination
    ));
    assert_eq!(result.frames.len(), 1);
    let ethernet = EthernetPacket::new(&result.frames[0]).expect("valid ethernet frame");
    assert_eq!(ethernet.get_source(), layer2.source);
    assert_eq!(ethernet.get_destination(), layer2.destination);
    assert_eq!(ethernet.get_ethertype(), EtherTypes::Ipv4);
}

#[test]
fn ipv4_builder_rejects_payload_exceeding_total_length_limit() {
    let spec = PacketSpec {
        target: DestinationSpec::default(),
        layer2: Layer2Spec::default(),
        ip: Some(IpSpec::default()),
        ipv6: Ipv6Spec::default(),
        transport: TransportSpec::Auto,
        payload: PayloadSpec {
            source: PayloadSource::Empty,
        },
        transmit: TransmissionSpec::default(),
        listener: ListenerSpec::default(),
        rules_file: None,
        logging: LoggingSpec::default(),
    };

    let oversized = vec![0u8; (u16::MAX as usize - IPV4_HEADER_LEN) + 1];
    let err = build_ipv4_packets(
        &spec,
        &oversized,
        Ipv4Addr::new(198, 51, 100, 10),
        Ipv4Addr::new(198, 51, 100, 20),
        IpNextHeaderProtocols::Udp,
    )
    .expect_err("IPv4 builder should reject oversized payloads");

    assert!(
        err.to_string().contains("IPv4 fragment length"),
        "unexpected error message: {}",
        err
    );
}

#[test]
fn packet_builder_without_layer2_uses_layer3_link_type() {
    let spec = PacketSpec {
        target: DestinationSpec::default(),
        layer2: Layer2Spec::default(),
        ip: Some(IpSpec::default()),
        ipv6: Ipv6Spec::default(),
        transport: TransportSpec::Auto,
        payload: PayloadSpec {
            source: PayloadSource::Empty,
        },
        transmit: TransmissionSpec::default(),
        listener: ListenerSpec::default(),
        rules_file: None,
        logging: LoggingSpec::default(),
    };

    let builder = Ipv4PacketBuilder {
        source: Ipv4Addr::new(198, 51, 100, 1),
        destination: Ipv4Addr::new(198, 51, 100, 2),
    };

    let transport = TransportBuild {
        bytes: vec![0u8; 2],
        protocol: IpNextHeaderProtocols::Tcp,
        label: "TCP",
    };

    let result = builder
        .build(&spec, &transport, None)
        .expect("ipv4 builder without layer2");

    assert!(matches!(result.link_type, LinkType::Ipv4));
    assert!(matches!(
        result.target,
        NetworkTarget::Ipv4(addr) if addr == builder.destination
    ));
}

#[test]
fn ipv6_packet_builder_uses_first_hop_target() {
    let spec = PacketSpec {
        target: DestinationSpec::default(),
        layer2: Layer2Spec::default(),
        ip: Some(IpSpec::default()),
        ipv6: Ipv6Spec::default(),
        transport: TransportSpec::Auto,
        payload: PayloadSpec {
            source: PayloadSource::Empty,
        },
        transmit: TransmissionSpec::default(),
        listener: ListenerSpec::default(),
        rules_file: None,
        logging: LoggingSpec::default(),
    };

    let builder = Ipv6PacketBuilder {
        source: Ipv6Addr::LOCALHOST,
        destination: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
        first_hop: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2),
    };

    let transport = TransportBuild {
        bytes: vec![0u8; 4],
        protocol: IpNextHeaderProtocols::Udp,
        label: "UDP",
    };

    let result = builder
        .build(&spec, &transport, None)
        .expect("ipv6 builder");

    assert!(matches!(result.link_type, LinkType::Ipv6));
    assert!(matches!(
        result.target,
        NetworkTarget::Ipv6(addr) if addr == builder.first_hop
    ));
}

#[test]
fn ipv6_packet_builder_produces_expected_length() {
    let payload = vec![0xde, 0xad, 0xbe, 0xef];
    let spec = PacketSpec {
        target: DestinationSpec::default(),
        layer2: Layer2Spec::default(),
        ip: Some(IpSpec::default()),
        ipv6: Ipv6Spec::default(),
        transport: TransportSpec::Auto,
        payload: PayloadSpec {
            source: PayloadSource::Empty,
        },
        transmit: TransmissionSpec::default(),
        listener: ListenerSpec::default(),
        rules_file: None,
        logging: LoggingSpec::default(),
    };

    let packets = build_ipv6_packets(
        &spec,
        &payload,
        Ipv6Addr::LOCALHOST,
        Ipv6Addr::LOCALHOST,
        IpNextHeaderProtocols::Tcp,
    )
    .expect("ipv6 packet build");
    assert_eq!(packets.len(), 1);
    let packet = &packets[0];
    assert_eq!(packet.len(), IPV6_HEADER_LEN + payload.len());
    let ipv6 = Ipv6Packet::new(packet).expect("valid ipv6 packet");
    assert_eq!(ipv6.get_payload_length() as usize, payload.len());
    assert_eq!(ipv6.get_next_header(), IpNextHeaderProtocols::Tcp);
}

#[test]
fn ipv6_extension_headers_follow_requested_order() {
    let payload = vec![0xaa, 0xbb, 0xcc, 0xdd];
    let spec = PacketSpec {
        target: DestinationSpec::default(),
        layer2: Layer2Spec::default(),
        ip: Some(IpSpec::default()),
        ipv6: Ipv6Spec {
            exthdrs: vec![
                Ipv6ExtHeader::DestinationOptions {
                    options: vec![0xde, 0xad, 0xbe, 0xef],
                },
                Ipv6ExtHeader::Routing {
                    routing_type: 0,
                    segments: vec![
                        Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
                        Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2),
                    ],
                    data: None,
                },
            ],
        },
        transport: TransportSpec::Auto,
        payload: PayloadSpec {
            source: PayloadSource::Empty,
        },
        transmit: TransmissionSpec::default(),
        listener: ListenerSpec::default(),
        rules_file: None,
        logging: LoggingSpec::default(),
    };

    let final_destination = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x99);
    let packets = build_ipv6_packets(
        &spec,
        &payload,
        Ipv6Addr::LOCALHOST,
        final_destination,
        IpNextHeaderProtocols::Tcp,
    )
    .expect("ipv6 packet build");
    assert_eq!(packets.len(), 1);
    let packet = &packets[0];
    let ipv6 = Ipv6Packet::new(packet).expect("valid ipv6 packet");
    assert_eq!(ipv6.get_next_header(), IpNextHeaderProtocols::Ipv6Opts);
    assert_eq!(
        packet.len(),
        IPV6_HEADER_LEN + 8 /* dest opts */ + 40 /* routing */ + payload.len()
    );

    let body = ipv6.payload();
    assert_eq!(body[0], IpNextHeaderProtocols::Ipv6Route.0);
    let first_segment = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
    let second_segment = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);

    assert_eq!(ipv6.get_destination(), first_segment);

    let routing_offset = 8;
    assert_eq!(body[routing_offset], IpNextHeaderProtocols::Tcp.0);
    assert_eq!(body[routing_offset + 2], 0); // routing type
    assert_eq!(body[routing_offset + 3], 2); // segments left

    let mut encoded_first = [0u8; 16];
    encoded_first.copy_from_slice(&body[routing_offset + 8..routing_offset + 24]);
    assert_eq!(Ipv6Addr::from(encoded_first), second_segment);
    let mut encoded_second = [0u8; 16];
    encoded_second.copy_from_slice(&body[routing_offset + 24..routing_offset + 40]);
    assert_eq!(Ipv6Addr::from(encoded_second), final_destination);
    assert_eq!(
        &body[routing_offset + 40..routing_offset + 40 + payload.len()],
        &payload
    );
}

#[test]
fn ipv6_destination_options_hdr_ext_len_and_padding() {
    let payload = vec![0x44, 0x55];
    let options = vec![0x11, 0x22, 0x33];
    let spec = PacketSpec {
        target: DestinationSpec::default(),
        layer2: Layer2Spec::default(),
        ip: Some(IpSpec::default()),
        ipv6: Ipv6Spec {
            exthdrs: vec![Ipv6ExtHeader::DestinationOptions {
                options: options.clone(),
            }],
        },
        transport: TransportSpec::Auto,
        payload: PayloadSpec {
            source: PayloadSource::Empty,
        },
        transmit: TransmissionSpec::default(),
        listener: ListenerSpec::default(),
        rules_file: None,
        logging: LoggingSpec::default(),
    };

    let packets = build_ipv6_packets(
        &spec,
        &payload,
        Ipv6Addr::LOCALHOST,
        Ipv6Addr::LOCALHOST,
        IpNextHeaderProtocols::Tcp,
    )
    .expect("ipv6 packet build");
    assert_eq!(packets.len(), 1);
    let packet = &packets[0];
    let ipv6 = Ipv6Packet::new(packet).expect("valid ipv6 packet");
    assert_eq!(
        packet.len(),
        IPV6_HEADER_LEN + 8 /* destination options */ + payload.len()
    );

    let body = ipv6.payload();
    assert_eq!(body[0], IpNextHeaderProtocols::Tcp.0);
    assert_eq!(body[1], 0, "Hdr Ext Len should be zero for 8-byte header");
    assert_eq!(&body[2..2 + options.len()], &options);
    assert!(body[2 + options.len()..8].iter().all(|&b| b == 0));
    assert_eq!(&body[8..8 + payload.len()], &payload);
}

#[test]
fn ipv6_destination_options_rounds_up_length() {
    let payload = vec![0x90, 0x91, 0x92];
    let options: Vec<u8> = (0u8..10).collect();
    let spec = PacketSpec {
        target: DestinationSpec::default(),
        layer2: Layer2Spec::default(),
        ip: Some(IpSpec::default()),
        ipv6: Ipv6Spec {
            exthdrs: vec![Ipv6ExtHeader::DestinationOptions {
                options: options.clone(),
            }],
        },
        transport: TransportSpec::Auto,
        payload: PayloadSpec {
            source: PayloadSource::Empty,
        },
        transmit: TransmissionSpec::default(),
        listener: ListenerSpec::default(),
        rules_file: None,
        logging: LoggingSpec::default(),
    };

    let packets = build_ipv6_packets(
        &spec,
        &payload,
        Ipv6Addr::LOCALHOST,
        Ipv6Addr::LOCALHOST,
        IpNextHeaderProtocols::Tcp,
    )
    .expect("ipv6 packet build");
    assert_eq!(packets.len(), 1);
    let packet = &packets[0];
    let ipv6 = Ipv6Packet::new(packet).expect("valid ipv6 packet");
    assert_eq!(
        packet.len(),
        IPV6_HEADER_LEN + 16 /* rounded destination options */ + payload.len()
    );

    let body = ipv6.payload();
    assert_eq!(body[0], IpNextHeaderProtocols::Tcp.0);
    assert_eq!(body[1], 1, "Hdr Ext Len should describe two 8-byte units");
    assert_eq!(&body[2..2 + options.len()], &options);
    assert!(body[2 + options.len()..16].iter().all(|&b| b == 0));
    assert_eq!(&body[16..16 + payload.len()], &payload);
}

#[test]
fn ipv6_destination_options_supports_maximum_length() {
    let payload = vec![0u8; 4];
    let options = vec![0x55; 2046];
    let spec = PacketSpec {
        target: DestinationSpec::default(),
        layer2: Layer2Spec::default(),
        ip: Some(IpSpec::default()),
        ipv6: Ipv6Spec {
            exthdrs: vec![Ipv6ExtHeader::DestinationOptions {
                options: options.clone(),
            }],
        },
        transport: TransportSpec::Auto,
        payload: PayloadSpec {
            source: PayloadSource::Empty,
        },
        transmit: TransmissionSpec::default(),
        listener: ListenerSpec::default(),
        rules_file: None,
        logging: LoggingSpec::default(),
    };

    let packets = build_ipv6_packets(
        &spec,
        &payload,
        Ipv6Addr::LOCALHOST,
        Ipv6Addr::LOCALHOST,
        IpNextHeaderProtocols::Tcp,
    )
    .expect("ipv6 packet build");
    assert_eq!(packets.len(), 1);
    let packet = &packets[0];
    let ipv6 = Ipv6Packet::new(packet).expect("valid ipv6 packet");
    assert_eq!(
        packet.len(),
        IPV6_HEADER_LEN + 2048 /* destination options */ + payload.len()
    );

    let body = ipv6.payload();
    assert_eq!(body[0], IpNextHeaderProtocols::Tcp.0);
    assert_eq!(body[1], 255);
    assert_eq!(&body[2..2 + options.len()], &options);
    let padding = &body[2 + options.len()..2048];
    assert!(padding.iter().all(|&b| b == 0));
    assert_eq!(&body[2048..2048 + payload.len()], &payload);
}

#[test]
fn ipv6_fragmentation_places_destination_options_after_fragment_header() {
    let payload: Vec<u8> = (0u8..48).collect();
    let dest_options = vec![0xde, 0xad, 0xbe, 0xef];

    let ip_spec = IpSpec {
        fragmentation: FragmentSpec {
            mtu: Some(80),
            ..Default::default()
        },
        ..Default::default()
    };

    let spec = PacketSpec {
        target: DestinationSpec::default(),
        layer2: Layer2Spec::default(),
        ip: Some(ip_spec),
        ipv6: Ipv6Spec {
            exthdrs: vec![Ipv6ExtHeader::DestinationOptions {
                options: dest_options.clone(),
            }],
        },
        transport: TransportSpec::Auto,
        payload: PayloadSpec {
            source: PayloadSource::Empty,
        },
        transmit: TransmissionSpec::default(),
        listener: ListenerSpec::default(),
        rules_file: None,
        logging: LoggingSpec::default(),
    };

    let fragments = build_ipv6_packets(
        &spec,
        &payload,
        Ipv6Addr::LOCALHOST,
        Ipv6Addr::LOCALHOST,
        IpNextHeaderProtocols::Tcp,
    )
    .expect("ipv6 fragmentation");

    assert!(fragments.len() >= 2, "expected fragmented output");

    let first = &fragments[0];
    let fragment_header_offset = IPV6_HEADER_LEN;
    assert_eq!(
        first[fragment_header_offset],
        IpNextHeaderProtocols::Ipv6Opts.0
    );

    let dest_offset = fragment_header_offset + IPV6_FRAGMENT_HEADER_LEN;
    assert_eq!(first[dest_offset], IpNextHeaderProtocols::Tcp.0);
    let hdr_ext_units = first[dest_offset + 1] as usize + 1;
    let dest_header_len = hdr_ext_units * 8;
    assert_eq!(
        &first[dest_offset + 2..dest_offset + 2 + dest_options.len()],
        &dest_options
    );

    let first_payload_start = dest_offset + dest_header_len;
    let first_payload = &first[first_payload_start..];

    let second = &fragments[1];
    assert_eq!(
        second[fragment_header_offset],
        IpNextHeaderProtocols::Ipv6Opts.0
    );
    let second_payload_start = fragment_header_offset + IPV6_FRAGMENT_HEADER_LEN;
    let second_payload = &second[second_payload_start..];

    let mut reassembled = Vec::new();
    reassembled.extend_from_slice(first_payload);
    reassembled.extend_from_slice(second_payload);
    assert_eq!(reassembled, payload);

    assert!(
        !second_payload.is_empty(),
        "expected additional payload beyond first fragment"
    );
    assert_eq!(second_payload[0], payload[first_payload.len()]);
}

#[test]
fn ipv6_routing_header_uses_configured_type() {
    let payload = vec![0x10, 0x20];
    let spec = PacketSpec {
        target: DestinationSpec::default(),
        layer2: Layer2Spec::default(),
        ip: Some(IpSpec::default()),
        ipv6: Ipv6Spec {
            exthdrs: vec![Ipv6ExtHeader::Routing {
                routing_type: 42,
                segments: vec![Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 9)],
                data: None,
            }],
        },
        transport: TransportSpec::Auto,
        payload: PayloadSpec {
            source: PayloadSource::Empty,
        },
        transmit: TransmissionSpec::default(),
        listener: ListenerSpec::default(),
        rules_file: None,
        logging: LoggingSpec::default(),
    };

    let packets = build_ipv6_packets(
        &spec,
        &payload,
        Ipv6Addr::LOCALHOST,
        Ipv6Addr::LOCALHOST,
        IpNextHeaderProtocols::Tcp,
    )
    .expect("ipv6 packet build");
    assert_eq!(packets.len(), 1);
    let packet = &packets[0];
    let ipv6 = Ipv6Packet::new(packet).expect("valid ipv6 packet");
    let body = ipv6.payload();
    assert_eq!(body[2], 42); // routing type
    assert_eq!(body[3], 1); // segments left
}

#[test]
fn ipv6_routing_header_uses_max_segments_and_length_fields() {
    let payload = vec![0xaa, 0xbb, 0xcc];
    let mut segments = Vec::new();
    for index in 0..23u8 {
        segments.push(Ipv6Addr::new(
            0x2001,
            0xdb8,
            0,
            0,
            0,
            0,
            0,
            (index as u16).wrapping_add(1),
        ));
    }

    let final_destination = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0xff);
    let spec = PacketSpec {
        target: DestinationSpec::default(),
        layer2: Layer2Spec::default(),
        ip: Some(IpSpec::default()),
        ipv6: Ipv6Spec {
            exthdrs: vec![Ipv6ExtHeader::Routing {
                routing_type: 7,
                segments: segments.clone(),
                data: None,
            }],
        },
        transport: TransportSpec::Auto,
        payload: PayloadSpec {
            source: PayloadSource::Empty,
        },
        transmit: TransmissionSpec::default(),
        listener: ListenerSpec::default(),
        rules_file: None,
        logging: LoggingSpec::default(),
    };

    let packets = build_ipv6_packets(
        &spec,
        &payload,
        Ipv6Addr::LOCALHOST,
        final_destination,
        IpNextHeaderProtocols::Tcp,
    )
    .expect("ipv6 packet build");
    assert_eq!(packets.len(), 1);
    let packet = &packets[0];
    let ipv6 = Ipv6Packet::new(packet).expect("valid ipv6 packet");
    assert_eq!(
        packet.len(),
        IPV6_HEADER_LEN + 376 /* routing header */ + payload.len()
    );

    let body = ipv6.payload();
    assert_eq!(body[0], IpNextHeaderProtocols::Tcp.0);
    assert_eq!(body[1], 46, "Hdr Ext Len should reflect 376-byte header");
    assert_eq!(body[2], 7);
    assert_eq!(body[3], segments.len() as u8);
    let mut encoded_first = [0u8; 16];
    encoded_first.copy_from_slice(&body[8..24]);
    assert_eq!(Ipv6Addr::from(encoded_first), segments[1]);
    let mut encoded_last = [0u8; 16];
    let last_offset = 8 + 16 * (segments.len() - 1);
    encoded_last.copy_from_slice(&body[last_offset..last_offset + 16]);
    assert_eq!(Ipv6Addr::from(encoded_last), final_destination);
}

#[test]
fn ipv6_routing_initial_destination_prefers_first_segment() {
    let fallback = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x99);
    let headers = vec![Ipv6ExtHeader::Routing {
        routing_type: 0,
        segments: vec![
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2),
        ],
        data: None,
    }];

    let selected = routing_initial_destination(&headers, fallback);
    assert_eq!(selected, Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));

    let empty_headers: Vec<Ipv6ExtHeader> = Vec::new();
    let empty_selected = routing_initial_destination(&empty_headers, fallback);
    assert_eq!(empty_selected, fallback);
}

#[test]
fn ipv6_dont_fragment_preserves_extension_headers() {
    let payload = vec![0x11, 0x22, 0x33];
    let ip_spec = IpSpec {
        fragmentation: FragmentSpec {
            dont_fragment: true,
            ..Default::default()
        },
        ..Default::default()
    };

    let spec = PacketSpec {
        target: DestinationSpec::default(),
        layer2: Layer2Spec::default(),
        ip: Some(ip_spec),
        ipv6: Ipv6Spec {
            exthdrs: vec![Ipv6ExtHeader::DestinationOptions {
                options: vec![0xde, 0xad, 0xbe, 0xef],
            }],
        },
        transport: TransportSpec::Auto,
        payload: PayloadSpec {
            source: PayloadSource::Empty,
        },
        transmit: TransmissionSpec::default(),
        listener: ListenerSpec::default(),
        rules_file: None,
        logging: LoggingSpec::default(),
    };

    let packets = build_ipv6_packets(
        &spec,
        &payload,
        Ipv6Addr::LOCALHOST,
        Ipv6Addr::LOCALHOST,
        IpNextHeaderProtocols::Tcp,
    )
    .expect("ipv6 packet build");
    assert_eq!(packets.len(), 1);
    let packet = &packets[0];
    let ipv6 = Ipv6Packet::new(packet).expect("valid ipv6 packet");
    assert_eq!(ipv6.get_next_header(), IpNextHeaderProtocols::Ipv6Opts);
    assert_eq!(
        packet.len(),
        IPV6_HEADER_LEN + 8 /* destination options */ + payload.len()
    );

    let body = ipv6.payload();
    assert_eq!(body[0], IpNextHeaderProtocols::Tcp.0);
    assert_eq!(&body[8..8 + payload.len()], &payload);
}

#[test]
fn plan_transmission_uses_routing_first_hop_for_ipv6_link_layer() {
    let first_hop = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
    let final_destination = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x99);
    let source_ip = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x42);

    let target = DestinationSpec {
        address: Some(TargetAddress::Ip(IpAddr::V6(final_destination))),
        ..Default::default()
    };

    let ip_spec = IpSpec {
        source: Some(IpAddr::V6(source_ip)),
        ..Default::default()
    };

    let layer2 = Layer2Spec {
        source: Some(MacAddr::new(0x00, 0x11, 0x22, 0x33, 0x44, 0x55)),
        destination: Some(MacAddr::new(0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff)),
        ..Default::default()
    };

    let spec = PacketSpec {
        target,
        layer2,
        ip: Some(ip_spec),
        ipv6: Ipv6Spec {
            exthdrs: vec![Ipv6ExtHeader::Routing {
                routing_type: 0,
                segments: vec![first_hop, final_destination],
                data: None,
            }],
        },
        transport: TransportSpec::Auto,
        payload: PayloadSpec {
            source: PayloadSource::Inline("payload".to_string()),
        },
        transmit: TransmissionSpec::default(),
        listener: ListenerSpec::default(),
        rules_file: None,
        logging: LoggingSpec::default(),
    };

    let iface = make_interface(
        "test0",
        vec![IpNetwork::V6(Ipv6Network::new(source_ip, 64).unwrap())],
    );

    let plan = plan_transmission_with_interface(&spec, iface, PlanningMode::Live)
        .expect("transmission plan");

    match plan.destination {
        NetworkTarget::Ipv6(addr) => assert_eq!(addr, first_hop),
        _ => panic!("expected IPv6 destination"),
    }

    let frame = EthernetPacket::new(&plan.frames[0]).expect("ethernet frame");
    assert_eq!(
        frame.get_destination(),
        MacAddr::new(0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff)
    );

    let ipv6 = Ipv6Packet::new(frame.payload()).expect("ipv6 packet");
    assert_eq!(ipv6.get_destination(), first_hop);
}

#[test]
fn icmpv6_segment_includes_valid_checksum() {
    let spec = crate::engine::spec::Icmpv6Spec {
        identifier: Some(0x1234),
        sequence: Some(0x0001),
        ..crate::engine::spec::Icmpv6Spec::default()
    };
    let src = IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1));
    let dst = IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2));
    let bytes = build_icmpv6_segment(&spec, &[], src, dst).expect("icmpv6 build");
    let packet = Icmpv6Packet::new(&bytes).expect("valid icmpv6 packet");
    let checksum = packet.get_checksum();
    assert_ne!(
        checksum, 0,
        "checksum should not be zero for populated packet"
    );
    if let (IpAddr::V6(src_ip), IpAddr::V6(dst_ip)) = (src, dst) {
        let recomputed = icmpv6_checksum(&packet, &src_ip, &dst_ip);
        assert_eq!(checksum, recomputed);
    } else {
        panic!("source and destination must be IPv6 for this test");
    }
}

#[test]
fn plan_transmission_marks_layer3_fallback_for_ipv6() {
    let destination = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
    let source = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);

    let target = DestinationSpec {
        address: Some(TargetAddress::Ip(IpAddr::V6(destination))),
        ..Default::default()
    };

    let ip_spec = IpSpec {
        source: Some(IpAddr::V6(source)),
        ..Default::default()
    };

    let spec = PacketSpec {
        target,
        layer2: Layer2Spec::default(),
        ip: Some(ip_spec),
        ipv6: Ipv6Spec::default(),
        transport: TransportSpec::Auto,
        payload: PayloadSpec {
            source: PayloadSource::Empty,
        },
        transmit: TransmissionSpec::default(),
        listener: ListenerSpec::default(),
        rules_file: None,
        logging: LoggingSpec::default(),
    };

    let iface = make_interface(
        "test0",
        vec![IpNetwork::V6(Ipv6Network::new(source, 64).unwrap())],
    );

    let plan = plan_transmission_with_interface(&spec, iface, PlanningMode::Live)
        .expect("transmission plan");

    assert!(matches!(plan.link_type, LinkType::Ipv6));
    assert!(
        plan.transmit.is_layer3(),
        "expected layer3 flag to be enabled"
    );
    assert!(
        plan.transmit.auto_layer3,
        "expected fallback to mark transmission as automatic layer3"
    );
}

#[test]
fn icmpv6_echo_includes_payload_bytes() {
    use crate::engine::spec::Icmpv6Spec;
    let spec = Icmpv6Spec {
        kind: Some(Icmpv6Types::EchoRequest.0),
        identifier: Some(0x0102),
        sequence: Some(0x0304),
        ..Default::default()
    };
    let payload = b"ping";
    let bytes = build_icmpv6_segment(
        &spec,
        payload,
        IpAddr::V6(Ipv6Addr::LOCALHOST),
        IpAddr::V6(Ipv6Addr::LOCALHOST),
    )
    .expect("icmpv6 segment");
    let packet = pnet::packet::icmpv6::Icmpv6Packet::new(&bytes).unwrap();
    assert_eq!(packet.get_icmpv6_type(), Icmpv6Types::EchoRequest);
    let body = packet.payload();
    assert_eq!(&body[4..], payload);
}

#[test]
fn ipv6_fragmentation_inserts_fragment_header() {
    let ip_spec = IpSpec {
        fragmentation: FragmentSpec {
            mtu: Some(80),
            ..Default::default()
        },
        ..Default::default()
    };
    let spec = PacketSpec {
        target: DestinationSpec::default(),
        layer2: Layer2Spec::default(),
        ip: Some(ip_spec),
        ipv6: Ipv6Spec::default(),
        transport: TransportSpec::Auto,
        payload: PayloadSpec {
            source: PayloadSource::Empty,
        },
        transmit: TransmissionSpec::default(),
        listener: ListenerSpec::default(),
        rules_file: None,
        logging: LoggingSpec::default(),
    };

    let payload = vec![0u8; 256];
    let packets = build_ipv6_packets(
        &spec,
        &payload,
        Ipv6Addr::LOCALHOST,
        Ipv6Addr::LOCALHOST,
        IpNextHeaderProtocols::Udp,
    )
    .expect("ipv6 fragments");

    assert!(packets.len() > 1, "expected multiple fragments");
    for (index, packet) in packets.iter().enumerate() {
        let ipv6 = Ipv6Packet::new(packet).expect("valid ipv6 fragment");
        assert_eq!(ipv6.get_next_header(), IpNextHeaderProtocols::Ipv6Frag);
        let fragment = ipv6.payload();
        assert!(fragment.len() >= 8, "fragment header should be present");
        assert_eq!(fragment[0], IpNextHeaderProtocols::Udp.0);
        let offset_field = u16::from_be_bytes([fragment[2], fragment[3]]);
        let more = (offset_field & 0x0001) == 1;
        if index < packets.len() - 1 {
            assert!(more, "non-final fragments should advertise more flag");
        } else {
            assert!(!more, "final fragment should clear more flag");
        }
    }
}

#[test]
fn tcp_ipv6_checksum_is_correct() {
    let source_ip = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1);
    let dest_ip = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 2);
    let mut tcp_buffer = [0u8; 20];
    let mut tcp_packet = MutableTcpPacket::new(&mut tcp_buffer).unwrap();
    tcp_packet.set_source(12345);
    tcp_packet.set_destination(54321);
    tcp_packet.set_sequence(1);
    tcp_packet.set_acknowledgement(1);
    tcp_packet.set_data_offset(5);
    tcp_packet.set_flags(0);
    tcp_packet.set_window(1024);
    tcp_packet.set_urgent_ptr(0);
    let checksum = tcp_ipv6_checksum(&tcp_packet.to_immutable(), &source_ip, &dest_ip);
    assert_eq!(checksum, 42869);
}

#[test]
fn udp_ipv6_checksum_is_correct() {
    let source_ip = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1);
    let dest_ip = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 2);
    let mut udp_buffer = [0u8; 8];
    let mut udp_packet = MutableUdpPacket::new(&mut udp_buffer).unwrap();
    udp_packet.set_source(12345);
    udp_packet.set_destination(54321);
    udp_packet.set_length(8);
    let checksum = udp_ipv6_checksum(&udp_packet.to_immutable(), &source_ip, &dest_ip);
    assert_eq!(checksum, 64368);
}

#[test]
fn tcp_ipv6_segment_checksum_matches() {
    let spec = TcpSpec {
        source_port: Some(4000),
        destination_port: Some(5000),
        flags: TcpFlagSet {
            syn: true,
            ..Default::default()
        },
        sequence: Some(1),
        acknowledgement: Some(0),
        window_size: Some(1024),
        options: None,
    };
    let payload = b"payload".to_vec();
    let src = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
    let dst = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
    let segment =
        build_tcp_segment(&spec, &payload, IpAddr::V6(src), IpAddr::V6(dst)).expect("segment");
    let packet = pnet::packet::tcp::TcpPacket::new(&segment).unwrap();
    let expected = tcp_ipv6_checksum(&packet, &src, &dst);
    assert_eq!(packet.get_checksum(), expected);

    let mut tampered = segment.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0xff;
    let tampered_packet = pnet::packet::tcp::TcpPacket::new(&tampered).unwrap();
    let tampered_sum = tcp_ipv6_checksum(&tampered_packet, &src, &dst);
    assert_ne!(tampered_sum, packet.get_checksum());
}

#[test]
fn udp_ipv6_segment_checksum_matches() {
    let spec = UdpSpec {
        source_port: Some(1234),
        destination_port: Some(4321),
    };
    let payload = b"hello".to_vec();
    let src = Ipv6Addr::LOCALHOST;
    let dst = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 2);
    let segment =
        build_udp_segment(&spec, &payload, IpAddr::V6(src), IpAddr::V6(dst)).expect("segment");
    let packet = pnet::packet::udp::UdpPacket::new(&segment).unwrap();
    let expected = udp_ipv6_checksum(&packet, &src, &dst);
    assert_eq!(packet.get_checksum(), expected);

    let mut tampered = segment.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0xff;
    let tampered_packet = pnet::packet::udp::UdpPacket::new(&tampered).unwrap();
    let tampered_sum = udp_ipv6_checksum(&tampered_packet, &src, &dst);
    assert_ne!(tampered_sum, packet.get_checksum());
}

#[test]
fn udp_builder_rejects_payload_exceeding_length_limit() {
    let spec = UdpSpec {
        source_port: Some(9999),
        destination_port: Some(8888),
    };
    let payload = vec![0u8; (u16::MAX as usize - UDP_HEADER_LEN) + 1];
    let err = build_udp_segment(
        &spec,
        &payload,
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)),
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 2)),
    )
    .expect_err("UDP builder should reject oversized payloads");

    assert!(
        err.to_string().contains("UDP datagram length"),
        "unexpected error message: {}",
        err
    );
}

#[test]
fn transport_builder_tcp_ipv6_checksum_matches() {
    let spec = TcpSpec {
        source_port: Some(1111),
        destination_port: Some(2222),
        flags: TcpFlagSet {
            syn: true,
            ..Default::default()
        },
        sequence: Some(10),
        acknowledgement: Some(0),
        window_size: Some(4096),
        options: None,
    };
    let payload = b"abc".to_vec();
    let src = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 10);
    let dst = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 20);
    let build = build_transport_segment(
        &TransportSpec::Tcp(spec.clone()),
        &payload,
        IpAddr::V6(src),
        IpAddr::V6(dst),
    )
    .expect("transport");
    assert_eq!(build.label, "TCP");
    let packet = pnet::packet::tcp::TcpPacket::new(&build.bytes).unwrap();
    let expected = tcp_ipv6_checksum(&packet, &src, &dst);
    assert_eq!(packet.get_checksum(), expected);
}

#[test]
fn transport_builder_udp_ipv6_checksum_matches() {
    let spec = UdpSpec {
        source_port: Some(3333),
        destination_port: Some(4444),
    };
    let payload = b"hello world".to_vec();
    let src = Ipv6Addr::LOCALHOST;
    let dst = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 30);
    let build = build_transport_segment(
        &TransportSpec::Udp(spec),
        &payload,
        IpAddr::V6(src),
        IpAddr::V6(dst),
    )
    .expect("transport");
    assert_eq!(build.label, "UDP");
    let packet = pnet::packet::udp::UdpPacket::new(&build.bytes).unwrap();
    let expected = udp_ipv6_checksum(&packet, &src, &dst);
    assert_eq!(packet.get_checksum(), expected);
}

#[test]
fn icmpv6_error_packet_uses_parameter_field() {
    use crate::engine::spec::Icmpv6Spec;

    let spec = Icmpv6Spec {
        kind: Some(Icmpv6Types::DestinationUnreachable.0),
        code: Some(1),
        identifier: None,
        sequence: None,
        parameter: Some(0x11223344),
    };
    let bytes = build_icmpv6_segment(
        &spec,
        &[0xaa, 0xbb],
        IpAddr::V6(Ipv6Addr::LOCALHOST),
        IpAddr::V6(Ipv6Addr::LOCALHOST),
    )
    .expect("icmpv6 segment");
    let packet = pnet::packet::icmpv6::Icmpv6Packet::new(&bytes).unwrap();
    assert_eq!(
        packet.get_icmpv6_type(),
        Icmpv6Types::DestinationUnreachable
    );
    assert_eq!(packet.payload()[0..4], [0x11, 0x22, 0x33, 0x44]);
    assert_eq!(packet.payload()[4..], [0xaa, 0xbb]);
}

#[test]
fn icmpv6_error_parameter_defaults_to_identifier_sequence() {
    use crate::engine::spec::Icmpv6Spec;

    let spec = Icmpv6Spec {
        kind: Some(Icmpv6Types::PacketTooBig.0),
        code: Some(0),
        identifier: Some(0xdead),
        sequence: Some(0xbeef),
        parameter: None,
    };
    let bytes = build_icmpv6_segment(
        &spec,
        &[],
        IpAddr::V6(Ipv6Addr::LOCALHOST),
        IpAddr::V6(Ipv6Addr::LOCALHOST),
    )
    .expect("icmpv6 segment");
    let packet = pnet::packet::icmpv6::Icmpv6Packet::new(&bytes).unwrap();
    assert_eq!(packet.payload()[0..4], [0xde, 0xad, 0xbe, 0xef]);
}
#[test]
fn tcp_segment_includes_supplied_options() {
    let flags = TcpFlagSet {
        syn: true,
        ..Default::default()
    };
    let spec = TcpSpec {
        source_port: Some(1000),
        destination_port: Some(2000),
        flags,
        sequence: Some(1),
        acknowledgement: Some(0),
        window_size: Some(30_000),
        options: Some(vec![0x02, 0x04, 0x05, 0xb4]),
    };
    let segment = build_tcp_segment(
        &spec,
        &[],
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
    )
    .expect("failed to build tcp segment");
    assert_eq!(segment.len(), TCP_HEADER_LEN + 4);
    assert_eq!(
        &segment[TCP_HEADER_LEN..TCP_HEADER_LEN + 4],
        &[0x02, 0x04, 0x05, 0xb4]
    );
    let data_offset = segment[12] >> 4;
    assert_eq!(data_offset, 6);
}

#[test]
fn hostname_destination_is_resolved() {
    let target = DestinationSpec {
        address: Some(TargetAddress::Host("localhost".to_string())),
        ..Default::default()
    };

    let ip_spec = IpSpec {
        source: Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
        ..Default::default()
    };

    let spec = PacketSpec {
        target,
        layer2: Layer2Spec::default(),
        ip: Some(ip_spec),
        ipv6: Ipv6Spec::default(),
        transport: TransportSpec::Auto,
        payload: PayloadSpec {
            source: PayloadSource::Empty,
        },
        transmit: TransmissionSpec::default(),
        listener: ListenerSpec::default(),
        rules_file: None,
        logging: LoggingSpec::default(),
    };

    let interface = make_interface("lo0", vec![]);

    let (_, destination) = resolve_ip_addresses(&spec, &interface).expect("hostname resolved");
    assert!(matches!(destination, IpAddr::V4(_)));
}

#[test]
fn desired_ipv6_prefers_hint_when_present() {
    let mut spec = PacketSpec {
        target: DestinationSpec::default(),
        layer2: Layer2Spec::default(),
        ip: Some(IpSpec {
            source: None,
            destination: None,
            prefer_ipv6: Some(true),
            ttl: None,
            tos: None,
            identification: None,
            fragmentation: FragmentSpec::default(),
        }),
        ipv6: Ipv6Spec::default(),
        transport: TransportSpec::Auto,
        payload: PayloadSpec {
            source: PayloadSource::Empty,
        },
        transmit: TransmissionSpec::default(),
        listener: ListenerSpec::default(),
        rules_file: None,
        logging: LoggingSpec::default(),
    };

    assert_eq!(desired_ipv6(&spec), Some(true));

    if let Some(ip) = spec.ip.as_mut() {
        ip.prefer_ipv6 = Some(false);
    }

    assert_eq!(desired_ipv6(&spec), Some(false));
}

#[test]
fn defaults_source_ipv4_to_interface_address() {
    let target = DestinationSpec {
        address: Some(TargetAddress::Ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)))),
        ..Default::default()
    };

    let spec = PacketSpec {
        target,
        layer2: Layer2Spec::default(),
        ip: None,
        ipv6: Ipv6Spec::default(),
        transport: TransportSpec::Auto,
        payload: PayloadSpec {
            source: PayloadSource::Empty,
        },
        transmit: TransmissionSpec::default(),
        listener: ListenerSpec::default(),
        rules_file: None,
        logging: LoggingSpec::default(),
    };

    let iface = make_interface(
        "eth0",
        vec![IpNetwork::V4(
            Ipv4Network::new(Ipv4Addr::new(198, 51, 100, 10), 24).unwrap(),
        )],
    );

    let (source, destination) = resolve_ip_addresses(&spec, &iface).expect("ipv4 resolution");
    assert_eq!(destination, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));
    assert_eq!(source, IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10)));
}

#[test]
fn defaults_source_ipv6_to_interface_address() {
    let target = DestinationSpec {
        address: Some(TargetAddress::Ip(IpAddr::V6(Ipv6Addr::new(
            0x2001, 0xdb8, 0, 0, 0, 0, 0, 2,
        )))),
        ..Default::default()
    };

    let spec = PacketSpec {
        target,
        layer2: Layer2Spec::default(),
        ip: None,
        ipv6: Ipv6Spec::default(),
        transport: TransportSpec::Auto,
        payload: PayloadSpec {
            source: PayloadSource::Empty,
        },
        transmit: TransmissionSpec::default(),
        listener: ListenerSpec::default(),
        rules_file: None,
        logging: LoggingSpec::default(),
    };

    let iface = make_interface(
        "eth0",
        vec![IpNetwork::V6(
            Ipv6Network::new(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1), 64).unwrap(),
        )],
    );

    let (source, destination) = resolve_ip_addresses(&spec, &iface).expect("ipv6 resolution");
    assert_eq!(
        destination,
        IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2))
    );
    assert_eq!(
        source,
        IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))
    );
}

#[test]
fn defaults_to_unspecified_when_interface_missing_address() {
    let target = DestinationSpec {
        address: Some(TargetAddress::Ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 5)))),
        ..Default::default()
    };

    let spec = PacketSpec {
        target,
        layer2: Layer2Spec::default(),
        ip: None,
        ipv6: Ipv6Spec::default(),
        transport: TransportSpec::Auto,
        payload: PayloadSpec {
            source: PayloadSource::Empty,
        },
        transmit: TransmissionSpec::default(),
        listener: ListenerSpec::default(),
        rules_file: None,
        logging: LoggingSpec::default(),
    };

    let iface = make_interface("eth0", vec![]);

    let (source, destination) = resolve_ip_addresses(&spec, &iface).expect("fallback resolution");
    assert_eq!(destination, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 5)));
    assert_eq!(source, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
}

#[derive(Default)]
struct CountingSender {
    sends: usize,
}

impl datalink::DataLinkSender for CountingSender {
    fn build_and_send(
        &mut self,
        _num_packets: usize,
        _packet_size: usize,
        _func: &mut dyn FnMut(&mut [u8]),
    ) -> Option<io::Result<()>> {
        Some(Ok(()))
    }

    fn send_to(
        &mut self,
        _packet: &[u8],
        _dst: Option<NetworkInterface>,
    ) -> Option<io::Result<()>> {
        self.sends += 1;
        Some(Ok(()))
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn send_loop_rejects_zero_iterations() {
    let interface = make_interface("eth0", vec![]);
    let plan = TransmissionPlan {
        frames: vec![vec![0u8; 32]],
        link_type: LinkType::Ethernet,
        transmit: TransmissionSpec {
            count: Some(0),
            ..TransmissionSpec::default()
        },
        destination: NetworkTarget::Ipv4(Ipv4Addr::LOCALHOST),
        interface: interface.clone(),
        protocol: IpNextHeaderProtocols::Tcp,
        summary: TransmissionSummary {
            payload_len: 32,
            largest_frame_len: 32,
            frame_count: 1,
            transport: "TCP",
        },
        logging: LoggingSpec::default(),
        mode: PlanningMode::Live,
        policy: TransmissionPolicy::default(),
    };

    let mut sender = CountingSender::default();
    let mut recorded = 0usize;
    let result = send_loop(&mut sender, &plan, &interface, &mut |_frame: &[u8]| {
        recorded += 1;
        Ok(())
    });

    assert!(matches!(
        result,
        Err(super::error::SenderError::SendControl(
            SendControlError::CountMustBePositive
        ))
    ));
    assert_eq!(sender.sends, 0);
    assert_eq!(recorded, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn layer3_send_rejects_zero_iterations() {
    let interface = make_interface("eth0", vec![]);
    let plan = TransmissionPlan {
        frames: vec![vec![0u8; IPV4_HEADER_LEN]],
        link_type: LinkType::Ipv4,
        transmit: TransmissionSpec {
            count: Some(0),
            ..TransmissionSpec::default()
        },
        destination: NetworkTarget::Ipv4(Ipv4Addr::LOCALHOST),
        interface,
        protocol: IpNextHeaderProtocols::Tcp,
        summary: TransmissionSummary {
            payload_len: 0,
            largest_frame_len: IPV4_HEADER_LEN,
            frame_count: 1,
            transport: "TCP",
        },
        logging: LoggingSpec::default(),
        mode: PlanningMode::Live,
        policy: TransmissionPolicy::default(),
    };

    let mut recorded = 0usize;
    let result = send_via_transport(plan, &mut |_frame: &[u8]| {
        recorded += 1;
        Ok(())
    });

    assert!(matches!(
        result,
        Err(super::error::SenderError::SendControl(
            SendControlError::CountMustBePositive
        ))
    ));
    assert_eq!(recorded, 0);
}

#[test]
fn ipv4_fragmentation_respects_mtu() {
    let src = Ipv4Addr::new(192, 0, 2, 1);
    let dst = Ipv4Addr::new(198, 51, 100, 10);
    let ip_spec = IpSpec {
        source: Some(IpAddr::V4(src)),
        destination: Some(IpAddr::V4(dst)),
        identification: Some(0x1000),
        fragmentation: FragmentSpec {
            mtu: Some(36),
            ..Default::default()
        },
        ..Default::default()
    };

    let spec = PacketSpec {
        target: DestinationSpec::default(),
        layer2: Layer2Spec::default(),
        ip: Some(ip_spec),
        ipv6: Ipv6Spec::default(),
        transport: TransportSpec::Icmp(IcmpSpec::default()),
        payload: PayloadSpec {
            source: PayloadSource::Empty,
        },
        transmit: TransmissionSpec::default(),
        listener: ListenerSpec::default(),
        rules_file: None,
        logging: LoggingSpec::default(),
    };

    let payload = vec![0u8; 48];
    let fragments = build_ipv4_packets(&spec, &payload, src, dst, IpNextHeaderProtocols::Udp)
        .expect("fragmentation should succeed");
    assert!(fragments.len() > 1);

    let first = Ipv4Packet::new(&fragments[0]).expect("first fragment invalid");
    assert_eq!(first.get_total_length(), (IPV4_HEADER_LEN + 16) as u16);
    assert!(first.get_flags() & pnet::packet::ipv4::Ipv4Flags::MoreFragments != 0);
    assert_eq!(first.get_fragment_offset(), 0);

    let last = Ipv4Packet::new(fragments.last().unwrap()).expect("last fragment invalid");
    assert_eq!(
        last.get_flags() & pnet::packet::ipv4::Ipv4Flags::MoreFragments,
        0
    );
    assert!(last.get_fragment_offset() > 0);
}

#[test]
fn metrics_snapshot_writes_json() {
    let temp = tempdir().expect("tempdir");
    let metrics_path = temp.path().join("metrics.json");

    let plan = TransmissionPlan {
        frames: vec![vec![0u8; 32], vec![0u8; 16]],
        link_type: LinkType::Ipv4,
        transmit: TransmissionSpec {
            count: Some(2),
            ..TransmissionSpec::default()
        },
        destination: NetworkTarget::Ipv4(Ipv4Addr::LOCALHOST),
        interface: NetworkInterface {
            name: "test0".to_string(),
            description: String::new(),
            index: 0,
            mac: None,
            ips: Vec::new(),
            flags: 0,
        },
        protocol: IpNextHeaderProtocols::Tcp,
        summary: TransmissionSummary {
            payload_len: 0,
            largest_frame_len: 32,
            frame_count: 2,
            transport: "TCP",
        },
        logging: LoggingSpec {
            log_file: None,
            pcap_write: None,
            metrics_json: Some(metrics_path.clone()),
            log_level: None,
            structured: false,
            prometheus_bind: None,
            allow_public_metrics: false,
        },
        mode: PlanningMode::Live,
        policy: TransmissionPolicy::default(),
    };

    emit_metrics_snapshot(&plan).expect("snapshot written");

    let data = fs::read_to_string(&metrics_path).expect("metrics file readable");
    let parsed: serde_json::Value = serde_json::from_str(&data).expect("valid json");
    assert_eq!(parsed["frames"]["per_iteration"], 2);
    assert_eq!(parsed["frames"]["bytes_per_iteration"], 48);
    assert_eq!(parsed["frames"]["largest"], 32);
    assert_eq!(parsed["mode"]["type"], "finite");
    assert_eq!(parsed["mode"]["attempts"], 2);
    assert_eq!(parsed["mode"]["units_per_attempt"], 2);
    assert_eq!(parsed["mode"]["total_emitted_units"], 4);
    assert_eq!(parsed["target"]["interface"], "test0");
}

#[test]
fn plan_transmission_assembles_tcp_packet() {
    let target = DestinationSpec {
        address: Some(TargetAddress::Ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)))),
        ..Default::default()
    };

    let ip_spec = IpSpec {
        source: Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 100))),
        ..Default::default()
    };

    let tcp_spec = TcpSpec {
        destination_port: Some(80),
        ..Default::default()
    };

    let spec = PacketSpec {
        target,
        layer2: Layer2Spec::default(),
        ip: Some(ip_spec),
        ipv6: Ipv6Spec::default(),
        transport: TransportSpec::Tcp(tcp_spec),
        payload: PayloadSpec {
            source: PayloadSource::Inline("test".to_string()),
        },
        transmit: TransmissionSpec::default(),
        listener: ListenerSpec::default(),
        rules_file: None,
        logging: LoggingSpec::default(),
    };

    let iface = make_interface(
        "test0",
        vec![IpNetwork::V4(
            Ipv4Network::new(Ipv4Addr::new(192, 0, 2, 100), 24).unwrap(),
        )],
    );

    let plan = plan_transmission_with_interface(&spec, iface, PlanningMode::Live)
        .expect("transmission plan");

    assert_eq!(plan.summary.transport, "TCP");
    assert_eq!(plan.frames.len(), 1);
    assert!(matches!(plan.link_type, LinkType::Ipv4));
    assert_eq!(plan.summary.payload_len, 4);
    assert_eq!(
        plan.summary.largest_frame_len,
        IPV4_HEADER_LEN + TCP_HEADER_LEN + 4
    );
}

#[test]
fn ipv6_fragmentation_preserves_extension_chain() {
    let mut ip_spec = IpSpec::default();
    ip_spec.fragmentation.mtu = Some(80);
    let spec = PacketSpec {
        target: DestinationSpec::default(),
        layer2: Layer2Spec::default(),
        ip: Some(ip_spec),
        ipv6: Ipv6Spec {
            exthdrs: vec![Ipv6ExtHeader::DestinationOptions {
                options: vec![0u8, 0u8],
            }],
        },
        transport: TransportSpec::Auto,
        payload: PayloadSpec {
            source: PayloadSource::Empty,
        },
        transmit: TransmissionSpec::default(),
        listener: ListenerSpec::default(),
        rules_file: None,
        logging: LoggingSpec::default(),
    };

    let payload = vec![0u8; 180];
    let packets = build_ipv6_packets(
        &spec,
        &payload,
        Ipv6Addr::LOCALHOST,
        Ipv6Addr::LOCALHOST,
        IpNextHeaderProtocols::Udp,
    )
    .expect("ipv6 fragments");

    assert!(packets.len() > 1, "expected multiple fragments");
    let mut offset = 0usize;
    for (index, packet) in packets.iter().enumerate() {
        let ipv6 = Ipv6Packet::new(packet).expect("valid ipv6 fragment");
        assert_eq!(ipv6.get_next_header(), IpNextHeaderProtocols::Ipv6Frag);
        let body = ipv6.payload();
        assert_eq!(body[0], IpNextHeaderProtocols::Ipv6Opts.0);

        if index == 0 {
            let dest_offset = IPV6_FRAGMENT_HEADER_LEN;
            assert_eq!(body[dest_offset], IpNextHeaderProtocols::Udp.0);
            let hdr_ext_units = body[dest_offset + 1] as usize + 1;
            let dest_header_len = hdr_ext_units * 8;
            assert_eq!(
                &body[dest_offset + 2..dest_offset + 4],
                &[0u8, 0u8],
                "destination options payload should be preserved",
            );
            let data = &body[dest_offset + dest_header_len..];
            let end = offset + data.len();
            assert_eq!(&payload[offset..end], data);
            offset = end;
        } else {
            let data = &body[IPV6_FRAGMENT_HEADER_LEN..];
            let end = offset + data.len();
            assert_eq!(&payload[offset..end], data);
            offset = end;
        }
    }
    assert_eq!(offset, payload.len());
}

#[test]
fn ipv4_fragment_offset_exceeding_maximum_is_rejected() {
    // IPv4 fragment offset field is 13 bits, so maximum value is 0x1FFF (8191).
    // This test ensures that offsets exceeding this limit are rejected.
    let spec = PacketSpec {
        target: DestinationSpec::default(),
        layer2: Layer2Spec::default(),
        ip: Some(IpSpec {
            destination: Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1))),
            identification: Some(12345),
            fragmentation: FragmentSpec {
                offset: Some(0x2000), // 8192, which is > 0x1FFF (8191)
                ..Default::default()
            },
            ..Default::default()
        }),
        ipv6: Ipv6Spec::default(),
        transport: TransportSpec::Auto,
        payload: PayloadSpec {
            source: PayloadSource::Inline("test".to_string()),
        },
        transmit: TransmissionSpec::default(),
        listener: ListenerSpec::default(),
        rules_file: None,
        logging: LoggingSpec::default(),
    };

    let transport = vec![0x00; 8];
    let err = build_ipv4_packets(
        &spec,
        &transport,
        Ipv4Addr::new(192, 0, 2, 1),
        Ipv4Addr::new(198, 51, 100, 1),
        IpNextHeaderProtocols::Udp,
    )
    .expect_err("IPv4 builder should reject fragment offset exceeding maximum");

    assert!(
        err.to_string()
            .contains("fragment offset exceeds maximum value"),
        "Error message should indicate fragment offset exceeds maximum, got: {}",
        err
    );
}

#[test]
fn build_icmpv6_segment_no_forced_u32_on_unknown_type() {
    use crate::engine::spec::Icmpv6Spec;
    use pnet::packet::icmpv6::Icmpv6Packet;
    use pnet::packet::Packet;
    use std::net::{IpAddr, Ipv6Addr};

    let spec = Icmpv6Spec {
        kind: Some(200), // Unknown/Custom type
        code: Some(0),
        identifier: None,
        sequence: None,
        parameter: None,
    };
    let payload = vec![0xAA, 0xBB, 0xCC, 0xDD];
    let src = IpAddr::V6(Ipv6Addr::LOCALHOST);
    let dst = IpAddr::V6(Ipv6Addr::LOCALHOST);

    let result = build_icmpv6_segment(&spec, &payload, src, dst).expect("ICMPv6 build failed");
    let packet = Icmpv6Packet::new(&result).expect("valid ICMPv6 packet");

    assert_eq!(
        result.len(),
        4 + payload.len(),
        "Packet length mismatch. Likely forced a u32 header. Got len {}, expected {}",
        result.len(),
        4 + payload.len()
    );

    let body = packet.payload();
    assert_eq!(body, payload.as_slice());
}

#[test]
fn tcp_options_not_overwritten_by_payload() {
    let options = vec![1, 2, 3, 4, 5, 6, 7, 8];
    let spec = TcpSpec {
        options: Some(options.clone()),
        ..Default::default()
    };
    let payload = vec![0xAA, 0xBB, 0xCC, 0xDD];
    let src = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let dst = IpAddr::V4(Ipv4Addr::LOCALHOST);

    let result = build_tcp_segment(&spec, &payload, src, dst).expect("TCP build failed");

    // Check options (raw bytes TCP_HEADER_LEN .. TCP_HEADER_LEN + options.len())
    let options_start = TCP_HEADER_LEN;
    let options_end = options_start + options.len();
    assert_eq!(
        &result[options_start..options_end],
        options.as_slice(),
        "Options were overwritten!"
    );

    // Check payload
    let payload_start = options_end;
    let payload_end = payload_start + payload.len();
    assert_eq!(
        &result[payload_start..payload_end],
        payload.as_slice(),
        "Payload was overwritten!"
    );
}
