// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr::engine::spec::{
    FragmentSpec, Icmpv6Spec, IpSpec, Ipv6ExtHeader, Ipv6Spec, Layer2Spec, PayloadSource,
    PayloadSpec, TransmissionSpec, TransportSpec, UdpSpec,
};
use packetcraftr::network::sender::{
    plan_transmission_with_interface, LinkType, NetworkTarget, PlanningMode,
};
use pnet::datalink::MacAddr;
use pnet::ipnetwork::{IpNetwork, Ipv4Network, Ipv6Network};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::Packet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
mod common;
use common::{base_spec, mock_interface};

#[test]
fn dry_run_ipv4_plan_skips_arp_resolution() {
    let mut spec = base_spec();
    let src_ip = Ipv4Addr::new(192, 0, 2, 1);
    let dst_ip = Ipv4Addr::new(198, 51, 100, 10);

    spec.target.address = Some(packetcraftr::engine::spec::TargetAddress::Ip(IpAddr::V4(
        dst_ip,
    )));
    spec.ip = Some(packetcraftr::engine::spec::IpSpec {
        source: Some(IpAddr::V4(src_ip)),
        ..Default::default()
    });

    let interface = mock_interface(
        "test0",
        None,
        vec![IpNetwork::V4(Ipv4Network::new(src_ip, 24).unwrap())],
    );

    let plan = plan_transmission_with_interface(&spec, interface, PlanningMode::DryRun)
        .expect("dry-run plan should succeed");

    assert!(matches!(plan.destination, NetworkTarget::Ipv4(addr) if addr == dst_ip));
    assert!(!plan.frames.is_empty(), "frames should be constructed");
    assert_eq!(plan.mode, PlanningMode::DryRun);
}

#[test]
fn ipv4_plan_with_mock_interface_builds_ethernet() {
    let mut spec = base_spec();
    let src_ip = Ipv4Addr::new(192, 0, 2, 1);
    let dst_ip = Ipv4Addr::new(198, 51, 100, 10);
    let src_mac = MacAddr::new(0, 1, 2, 3, 4, 5);
    let dst_mac = MacAddr::new(10, 11, 12, 13, 14, 15);

    spec.ip = Some(IpSpec {
        source: Some(IpAddr::V4(src_ip)),
        destination: Some(IpAddr::V4(dst_ip)),
        prefer_ipv6: None,
        ttl: Some(64),
        tos: None,
        identification: Some(0x1000),
        fragmentation: FragmentSpec::default(),
    });
    spec.layer2 = Layer2Spec {
        source: Some(src_mac),
        destination: Some(dst_mac),
        ethertype: None,
        vlan: None,
    };
    spec.transport = TransportSpec::Udp(UdpSpec {
        source_port: Some(1234),
        destination_port: Some(4321),
    });
    spec.payload = PayloadSpec {
        source: PayloadSource::Inline("hello".to_string()),
    };

    let interface = mock_interface(
        "test0",
        Some(src_mac),
        vec![IpNetwork::V4(Ipv4Network::new(src_ip, 24).unwrap())],
    );

    let plan = plan_transmission_with_interface(&spec, interface, PlanningMode::Live)
        .expect("plan should succeed");

    assert!(matches!(plan.destination, NetworkTarget::Ipv4(addr) if addr == dst_ip));
    assert!(matches!(plan.link_type, LinkType::Ethernet));
    assert!(!plan.frames.is_empty(), "frames should be constructed");
    let frame = &plan.frames[0];
    assert!(frame.len() > 14);
    assert_eq!(&frame[0..6], &dst_mac.octets());
    assert_eq!(&frame[6..12], &src_mac.octets());
    assert_eq!(plan.summary.transport, "UDP");
}

#[test]
fn ipv6_plan_without_layer2_prefers_layer3() {
    let mut spec = base_spec();
    let src_ip = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
    let dst_ip = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2);

    spec.ip = Some(IpSpec {
        source: Some(IpAddr::V6(src_ip)),
        destination: Some(IpAddr::V6(dst_ip)),
        prefer_ipv6: None,
        ttl: Some(64),
        tos: None,
        identification: None,
        fragmentation: FragmentSpec::default(),
    });
    spec.transport = TransportSpec::Icmpv6(Icmpv6Spec::default());
    spec.transmit = TransmissionSpec {
        count: None,
        interval: None,
        flood: false,
        loop_send: false,
        force_layer3: true,
        ipv6_nd: false,
        auto_layer3: true,
    };

    let interface = mock_interface(
        "test1",
        None,
        vec![IpNetwork::V6(Ipv6Network::new(src_ip, 64).unwrap())],
    );

    let plan = plan_transmission_with_interface(&spec, interface, PlanningMode::Live)
        .expect("plan should succeed");

    assert!(matches!(plan.link_type, LinkType::Ipv6));
    assert!(plan.summary.frame_count > 0);
    assert!(plan.transmit.is_layer3());
    assert!(plan.transmit.auto_layer3);
}

#[test]
fn ipv6_end_to_end_plan_builds_routing_extension_chain() {
    let mut spec = base_spec();
    let src_ip = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x10);
    let first_hop = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x20);
    let second_hop = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x30);
    let final_destination = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x99);

    spec.ip = Some(IpSpec {
        source: Some(IpAddr::V6(src_ip)),
        destination: Some(IpAddr::V6(final_destination)),
        prefer_ipv6: None,
        ttl: Some(64),
        tos: None,
        identification: None,
        fragmentation: FragmentSpec::default(),
    });
    spec.ipv6 = Ipv6Spec {
        exthdrs: vec![
            Ipv6ExtHeader::DestinationOptions {
                options: vec![0xde, 0xad, 0xbe, 0xef],
            },
            Ipv6ExtHeader::Routing {
                routing_type: 2,
                segments: vec![first_hop, second_hop],
                data: None,
            },
        ],
    };
    spec.transport = TransportSpec::Udp(UdpSpec {
        source_port: Some(1234),
        destination_port: Some(4321),
    });
    spec.payload = PayloadSpec {
        source: PayloadSource::Inline("payload".to_string()),
    };
    spec.transmit.force_layer3 = true;

    let interface = mock_interface(
        "test2",
        None,
        vec![IpNetwork::V6(Ipv6Network::new(src_ip, 64).unwrap())],
    );

    let plan = plan_transmission_with_interface(&spec, interface, PlanningMode::Live)
        .expect("plan should succeed");

    assert!(matches!(plan.link_type, LinkType::Ipv6));
    assert!(matches!(plan.destination, NetworkTarget::Ipv6(addr) if addr == first_hop));
    assert_eq!(plan.summary.transport, "UDP");
    assert!(!plan.frames.is_empty(), "frames should be constructed");

    let ipv6 = Ipv6Packet::new(&plan.frames[0]).expect("valid ipv6 packet");
    assert_eq!(ipv6.get_destination(), first_hop);
    assert_eq!(ipv6.get_next_header(), IpNextHeaderProtocols::Ipv6Opts);

    let body = ipv6.payload();
    assert_eq!(body[0], IpNextHeaderProtocols::Ipv6Route.0);

    let routing_offset = 8; // destination options header is 8 bytes when aligned without options
    assert_eq!(body[routing_offset], IpNextHeaderProtocols::Udp.0);
    assert_eq!(body[routing_offset + 2], 2); // routing type
    assert_eq!(body[routing_offset + 3], 2); // segments left

    let mut encoded_second = [0u8; 16];
    encoded_second.copy_from_slice(&body[routing_offset + 8..routing_offset + 24]);
    assert_eq!(Ipv6Addr::from(encoded_second), second_hop);

    let mut encoded_final = [0u8; 16];
    encoded_final.copy_from_slice(&body[routing_offset + 24..routing_offset + 40]);
    assert_eq!(Ipv6Addr::from(encoded_final), final_destination);
}
