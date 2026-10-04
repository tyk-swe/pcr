// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
#![allow(dead_code)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::SystemTime;

use bytes::Bytes;

use super::request::push_vlan;
use super::{build_request_frame, match_neighbor_response};
use crate::neighbor::{MAX_VLAN_TAGS, Request as NeighborRequest};
use packetcraftr_core::build::{Builder, Options};
use packetcraftr_core::codec::{Context, Mode};
use packetcraftr_core::field::WireValue;
use packetcraftr_core::frame::{Frame, LinkType};
use packetcraftr_core::layer::{Layer, Raw};
use packetcraftr_core::packet::{MacAddress, Packet, VlanKind, VlanTag};
use packetcraftr_core::protocol::builtin;
use packetcraftr_core::protocol::link::{Arp, Ethernet};
use packetcraftr_core::protocol::network::{Icmpv6, Ipv6, ndp};
use packetcraftr_netio::interface::Id as InterfaceId;

/// A stacked 802.1ad (PCP 5, DEI, VLAN 100) and 802.1Q (PCP 1, VLAN 200)
/// ARP request for 192.0.2.99, padded to the untagged Ethernet minimum.
const STACKED_ARP_REQUEST: [u8; 68] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x88, 0xa8, 0xb0, 0x64,
    0x81, 0x00, 0x20, 0xc8, 0x08, 0x06, 0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01, 0x02, 0x00,
    0x00, 0x00, 0x00, 0x01, 0xc0, 0x00, 0x02, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00,
    0x02, 0x63, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
];

/// An 802.1Q (PCP 3, DEI, VLAN 409) neighbor solicitation for 2001:db8::abcd.
const TAGGED_SOLICITATION: [u8; 90] = [
    0x33, 0x33, 0xff, 0x00, 0xab, 0xcd, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x81, 0x00, 0x71, 0x99,
    0x86, 0xdd, 0x60, 0x00, 0x00, 0x00, 0x00, 0x20, 0x3a, 0xff, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xff, 0x02, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xff, 0x00, 0xab, 0xcd, 0x87, 0x00, 0xc4, 0x8f, 0x00, 0x00,
    0x00, 0x00, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xab, 0xcd, 0x01, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
];

const CAPTURED_STACKED_ARP_REPLY: [u8; 68] = [
    0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x02, 0x88, 0xa8, 0xb0, 0x64,
    0x81, 0x00, 0x20, 0xc8, 0x08, 0x06, 0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x02, 0x02, 0x00,
    0x00, 0x00, 0x00, 0x02, 0xc0, 0x00, 0x02, 0x02, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0xc0, 0x00,
    0x02, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
];

/// A captured solicited advertisement for 2001:db8::2 on VLAN 409, remarked
/// to PCP 0, behind a Hop-by-Hop header and followed by link padding.
const CAPTURED_TAGGED_ADVERTISEMENT: [u8; 102] = [
    0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x02, 0x81, 0x00, 0x01, 0x99,
    0x86, 0xdd, 0x60, 0x00, 0x00, 0x00, 0x00, 0x28, 0x00, 0xff, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x3a, 0x00, 0x01, 0x04, 0x00, 0x00,
    0x00, 0x00, 0x88, 0x00, 0x8a, 0x71, 0x60, 0x00, 0x00, 0x00, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x02, 0x01, 0x02, 0x00, 0x00, 0x00,
    0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
];

const INTERFACE_MAC: MacAddress = MacAddress([0x02, 0, 0, 0, 0, 1]);
const SENDER: MacAddress = MacAddress([0x02, 0, 0, 0, 0, 2]);

fn request(source: IpAddr, target: IpAddr) -> NeighborRequest {
    NeighborRequest {
        interface: InterfaceId {
            name: "fixture0".to_owned(),
            index: 7,
        },
        interface_source: source,
        interface_mac: INTERFACE_MAC,
        target,
        vlan_tags: Vec::new(),
        mtu: 1_500,
        link_type: LinkType::ETHERNET,
    }
}

fn ipv4_request() -> NeighborRequest {
    request(
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)),
    )
}

fn ipv6_request() -> NeighborRequest {
    request(
        IpAddr::V6("2001:db8::1".parse().expect("source")),
        IpAddr::V6("2001:db8::2".parse().expect("target")),
    )
}

fn tag(kind: VlanKind, priority: u8, drop_eligible: bool, vlan_id: u16) -> VlanTag {
    VlanTag {
        kind,
        priority,
        drop_eligible,
        vlan_id,
    }
}

fn capture(bytes: impl Into<Bytes>) -> Frame {
    Frame::new(SystemTime::UNIX_EPOCH, LinkType::ETHERNET, bytes).expect("fixture frame must fit")
}

fn build(packet: Packet) -> Vec<u8> {
    Builder::new(builtin::registry())
        .build(packet, Context::default(), Options::default())
        .expect("fixture builds")
        .bytes
        .to_vec()
}

fn reply_link(request: &NeighborRequest, sender: MacAddress) -> Packet {
    let mut packet = Packet::new();
    packet.push(Ethernet {
        destination: request.interface_mac.0,
        source: sender.0,
        ether_type: WireValue::Auto,
    });
    for tag in &request.vlan_tags {
        push_vlan(&mut packet, *tag);
    }
    packet
}

fn arp_response(request: &NeighborRequest, sender: MacAddress) -> Vec<u8> {
    let (IpAddr::V4(interface_source), IpAddr::V4(target)) =
        (request.interface_source, request.target)
    else {
        panic!("ARP fixture must use IPv4")
    };
    let mut packet = reply_link(request, sender);
    packet.push(Arp {
        operation: 2,
        sender_hardware: sender.0,
        sender_protocol: target,
        target_hardware: request.interface_mac.0,
        target_protocol: interface_source,
        ..Arp::default()
    });
    build(packet)
}

fn advertisement(request: &NeighborRequest, sender: MacAddress) -> ndp::NeighborAdvertisement {
    let IpAddr::V6(target) = request.target else {
        panic!("NDP fixture must use IPv6")
    };
    ndp::NeighborAdvertisement {
        router: false,
        solicited: true,
        override_address: true,
        reserved: 0,
        target,
        options: vec![ndp::MessageOption::target_link_layer(sender)],
    }
}

fn advertisement_ipv6(request: &NeighborRequest) -> Ipv6 {
    let (IpAddr::V6(interface_source), IpAddr::V6(target)) =
        (request.interface_source, request.target)
    else {
        panic!("NDP fixture must use IPv6")
    };
    Ipv6 {
        hop_limit: 255,
        source: target,
        destination: interface_source,
        ..Ipv6::default()
    }
}

fn advertisement_frame(
    request: &NeighborRequest,
    sender: MacAddress,
    ipv6: Ipv6,
    extensions: Vec<Box<dyn Layer>>,
    message: Icmpv6,
) -> Vec<u8> {
    let mut packet = reply_link(request, sender);
    packet.push(ipv6);
    for extension in extensions {
        packet.push_boxed(extension);
    }
    packet.push(message);
    build(packet)
}

fn neighbor_advertisement(request: &NeighborRequest, sender: MacAddress) -> Vec<u8> {
    let message = advertisement(request, sender)
        .to_icmpv6()
        .expect("advertisement encodes");
    advertisement_frame(
        request,
        sender,
        advertisement_ipv6(request),
        Vec::new(),
        message,
    )
}

fn with_advertisement(
    request: &NeighborRequest,
    edit: impl FnOnce(&mut ndp::NeighborAdvertisement),
) -> Vec<u8> {
    let mut advertisement = advertisement(request, SENDER);
    edit(&mut advertisement);
    let message = advertisement.to_icmpv6().expect("advertisement encodes");
    advertisement_frame(
        request,
        SENDER,
        advertisement_ipv6(request),
        Vec::new(),
        message,
    )
}

fn with_ipv6(request: &NeighborRequest, edit: impl FnOnce(&mut Ipv6)) -> Vec<u8> {
    let mut ipv6 = advertisement_ipv6(request);
    edit(&mut ipv6);
    let message = advertisement(request, SENDER)
        .to_icmpv6()
        .expect("advertisement encodes");
    advertisement_frame(request, SENDER, ipv6, Vec::new(), message)
}

fn with_extensions(request: &NeighborRequest, extensions: Vec<Box<dyn Layer>>) -> Vec<u8> {
    let message = advertisement(request, SENDER)
        .to_icmpv6()
        .expect("advertisement encodes");
    advertisement_frame(
        request,
        SENDER,
        advertisement_ipv6(request),
        extensions,
        message,
    )
}

fn pad_n() -> Bytes {
    Bytes::from_static(&[1, 4, 0, 0, 0, 0])
}

fn advertisement_message(request: &NeighborRequest) -> Vec<u8> {
    let mut packet = Packet::new();
    packet.push(advertisement_ipv6(request));
    packet.push(
        advertisement(request, SENDER)
            .to_icmpv6()
            .expect("advertisement encodes"),
    );
    let built = Builder::new(builtin::registry())
        .build(packet, Context::default(), Options::default())
        .expect("advertisement builds");
    let start = built.layout.layer(1).expect("ICMPv6 layer").range.start;
    built.bytes[start..].to_vec()
}

fn opaque_payload_frame(
    request: &NeighborRequest,
    next_header: u8,
    extension: Option<Box<dyn Layer>>,
    payload: Vec<u8>,
) -> Vec<u8> {
    let mut packet = reply_link(request, SENDER);
    packet.push(Ipv6 {
        next_header: WireValue::Exact(next_header),
        ..advertisement_ipv6(request)
    });
    if let Some(extension) = extension {
        packet.push_boxed(extension);
    }
    packet.push(Raw::new(payload));
    Builder::new(builtin::registry())
        .build(
            packet,
            Context::default(),
            Options {
                mode: Mode::Permissive,
                ..Options::default()
            },
        )
        .expect("fixture builds")
        .bytes
        .to_vec()
}

#[test]
fn request_builder_rejects_family_and_mtu_mismatches() {
    // An ARP message is 28 bytes, a solicitation 40 + 32 bytes of IPv6.
    for (mut request, fits) in [(ipv4_request(), 28), (ipv6_request(), 72)] {
        request.mtu = fits;
        assert!(build_request_frame(&request).is_ok());
        request.mtu = fits - 1;
        let error = build_request_frame(&request).expect_err("MTU refusal");
        assert!(matches!(
            error,
            crate::neighbor::Error::InvalidRequest { .. }
        ));
        assert!(
            error
                .to_string()
                .ends_with(&format!("is {fits} bytes but route MTU is {}", fits - 1)),
            "{error}"
        );
    }

    let mixed = request(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(Ipv6Addr::LOCALHOST),
    );
    assert!(matches!(
        build_request_frame(&mixed),
        Err(crate::neighbor::Error::InvalidRequest { .. })
    ));
}

#[test]
fn replies_deeper_than_the_discovery_tag_limit_are_refused() {
    let mut request = ipv4_request();
    request.vlan_tags = vec![tag(VlanKind::Ieee8021Q, 0, false, 7); MAX_VLAN_TAGS + 1];
    assert_eq!(
        match_neighbor_response(&request, &capture(arp_response(&request, SENDER))),
        None
    );
    request.vlan_tags.pop();
    assert_eq!(
        match_neighbor_response(&request, &capture(arp_response(&request, SENDER))),
        Some(SENDER)
    );
}

#[test]
fn routed_neighbor_advertisements_are_not_local_replies() {
    use packetcraftr_core::protocol::network::SegmentRoutingHeader;
    let request = ipv6_request();
    let bytes = with_extensions(
        &request,
        vec![Box::new(SegmentRoutingHeader {
            segments_left: WireValue::Exact(1),
            segments: vec![
                "2001:db8::1".parse().unwrap(),
                "2001:db8::99".parse().unwrap(),
            ],
            ..Default::default()
        })],
    );
    assert_eq!(match_neighbor_response(&request, &capture(bytes)), None);
    assert_eq!(
        match_neighbor_response(&request, &capture(neighbor_advertisement(&request, SENDER))),
        Some(SENDER)
    );
}
