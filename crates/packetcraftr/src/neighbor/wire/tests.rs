// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::SystemTime;

use bytes::Bytes;

use super::request::push_vlan;
use super::{build_request_frame, is_unicast_mac, match_neighbor_response};
use crate::neighbor::Request as NeighborRequest;
use crate::route::MAX_VLAN_TAGS;
use packetcraftr_core::build::{Builder, Options};
use packetcraftr_core::codec::{Context, Mode};
use packetcraftr_core::decode::{self, Dissector};
use packetcraftr_core::diagnostic::ICMPV6_CHECKSUM;
use packetcraftr_core::field::WireValue;
use packetcraftr_core::frame::{Frame, LinkType};
use packetcraftr_core::layer::{Layer, Raw};
use packetcraftr_core::packet::{MacAddress, Packet, VlanKind, VlanTag};
use packetcraftr_core::protocol::builtin;
use packetcraftr_core::protocol::link::{Arp, Ethernet};
use packetcraftr_core::protocol::network::{
    DestinationOptions, Fragment, HopByHop, Icmpv6, Ipv6, ndp,
};
use packetcraftr_core::protocol::tunnel::Ah;
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

/// A captured ARP reply from 192.0.2.2 on the stacked VLAN link, padded.
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
        deadline: None,
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

/// The Ethernet header and VLAN tags of a reply from `sender` to the
/// requesting interface.
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

/// The solicited advertisement `request` expects from `sender`.
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

/// The IPv6 header of an advertisement from the target to the requester.
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

/// An advertisement frame from `sender` with `ipv6`, `extensions`, and
/// `message`, its ICMPv6 checksum computed by the builder.
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

/// The expected advertisement's ICMPv6 bytes, checksummed for its IPv6
/// addresses, for frames that carry it as opaque payload.
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

/// A reply whose IPv6 payload after `extension` is the opaque `payload`.
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
fn arp_request_has_exact_broadcast_envelope_and_wire_fields() {
    let request = request(
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 99)),
    );
    let (frame, destination) = build_request_frame(&request).expect("ARP request");

    assert_eq!(destination, MacAddress([0xff; 6]));
    assert_eq!(
        frame.as_ref(),
        &[
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06,
            0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
            0xc0, 0x00, 0x02, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x02, 0x63,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ],
        "broadcast ARP request padded to the 60-byte Ethernet minimum"
    );
}

#[test]
fn neighbor_solicitation_uses_solicited_multicast_and_valid_checksum() {
    let request = request(
        IpAddr::V6("2001:db8::1".parse().expect("source")),
        IpAddr::V6("2001:db8::abcd".parse().expect("target")),
    );
    let (frame, destination) = build_request_frame(&request).expect("neighbor solicitation");

    assert_eq!(
        destination,
        MacAddress([0x33, 0x33, 0xff, 0x00, 0xab, 0xcd])
    );
    assert_eq!(
        frame.as_ref(),
        &[
            0x33, 0x33, 0xff, 0x00, 0xab, 0xcd, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x86, 0xdd,
            0x60, 0x00, 0x00, 0x00, 0x00, 0x20, 0x3a, 0xff, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xff, 0x02, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xff, 0x00, 0xab, 0xcd, 0x87, 0x00,
            0xc4, 0x8f, 0x00, 0x00, 0x00, 0x00, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xab, 0xcd, 0x01, 0x01, 0x02, 0x00, 0x00, 0x00,
            0x00, 0x01,
        ]
    );

    let decoded = Dissector::new(builtin::registry())
        .decode(capture(frame), decode::Options::default())
        .expect("solicitation dissects");
    assert!(
        decoded
            .diagnostics
            .iter()
            .all(|diagnostic| diagnostic.code != ICMPV6_CHECKSUM)
    );
    let ipv6 = decoded
        .packet
        .layer(1)
        .and_then(|layer| layer.downcast_ref::<Ipv6>());
    assert_eq!(
        ipv6.map(|ipv6| (ipv6.hop_limit, ipv6.destination)),
        Some((255, "ff02::1:ff00:abcd".parse().expect("group")))
    );
    let message = decoded
        .packet
        .layer(2)
        .and_then(|layer| layer.downcast_ref::<Icmpv6>())
        .expect("ICMPv6 message");
    assert_eq!(message.icmp_type, ndp::NEIGHBOR_SOLICITATION);
    let solicitation = ndp::NeighborSolicitation::decode(&message.body).expect("solicitation");
    assert_eq!(IpAddr::V6(solicitation.target), request.target);
    assert_eq!(
        solicitation.options,
        [ndp::MessageOption::source_link_layer(INTERFACE_MAC)]
    );
}

#[test]
fn vlan_tagged_requests_carry_the_stack_in_order_and_keep_untagged_padding() {
    let mut arp = request(
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 99)),
    );
    arp.vlan_tags = vec![
        tag(VlanKind::Ieee8021Ad, 5, true, 100),
        tag(VlanKind::Ieee8021Q, 1, false, 200),
    ];
    let (frame, _) = build_request_frame(&arp).expect("tagged ARP request");
    assert_eq!(frame.as_ref(), STACKED_ARP_REQUEST);

    let mut solicitation = request(
        IpAddr::V6("2001:db8::1".parse().expect("source")),
        IpAddr::V6("2001:db8::abcd".parse().expect("target")),
    );
    solicitation.vlan_tags = vec![tag(VlanKind::Ieee8021Q, 3, true, 409)];
    let (frame, _) = build_request_frame(&solicitation).expect("tagged solicitation");
    assert_eq!(frame.as_ref(), TAGGED_SOLICITATION);
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
fn arp_response_matcher_accepts_only_exact_correlated_evidence() {
    let request = ipv4_request();
    let bytes = arp_response(&request, SENDER);
    assert_eq!(
        match_neighbor_response(&request, &capture(bytes.clone())),
        Some(SENDER)
    );

    let mut wrong_operation = bytes.clone();
    wrong_operation[21] = 1;
    assert_eq!(
        match_neighbor_response(&request, &capture(wrong_operation)),
        None
    );

    let mut wrong_sender = bytes.clone();
    wrong_sender[6] ^= 1;
    assert_eq!(
        match_neighbor_response(&request, &capture(wrong_sender)),
        None
    );

    for (offset, field) in [
        (0, "Ethernet destination"),
        (31, "ARP sender address"),
        (37, "ARP target hardware address"),
        (41, "ARP target address"),
    ] {
        let mut mismatched = bytes.clone();
        mismatched[offset] ^= 1;
        assert_eq!(
            match_neighbor_response(&request, &capture(mismatched)),
            None,
            "{field} must correlate exactly"
        );
    }

    let mut non_ethernet = bytes.clone();
    non_ethernet[18] = 7;
    assert_eq!(
        match_neighbor_response(&request, &capture(non_ethernet)),
        None,
        "only Ethernet/IPv4 ARP is evidence"
    );

    let mut multicast_sender = bytes.clone();
    multicast_sender[6] |= 1;
    multicast_sender[22] |= 1;
    assert_eq!(
        match_neighbor_response(&request, &capture(multicast_sender)),
        None
    );

    let mut wrong_interface = capture(bytes.clone());
    wrong_interface.interface = Some(request.interface.index + 1);
    assert_eq!(match_neighbor_response(&request, &wrong_interface), None);

    let wrong_link =
        Frame::new(SystemTime::UNIX_EPOCH, LinkType::RAW, bytes).expect("fixture frame");
    assert_eq!(match_neighbor_response(&request, &wrong_link), None);

    let mut tagged = request.clone();
    tagged
        .vlan_tags
        .push(tag(VlanKind::Ieee8021Q, 3, true, 409));
    let tagged_bytes = arp_response(&tagged, SENDER);
    assert_eq!(
        match_neighbor_response(&tagged, &capture(tagged_bytes.clone())),
        Some(SENDER)
    );
    assert_eq!(
        match_neighbor_response(&request, &capture(tagged_bytes)),
        None
    );
}

#[test]
fn captured_vlan_tagged_replies_resolve_their_sender() {
    let mut arp = ipv4_request();
    arp.vlan_tags = vec![
        tag(VlanKind::Ieee8021Ad, 5, true, 100),
        tag(VlanKind::Ieee8021Q, 1, false, 200),
    ];
    assert_eq!(
        match_neighbor_response(&arp, &capture(CAPTURED_STACKED_ARP_REPLY.to_vec())),
        Some(SENDER)
    );
    arp.vlan_tags.reverse();
    assert_eq!(
        match_neighbor_response(&arp, &capture(CAPTURED_STACKED_ARP_REPLY.to_vec())),
        None,
        "tag order identifies the link"
    );

    let mut ndp = ipv6_request();
    ndp.vlan_tags = vec![tag(VlanKind::Ieee8021Q, 3, true, 409)];
    assert_eq!(
        match_neighbor_response(&ndp, &capture(CAPTURED_TAGGED_ADVERTISEMENT.to_vec())),
        Some(SENDER),
        "the Hop-by-Hop header, remarked PCP, and link padding are accepted"
    );
    ndp.vlan_tags[0].vlan_id = 410;
    assert_eq!(
        match_neighbor_response(&ndp, &capture(CAPTURED_TAGGED_ADVERTISEMENT.to_vec())),
        None
    );
}

#[test]
fn neighbor_response_matches_the_vlan_link_not_its_per_frame_priority() {
    let mut request = ipv4_request();
    request
        .vlan_tags
        .push(tag(VlanKind::Ieee8021Q, 5, true, 100));
    let reply_on = |tags: Vec<VlanTag>| {
        let mut responder = request.clone();
        responder.vlan_tags = tags;
        capture(arp_response(&responder, SENDER))
    };
    let tag = request.vlan_tags[0];

    let remarked = VlanTag {
        priority: 0,
        drop_eligible: false,
        ..tag
    };
    assert_eq!(
        match_neighbor_response(&request, &reply_on(vec![remarked])),
        Some(SENDER),
        "PCP and DEI are per-frame markings a responder may change"
    );
    for (other_link, field) in [
        (
            vec![VlanTag {
                vlan_id: 101,
                ..tag
            }],
            "VLAN ID",
        ),
        (
            vec![VlanTag {
                kind: VlanKind::Ieee8021Ad,
                ..tag
            }],
            "TPID kind",
        ),
        (vec![tag, tag], "tag depth"),
    ] {
        assert_eq!(
            match_neighbor_response(&request, &reply_on(other_link)),
            None,
            "{field} identifies the logical link"
        );
    }
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
fn neighbor_advertisement_matcher_validates_flags_checksum_and_option() {
    let request = ipv6_request();
    let bytes = neighbor_advertisement(&request, SENDER);
    assert_eq!(
        match_neighbor_response(&request, &capture(bytes.clone())),
        Some(SENDER)
    );

    let mut bad_checksum = bytes;
    *bad_checksum.last_mut().expect("last option byte") ^= 1;
    assert_eq!(
        match_neighbor_response(&request, &capture(bad_checksum)),
        None
    );

    let other_host = "2001:db8::3".parse::<Ipv6Addr>().expect("address");
    for (reply, field) in [
        (with_ipv6(&request, |ipv6| ipv6.hop_limit = 64), "hop limit"),
        (
            with_ipv6(&request, |ipv6| ipv6.source = Ipv6Addr::UNSPECIFIED),
            "unspecified source",
        ),
        (
            with_ipv6(&request, |ipv6| {
                ipv6.source = "ff02::1".parse().expect("group");
            }),
            "multicast source",
        ),
        (
            with_ipv6(&request, |ipv6| ipv6.destination = other_host),
            "IPv6 destination",
        ),
        (
            with_advertisement(&request, |advertisement| advertisement.solicited = false),
            "solicited flag",
        ),
        (
            with_advertisement(&request, |advertisement| advertisement.target = other_host),
            "advertised target",
        ),
        (
            with_advertisement(&request, |advertisement| {
                advertisement.options = vec![ndp::MessageOption::Other {
                    kind: 99,
                    value: Bytes::from_static(&[0; 6]),
                }];
            }),
            "target link-layer option",
        ),
        (
            with_advertisement(&request, |advertisement| {
                advertisement.options = vec![ndp::MessageOption::TargetLinkLayerAddress(
                    Bytes::from_static(&[0x02, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0]),
                )];
            }),
            "Ethernet-sized target link-layer option",
        ),
        (
            with_advertisement(&request, |advertisement| {
                advertisement
                    .options
                    .push(ndp::MessageOption::target_link_layer(MacAddress([
                        0x02, 0, 0, 0, 0, 3,
                    ])));
            }),
            "conflicting target link-layer options",
        ),
    ] {
        assert_eq!(
            match_neighbor_response(&request, &capture(reply)),
            None,
            "{field} must be valid"
        );
    }

    let repeated = with_advertisement(&request, |advertisement| {
        advertisement
            .options
            .insert(0, ndp::MessageOption::source_link_layer(SENDER));
        advertisement
            .options
            .push(ndp::MessageOption::target_link_layer(SENDER));
    });
    assert_eq!(
        match_neighbor_response(&request, &capture(repeated)),
        Some(SENDER),
        "other options and repeated agreeing options are accepted"
    );

    let mut body = advertisement(&request, SENDER)
        .encode()
        .expect("advertisement encodes")
        .to_vec();
    // A zero-length option, which no NDP encoder produces.
    body.extend_from_slice(&[ndp::TARGET_LINK_LAYER_ADDRESS, 0, 0, 0, 0, 0, 0, 0]);
    let zero_length_option = advertisement_frame(
        &request,
        SENDER,
        advertisement_ipv6(&request),
        Vec::new(),
        Icmpv6 {
            icmp_type: ndp::NEIGHBOR_ADVERTISEMENT,
            code: 0,
            checksum: WireValue::Auto,
            body: body.into(),
        },
    );
    assert_eq!(
        match_neighbor_response(&request, &capture(zero_length_option)),
        None
    );
}

#[test]
fn neighbor_advertisement_accepts_extensions_and_rejects_fragments() {
    let request = ipv6_request();
    let accepted: Vec<(Vec<Box<dyn Layer>>, &str)> = vec![
        (
            vec![Box::new(HopByHop {
                next_header: WireValue::Auto,
                options: pad_n(),
            })],
            "Hop-by-Hop",
        ),
        (
            vec![Box::new(DestinationOptions {
                next_header: WireValue::Auto,
                options: pad_n(),
            })],
            "Destination Options",
        ),
        (vec![Box::new(Ah::default())], "Authentication Header"),
        (
            vec![
                Box::new(HopByHop {
                    next_header: WireValue::Auto,
                    options: pad_n(),
                }),
                Box::new(Ah::default()),
                Box::new(DestinationOptions {
                    next_header: WireValue::Auto,
                    options: pad_n(),
                }),
            ],
            "extension chain",
        ),
    ];
    for (extensions, chain) in accepted {
        assert_eq!(
            match_neighbor_response(&request, &capture(with_extensions(&request, extensions))),
            Some(SENDER),
            "{chain}"
        );
    }

    let unfragmented = opaque_payload_frame(&request, 58, None, advertisement_message(&request));
    assert_eq!(
        match_neighbor_response(&request, &capture(unfragmented)),
        Some(SENDER)
    );
    // RFC 6980: fragmented NDP is discarded, including an atomic fragment.
    for fragment in [
        Fragment::default(),
        Fragment {
            more_fragments: true,
            identification: 9,
            ..Fragment::default()
        },
    ] {
        let fragmented = opaque_payload_frame(
            &request,
            44,
            Some(Box::new(Fragment {
                next_header: WireValue::Exact(58),
                ..fragment
            })),
            advertisement_message(&request),
        );
        assert_eq!(
            match_neighbor_response(&request, &capture(fragmented)),
            None
        );
    }
}

#[test]
fn advertisements_the_codecs_cannot_reach_are_refused() {
    let request = ipv6_request();
    let home = "2001:db8::9".parse::<Ipv6Addr>().expect("home address");
    // A type 2 routing header with one segment left: the datagram is not at
    // its final destination, and no codec types it.
    let mut routed = vec![58, 2, 2, 1, 0, 0, 0, 0];
    routed.extend_from_slice(&home.octets());
    routed.extend(advertisement_message(&request));
    let routed = opaque_payload_frame(&request, 43, None, routed);
    assert_eq!(match_neighbor_response(&request, &capture(routed)), None);

    let mut truncated = neighbor_advertisement(&request, SENDER);
    truncated.truncate(truncated.len() - 1);
    assert_eq!(match_neighbor_response(&request, &capture(truncated)), None);

    let mut padded = neighbor_advertisement(&request, SENDER);
    padded.extend_from_slice(&[0; 3]);
    assert_eq!(
        match_neighbor_response(&request, &capture(padded)),
        Some(SENDER),
        "link padding after the declared IPv6 payload is ignored"
    );
}

#[test]
fn mac_validation_accepts_only_individual_addresses() {
    assert!(is_unicast_mac(MacAddress([0x02, 0, 0, 0, 0, 1])));
    assert!(!is_unicast_mac(MacAddress([0; 6])));
    assert!(!is_unicast_mac(MacAddress([0xff; 6])));
    assert!(!is_unicast_mac(MacAddress([0x01, 0, 0, 0, 0, 1])));
}
