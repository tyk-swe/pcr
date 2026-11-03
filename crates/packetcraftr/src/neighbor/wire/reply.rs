// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr_core::protocol::BuiltinProtocol;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::neighbor::{MAX_VLAN_TAGS, Request as NeighborRequest};
use packetcraftr_core::decode::{self, DecodedPacket, Dissector};
use packetcraftr_core::diagnostic::ICMPV6_CHECKSUM;
use packetcraftr_core::frame::{Frame, LinkType};
use packetcraftr_core::layer::Layer;
use packetcraftr_core::packet::{MacAddress, VlanTag};
use packetcraftr_core::protocol::builtin;
use packetcraftr_core::protocol::identity::{self, NetworkHeader};
use packetcraftr_core::protocol::link::Arp;
use packetcraftr_core::protocol::network::ndp;

use super::is_unicast_mac;
use super::request::NDP_HOP_LIMIT;

pub(in crate::neighbor) fn match_neighbor_response(
    request: &NeighborRequest,
    frame: &Frame,
) -> Option<MacAddress> {
    if frame.link_type != LinkType::ETHERNET
        || frame
            .interface
            .is_some_and(|index| index != request.interface.index)
    {
        return None;
    }
    let decoded = Dissector::new(builtin::registry())
        .decode(frame.clone(), decode::Options::default())
        .ok()?;
    let (source, destination) = identity::link_addresses(decoded.packet.layer(0)?)?;
    let vlan_tags = decoded
        .packet
        .iter()
        .skip(1)
        .map_while(identity::vlan_tag)
        .collect::<Vec<_>>();
    if vlan_tags.len() > MAX_VLAN_TAGS
        || destination != request.interface_mac.0
        || !same_vlan_link(&vlan_tags, &request.vlan_tags)
    {
        return None;
    }
    let sender = MacAddress(source);
    let network = 1 + vlan_tags.len();
    let responder = match (request.interface_source, request.target) {
        (IpAddr::V4(source), IpAddr::V4(target)) => {
            arp_reply(decoded.packet.layer(network)?, request, source, target)?
        }
        (IpAddr::V6(source), IpAddr::V6(target)) => {
            advertisement(&decoded, network, source, target)?
        }
        _ => return None,
    };
    (responder == sender && is_unicast_mac(responder)).then_some(responder)
}

/// VLAN kind and ID identify the logical link. Priority and drop eligibility
/// are per-frame markings that a responder or switch may set independently.
fn same_vlan_link(captured: &[VlanTag], requested: &[VlanTag]) -> bool {
    captured.len() == requested.len()
        && captured.iter().zip(requested).all(|(captured, requested)| {
            captured.kind == requested.kind && captured.vlan_id == requested.vlan_id
        })
}

fn arp_reply(
    layer: &dyn Layer,
    request: &NeighborRequest,
    source: Ipv4Addr,
    target: Ipv4Addr,
) -> Option<MacAddress> {
    let arp = identity::arp_message(layer)?;
    (arp.operation == Arp::OPERATION_REPLY
        && arp.sender_protocol == target
        && arp.target_protocol == source
        && arp.target_hardware == request.interface_mac.0)
        .then_some(MacAddress(arp.sender_hardware))
}

/// A fragment header refuses the reply: RFC 6980 requires receivers to
/// discard fragmented Neighbor Discovery messages.
fn advertisement(
    decoded: &DecodedPacket,
    network: usize,
    interface_source: Ipv6Addr,
    target: Ipv6Addr,
) -> Option<MacAddress> {
    let Some(NetworkHeader::V6 {
        source,
        destination,
        hop_limit,
        ..
    }) = identity::network_header(decoded.packet.layer(network)?)
    else {
        return None;
    };
    if hop_limit != NDP_HOP_LIMIT
        || source.is_unspecified()
        || source.is_multicast()
        || destination != interface_source
    {
        return None;
    }
    let (index, icmp) = decoded
        .packet
        .iter()
        .enumerate()
        .skip(network + 1)
        .find(|(_, layer)| !is_unfragmented_extension(*layer))?;
    let icmp = identity::icmp_message(icmp)
        .filter(|message| message.protocol == BuiltinProtocol::Icmpv6)?;
    let checksum_failed = decoded
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.code == ICMPV6_CHECKSUM && diagnostic.layer == Some(index));
    if checksum_failed || icmp.icmp_type != ndp::NEIGHBOR_ADVERTISEMENT || icmp.code != 0 {
        return None;
    }
    let advertisement = ndp::NeighborAdvertisement::decode(icmp.body).ok()?;
    if !advertisement.solicited
        || advertisement.target != target
        || advertisement.target.is_multicast()
    {
        return None;
    }
    let mut target_mac = None;
    for option in &advertisement.options {
        if let ndp::MessageOption::TargetLinkLayerAddress(_) = option {
            let mac = option.ethernet_address()?;
            if target_mac.is_some_and(|existing| existing != mac) {
                return None;
            }
            target_mac = Some(mac);
        }
    }
    target_mac
}

fn is_unfragmented_extension(layer: &dyn Layer) -> bool {
    BuiltinProtocol::Ipv6HopByHop.identifies(layer)
        || BuiltinProtocol::Ipv6DestinationOptions.identifies(layer)
        || BuiltinProtocol::Ipv6Srh.identifies(layer)
        || BuiltinProtocol::Ah.identifies(layer)
}
