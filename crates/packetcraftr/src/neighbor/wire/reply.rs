// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! ARP replies and neighbor advertisements read through the dissector.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::neighbor::Request as NeighborRequest;
use crate::route::MAX_VLAN_TAGS;
use packetcraftr_core::decode::{self, DecodedPacket, Dissector};
use packetcraftr_core::diagnostic::ICMPV6_CHECKSUM;
use packetcraftr_core::frame::{Frame, LinkType};
use packetcraftr_core::layer::Layer;
use packetcraftr_core::packet::{MacAddress, VlanKind, VlanTag};
use packetcraftr_core::protocol::builtin;
use packetcraftr_core::protocol::link::{Arp, Ethernet, Vlan, Vlan8021ad};
use packetcraftr_core::protocol::network::{
    DestinationOptions, HopByHop, Icmpv6, Ipv6, SegmentRoutingHeader, ndp,
};
use packetcraftr_core::protocol::tunnel::Ah;

use super::is_unicast_mac;
use super::request::NDP_HOP_LIMIT;

const ARP_REPLY: u16 = 2;

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
    let ethernet = decoded.packet.layer(0)?.downcast_ref::<Ethernet>()?;
    let vlan_tags = decoded
        .packet
        .iter()
        .skip(1)
        .map_while(vlan_tag)
        .collect::<Vec<_>>();
    if vlan_tags.len() > MAX_VLAN_TAGS
        || ethernet.destination != request.interface_mac.0
        || !same_vlan_link(&vlan_tags, &request.vlan_tags)
    {
        return None;
    }
    let sender = MacAddress(ethernet.source);
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

fn vlan_tag(layer: &dyn Layer) -> Option<VlanTag> {
    if let Some(tag) = layer.downcast_ref::<Vlan>() {
        return Some(VlanTag {
            kind: VlanKind::Ieee8021Q,
            priority: tag.priority,
            drop_eligible: tag.drop_eligible,
            vlan_id: tag.vlan_id,
        });
    }
    layer.downcast_ref::<Vlan8021ad>().map(|tag| VlanTag {
        kind: VlanKind::Ieee8021Ad,
        priority: tag.priority,
        drop_eligible: tag.drop_eligible,
        vlan_id: tag.vlan_id,
    })
}

/// VLAN kind and ID identify the logical link. Priority and drop eligibility
/// are per-frame markings that a responder or switch may set independently.
fn same_vlan_link(captured: &[VlanTag], requested: &[VlanTag]) -> bool {
    captured.len() == requested.len()
        && captured.iter().zip(requested).all(|(captured, requested)| {
            captured.kind == requested.kind && captured.vlan_id == requested.vlan_id
        })
}

/// The sender of an Ethernet/IPv4 ARP reply from `target` to this request.
/// The codec only types Ethernet/IPv4 ARP, so other address families never
/// reach this check.
fn arp_reply(
    layer: &dyn Layer,
    request: &NeighborRequest,
    source: Ipv4Addr,
    target: Ipv4Addr,
) -> Option<MacAddress> {
    let arp = layer.downcast_ref::<Arp>()?;
    (arp.operation == ARP_REPLY
        && arp.sender_protocol == target
        && arp.target_protocol == source
        && arp.target_hardware == request.interface_mac.0)
        .then_some(MacAddress(arp.sender_hardware))
}

/// The target link-layer address of a solicited advertisement for `target`
/// sent to `interface_source` (RFC 4861 section 7.1.2).
///
/// Extension headers before the message are accepted when the codecs type
/// them. A fragment header refuses the reply: RFC 6980 requires receivers to
/// discard fragmented Neighbor Discovery messages.
fn advertisement(
    decoded: &DecodedPacket,
    network: usize,
    interface_source: Ipv6Addr,
    target: Ipv6Addr,
) -> Option<MacAddress> {
    let ipv6 = decoded.packet.layer(network)?.downcast_ref::<Ipv6>()?;
    if ipv6.hop_limit != NDP_HOP_LIMIT
        || ipv6.source.is_unspecified()
        || ipv6.source.is_multicast()
        || ipv6.destination != interface_source
    {
        return None;
    }
    let (index, icmp) = decoded
        .packet
        .iter()
        .enumerate()
        .skip(network + 1)
        .find(|(_, layer)| !is_unfragmented_extension(*layer))?;
    let icmp = icmp.downcast_ref::<Icmpv6>()?;
    let checksum_failed = decoded
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.code == ICMPV6_CHECKSUM && diagnostic.layer == Some(index));
    if checksum_failed || icmp.icmp_type != ndp::NEIGHBOR_ADVERTISEMENT || icmp.code != 0 {
        return None;
    }
    let advertisement = ndp::NeighborAdvertisement::decode(&icmp.body).ok()?;
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
    layer.is::<HopByHop>()
        || layer.is::<DestinationOptions>()
        || layer.is::<SegmentRoutingHeader>()
        || layer.is::<Ah>()
}
