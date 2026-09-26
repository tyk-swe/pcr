// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! ARP requests and neighbor solicitations built from core layers.

use std::net::IpAddr;

use bytes::Bytes;

use crate::neighbor::Request as NeighborRequest;
use crate::neighbor::error::invalid_request;
use packetcraftr_core::build::{Builder, BuiltPacket, Options};
use packetcraftr_core::codec::Context;
use packetcraftr_core::field::WireValue;
use packetcraftr_core::layer::Padding;
use packetcraftr_core::packet::{MacAddress, Packet, VlanKind, VlanTag};
use packetcraftr_core::protocol::builtin;
use packetcraftr_core::protocol::link::{Arp, Ethernet, Vlan, Vlan8021ad};
use packetcraftr_core::protocol::network::{Ipv6, ndp};

/// Shortest Ethernet frame without its frame check sequence.
const ETHERNET_MINIMUM_WITHOUT_FCS: usize = 60;
pub(super) const ARP_REQUEST: u16 = 1;
/// Hop limit RFC 4861 requires on every Neighbor Discovery message.
pub(super) const NDP_HOP_LIMIT: u8 = 255;

pub(in crate::neighbor) fn build_request_frame(
    request: &NeighborRequest,
) -> Result<(Bytes, MacAddress), crate::neighbor::Error> {
    match (request.interface_source, request.target) {
        (IpAddr::V4(source), IpAddr::V4(target)) => {
            let destination = MacAddress([0xff; 6]);
            let mut packet = link_header(request, destination);
            let network = packet.len();
            packet.push(Arp {
                operation: ARP_REQUEST,
                sender_hardware: request.interface_mac.0,
                sender_protocol: source,
                target_hardware: [0; 6],
                target_protocol: target,
                ..Arp::default()
            });
            Ok((
                finish(request, packet, network, "ARP request")?,
                destination,
            ))
        }
        (IpAddr::V6(source), IpAddr::V6(target)) => {
            let group = ndp::solicited_node_multicast(target);
            let destination = MacAddress::for_ip_multicast(IpAddr::V6(group))
                .ok_or_else(|| invalid_request("solicited-node group is not multicast"))?;
            let solicitation = ndp::NeighborSolicitation {
                reserved: 0,
                target,
                options: vec![ndp::MessageOption::source_link_layer(request.interface_mac)],
            };
            let message = solicitation.to_icmpv6().map_err(|source| {
                invalid_request(format!("neighbor solicitation does not encode: {source}"))
            })?;
            let mut packet = link_header(request, destination);
            let network = packet.len();
            packet.push(Ipv6 {
                hop_limit: NDP_HOP_LIMIT,
                source,
                destination: group,
                ..Ipv6::default()
            });
            packet.push(message);
            let bytes = finish(request, packet, network, "IPv6 neighbor solicitation")?;
            Ok((bytes, destination))
        }
        _ => Err(invalid_request("source and target address families differ")),
    }
}

/// The Ethernet header and the request's VLAN tags, sent from the interface.
fn link_header(request: &NeighborRequest, destination: MacAddress) -> Packet {
    let mut packet = Packet::new();
    packet.push(Ethernet {
        destination: destination.0,
        source: request.interface_mac.0,
        ether_type: WireValue::Auto,
    });
    for tag in &request.vlan_tags {
        push_vlan(&mut packet, *tag);
    }
    packet
}

/// Builds `packet`, checks the bytes from its `network` layer on against the
/// route MTU, and pads the frame.
///
/// Padding brings the frame without its VLAN tags to the Ethernet minimum,
/// so a switch that strips the tags still forwards a full-size frame.
fn finish(
    request: &NeighborRequest,
    mut packet: Packet,
    network: usize,
    name: &str,
) -> Result<Bytes, crate::neighbor::Error> {
    let built = build_packet(packet.clone())?;
    let (Some(ethernet), Some(network)) = (built.layout.layer(0), built.layout.layer(network))
    else {
        return Err(invalid_request(format!("{name} has no network layer")));
    };
    let network_length = built.bytes.len().saturating_sub(network.range.start);
    if network_length > usize::try_from(request.mtu).unwrap_or(usize::MAX) {
        return Err(invalid_request(format!(
            "{name} is {network_length} bytes but route MTU is {}",
            request.mtu
        )));
    }
    let tags_length = network.range.start.saturating_sub(ethernet.range.end);
    let padding = (ETHERNET_MINIMUM_WITHOUT_FCS + tags_length).saturating_sub(built.bytes.len());
    if padding == 0 {
        return Ok(built.bytes);
    }
    packet.push(Padding::new(vec![0_u8; padding]));
    Ok(build_packet(packet)?.bytes)
}

fn push_vlan(packet: &mut Packet, tag: VlanTag) {
    let VlanTag {
        kind,
        priority,
        drop_eligible,
        vlan_id,
    } = tag;
    match kind {
        VlanKind::Ieee8021Q => packet.push(Vlan {
            priority,
            drop_eligible,
            vlan_id,
            ether_type: WireValue::Auto,
        }),
        VlanKind::Ieee8021Ad => packet.push(Vlan8021ad {
            priority,
            drop_eligible,
            vlan_id,
            ether_type: WireValue::Auto,
        }),
    };
}

fn build_packet(packet: Packet) -> Result<BuiltPacket, crate::neighbor::Error> {
    Builder::new(builtin::registry())
        .build(packet, Context::default(), Options::default())
        .map_err(|source| invalid_request(format!("discovery frame does not build: {source}")))
}
