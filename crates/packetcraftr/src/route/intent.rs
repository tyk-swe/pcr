// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::IpAddr;

use super::model::MAX_VLAN_TAGS;
use packetcraftr_core::{
    packet::{MacAddress, Packet, VlanTag},
    protocol::BuiltinProtocol,
    protocol::link::{Arp, Ethernet},
    protocol::semantics,
};

use super::error::Error;

pub(super) fn packet_has_link_layer_intent(packet: &Packet) -> bool {
    semantics::outer_layers(packet).any(|layer| {
        matches!(
            BuiltinProtocol::of(layer),
            Some(BuiltinProtocol::Ethernet | BuiltinProtocol::Vlan | BuiltinProtocol::Vlan8021ad)
        )
    })
}

/// The MAC addresses of the outer Ethernet header, as (source, destination);
/// an all-zero address counts as unset.
pub(super) fn outer_ethernet_macs(packet: &Packet) -> (Option<MacAddress>, Option<MacAddress>) {
    semantics::outer_layers(packet)
        .find_map(|layer| layer.downcast_ref::<Ethernet>())
        .map_or((None, None), |ethernet| {
            (set_mac(ethernet.source), set_mac(ethernet.destination))
        })
}

fn set_mac(value: [u8; 6]) -> Option<MacAddress> {
    (value != [0; 6]).then_some(MacAddress(value))
}

pub(super) fn extract_neighbor_vlan_tags(packet: &Packet) -> Result<Vec<VlanTag>, Error> {
    let tags = semantics::vlan_tags(packet).map_err(|source| Error::InvalidNeighborVlan {
        message: "the VLAN stack could not be read".to_owned(),
        source: Some(Box::new(source)),
    })?;
    if tags.len() > MAX_VLAN_TAGS {
        return Err(Error::InvalidNeighborVlan {
            message: format!("more than {MAX_VLAN_TAGS} VLAN headers are not supported"),
            source: None,
        });
    }
    Ok(tags)
}

pub(super) fn arp_link_macs(packet: &Packet) -> (Option<MacAddress>, Option<MacAddress>) {
    let Some(arp) = semantics::outer_layers(packet).find_map(|layer| layer.downcast_ref::<Arp>())
    else {
        return (None, None);
    };
    let target = set_mac(arp.target_hardware)
        .or_else(|| (arp.operation == 1).then_some(MacAddress([0xff; 6])));
    (set_mac(arp.sender_hardware), target)
}

pub(super) fn multicast_mac(destination: IpAddr) -> Option<MacAddress> {
    match destination {
        IpAddr::V4(address) if address.is_multicast() => {
            let octets = address.octets();
            Some(MacAddress([
                0x01,
                0x00,
                0x5e,
                octets[1] & 0x7f,
                octets[2],
                octets[3],
            ]))
        }
        IpAddr::V6(address) if address.is_multicast() => {
            let octets = address.octets();
            Some(MacAddress([
                0x33, 0x33, octets[12], octets[13], octets[14], octets[15],
            ]))
        }
        _ => None,
    }
}
