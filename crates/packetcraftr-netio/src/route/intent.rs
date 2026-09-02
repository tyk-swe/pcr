// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Packet and link-layer intent extraction helpers for route planning.

use std::net::IpAddr;

use packetcraftr_core::{Packet, field::FieldValue, packet::semantics, protocol::BuiltinProtocol};

use super::error::Error;
use crate::link::{MAX_VLAN_TAGS, MacAddress, VlanTag};

pub(super) fn packet_has_link_layer_intent(packet: &Packet) -> bool {
    semantics::outer_layers(packet).any(|layer| {
        matches!(
            BuiltinProtocol::of(layer),
            Some(BuiltinProtocol::Ethernet | BuiltinProtocol::Vlan | BuiltinProtocol::Vlan8021ad)
        )
    })
}

pub(super) fn outer_ethernet_mac(packet: &Packet, field: &str) -> Option<MacAddress> {
    semantics::outer_layers(packet)
        .find(|layer| BuiltinProtocol::of(*layer) == Some(BuiltinProtocol::Ethernet))
        .and_then(|layer| layer.field(field))
        .and_then(|value| match value {
            FieldValue::Mac(value) if value != [0; 6] => Some(MacAddress(value)),
            _ => None,
        })
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
    let Some(layer) = semantics::outer_layers(packet)
        .find(|layer| BuiltinProtocol::of(*layer) == Some(BuiltinProtocol::Arp))
    else {
        return (None, None);
    };
    let source = match layer.field("sender_hardware") {
        Some(FieldValue::Mac(value)) if value != [0; 6] => Some(MacAddress(value)),
        _ => None,
    };
    let operation = match layer.field("operation") {
        Some(FieldValue::Unsigned(value)) => Some(value),
        _ => None,
    };
    let target = match layer.field("target_hardware") {
        Some(FieldValue::Mac(value)) if value != [0; 6] => Some(MacAddress(value)),
        _ if operation == Some(1) => Some(MacAddress([0xff; 6])),
        _ => None,
    };
    (source, target)
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
