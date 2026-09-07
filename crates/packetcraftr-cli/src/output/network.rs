// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Shared serialized interface, endpoint, and route representations.

use packetcraftr_core::packet::link::VlanTag;

use packetcraftr_core::packet::link::MacAddress;

use packetcraftr_netio::route::SelectionReason;

use packetcraftr_netio::route::Scope;

use packetcraftr_netio::link::Mode as LinkMode;

use packetcraftr_netio::link::Capability;

use packetcraftr_netio::interface::Id as InterfaceId;

use packetcraftr_netio::interface::Flags;

use std::net::IpAddr;

use serde::Serialize;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Interface {
    pub name: String,
    pub index: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mac: Option<String>,
    pub addresses: Vec<String>,
    pub flags: Flags,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mtu: Option<u32>,
    pub capability: Capability,
    pub link_type: u32,
}

impl From<packetcraftr_netio::interface::Info> for Interface {
    fn from(interface: packetcraftr_netio::interface::Info) -> Self {
        Self {
            name: interface.id.name,
            index: interface.id.index,
            description: interface.description,
            mac: interface.mac_address.map(|value| value.to_string()),
            addresses: interface
                .addresses
                .into_iter()
                .map(|value| format!("{}/{}", value.address, value.prefix_length))
                .collect(),
            flags: interface.flags,
            mtu: interface.mtu,
            capability: interface.capability,
            link_type: interface.link_type.0,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Decision {
    pub interface: InterfaceId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_mac: Option<MacAddress>,
    #[serde(rename = "selected_address")]
    pub selected_source: Option<IpAddr>,
    pub preferred_source: Option<IpAddr>,
    pub next_hop: Option<IpAddr>,
    pub selection_reason: SelectionReason,
    pub destination_scope: Scope,
    pub mtu: u32,
    pub capability: Capability,
    pub link_type: u32,
}

impl From<packetcraftr_netio::route::Decision> for Decision {
    fn from(value: packetcraftr_netio::route::Decision) -> Self {
        Self {
            interface: value.interface,
            source_mac: value.source_mac,
            selected_source: value.selected_source,
            preferred_source: value.preferred_source,
            next_hop: value.next_hop,
            selection_reason: value.selection_reason,
            destination_scope: value.destination_scope,
            mtu: value.mtu,
            capability: value.capability,
            link_type: value.link_type.0,
        }
    }
}

/// A materialized send path: the route that was selected, plus everything the
/// link layer needed on top of it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Plan {
    /// Serialized as `route`, which is also what [`super::plan::Report`] calls
    /// this whole plan one level up.
    #[serde(rename = "route")]
    pub decision: Decision,
    pub mode: LinkMode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lookup_destination: Option<IpAddr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub final_destination: Option<IpAddr>,
    pub visited_destinations: Vec<IpAddr>,
    pub packet_source: Option<IpAddr>,
    pub neighbor_source: Option<IpAddr>,
    pub neighbor_target: Option<IpAddr>,
    pub destination_mac: Option<MacAddress>,
    pub source_mac: Option<MacAddress>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub neighbor_vlan_tags: Vec<VlanTag>,
    pub synthesized_ethernet: bool,
}

impl From<packetcraftr_netio::route::Plan> for Plan {
    fn from(value: packetcraftr_netio::route::Plan) -> Self {
        Self {
            decision: value.decision.into(),
            mode: value.mode,
            lookup_destination: value.lookup_destination,
            final_destination: value.final_destination,
            visited_destinations: value.visited_destinations,
            packet_source: value.packet_source,
            neighbor_source: value.neighbor_source,
            neighbor_target: value.neighbor_target,
            destination_mac: value.destination_mac,
            source_mac: value.source_mac,
            neighbor_vlan_tags: value.neighbor_vlan_tags.into_iter().collect(),
            synthesized_ethernet: value.synthesized_ethernet,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The colour and wording of every text renderer follows `as_str`, so a
    /// serde rename that outran it would silently split the two views apart.
    #[test]
    fn link_text_spellings_match_the_serialized_document() {
        for mode in [LinkMode::Auto, LinkMode::Layer2, LinkMode::Layer3] {
            let serialized = serde_json::to_string(&mode).expect("mirror enums serialize");
            assert_eq!(serialized, format!("\"{}\"", mode.as_str()));
        }

        for capability in [
            Capability::Layer2,
            Capability::Layer3,
            Capability::Layer2AndLayer3,
        ] {
            let serialized = serde_json::to_string(&capability).expect("mirror enums serialize");
            assert_eq!(serialized, format!("\"{}\"", capability.as_str()));
        }
    }
}
