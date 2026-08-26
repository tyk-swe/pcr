// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Shared serialized interface and route representations.

use std::fmt;
use std::net::IpAddr;

use serde::Serialize;

use packetcraftr_netio::link::{Capability as LinkCapability, Mode as LinkMode};

/// Stable interface shape used by both the text and JSON renderers.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Flags {
    pub up: bool,
    pub broadcast: bool,
    pub loopback: bool,
    pub point_to_point: bool,
    pub multicast: bool,
}

impl From<packetcraftr_netio::interface::Flags> for Flags {
    fn from(value: packetcraftr_netio::interface::Flags) -> Self {
        Self {
            up: value.up,
            broadcast: value.broadcast,
            loopback: value.loopback,
            point_to_point: value.point_to_point,
            multicast: value.multicast,
        }
    }
}

mirror_enum! {
    #[serde(rename_all = "snake_case")]
    pub enum Capability from LinkCapability {
        Layer2 = Layer2,
        Layer3 = Layer3,
        #[serde(rename = "layer2_and3")]
        Layer2AndLayer3 = Layer2AndLayer3,
    }
}

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
            flags: interface.flags.into(),
            mtu: interface.mtu,
            capability: interface.capability.into(),
            link_type: interface.link_type.0,
        }
    }
}

/// Aggregate result of `plan`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct InterfaceId {
    pub name: String,
    pub index: u32,
}

impl From<packetcraftr_netio::interface::Id> for InterfaceId {
    fn from(value: packetcraftr_netio::interface::Id) -> Self {
        Self {
            name: value.name,
            index: value.index,
        }
    }
}

mirror_enum! {
    #[serde(rename_all = "snake_case")]
    pub enum SelectionReason from packetcraftr_netio::route::SelectionReason {
        Local = Local,
        OnLink = OnLink,
        Broadcast = Broadcast,
        Gateway = Gateway,
        InterfaceOnly = InterfaceOnly,
    }
}

mirror_enum! {
    #[serde(rename_all = "snake_case")]
    pub enum Scope from packetcraftr_netio::route::Scope {
        Host = Host,
        Link = Link,
        Private = Private,
        Global = Global,
        Multicast = Multicast,
        Unspecified = Unspecified,
    }
}

mirror_enum! {
    #[serde(rename_all = "snake_case")]
    pub enum Mode from LinkMode {
        Auto = Auto,
        Layer2 = Layer2,
        Layer3 = Layer3,
    }
}

/// Output-owned MAC representation that keeps the versioned JSON contract
/// independent from the routing model's representation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct MacAddress(pub [u8; 6]);

impl From<packetcraftr_netio::link::MacAddress> for MacAddress {
    fn from(value: packetcraftr_netio::link::MacAddress) -> Self {
        Self(value.0)
    }
}

impl fmt::Display for MacAddress {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = self.0;
        write!(
            formatter,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            value[0], value[1], value[2], value[3], value[4], value[5]
        )
    }
}

mirror_enum! {
    #[serde(rename_all = "snake_case")]
    pub enum VlanKind from packetcraftr_netio::neighbor::VlanKind {
        Ieee8021Q = Ieee8021Q,
        Ieee8021Ad = Ieee8021Ad,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct VlanTag {
    pub kind: VlanKind,
    pub priority: u8,
    pub drop_eligible: bool,
    pub vlan_id: u16,
}

impl From<packetcraftr_netio::neighbor::VlanTag> for VlanTag {
    fn from(value: packetcraftr_netio::neighbor::VlanTag) -> Self {
        Self {
            kind: value.kind.into(),
            priority: value.priority,
            drop_eligible: value.drop_eligible,
            vlan_id: value.vlan_id,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Decision {
    pub interface: InterfaceId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
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
            interface: value.interface.into(),
            source_mac: value.source_mac.map(Into::into),
            selected_source: value.selected_source,
            preferred_source: value.preferred_source,
            next_hop: value.next_hop,
            selection_reason: value.selection_reason.into(),
            destination_scope: value.destination_scope.into(),
            mtu: value.mtu,
            capability: value.capability.into(),
            link_type: value.link_type.0,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Plan {
    #[serde(rename = "route")]
    pub decision: Decision,
    pub mode: Mode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lookup_destination: Option<IpAddr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub final_destination: Option<IpAddr>,
    pub visited_destinations: Vec<IpAddr>,
    pub packet_source: Option<IpAddr>,
    pub neighbor_source: Option<IpAddr>,
    pub neighbor_target: Option<IpAddr>,
    pub destination_mac: Option<MacAddress>,
    pub source_mac: Option<MacAddress>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub neighbor_vlan_tags: Vec<VlanTag>,
    pub synthesized_ethernet: bool,
}

impl From<packetcraftr_netio::route::Plan> for Plan {
    fn from(value: packetcraftr_netio::route::Plan) -> Self {
        Self {
            decision: value.decision.into(),
            mode: value.mode.into(),
            lookup_destination: value.lookup_destination,
            final_destination: value.final_destination,
            visited_destinations: value.visited_destinations,
            packet_source: value.packet_source,
            neighbor_source: value.neighbor_source,
            neighbor_target: value.neighbor_target,
            destination_mac: value.destination_mac.map(Into::into),
            source_mac: value.source_mac.map(Into::into),
            neighbor_vlan_tags: value
                .neighbor_vlan_tags
                .into_iter()
                .map(Into::into)
                .collect(),
            synthesized_ethernet: value.synthesized_ethernet,
        }
    }
}
