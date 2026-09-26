// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Shared serialized interface, endpoint, and route representations.

use std::net::IpAddr;

use serde::Serialize;

use packetcraftr_core::packet as library_packet;
use packetcraftr_netio::{interface, link, route};

use super::capture::TimestampSource;

/// A native interface, identified by its name and OS index.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
pub struct InterfaceId {
    pub name: String,
    pub index: u32,
}

impl From<interface::Id> for InterfaceId {
    fn from(value: interface::Id) -> Self {
        Self {
            name: value.name,
            index: value.index,
        }
    }
}

impl From<&interface::Id> for InterfaceId {
    fn from(value: &interface::Id) -> Self {
        value.clone().into()
    }
}

/// A requested interface publishes the half its selector names, leaving the
/// other half empty.
impl From<packetcraftr::route::Interface> for InterfaceId {
    fn from(value: packetcraftr::route::Interface) -> Self {
        match value {
            packetcraftr::route::Interface::Id(id) => id.into(),
            packetcraftr::route::Interface::Name(name) => Self { name, index: 0 },
            packetcraftr::route::Interface::Index(index) => Self {
                name: String::new(),
                index: index.get(),
            },
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize)]
pub struct Flags {
    pub up: bool,
    pub broadcast: bool,
    pub loopback: bool,
    pub point_to_point: bool,
    pub multicast: bool,
}

impl From<interface::Flags> for Flags {
    fn from(value: interface::Flags) -> Self {
        Self {
            up: value.up,
            broadcast: value.broadcast,
            loopback: value.loopback,
            point_to_point: value.point_to_point,
            multicast: value.multicast,
        }
    }
}

published_enum! {
    /// The link layers an interface can transmit at.
    pub enum Capability from link::Capability {
        Layer2 => "layer2",
        Layer3 => "layer3",
        Layer2AndLayer3 => "layer2_and3",
    }
}

published_enum! {
    /// The link layer a transmission uses or requested.
    pub enum LinkMode from link::Mode {
        Auto => "auto",
        Layer2 => "layer2",
        Layer3 => "layer3",
    }
}

published_enum! {
    /// Why a route lookup chose its next hop.
    pub enum SelectionReason from route::SelectionReason {
        Local => "local",
        OnLink => "on_link",
        Broadcast => "broadcast",
        Gateway => "gateway",
        InterfaceOnly => "interface_only",
    }
}

published_enum! {
    /// The address scope of a route's destination.
    pub enum Scope from route::Scope {
        Host => "host",
        Link => "link",
        Private => "private",
        Global => "global",
        Multicast => "multicast",
        Unspecified => "unspecified",
    }
}

/// A 48-bit MAC address, published as its six octets.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
pub struct MacAddress(pub [u8; 6]);

/// Colon-separated lowercase octets, as text output prints them.
impl std::fmt::Display for MacAddress {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let [a, b, c, d, e, f] = self.0;
        write!(formatter, "{a:02x}:{b:02x}:{c:02x}:{d:02x}:{e:02x}:{f:02x}")
    }
}

impl From<library_packet::MacAddress> for MacAddress {
    fn from(value: library_packet::MacAddress) -> Self {
        Self(value.0)
    }
}

published_enum! {
    /// The 802.1Q tag family a VLAN tag belongs to.
    pub enum VlanKind from library_packet::VlanKind {
        Ieee8021Q => "ieee8021_q",
        Ieee8021Ad => "ieee8021_ad",
    }
}

/// One VLAN tag a neighbor was resolved through.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
pub struct VlanTag {
    pub kind: VlanKind,
    pub priority: u8,
    pub drop_eligible: bool,
    pub vlan_id: u16,
}

impl From<library_packet::VlanTag> for VlanTag {
    fn from(value: library_packet::VlanTag) -> Self {
        Self {
            kind: value.kind.into(),
            priority: value.priority,
            drop_eligible: value.drop_eligible,
            vlan_id: value.vlan_id,
        }
    }
}

/// One packet timestamp type a native backend advertises for an interface.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct TimestampType {
    pub value: i32,
    pub name: Option<String>,
    pub description: Option<String>,
    pub source: Option<TimestampSource>,
}

impl From<packetcraftr_netio::capture::TimestampType> for TimestampType {
    fn from(value: packetcraftr_netio::capture::TimestampType) -> Self {
        Self {
            value: value.value,
            name: value.name,
            description: value.description,
            source: value.source.map(Into::into),
        }
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
    /// Timestamp types the capture backend advertises for this interface;
    /// present only when `interfaces --timestamp-types` enumerated them.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp_types: Option<Vec<TimestampType>>,
}

impl From<interface::Info> for Interface {
    fn from(interface: interface::Info) -> Self {
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
            timestamp_types: None,
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

impl From<route::Decision> for Decision {
    fn from(value: route::Decision) -> Self {
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

impl From<packetcraftr::route::Plan> for Plan {
    fn from(value: packetcraftr::route::Plan) -> Self {
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
