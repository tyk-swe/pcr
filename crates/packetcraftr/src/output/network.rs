// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Shared serialized interface and route representations.

use std::fmt;
use std::net::IpAddr;

use serde::Serialize;

use packetcraftr_netio::{
    interface::{Flags as InterfaceFlags, Id as InterfaceId, Info as InterfaceInfo},
    link::{Capability as LinkCapability, Mode as LinkMode},
    route::{Decision as RouteDecision, Plan as PlannedRoute},
};

/// Stable interface shape used by both the text and JSON renderers.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct InterfaceFlagsOutput {
    pub up: bool,
    pub broadcast: bool,
    pub loopback: bool,
    pub point_to_point: bool,
    pub multicast: bool,
}

impl From<InterfaceFlags> for InterfaceFlagsOutput {
    fn from(value: InterfaceFlags) -> Self {
        Self {
            up: value.up,
            broadcast: value.broadcast,
            loopback: value.loopback,
            point_to_point: value.point_to_point,
            multicast: value.multicast,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InterfaceCapabilityOutput {
    Layer2,
    Layer3,
    Layer2And3,
}

impl From<LinkCapability> for InterfaceCapabilityOutput {
    fn from(value: LinkCapability) -> Self {
        match value {
            LinkCapability::Layer2 => Self::Layer2,
            LinkCapability::Layer3 => Self::Layer3,
            LinkCapability::Layer2And3 => Self::Layer2And3,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct InterfaceOutput {
    pub name: String,
    pub index: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mac: Option<String>,
    pub addresses: Vec<String>,
    pub flags: InterfaceFlagsOutput,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mtu: Option<u32>,
    pub capability: InterfaceCapabilityOutput,
    pub link_type: u32,
}

impl From<InterfaceInfo> for InterfaceOutput {
    fn from(interface: InterfaceInfo) -> Self {
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
pub struct RouteInterfaceOutput {
    pub name: String,
    pub index: u32,
}

impl From<InterfaceId> for RouteInterfaceOutput {
    fn from(value: InterfaceId) -> Self {
        Self {
            name: value.name,
            index: value.index,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteSelectionOutput {
    Local,
    OnLink,
    Gateway,
    InterfaceOnly,
}

impl From<packetcraftr_netio::route::SelectionReason> for RouteSelectionOutput {
    fn from(value: packetcraftr_netio::route::SelectionReason) -> Self {
        match value {
            packetcraftr_netio::route::SelectionReason::Local => Self::Local,
            packetcraftr_netio::route::SelectionReason::OnLink => Self::OnLink,
            packetcraftr_netio::route::SelectionReason::Gateway => Self::Gateway,
            packetcraftr_netio::route::SelectionReason::InterfaceOnly => Self::InterfaceOnly,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteScopeOutput {
    Host,
    Link,
    Private,
    Global,
    Multicast,
    Unspecified,
}

impl From<packetcraftr_netio::route::Scope> for RouteScopeOutput {
    fn from(value: packetcraftr_netio::route::Scope) -> Self {
        match value {
            packetcraftr_netio::route::Scope::Host => Self::Host,
            packetcraftr_netio::route::Scope::Link => Self::Link,
            packetcraftr_netio::route::Scope::Private => Self::Private,
            packetcraftr_netio::route::Scope::Global => Self::Global,
            packetcraftr_netio::route::Scope::Multicast => Self::Multicast,
            packetcraftr_netio::route::Scope::Unspecified => Self::Unspecified,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteModeOutput {
    Auto,
    Layer2,
    Layer3,
}

impl From<LinkMode> for RouteModeOutput {
    fn from(value: LinkMode) -> Self {
        match value {
            LinkMode::Auto => Self::Auto,
            LinkMode::Layer2 => Self::Layer2,
            LinkMode::Layer3 => Self::Layer3,
        }
    }
}

/// Output-owned MAC representation that keeps the versioned JSON contract
/// independent from the routing model's representation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct RouteMacAddressOutput(pub [u8; 6]);

impl From<packetcraftr_netio::link::MacAddress> for RouteMacAddressOutput {
    fn from(value: packetcraftr_netio::link::MacAddress) -> Self {
        Self(value.0)
    }
}

impl fmt::Display for RouteMacAddressOutput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = self.0;
        write!(
            formatter,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            value[0], value[1], value[2], value[3], value[4], value[5]
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteVlanKindOutput {
    Ieee8021Q,
    Ieee8021Ad,
}

impl From<packetcraftr_netio::neighbor::VlanKind> for RouteVlanKindOutput {
    fn from(value: packetcraftr_netio::neighbor::VlanKind) -> Self {
        match value {
            packetcraftr_netio::neighbor::VlanKind::Ieee8021Q => Self::Ieee8021Q,
            packetcraftr_netio::neighbor::VlanKind::Ieee8021Ad => Self::Ieee8021Ad,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct RouteVlanTagOutput {
    pub kind: RouteVlanKindOutput,
    pub priority: u8,
    pub drop_eligible: bool,
    pub vlan_id: u16,
}

impl From<packetcraftr_netio::neighbor::VlanTag> for RouteVlanTagOutput {
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
pub struct RouteDecisionOutput {
    pub interface: RouteInterfaceOutput,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_mac: Option<RouteMacAddressOutput>,
    pub selected_address: Option<IpAddr>,
    pub preferred_source: Option<IpAddr>,
    pub next_hop: Option<IpAddr>,
    pub selection_reason: RouteSelectionOutput,
    pub destination_scope: RouteScopeOutput,
    pub mtu: u32,
    pub capability: InterfaceCapabilityOutput,
    pub link_type: u32,
}

impl From<RouteDecision> for RouteDecisionOutput {
    fn from(value: RouteDecision) -> Self {
        Self {
            interface: value.interface.into(),
            source_mac: value.source_mac.map(Into::into),
            selected_address: value.selected_address,
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
pub struct PlannedRouteOutput {
    pub route: RouteDecisionOutput,
    pub mode: RouteModeOutput,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lookup_destination: Option<IpAddr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub final_destination: Option<IpAddr>,
    pub visited_destinations: Vec<IpAddr>,
    pub packet_source: Option<IpAddr>,
    pub neighbor_source: Option<IpAddr>,
    pub neighbor_target: Option<IpAddr>,
    pub destination_mac: Option<RouteMacAddressOutput>,
    pub source_mac: Option<RouteMacAddressOutput>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub neighbor_vlan_tags: Vec<RouteVlanTagOutput>,
    pub synthesized_ethernet: bool,
}

impl From<PlannedRoute> for PlannedRouteOutput {
    fn from(value: PlannedRoute) -> Self {
        Self {
            route: value.route.into(),
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
