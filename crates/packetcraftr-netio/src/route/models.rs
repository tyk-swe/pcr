// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::{IpAddr, Ipv4Addr};

use crate::interface::Id as InterfaceId;
use crate::link::{Capability, MacAddress, Mode};
use crate::neighbor::VlanTag as NeighborVlanTag;
use packetcraftr_core::error::{Classification, Kind};
use packetcraftr_core::frame::LinkType;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scope {
    Host,
    Link,
    Private,
    Global,
    Multicast,
    Unspecified,
}

/// Why the operating system selected a route. The concrete next hop remains
/// in [`Decision::next_hop`]; this enum is stable across native APIs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SelectionReason {
    Local,
    OnLink,
    Broadcast,
    Gateway,
    InterfaceOnly,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Decision {
    pub interface: InterfaceId,
    /// Interface-owned source MAC used for Layer 2 materialization.
    pub source_mac: Option<MacAddress>,
    pub selected_source: Option<IpAddr>,
    pub preferred_source: Option<IpAddr>,
    pub next_hop: Option<IpAddr>,
    pub selection_reason: SelectionReason,
    pub destination_scope: Scope,
    pub mtu: u32,
    pub capability: Capability,
    pub link_type: LinkType,
}

impl Decision {
    pub(crate) fn is_ipv4_broadcast(&self, destination: Option<IpAddr>) -> bool {
        self.next_hop.is_none()
            && matches!(destination, Some(IpAddr::V4(address)) if
                address == Ipv4Addr::BROADCAST
                    || self.selection_reason == SelectionReason::Broadcast)
    }
}

pub trait Provider: Send + Sync {
    type Error: std::error::Error + Send + Sync + 'static;

    /// Passively selects a consistent per-exchange route snapshot without neighbor traffic.
    /// `preferred_source` constrains interface selection but never rewrites packet source.
    fn lookup_with_preferences(
        &self,
        destination: IpAddr,
        interface_hint: Option<&InterfaceId>,
        preferred_source: Option<IpAddr>,
    ) -> Result<Decision, Self::Error>;

    /// Passively selects an interface for destination-free packets without default-route IP
    /// lookup or neighbor traffic. Defaults to `None` for IP-only providers.
    fn lookup_interface(&self, _interface: &InterfaceId) -> Result<Option<Decision>, Self::Error> {
        Ok(None)
    }

    /// Classifies a provider-specific failure without forcing injected
    /// providers to expose native operating-system error types. The default is
    /// a runtime route failure; native providers override it with their exact
    /// capability or invariant class.
    fn classify_error(&self, _error: &Self::Error) -> Classification {
        Classification::new(
            "io.route",
            Kind::Io,
            Some(
                "inspect the route table, interface selection, and provider diagnostic before retrying",
            ),
        )
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Options {
    pub link_mode: Mode,
    pub interface: Option<InterfaceId>,
    /// Interface-owned source that constrains route selection without rewriting packet source.
    pub preferred_source: Option<IpAddr>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Plan {
    pub decision: Decision,
    pub mode: Mode,
    /// Route lookup destination. For an SRH this is the first visited segment.
    /// Destination-free Layer 2 frames have no lookup destination.
    pub lookup_destination: Option<IpAddr>,
    /// Final network-layer destination used for transport checksums. This is
    /// absent for a packet containing no network-layer route.
    pub final_destination: Option<IpAddr>,
    /// Ordered SRH visit targets, or the single final destination without SRH.
    pub visited_destinations: Vec<IpAddr>,
    pub packet_source: Option<IpAddr>,
    pub neighbor_source: Option<IpAddr>,
    pub neighbor_target: Option<IpAddr>,
    pub destination_mac: Option<MacAddress>,
    pub source_mac: Option<MacAddress>,
    /// Planned VLAN stack reused for ARP/NDP to stay on the same logical link.
    pub neighbor_vlan_tags: Vec<NeighborVlanTag>,
    pub synthesized_ethernet: bool,
}

impl Plan {
    pub fn needs_neighbor_resolution(&self) -> bool {
        self.mode == Mode::Layer2
            && self.destination_mac.is_none()
            && self
                .lookup_destination
                .is_none_or(|destination| !destination.is_multicast())
    }
}
