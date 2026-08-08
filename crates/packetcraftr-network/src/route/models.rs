// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::interface::Id as InterfaceId;
use crate::link::{Capability, MacAddress, Mode};
use crate::neighbor::VlanTag as NeighborVlanTag;
use packetcraftr_packet::error::{Classification, Kind};
use packetcraftr_packet::frame::LinkType;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DestinationScope {
    Host,
    Link,
    Private,
    Global,
    Multicast,
    Unspecified,
}

/// Why the operating system selected a route. The concrete next hop remains
/// in `RouteDecision::next_hop`; this enum is stable across native APIs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteSelectionReason {
    Local,
    OnLink,
    Gateway,
    InterfaceOnly,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteDecision {
    pub interface: InterfaceId,
    /// Interface-owned source MAC used for Layer 2 materialization.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_mac: Option<MacAddress>,
    pub selected_address: Option<IpAddr>,
    pub preferred_source: Option<IpAddr>,
    pub next_hop: Option<IpAddr>,
    pub selection_reason: RouteSelectionReason,
    pub destination_scope: DestinationScope,
    pub mtu: u32,
    pub capability: Capability,
    pub link_type: LinkType,
}

pub trait RouteProvider: Send + Sync {
    type Error: std::error::Error + Send + Sync + 'static;

    /// Passive lookup only. Implementations must not emit neighbor traffic.
    ///
    /// A client may reuse a successful decision for identical arguments during
    /// one exchange, so implementations should provide a consistent snapshot
    /// for the duration of that operation.
    /// Passive lookup with an interface-owned source preference. This source
    /// is distinct from an explicitly spoofed source encoded in a packet.
    fn lookup_with_preferences(
        &self,
        destination: IpAddr,
        interface_hint: Option<&InterfaceId>,
        preferred_source: Option<IpAddr>,
    ) -> Result<RouteDecision, Self::Error>;

    /// Select a concrete interface for a packet that has no network-layer
    /// destination. Implementations must perform passive interface discovery
    /// only; they must not substitute a default-route IP lookup or emit
    /// neighbor traffic.
    ///
    /// The default preserves source compatibility for route providers that
    /// only support IP lookup. Such providers cannot plan destination-free
    /// Layer 2 packets until they implement this method.
    fn lookup_interface(
        &self,
        _interface: &InterfaceId,
    ) -> Result<Option<RouteDecision>, Self::Error> {
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
pub struct PlanOptions {
    pub link_mode: Mode,
    pub interface: Option<InterfaceId>,
    /// Interface-owned source used to constrain native route selection. This
    /// does not rewrite an explicit source already present in the packet.
    pub preferred_source: Option<IpAddr>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlannedRoute {
    pub route: RouteDecision,
    pub mode: Mode,
    /// Route lookup destination. For an SRH this is the first visited segment.
    /// Destination-free Layer 2 frames have no lookup destination.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lookup_destination: Option<IpAddr>,
    /// Final network-layer destination used for transport checksums. This is
    /// absent for a packet containing no network-layer route.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub final_destination: Option<IpAddr>,
    /// Ordered SRH visit targets, or the single final destination without SRH.
    pub visited_destinations: Vec<IpAddr>,
    pub packet_source: Option<IpAddr>,
    pub neighbor_source: Option<IpAddr>,
    pub neighbor_target: Option<IpAddr>,
    pub destination_mac: Option<MacAddress>,
    pub source_mac: Option<MacAddress>,
    /// Exact VLAN stack from the planned packet. Active ARP/NDP requests use
    /// the same tags so resolution cannot cross a logical link boundary.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub neighbor_vlan_tags: Vec<NeighborVlanTag>,
    pub synthesized_ethernet: bool,
}

impl PlannedRoute {
    pub fn needs_neighbor_resolution(&self) -> bool {
        self.mode == Mode::Layer2
            && self.destination_mac.is_none()
            && self
                .lookup_destination
                .is_none_or(|destination| !destination.is_multicast())
    }
}
