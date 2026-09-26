// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::{IpAddr, Ipv4Addr};

use packetcraftr_core::packet::{MacAddress, VlanTag};
use packetcraftr_netio::interface::Id as InterfaceId;
use packetcraftr_netio::link::Mode;
use packetcraftr_netio::route::{Decision, SelectionReason};

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
    /// Route lookup destination. For an SRH this is the first visited segment;
    /// for IPv4 LSRR/SSRR it is the header destination, the first hop the
    /// route visits. Destination-free Layer 2 frames have no lookup
    /// destination.
    pub lookup_destination: Option<IpAddr>,
    /// Final network-layer destination used for transport checksums. This is
    /// absent for a packet containing no network-layer route.
    pub final_destination: Option<IpAddr>,
    /// Ordered source-route visit targets: the SRH segments still to visit, or
    /// the IPv4 header destination followed by the remaining LSRR/SSRR hops;
    /// without a source route, the single final destination.
    pub visited_destinations: Vec<IpAddr>,
    pub packet_source: Option<IpAddr>,
    pub neighbor_source: Option<IpAddr>,
    pub neighbor_target: Option<IpAddr>,
    pub destination_mac: Option<MacAddress>,
    pub source_mac: Option<MacAddress>,
    /// Planned VLAN stack reused for ARP/NDP to stay on the same logical link.
    pub neighbor_vlan_tags: Vec<VlanTag>,
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

/// Whether `destination` is an IPv4 broadcast the route delivers without a
/// next hop.
pub(super) fn is_ipv4_broadcast(route: &Decision, destination: Option<IpAddr>) -> bool {
    route.next_hop.is_none()
        && matches!(destination, Some(IpAddr::V4(address)) if
            address == Ipv4Addr::BROADCAST
                || route.selection_reason == SelectionReason::Broadcast)
}
