// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::fmt;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::core::{CapturedFrame, FieldValue, LinkType, Packet, ProtocolId};

use super::provider::CaptureStatistics;

/// Maximum explicit VLAN headers copied into a neighbor-discovery request.
pub const MAX_NEIGHBOR_VLAN_TAGS: usize = 8;

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct InterfaceId {
    pub name: String,
    pub index: u32,
}

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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LinkCapability {
    Layer2,
    Layer3,
    Layer2And3,
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

impl LinkCapability {
    fn supports_layer2(self) -> bool {
        matches!(self, Self::Layer2 | Self::Layer2And3)
    }

    fn supports_layer3(self) -> bool {
        matches!(self, Self::Layer3 | Self::Layer2And3)
    }
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
    pub capability: LinkCapability,
    pub link_type: super::LinkType,
}

pub trait RouteProvider: Send + Sync {
    type Error: std::error::Error + Send + Sync + 'static;

    /// Passive lookup only. Implementations must not emit neighbor traffic.
    fn lookup(
        &self,
        destination: IpAddr,
        interface_hint: Option<&InterfaceId>,
    ) -> Result<RouteDecision, Self::Error>;

    /// Passive lookup with an interface-owned source preference. This source
    /// is distinct from an explicitly spoofed source encoded in a packet.
    /// Existing injected providers retain source compatibility through the
    /// default implementation and receive a typed planner rejection if they
    /// do not honor a requested source.
    fn lookup_with_preferences(
        &self,
        destination: IpAddr,
        interface_hint: Option<&InterfaceId>,
        _preferred_source: Option<IpAddr>,
    ) -> Result<RouteDecision, Self::Error> {
        self.lookup(destination, interface_hint)
    }

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
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LinkMode {
    #[default]
    Auto,
    Layer2,
    Layer3,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PlanOptions {
    pub link_mode: LinkMode,
    pub interface: Option<InterfaceId>,
    /// Interface-owned source used to constrain native route selection. This
    /// does not rewrite an explicit source already present in the packet.
    pub preferred_source: Option<IpAddr>,
}

/// Errors emitted by the current target's passive route/interface adapter.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum NativeRouteError {
    #[error("native route selection is unavailable: {message}")]
    Unsupported { message: String },
    #[error("no route to {destination} was found")]
    RouteNotFound { destination: IpAddr },
    #[error("interface {name} (index {index}) was not found")]
    InterfaceNotFound { name: String, index: u32 },
    #[error(
        "interface preference {requested} (index {requested_index}) resolved to {actual} (index {actual_index})"
    )]
    InterfaceMismatch {
        requested: String,
        requested_index: u32,
        actual: String,
        actual_index: u32,
    },
    #[error("preferred source {preferred_source} has a different address family than destination {destination}")]
    SourceFamilyMismatch {
        preferred_source: IpAddr,
        destination: IpAddr,
    },
    #[error("preferred source {preferred_source} is not assigned to interface {interface}")]
    SourceUnavailable {
        preferred_source: IpAddr,
        interface: String,
    },
    #[error("native route response was invalid: {message}")]
    InvalidResponse { message: String },
    #[error("native operation {operation} failed: {message}")]
    OperatingSystem {
        operation: &'static str,
        message: String,
    },
}

/// Route provider backed by the adapter selected for the current target and
/// the explicit `native-route` feature.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemRouteProvider;

impl RouteProvider for SystemRouteProvider {
    type Error = NativeRouteError;

    fn lookup(
        &self,
        destination: IpAddr,
        interface_hint: Option<&InterfaceId>,
    ) -> Result<RouteDecision, Self::Error> {
        super::platform::system_route(destination, interface_hint, None)
    }

    fn lookup_with_preferences(
        &self,
        destination: IpAddr,
        interface_hint: Option<&InterfaceId>,
        preferred_source: Option<IpAddr>,
    ) -> Result<RouteDecision, Self::Error> {
        super::platform::system_route(destination, interface_hint, preferred_source)
    }

    fn lookup_interface(
        &self,
        interface: &InterfaceId,
    ) -> Result<Option<RouteDecision>, Self::Error> {
        super::platform::system_interface_route(interface).map(Some)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlannedRoute {
    pub route: RouteDecision,
    pub mode: LinkMode,
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
        self.mode == LinkMode::Layer2
            && self.destination_mac.is_none()
            && self
                .lookup_destination
                .is_none_or(|destination| !destination.is_multicast())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct MacAddress(pub [u8; 6]);

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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NeighborVlanKind {
    Ieee8021Q,
    Ieee8021Ad,
}

impl NeighborVlanKind {
    pub const fn ether_type(self) -> u16 {
        match self {
            Self::Ieee8021Q => 0x8100,
            Self::Ieee8021Ad => 0x88a8,
        }
    }
}

/// One fixed-width tag copied from the packet's explicit VLAN stack for
/// active neighbor discovery.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NeighborVlanTag {
    pub kind: NeighborVlanKind,
    pub priority: u8,
    pub drop_eligible: bool,
    pub vlan_id: u16,
}

/// Complete, interface-owned context for one active ARP/NDP lookup. Packet
/// source fields are intentionally absent so spoofed values cannot leak into
/// discovery traffic.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NeighborRequest {
    pub interface: InterfaceId,
    pub interface_source: IpAddr,
    pub interface_mac: MacAddress,
    pub target: IpAddr,
    pub vlan_tags: Vec<NeighborVlanTag>,
    pub mtu: u32,
    pub link_type: LinkType,
}

/// Bounded evidence returned by an active resolver and retained with the
/// materialized route.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NeighborResolution {
    pub mac_address: MacAddress,
    pub attempts: u32,
    pub cache_hit: bool,
    pub captured: Vec<CapturedFrame>,
    pub evidence_truncated: bool,
    pub capture_statistics: CaptureStatistics,
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum PlanError {
    #[error("route lookup for {destination} failed: {message}")]
    RouteLookup {
        destination: IpAddr,
        message: String,
    },
    #[error("packet has no IP destination and none was supplied")]
    MissingDestination,
    #[error("destination-free Layer 2 planning requires an explicit interface")]
    MissingLayer2Interface,
    #[error("route provider cannot select interface {interface} without an IP destination")]
    InterfaceLookupUnsupported { interface: String },
    #[error("interface lookup for {interface} failed: {message}")]
    InterfaceLookup { interface: String, message: String },
    #[error(
        "route provider selected {selected} (index {selected_index}) instead of requested {requested} (index {requested_index})"
    )]
    InterfaceMismatch {
        requested: String,
        requested_index: u32,
        selected: String,
        selected_index: u32,
    },
    #[error("destination-free Layer 2 packet has no complete destination MAC address")]
    MissingLayer2DestinationMac,
    #[error("explicit Layer 3 mode cannot carry Ethernet or VLAN layers")]
    EthernetInLayer3,
    #[error("capture-only link header {protocol} cannot be used for live transmission")]
    OfflineOnlyLinkHeader { protocol: ProtocolId },
    #[error("selected interface does not support Layer 2 transmission")]
    Layer2Unsupported,
    #[error("selected interface does not support Layer 3 transmission")]
    Layer3Unsupported,
    #[error("Layer 2 planning requires an interface-owned source address for neighbor resolution")]
    MissingNeighborSource,
    #[error("route source address family does not match destination {destination}")]
    SourceFamilyMismatch { destination: IpAddr },
    #[error("preferred route source {preferred_source} has a different address family than destination {destination}")]
    PreferredSourceFamilyMismatch {
        preferred_source: IpAddr,
        destination: IpAddr,
    },
    #[error("route provider did not select preferred source {requested}; selected {selected:?}")]
    PreferredSourceNotSelected {
        requested: IpAddr,
        selected: Option<IpAddr>,
    },
    #[error("route did not select a source address for the packet")]
    MissingPacketSource,
    #[error("invalid Segment Routing Header route state: {message}")]
    InvalidSegmentRouting { message: String },
    #[error("packet carries an invalid neighbor-discovery VLAN stack: {message}")]
    InvalidNeighborVlan { message: String },
}

#[derive(Clone, Debug, Default)]
pub struct RoutePlanner;

fn has_link_layer_intent(packet: &Packet) -> bool {
    packet.iter().any(|layer| {
        matches!(
            layer.protocol_id().as_str(),
            "ethernet" | "vlan" | "vlan8021ad"
        )
    })
}

impl RoutePlanner {
    /// Perform passive route/source/link selection. This never invokes ARP/NDP,
    /// capture, or transmission.
    pub fn plan<P: RouteProvider>(
        &self,
        packet: &Packet,
        destination: Option<IpAddr>,
        options: &PlanOptions,
        provider: &P,
    ) -> Result<PlannedRoute, PlanError> {
        if let Some(protocol) = packet.iter().find_map(|layer| {
            matches!(
                layer.protocol_id().as_str(),
                "bsd_null" | "bsd_loop" | "linux_sll" | "linux_sll2"
            )
            .then(|| layer.protocol_id())
        }) {
            return Err(PlanError::OfflineOnlyLinkHeader { protocol });
        }
        let has_link_layer_intent = has_link_layer_intent(packet);
        if options.link_mode == LinkMode::Layer3 && has_link_layer_intent {
            return Err(PlanError::EthernetInLayer3);
        }
        let has_ip = packet
            .iter()
            .any(|layer| matches!(layer.protocol_id().as_str(), "ipv4" | "ipv6"));
        let ip_root = packet
            .layer(0)
            .is_some_and(|layer| matches!(layer.protocol_id().as_str(), "ipv4" | "ipv6"));

        let packet_destination = packet_ip_field(packet, "destination");
        let srh = srh_route(packet)?;
        let final_destination = srh
            .as_ref()
            .and_then(|route| route.segments.last())
            .copied()
            .or(packet_destination)
            .or(destination);
        let lookup_destination = srh
            .as_ref()
            .map(|route| route.segments[route.active_index])
            .or(packet_destination)
            .or(final_destination);

        if let (Some(preferred_source), Some(lookup_destination)) =
            (options.preferred_source, lookup_destination)
        {
            if preferred_source.is_ipv4() != lookup_destination.is_ipv4() {
                return Err(PlanError::PreferredSourceFamilyMismatch {
                    preferred_source,
                    destination: lookup_destination,
                });
            }
        }

        if final_destination.is_none() && (has_ip || options.link_mode == LinkMode::Layer3) {
            return Err(PlanError::MissingDestination);
        }

        let route = match lookup_destination {
            Some(lookup_destination) => provider
                .lookup_with_preferences(
                    lookup_destination,
                    options.interface.as_ref(),
                    options.preferred_source,
                )
                .map_err(|source| PlanError::RouteLookup {
                    destination: lookup_destination,
                    message: source.to_string(),
                })?,
            None => {
                let interface = options
                    .interface
                    .as_ref()
                    .ok_or(PlanError::MissingLayer2Interface)?;
                provider
                    .lookup_interface(interface)
                    .map_err(|source| PlanError::InterfaceLookup {
                        interface: interface.name.clone(),
                        message: source.to_string(),
                    })?
                    .ok_or_else(|| PlanError::InterfaceLookupUnsupported {
                        interface: interface.name.clone(),
                    })?
            }
        };
        if let Some(requested) = &options.interface {
            if route.interface != *requested {
                return Err(PlanError::InterfaceMismatch {
                    requested: requested.name.clone(),
                    requested_index: requested.index,
                    selected: route.interface.name.clone(),
                    selected_index: route.interface.index,
                });
            }
        }
        if let Some(requested) = options.preferred_source {
            if route.selected_address != Some(requested)
                && route.preferred_source != Some(requested)
            {
                return Err(PlanError::PreferredSourceNotSelected {
                    requested,
                    selected: route.selected_address.or(route.preferred_source),
                });
            }
        }

        let mode = match options.link_mode {
            LinkMode::Layer3 => LinkMode::Layer3,
            LinkMode::Layer2 => LinkMode::Layer2,
            LinkMode::Auto if has_link_layer_intent => LinkMode::Layer2,
            LinkMode::Auto if ip_root && route.capability.supports_layer3() => LinkMode::Layer3,
            LinkMode::Auto => LinkMode::Layer2,
        };
        if mode == LinkMode::Layer2 && !route.capability.supports_layer2() {
            return Err(PlanError::Layer2Unsupported);
        }
        if mode == LinkMode::Layer3 && !route.capability.supports_layer3() {
            return Err(PlanError::Layer3Unsupported);
        }

        let explicit_source = packet_ip_field(packet, "source");
        let packet_source = has_ip
            .then(|| {
                explicit_source
                    .or(route.preferred_source)
                    .or(route.selected_address)
            })
            .flatten();
        if let (Some(source), Some(final_destination)) = (packet_source, final_destination) {
            if source.is_ipv4() != final_destination.is_ipv4() {
                return Err(PlanError::SourceFamilyMismatch {
                    destination: final_destination,
                });
            }
        }
        if has_ip && packet_source.is_none() {
            return Err(PlanError::MissingPacketSource);
        }
        let neighbor_source = lookup_destination.and_then(|lookup_destination| {
            route
                .selected_address
                .filter(|source| source.is_ipv4() == lookup_destination.is_ipv4())
                .or_else(|| {
                    route
                        .preferred_source
                        .filter(|source| source.is_ipv4() == lookup_destination.is_ipv4())
                })
        });
        let explicit_destination_mac = packet
            .iter()
            .find(|layer| layer.protocol_id().as_str() == "ethernet")
            .and_then(|layer| layer.field("destination"))
            .and_then(|value| match value {
                FieldValue::Mac(value) if value != [0; 6] => Some(MacAddress(value)),
                _ => None,
            });
        let explicit_source_mac = packet
            .iter()
            .find(|layer| layer.protocol_id().as_str() == "ethernet")
            .and_then(|layer| layer.field("source"))
            .and_then(|value| match value {
                FieldValue::Mac(value) if value != [0; 6] => Some(MacAddress(value)),
                _ => None,
            });
        let (arp_source_mac, arp_destination_mac) = arp_link_macs(packet);
        let destination_mac = explicit_destination_mac
            .or(arp_destination_mac)
            .or_else(|| lookup_destination.and_then(multicast_mac));
        if mode == LinkMode::Layer2 && destination_mac.is_none() {
            let Some(lookup_destination) = lookup_destination else {
                return Err(PlanError::MissingLayer2DestinationMac);
            };
            if neighbor_source.is_none() && !lookup_destination.is_multicast() {
                return Err(PlanError::MissingNeighborSource);
            }
        }
        let source_mac = explicit_source_mac.or(arp_source_mac).or(route.source_mac);
        let neighbor_vlan_tags = neighbor_vlan_tags(packet)?;
        let visited_destinations = srh.map_or_else(
            || final_destination.into_iter().collect(),
            |route| route.segments[route.active_index..].to_vec(),
        );

        Ok(PlannedRoute {
            neighbor_target: (mode == LinkMode::Layer2)
                .then(|| {
                    lookup_destination.map(|destination| route.next_hop.unwrap_or(destination))
                })
                .flatten(),
            destination_mac,
            source_mac,
            neighbor_vlan_tags,
            synthesized_ethernet: mode == LinkMode::Layer2
                && !packet
                    .iter()
                    .any(|layer| layer.protocol_id().as_str() == "ethernet"),
            route,
            mode,
            lookup_destination,
            final_destination,
            visited_destinations,
            packet_source,
            neighbor_source,
        })
    }

    pub fn materialize<N: NeighborResolver>(
        &self,
        mut plan: PlannedRoute,
        resolver: &N,
    ) -> Result<MaterializedRoute, NeighborError> {
        let mut neighbor_resolution = None;
        if plan.needs_neighbor_resolution() {
            let target =
                plan.neighbor_target
                    .ok_or_else(|| NeighborError::MissingNeighborTarget {
                        interface: plan.route.interface.name.clone(),
                    })?;
            let source =
                plan.neighbor_source
                    .ok_or_else(|| NeighborError::MissingNeighborSource {
                        interface: plan.route.interface.name.clone(),
                    })?;
            let interface_mac =
                plan.route
                    .source_mac
                    .ok_or_else(|| NeighborError::MissingSourceMac {
                        interface: plan.route.interface.name.clone(),
                    })?;
            let resolution = resolver.resolve_request(&NeighborRequest {
                interface: plan.route.interface.clone(),
                interface_source: source,
                interface_mac,
                target,
                vlan_tags: plan.neighbor_vlan_tags.clone(),
                mtu: plan.route.mtu,
                link_type: plan.route.link_type,
            })?;
            plan.destination_mac = Some(resolution.mac_address);
            neighbor_resolution = Some(resolution);
        }
        if plan.mode == LinkMode::Layer2 && plan.source_mac.is_none() {
            return Err(NeighborError::MissingSourceMac {
                interface: plan.route.interface.name.clone(),
            });
        }
        Ok(MaterializedRoute {
            plan,
            neighbor_resolution,
        })
    }
}

#[cfg(feature = "native-route")]
pub(super) fn classify_destination(address: IpAddr) -> DestinationScope {
    if address.is_unspecified() {
        return DestinationScope::Unspecified;
    }
    if address.is_multicast() {
        return DestinationScope::Multicast;
    }
    if address.is_loopback() {
        return DestinationScope::Host;
    }
    match address {
        IpAddr::V4(address) if address.is_link_local() => DestinationScope::Link,
        IpAddr::V6(address) if address.is_unicast_link_local() => DestinationScope::Link,
        IpAddr::V4(address) if address.is_private() => DestinationScope::Private,
        IpAddr::V6(address) if address.is_unique_local() => DestinationScope::Private,
        _ => DestinationScope::Global,
    }
}

pub trait NeighborResolver: Send + Sync {
    fn resolve(
        &self,
        interface: &InterfaceId,
        interface_source: IpAddr,
        target: IpAddr,
    ) -> Result<MacAddress, NeighborError>;

    /// Resolve with exact route/link context. Existing injected resolvers keep
    /// source compatibility through the legacy method and receive an empty
    /// evidence record; active resolvers override this method.
    fn resolve_request(
        &self,
        request: &NeighborRequest,
    ) -> Result<NeighborResolution, NeighborError> {
        self.resolve(&request.interface, request.interface_source, request.target)
            .map(|mac_address| NeighborResolution {
                mac_address,
                attempts: 1,
                cache_hit: false,
                captured: Vec::new(),
                evidence_truncated: false,
                capture_statistics: CaptureStatistics::default(),
            })
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum NeighborError {
    #[error("neighbor resolution for {target} on {interface} failed: {message}")]
    Resolution {
        interface: String,
        target: IpAddr,
        message: String,
    },
    #[error(
        "neighbor resolution returned no address for {target} on {interface} after {attempts} attempt(s)"
    )]
    NotFound {
        interface: String,
        target: IpAddr,
        attempts: u32,
        captured: Vec<CapturedFrame>,
        evidence_truncated: bool,
        capture_statistics: CaptureStatistics,
    },
    #[error("interface {interface} has no source MAC for Layer 2 transmission")]
    MissingSourceMac { interface: String },
    #[error("Layer 2 plan on {interface} has no neighbor target")]
    MissingNeighborTarget { interface: String },
    #[error("Layer 2 plan on {interface} has no interface-owned neighbor source address")]
    MissingNeighborSource { interface: String },
    #[error("neighbor request is invalid: {message}")]
    InvalidRequest { message: String },
    #[error("neighbor resolver configuration is invalid: {message}")]
    InvalidConfiguration { message: String },
    #[error("neighbor resolver state failed: {message}")]
    State { message: String },
    #[error(
        "neighbor resolution for {target} on {interface} failed and capture cleanup also failed: operation={operation}; cleanup={cleanup}"
    )]
    OperationAndCleanup {
        interface: String,
        target: IpAddr,
        operation: String,
        cleanup: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MaterializedRoute {
    pub plan: PlannedRoute,
    pub neighbor_resolution: Option<NeighborResolution>,
}

fn neighbor_vlan_tags(packet: &Packet) -> Result<Vec<NeighborVlanTag>, PlanError> {
    let mut tags = Vec::new();
    for layer in packet
        .iter()
        .filter(|layer| matches!(layer.protocol_id().as_str(), "vlan" | "vlan8021ad"))
    {
        if tags.len() >= MAX_NEIGHBOR_VLAN_TAGS {
            return Err(PlanError::InvalidNeighborVlan {
                message: format!(
                    "more than {MAX_NEIGHBOR_VLAN_TAGS} VLAN headers are not supported"
                ),
            });
        }
        let priority = match layer.field("priority") {
            Some(FieldValue::Unsigned(value)) => u8::try_from(value)
                .ok()
                .filter(|value| *value <= 7)
                .ok_or_else(|| PlanError::InvalidNeighborVlan {
                    message: format!("priority {value} is outside 0..=7"),
                })?,
            _ => {
                return Err(PlanError::InvalidNeighborVlan {
                    message: "priority is missing or is not unsigned".to_owned(),
                })
            }
        };
        let drop_eligible = match layer.field("drop_eligible") {
            Some(FieldValue::Bool(value)) => value,
            _ => {
                return Err(PlanError::InvalidNeighborVlan {
                    message: "drop_eligible is missing or is not boolean".to_owned(),
                })
            }
        };
        let vlan_id = match layer.field("vlan_id") {
            Some(FieldValue::Unsigned(value)) => u16::try_from(value)
                .ok()
                .filter(|value| *value <= 4095)
                .ok_or_else(|| PlanError::InvalidNeighborVlan {
                    message: format!("VLAN identifier {value} is outside 0..=4095"),
                })?,
            _ => {
                return Err(PlanError::InvalidNeighborVlan {
                    message: "vlan_id is missing or is not unsigned".to_owned(),
                })
            }
        };
        tags.push(NeighborVlanTag {
            kind: if layer.protocol_id().as_str() == "vlan8021ad" {
                NeighborVlanKind::Ieee8021Ad
            } else {
                NeighborVlanKind::Ieee8021Q
            },
            priority,
            drop_eligible,
            vlan_id,
        });
    }
    Ok(tags)
}

fn packet_ip_field(packet: &Packet, field: &str) -> Option<IpAddr> {
    packet.iter().find_map(|layer| {
        if !matches!(layer.protocol_id().as_str(), "ipv4" | "ipv6") {
            return None;
        }
        match layer.field(field) {
            Some(FieldValue::Ipv4(value)) if !value.is_unspecified() => Some(IpAddr::V4(value)),
            Some(FieldValue::Ipv6(value)) if !value.is_unspecified() => Some(IpAddr::V6(value)),
            _ => None,
        }
    })
}

fn arp_link_macs(packet: &Packet) -> (Option<MacAddress>, Option<MacAddress>) {
    let Some(layer) = packet
        .iter()
        .find(|layer| layer.protocol_id().as_str() == "arp")
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

struct SrhRoute {
    segments: Vec<IpAddr>,
    active_index: usize,
}

fn srh_route(packet: &Packet) -> Result<Option<SrhRoute>, PlanError> {
    let Some(layer) = packet.iter().find(|layer| {
        if !matches!(layer.protocol_id().as_str(), "ipv6_srh" | "srh") {
            return false;
        }
        true
    }) else {
        return Ok(None);
    };
    let Some(FieldValue::List(values)) = layer.field("segments") else {
        return Err(PlanError::InvalidSegmentRouting {
            message: "segments are missing or not an IPv6 list".to_owned(),
        });
    };
    let segments = values
        .into_iter()
        .map(|segment| match segment {
            FieldValue::Ipv6(value) => Ok(IpAddr::V6(value)),
            _ => Err(PlanError::InvalidSegmentRouting {
                message: "segment list contains a non-IPv6 value".to_owned(),
            }),
        })
        .collect::<Result<Vec<_>, _>>()?;
    let last = segments
        .len()
        .checked_sub(1)
        .ok_or_else(|| PlanError::InvalidSegmentRouting {
            message: "segment list is empty".to_owned(),
        })?;
    let segments_left = match layer.field("segments_left") {
        Some(FieldValue::Unsigned(value)) => {
            usize::try_from(value).map_err(|_| PlanError::InvalidSegmentRouting {
                message: "segments_left cannot be represented".to_owned(),
            })?
        }
        Some(FieldValue::Bytes(value)) if value.len() == 1 => usize::from(value[0]),
        Some(FieldValue::Text(value)) if value.eq_ignore_ascii_case("auto") => last,
        _ => {
            return Err(PlanError::InvalidSegmentRouting {
                message: "segments_left must be Auto, Exact, or one raw byte".to_owned(),
            })
        }
    };
    if segments_left > last {
        return Err(PlanError::InvalidSegmentRouting {
            message: format!("segments_left {segments_left} exceeds last entry {last}"),
        });
    }
    Ok(Some(SrhRoute {
        segments,
        active_index: last - segments_left,
    }))
}

fn multicast_mac(destination: IpAddr) -> Option<MacAddress> {
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

#[cfg(test)]
mod tests {
    use std::convert::Infallible;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    use bytes::Bytes;

    use super::*;
    use crate::core::{Raw, WireValue};
    use crate::protocols::{Ethernet, Ipv4, Ipv6, SegmentRoutingHeader, Vlan, Vlan8021ad};

    struct FixedRoute(RouteDecision);

    impl RouteProvider for FixedRoute {
        type Error = Infallible;

        fn lookup(
            &self,
            _destination: IpAddr,
            _interface_hint: Option<&InterfaceId>,
        ) -> Result<RouteDecision, Self::Error> {
            Ok(self.0.clone())
        }
    }

    struct PreferenceAwareRoute;

    impl RouteProvider for PreferenceAwareRoute {
        type Error = Infallible;

        fn lookup(
            &self,
            _destination: IpAddr,
            _interface_hint: Option<&InterfaceId>,
        ) -> Result<RouteDecision, Self::Error> {
            Ok(route(None))
        }

        fn lookup_with_preferences(
            &self,
            _destination: IpAddr,
            _interface_hint: Option<&InterfaceId>,
            preferred_source: Option<IpAddr>,
        ) -> Result<RouteDecision, Self::Error> {
            let mut decision = route(None);
            if let Some(preferred_source) = preferred_source {
                decision.selected_address = Some(preferred_source);
                decision.preferred_source = Some(preferred_source);
            }
            Ok(decision)
        }
    }

    struct InterfaceOnlyRoute {
        decision: RouteDecision,
        ip_lookups: AtomicUsize,
        interface_lookups: AtomicUsize,
    }

    impl InterfaceOnlyRoute {
        fn new(decision: RouteDecision) -> Self {
            Self {
                decision,
                ip_lookups: AtomicUsize::new(0),
                interface_lookups: AtomicUsize::new(0),
            }
        }
    }

    impl RouteProvider for InterfaceOnlyRoute {
        type Error = Infallible;

        fn lookup(
            &self,
            _destination: IpAddr,
            _interface_hint: Option<&InterfaceId>,
        ) -> Result<RouteDecision, Self::Error> {
            self.ip_lookups.fetch_add(1, Ordering::SeqCst);
            Ok(self.decision.clone())
        }

        fn lookup_interface(
            &self,
            _interface: &InterfaceId,
        ) -> Result<Option<RouteDecision>, Self::Error> {
            self.interface_lookups.fetch_add(1, Ordering::SeqCst);
            Ok(Some(self.decision.clone()))
        }
    }

    struct NeverResolve;

    impl NeighborResolver for NeverResolve {
        fn resolve(
            &self,
            _interface: &InterfaceId,
            _interface_source: IpAddr,
            _target: IpAddr,
        ) -> Result<MacAddress, NeighborError> {
            unreachable!("invalid plan must fail before calling the resolver")
        }
    }

    struct RecordingResolver {
        request: Mutex<Option<NeighborRequest>>,
        resolution: NeighborResolution,
    }

    impl NeighborResolver for RecordingResolver {
        fn resolve(
            &self,
            _interface: &InterfaceId,
            _interface_source: IpAddr,
            _target: IpAddr,
        ) -> Result<MacAddress, NeighborError> {
            unreachable!("rich neighbor context must be used during materialization")
        }

        fn resolve_request(
            &self,
            request: &NeighborRequest,
        ) -> Result<NeighborResolution, NeighborError> {
            *self.request.lock().unwrap() = Some(request.clone());
            Ok(self.resolution.clone())
        }
    }

    fn route(next_hop: Option<IpAddr>) -> RouteDecision {
        RouteDecision {
            interface: InterfaceId {
                name: "test0".to_owned(),
                index: 7,
            },
            source_mac: Some(MacAddress([2, 0, 0, 0, 0, 1])),
            selected_address: Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))),
            preferred_source: Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))),
            next_hop,
            selection_reason: if next_hop.is_some() {
                RouteSelectionReason::Gateway
            } else {
                RouteSelectionReason::OnLink
            },
            destination_scope: DestinationScope::Global,
            mtu: 1500,
            capability: LinkCapability::Layer2And3,
            link_type: super::super::LinkType::ETHERNET,
        }
    }

    fn canonical_link_intent_packets() -> Vec<(&'static str, Packet)> {
        let network_layer = || Ipv4 {
            source: Ipv4Addr::new(192, 0, 2, 10),
            destination: Ipv4Addr::new(198, 51, 100, 1),
            ..Ipv4::default()
        };

        let mut ethernet = Packet::new();
        ethernet.push(Ethernet::default()).push(network_layer());

        let mut customer_vlan_root = Packet::new();
        customer_vlan_root
            .push(Vlan::default())
            .push(network_layer());

        let mut service_vlan_root = Packet::new();
        service_vlan_root
            .push(Vlan8021ad::default())
            .push(network_layer());

        let mut ethernet_stacked = Packet::new();
        ethernet_stacked
            .push(Ethernet::default())
            .push(Vlan8021ad {
                vlan_id: 100,
                ..Vlan8021ad::default()
            })
            .push(Vlan {
                vlan_id: 200,
                ..Vlan::default()
            })
            .push(network_layer());

        let mut vlan_rooted_stacked = Packet::new();
        vlan_rooted_stacked
            .push(Vlan8021ad {
                vlan_id: 100,
                ..Vlan8021ad::default()
            })
            .push(Vlan {
                vlan_id: 200,
                ..Vlan::default()
            })
            .push(network_layer());

        // This deliberately unusual order proves canonical link intent wins
        // over the otherwise Layer 3-capable IP-root Auto branch.
        let mut ip_root_with_service_vlan = Packet::new();
        ip_root_with_service_vlan
            .push(network_layer())
            .push(Vlan8021ad::default());

        vec![
            ("ethernet", ethernet),
            ("vlan", customer_vlan_root),
            ("vlan8021ad", service_vlan_root),
            ("ethernet-stacked-vlan", ethernet_stacked),
            ("vlan-rooted-stacked-vlan", vlan_rooted_stacked),
            ("ip-root-with-service-vlan", ip_root_with_service_vlan),
        ]
    }

    #[test]
    fn explicit_layer3_rejects_every_canonical_link_intent_before_route_lookup() {
        for (case, packet) in canonical_link_intent_packets() {
            let provider = InterfaceOnlyRoute::new(route(None));
            let error = RoutePlanner
                .plan(
                    &packet,
                    None,
                    &PlanOptions {
                        link_mode: LinkMode::Layer3,
                        interface: None,
                        preferred_source: None,
                    },
                    &provider,
                )
                .unwrap_err();

            assert!(matches!(error, PlanError::EthernetInLayer3), "{case}");
            assert_eq!(provider.ip_lookups.load(Ordering::SeqCst), 0, "{case}");
            assert_eq!(
                provider.interface_lookups.load(Ordering::SeqCst),
                0,
                "{case}"
            );
        }
    }

    #[test]
    fn auto_selects_layer2_for_canonical_single_and_stacked_link_intent() {
        for (case, packet) in canonical_link_intent_packets() {
            let protocol_ids = packet
                .iter()
                .map(|layer| layer.protocol_id().to_string())
                .collect::<Vec<_>>();
            assert!(
                protocol_ids.iter().any(|protocol| {
                    matches!(protocol.as_str(), "ethernet" | "vlan" | "vlan8021ad")
                }),
                "{case}: {protocol_ids:?}"
            );

            let plan = RoutePlanner
                .plan(
                    &packet,
                    None,
                    &PlanOptions::default(),
                    &FixedRoute(route(None)),
                )
                .unwrap();

            assert_eq!(plan.mode, LinkMode::Layer2, "{case}: {protocol_ids:?}");
        }
    }

    #[test]
    fn injected_provider_can_honor_a_source_preference() {
        let preferred_source = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 99));
        let mut packet = Packet::new();
        packet.push(Ipv4 {
            source: Ipv4Addr::new(192, 0, 2, 99),
            destination: Ipv4Addr::new(198, 51, 100, 1),
            ..Ipv4::default()
        });

        let plan = RoutePlanner
            .plan(
                &packet,
                None,
                &PlanOptions {
                    link_mode: LinkMode::Layer3,
                    interface: None,
                    preferred_source: Some(preferred_source),
                },
                &PreferenceAwareRoute,
            )
            .unwrap();

        assert_eq!(plan.route.selected_address, Some(preferred_source));
        assert_eq!(plan.route.preferred_source, Some(preferred_source));
    }

    #[test]
    fn legacy_injected_provider_rejects_an_unhonored_source_preference() {
        let preferred_source = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 99));
        let mut packet = Packet::new();
        packet.push(Ipv4 {
            source: Ipv4Addr::new(192, 0, 2, 99),
            destination: Ipv4Addr::new(198, 51, 100, 1),
            ..Ipv4::default()
        });

        let error = RoutePlanner
            .plan(
                &packet,
                None,
                &PlanOptions {
                    link_mode: LinkMode::Layer3,
                    interface: None,
                    preferred_source: Some(preferred_source),
                },
                &FixedRoute(route(None)),
            )
            .unwrap_err();
        assert!(matches!(
            error,
            PlanError::PreferredSourceNotSelected {
                requested,
                selected: Some(selected),
            } if requested == preferred_source
                && selected == IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))
        ));
    }

    #[test]
    fn preferred_source_family_is_rejected_before_provider_lookup() {
        let provider = InterfaceOnlyRoute::new(route(None));
        let mut packet = Packet::new();
        packet.push(Ipv4 {
            destination: Ipv4Addr::new(198, 51, 100, 1),
            ..Ipv4::default()
        });
        let preferred_source = IpAddr::V6(Ipv6Addr::LOCALHOST);

        let error = RoutePlanner
            .plan(
                &packet,
                None,
                &PlanOptions {
                    link_mode: LinkMode::Layer3,
                    interface: None,
                    preferred_source: Some(preferred_source),
                },
                &provider,
            )
            .unwrap_err();
        assert!(matches!(
            error,
            PlanError::PreferredSourceFamilyMismatch {
                preferred_source: actual,
                destination,
            } if actual == preferred_source
                && destination == IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1))
        ));
        assert_eq!(provider.ip_lookups.load(Ordering::SeqCst), 0);
    }

    #[cfg(not(feature = "native-route"))]
    #[test]
    fn system_route_provider_reports_the_feature_boundary() {
        assert!(matches!(
            SystemRouteProvider.lookup(IpAddr::V4(Ipv4Addr::LOCALHOST), None),
            Err(NativeRouteError::Unsupported { message })
                if message.contains("native-route")
        ));
    }

    #[test]
    fn auto_link_intent_does_not_fall_back_when_layer2_is_unsupported() {
        let packet = canonical_link_intent_packets()
            .into_iter()
            .find_map(|(case, packet)| (case == "vlan8021ad").then_some(packet))
            .unwrap();
        let decision = RouteDecision {
            capability: LinkCapability::Layer3,
            link_type: super::super::LinkType::IPV4,
            ..route(None)
        };

        for link_mode in [LinkMode::Auto, LinkMode::Layer2] {
            let error = RoutePlanner
                .plan(
                    &packet,
                    None,
                    &PlanOptions {
                        link_mode,
                        interface: None,
                        preferred_source: None,
                    },
                    &FixedRoute(decision.clone()),
                )
                .unwrap_err();

            assert!(
                matches!(error, PlanError::Layer2Unsupported),
                "{link_mode:?}"
            );
        }
    }

    #[test]
    fn on_link_and_gateway_neighbor_targets_are_family_independent() {
        let cases = [
            (
                "IPv4 on-link",
                "192.0.2.10".parse().unwrap(),
                "192.0.2.20".parse().unwrap(),
                None,
            ),
            (
                "IPv4 gateway",
                "192.0.2.10".parse().unwrap(),
                "198.51.100.1".parse().unwrap(),
                Some("192.0.2.1".parse().unwrap()),
            ),
            (
                "IPv6 on-link",
                "2001:db8::10".parse().unwrap(),
                "2001:db8::20".parse().unwrap(),
                None,
            ),
            (
                "IPv6 gateway",
                "2001:db8::10".parse().unwrap(),
                "2001:db8:1::1".parse().unwrap(),
                Some("fe80::1".parse().unwrap()),
            ),
        ];

        for (case, source, destination, gateway) in cases {
            let mut decision = route(gateway);
            decision.selected_address = Some(source);
            decision.preferred_source = Some(source);
            let mut packet = Packet::new();
            packet.push(Raw::new(Bytes::new()));
            let plan = RoutePlanner
                .plan(
                    &packet,
                    Some(destination),
                    &PlanOptions {
                        link_mode: LinkMode::Layer2,
                        interface: None,
                        preferred_source: None,
                    },
                    &FixedRoute(decision),
                )
                .unwrap();

            assert_eq!(
                plan.neighbor_target,
                Some(gateway.unwrap_or(destination)),
                "{case}"
            );
            assert!(plan.destination_mac.is_none(), "{case}");
        }
    }

    #[test]
    fn materialization_uses_interface_identity_and_retains_resolution_evidence() {
        let gateway = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let destination = Ipv4Addr::new(198, 51, 100, 1);
        let spoofed_ip = Ipv4Addr::new(203, 0, 113, 99);
        let spoofed_mac = [0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee];
        let resolved_mac = MacAddress([0x02, 0, 0, 0, 0, 2]);
        let captured = CapturedFrame::new(
            std::time::SystemTime::UNIX_EPOCH,
            LinkType::ETHERNET,
            Bytes::from_static(&[0; 14]),
        )
        .unwrap();
        let resolution = NeighborResolution {
            mac_address: resolved_mac,
            attempts: 2,
            cache_hit: false,
            captured: vec![captured],
            evidence_truncated: true,
            capture_statistics: CaptureStatistics {
                received_frames: 2,
                received_bytes: 120,
                ..CaptureStatistics::default()
            },
        };
        let resolver = RecordingResolver {
            request: Mutex::new(None),
            resolution: resolution.clone(),
        };
        let mut packet = Packet::new();
        packet
            .push(Ethernet {
                source: spoofed_mac,
                ..Ethernet::default()
            })
            .push(Vlan8021ad {
                priority: 5,
                vlan_id: 100,
                ..Vlan8021ad::default()
            })
            .push(Vlan {
                priority: 1,
                drop_eligible: true,
                vlan_id: 200,
                ..Vlan::default()
            })
            .push(Ipv4 {
                source: spoofed_ip,
                destination,
                ..Ipv4::default()
            });

        let plan = RoutePlanner
            .plan(
                &packet,
                None,
                &PlanOptions {
                    link_mode: LinkMode::Layer2,
                    interface: None,
                    preferred_source: None,
                },
                &FixedRoute(route(Some(gateway))),
            )
            .unwrap();
        assert_eq!(plan.packet_source, Some(IpAddr::V4(spoofed_ip)));
        assert_eq!(plan.source_mac, Some(MacAddress(spoofed_mac)));

        let materialized = RoutePlanner.materialize(plan, &resolver).unwrap();
        assert_eq!(materialized.plan.destination_mac, Some(resolved_mac));
        assert_eq!(materialized.neighbor_resolution, Some(resolution));
        assert_eq!(
            *resolver.request.lock().unwrap(),
            Some(NeighborRequest {
                interface: InterfaceId {
                    name: "test0".to_owned(),
                    index: 7,
                },
                interface_source: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
                interface_mac: MacAddress([2, 0, 0, 0, 0, 1]),
                target: gateway,
                vlan_tags: vec![
                    NeighborVlanTag {
                        kind: NeighborVlanKind::Ieee8021Ad,
                        priority: 5,
                        drop_eligible: false,
                        vlan_id: 100,
                    },
                    NeighborVlanTag {
                        kind: NeighborVlanKind::Ieee8021Q,
                        priority: 1,
                        drop_eligible: true,
                        vlan_id: 200,
                    },
                ],
                mtu: 1500,
                link_type: LinkType::ETHERNET,
            })
        );
    }

    #[test]
    fn fully_specified_layer2_frame_needs_no_neighbor_source() {
        let destination = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1));
        let mut packet = Packet::new();
        packet
            .push(crate::protocols::Ethernet {
                source: [2, 0, 0, 0, 0, 1],
                destination: [2, 0, 0, 0, 0, 2],
                ..crate::protocols::Ethernet::default()
            })
            .push(Raw::new(Bytes::from_static(b"frame")));
        let route = RouteDecision {
            selected_address: None,
            preferred_source: None,
            source_mac: None,
            ..route(None)
        };

        let plan = RoutePlanner
            .plan(
                &packet,
                Some(destination),
                &PlanOptions {
                    link_mode: LinkMode::Layer2,
                    interface: None,
                    preferred_source: None,
                },
                &FixedRoute(route),
            )
            .unwrap();

        assert_eq!(plan.neighbor_source, None);
        assert_eq!(plan.source_mac, Some(MacAddress([2, 0, 0, 0, 0, 1])));
        assert_eq!(plan.destination_mac, Some(MacAddress([2, 0, 0, 0, 0, 2])));
    }

    #[test]
    fn destination_free_custom_ethernet_uses_only_interface_lookup() {
        let mut packet = Packet::new();
        packet
            .push(crate::protocols::Ethernet {
                source: [2, 0, 0, 0, 0, 1],
                destination: [2, 0, 0, 0, 0, 2],
                ether_type: WireValue::Exact(0x88b5),
            })
            .push(Raw::new(Bytes::from_static(b"custom")));
        let decision = RouteDecision {
            selected_address: None,
            preferred_source: None,
            next_hop: None,
            ..route(None)
        };
        let interface = decision.interface.clone();
        let provider = InterfaceOnlyRoute::new(decision);

        let plan = RoutePlanner
            .plan(
                &packet,
                None,
                &PlanOptions {
                    link_mode: LinkMode::Auto,
                    interface: Some(interface),
                    preferred_source: None,
                },
                &provider,
            )
            .unwrap();

        assert_eq!(provider.ip_lookups.load(Ordering::SeqCst), 0);
        assert_eq!(provider.interface_lookups.load(Ordering::SeqCst), 1);
        assert_eq!(plan.lookup_destination, None);
        assert_eq!(plan.final_destination, None);
        assert!(plan.visited_destinations.is_empty());
        assert_eq!(plan.destination_mac, Some(MacAddress([2, 0, 0, 0, 0, 2])));
        assert!(!plan.needs_neighbor_resolution());
        RoutePlanner.materialize(plan, &NeverResolve).unwrap();
    }

    #[test]
    fn destination_free_layer2_requires_explicit_interface() {
        let mut packet = Packet::new();
        packet.push(crate::protocols::Ethernet {
            source: [2, 0, 0, 0, 0, 1],
            destination: [2, 0, 0, 0, 0, 2],
            ether_type: WireValue::Exact(0x88b5),
        });
        let provider = InterfaceOnlyRoute::new(route(None));

        let error = RoutePlanner
            .plan(&packet, None, &PlanOptions::default(), &provider)
            .unwrap_err();

        assert!(matches!(error, PlanError::MissingLayer2Interface));
        assert_eq!(provider.ip_lookups.load(Ordering::SeqCst), 0);
        assert_eq!(provider.interface_lookups.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn complete_arp_synthesizes_broadcast_envelope_without_ip_route() {
        let mut packet = Packet::new();
        packet.push(crate::protocols::Arp {
            sender_hardware: [2, 0, 0, 0, 0, 1],
            sender_protocol: Ipv4Addr::new(192, 0, 2, 10),
            target_protocol: Ipv4Addr::new(192, 0, 2, 20),
            ..crate::protocols::Arp::default()
        });
        let decision = RouteDecision {
            source_mac: None,
            selected_address: None,
            preferred_source: None,
            next_hop: None,
            ..route(None)
        };
        let interface = decision.interface.clone();
        let provider = InterfaceOnlyRoute::new(decision);

        let plan = RoutePlanner
            .plan(
                &packet,
                None,
                &PlanOptions {
                    link_mode: LinkMode::Layer2,
                    interface: Some(interface),
                    preferred_source: None,
                },
                &provider,
            )
            .unwrap();

        assert_eq!(provider.ip_lookups.load(Ordering::SeqCst), 0);
        assert_eq!(plan.destination_mac, Some(MacAddress([0xff; 6])));
        assert_eq!(plan.source_mac, Some(MacAddress([2, 0, 0, 0, 0, 1])));
        assert!(plan.synthesized_ethernet);
        assert!(!plan.needs_neighbor_resolution());
        RoutePlanner.materialize(plan, &NeverResolve).unwrap();
    }

    #[test]
    fn externally_constructed_invalid_plan_returns_typed_error() {
        let destination = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1));
        let mut packet = Packet::new();
        packet.push(Raw::new(Bytes::new()));
        let mut plan = RoutePlanner
            .plan(
                &packet,
                Some(destination),
                &PlanOptions {
                    link_mode: LinkMode::Layer2,
                    interface: None,
                    preferred_source: None,
                },
                &FixedRoute(route(None)),
            )
            .unwrap();
        plan.neighbor_target = None;
        plan.destination_mac = None;

        assert_eq!(
            RoutePlanner.materialize(plan, &NeverResolve).unwrap_err(),
            NeighborError::MissingNeighborTarget {
                interface: "test0".to_owned()
            }
        );
    }

    #[test]
    fn srh_route_lookup_uses_the_current_active_segment() {
        let source: std::net::Ipv6Addr = "2001:db8::1".parse().unwrap();
        let first: std::net::Ipv6Addr = "2001:db8::10".parse().unwrap();
        let final_destination: std::net::Ipv6Addr = "2001:db8::20".parse().unwrap();
        let mut packet = Packet::new();
        packet
            .push(Ipv6 {
                source,
                destination: final_destination,
                ..Ipv6::default()
            })
            .push(SegmentRoutingHeader {
                segments: vec![first, final_destination],
                segments_left: WireValue::Raw(Bytes::from_static(&[0])),
                ..SegmentRoutingHeader::default()
            });
        let decision = RouteDecision {
            selected_address: Some(IpAddr::V6(source)),
            preferred_source: Some(IpAddr::V6(source)),
            next_hop: None,
            capability: LinkCapability::Layer3,
            link_type: super::super::LinkType::IPV6,
            ..route(None)
        };
        let plan = RoutePlanner
            .plan(
                &packet,
                None,
                &PlanOptions {
                    link_mode: LinkMode::Layer3,
                    interface: None,
                    preferred_source: None,
                },
                &FixedRoute(decision),
            )
            .unwrap();
        assert_eq!(plan.lookup_destination, Some(IpAddr::V6(final_destination)));
        assert_eq!(
            plan.visited_destinations,
            vec![IpAddr::V6(final_destination)]
        );
    }
}
