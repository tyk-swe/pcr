use std::net::IpAddr;

use thiserror::Error;

use crate::capture::Frame;
use crate::error::{Category, Classification, Classified, Kind};
use crate::net::{Error as LiveIoError, capture::CaptureStatistics};
use crate::packet::{
    Packet,
    field::FieldValue,
    layer::ProtocolId,
    semantics::{self, BuiltinProtocol},
};

#[cfg(all(
    feature = "native-route",
    any(target_os = "linux", target_os = "macos", windows)
))]
use super::models::DestinationScope;
use super::models::{
    InterfaceId, LinkMode, MAX_NEIGHBOR_VLAN_TAGS, MacAddress, NeighborRequest, NeighborResolution,
    NeighborVlanKind, NeighborVlanTag, PlanOptions, PlannedRoute, RouteProvider,
};

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum PlanError {
    #[error("route lookup for {destination} failed: {message}")]
    RouteLookup {
        destination: IpAddr,
        message: String,
        failure: Classification,
    },
    #[error("packet has no IP destination and none was supplied")]
    MissingDestination,
    #[error("destination-free Layer 2 planning requires an explicit interface")]
    MissingLayer2Interface,
    #[error("route provider cannot select interface {interface} without an IP destination")]
    InterfaceLookupUnsupported { interface: String },
    #[error("interface lookup for {interface} failed: {message}")]
    InterfaceLookup {
        interface: String,
        message: String,
        failure: Classification,
    },
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
    #[error(
        "preferred route source {preferred_source} has a different address family than destination {destination}"
    )]
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
    #[error("invalid IPv4 source-route state: {message}")]
    InvalidSourceRouting { message: String },
    #[error("packet carries an invalid neighbor-discovery VLAN stack: {message}")]
    InvalidNeighborVlan { message: String },
}

impl Classified for PlanError {
    fn classification(&self) -> Classification {
        match self {
            Self::RouteLookup { failure, .. } | Self::InterfaceLookup { failure, .. } => *failure,
            Self::MissingLayer2Interface => Classification::new(
                "cli.interface_required",
                Kind::Cli,
                Some("select an explicit interface for a destination-free Layer 2 packet"),
            ),
            Self::InterfaceLookupUnsupported { .. }
            | Self::Layer2Unsupported
            | Self::Layer3Unsupported => Classification::new(
                "capability.link_mode",
                Kind::Capability,
                Some(
                    "select a provider and interface that support the explicitly requested link mode",
                ),
            ),
            Self::OfflineOnlyLinkHeader { .. } => Classification::new(
                "packet.offline_link_header",
                Kind::Packet,
                Some("replace the capture-only header with a live Ethernet or raw-IP packet root"),
            ),
            Self::MissingDestination
            | Self::MissingLayer2DestinationMac
            | Self::EthernetInLayer3
            | Self::SourceFamilyMismatch { .. }
            | Self::PreferredSourceFamilyMismatch { .. }
            | Self::InvalidSegmentRouting { .. }
            | Self::InvalidSourceRouting { .. }
            | Self::InvalidNeighborVlan { .. } => Classification::new(
                "packet.plan",
                Kind::Packet,
                Some(
                    "correct the packet destination, address family, or link-layer intent before planning again",
                ),
            ),
            Self::InterfaceMismatch { .. }
            | Self::MissingNeighborSource
            | Self::PreferredSourceNotSelected { .. }
            | Self::MissingPacketSource => Classification::new(
                "internal.route_contract",
                Kind::Internal,
                Some(
                    "do not transmit with the inconsistent route result; inspect or replace the route provider",
                ),
            ),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct RoutePlanner;

fn packet_has_link_layer_intent(packet: &Packet) -> bool {
    packet.iter().any(|layer| {
        matches!(
            BuiltinProtocol::of(layer),
            Some(BuiltinProtocol::Ethernet | BuiltinProtocol::Vlan | BuiltinProtocol::Vlan8021ad)
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
                BuiltinProtocol::of(layer),
                Some(
                    BuiltinProtocol::BsdNull
                        | BuiltinProtocol::BsdLoop
                        | BuiltinProtocol::LinuxSll
                        | BuiltinProtocol::LinuxSll2
                )
            )
            .then(|| layer.protocol_id())
        }) {
            return Err(PlanError::OfflineOnlyLinkHeader { protocol });
        }
        let has_link_layer_intent = packet_has_link_layer_intent(packet);
        if options.link_mode == LinkMode::Layer3 && has_link_layer_intent {
            return Err(PlanError::EthernetInLayer3);
        }
        let outer_ip_protocol = packet.iter().find_map(|layer| {
            let protocol = BuiltinProtocol::of(layer)?;
            protocol.is_ip().then_some(protocol)
        });
        let ip_path = semantics::outer_ip_path(packet).map_err(|source| {
            let message = source.to_string();
            match outer_ip_protocol {
                Some(BuiltinProtocol::Ipv4) => PlanError::InvalidSourceRouting { message },
                _ => PlanError::InvalidSegmentRouting { message },
            }
        })?;
        if ip_path.as_ref().is_some_and(|path| {
            matches!(path.header_destination, IpAddr::V4(destination) if destination.is_unspecified())
                && !path.declared_route_destinations.is_empty()
        }) {
            return Err(PlanError::InvalidSourceRouting {
                message: "the IPv4 header destination must name the active LSRR/SSRR hop"
                    .to_owned(),
            });
        }
        let has_ip = ip_path.is_some();
        let ip_root = packet
            .layer(0)
            .and_then(BuiltinProtocol::of)
            .is_some_and(BuiltinProtocol::is_ip);

        let packet_destination = ip_path
            .as_ref()
            .map(|path| path.header_destination)
            .filter(|destination| !destination.is_unspecified());
        let final_destination = ip_path
            .as_ref()
            .map(|path| path.final_destination)
            .filter(|destination| !destination.is_unspecified())
            .or(destination);
        let lookup_destination = ip_path
            .as_ref()
            .map(|path| path.active_destination)
            .filter(|destination| !destination.is_unspecified())
            .or(packet_destination)
            .or(final_destination);

        if let (Some(preferred_source), Some(lookup_destination)) =
            (options.preferred_source, lookup_destination)
            && preferred_source.is_ipv4() != lookup_destination.is_ipv4()
        {
            return Err(PlanError::PreferredSourceFamilyMismatch {
                preferred_source,
                destination: lookup_destination,
            });
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
                    failure: provider.classify_error(&source),
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
                        failure: provider.classify_error(&source),
                        message: source.to_string(),
                    })?
                    .ok_or_else(|| PlanError::InterfaceLookupUnsupported {
                        interface: interface.name.clone(),
                    })?
            }
        };
        if let Some(requested) = &options.interface
            && route.interface != *requested
        {
            return Err(PlanError::InterfaceMismatch {
                requested: requested.name.clone(),
                requested_index: requested.index,
                selected: route.interface.name.clone(),
                selected_index: route.interface.index,
            });
        }
        if let Some(requested) = options.preferred_source
            && route.selected_address != Some(requested)
            && route.preferred_source != Some(requested)
        {
            return Err(PlanError::PreferredSourceNotSelected {
                requested,
                selected: route.selected_address.or(route.preferred_source),
            });
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

        let explicit_source = ip_path
            .as_ref()
            .map(|path| path.source)
            .filter(|source| !source.is_unspecified());
        let packet_source = has_ip
            .then(|| {
                explicit_source
                    .or(route.preferred_source)
                    .or(route.selected_address)
            })
            .flatten();
        if let (Some(source), Some(final_destination)) = (packet_source, final_destination)
            && source.is_ipv4() != final_destination.is_ipv4()
        {
            return Err(PlanError::SourceFamilyMismatch {
                destination: final_destination,
            });
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
            .find(|layer| BuiltinProtocol::of(*layer) == Some(BuiltinProtocol::Ethernet))
            .and_then(|layer| layer.field(semantics::DESTINATION))
            .and_then(|value| match value {
                FieldValue::Mac(value) if value != [0; 6] => Some(MacAddress(value)),
                _ => None,
            });
        let explicit_source_mac = packet
            .iter()
            .find(|layer| BuiltinProtocol::of(*layer) == Some(BuiltinProtocol::Ethernet))
            .and_then(|layer| layer.field(semantics::SOURCE))
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
        let neighbor_vlan_tags = extract_neighbor_vlan_tags(packet)?;
        let mut visited_destinations = ip_path
            .map(|path| {
                path.visited_destinations
                    .into_iter()
                    .filter(|destination| !destination.is_unspecified())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        if visited_destinations.is_empty()
            && let Some(final_destination) = final_destination
        {
            visited_destinations.push(final_destination);
        }

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
                    .any(|layer| BuiltinProtocol::of(layer) == Some(BuiltinProtocol::Ethernet)),
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

#[cfg(all(
    feature = "native-route",
    any(target_os = "linux", target_os = "macos", windows)
))]
pub(in crate::net) fn classify_destination(address: IpAddr) -> DestinationScope {
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
        captured: Vec<Frame>,
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
    #[error("neighbor resolution for {target} on {interface} failed while {operation}: {source}")]
    Io {
        interface: String,
        target: IpAddr,
        operation: &'static str,
        source: LiveIoError,
    },
    #[error(
        "neighbor resolution for {target} on {interface} completed but capture cleanup failed: {source}"
    )]
    Cleanup {
        interface: String,
        target: IpAddr,
        source: LiveIoError,
    },
    #[error(
        "neighbor resolution for {target} on {interface} failed and capture cleanup also failed: operation={operation}; cleanup={cleanup}"
    )]
    OperationAndCleanup {
        interface: String,
        target: IpAddr,
        operation: Box<NeighborError>,
        cleanup: LiveIoError,
    },
}

impl Classified for NeighborError {
    fn classification(&self) -> Classification {
        match self {
            Self::Io { source, .. } => source.classification(),
            Self::Cleanup { source, .. } => source
                .classification()
                .with_category(Category::Cleanup),
            Self::OperationAndCleanup { operation, .. } => operation
                .classification()
                .with_category(Category::Cleanup),
            Self::NotFound { .. } => Classification::new(
                "io.neighbor_timeout",
                Kind::Io,
                Some("inspect the selected gateway, VLAN, and interface; the finite neighbor-resolution budget was exhausted"),
            )
            .with_category(Category::Timeout),
            Self::Resolution { .. } => Classification::new(
                "io.neighbor",
                Kind::Io,
                Some("inspect the correlated ARP/NDP evidence and selected logical link before retrying"),
            ),
            Self::InvalidConfiguration { .. } => Classification::new(
                "cli.neighbor_limit",
                Kind::Cli,
                Some("use finite non-zero neighbor attempts, timeouts, cache limits, and capture bounds"),
            ),
            Self::MissingSourceMac { .. }
            | Self::MissingNeighborTarget { .. }
            | Self::MissingNeighborSource { .. }
            | Self::InvalidRequest { .. }
            | Self::State { .. } => Classification::new(
                "internal.neighbor_invariant",
                Kind::Internal,
                Some("do not transmit with the incomplete neighbor request or inconsistent resolver state"),
            ),
        }
    }

    fn causes(&self) -> Vec<String> {
        match self {
            Self::Io { source, .. } | Self::Cleanup { source, .. } => {
                vec![source.to_string()]
            }
            Self::OperationAndCleanup {
                operation, cleanup, ..
            } => vec![operation.to_string(), cleanup.to_string()],
            _ => Vec::new(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MaterializedRoute {
    pub plan: PlannedRoute,
    pub neighbor_resolution: Option<NeighborResolution>,
}

fn extract_neighbor_vlan_tags(packet: &Packet) -> Result<Vec<NeighborVlanTag>, PlanError> {
    let metadata =
        semantics::vlan_metadata(packet).map_err(|source| PlanError::InvalidNeighborVlan {
            message: source.to_string(),
        })?;
    if metadata.len() > MAX_NEIGHBOR_VLAN_TAGS {
        return Err(PlanError::InvalidNeighborVlan {
            message: format!("more than {MAX_NEIGHBOR_VLAN_TAGS} VLAN headers are not supported"),
        });
    }
    Ok(metadata
        .into_iter()
        .map(|tag| NeighborVlanTag {
            kind: match tag.kind {
                semantics::VlanKind::Ieee8021Q => NeighborVlanKind::Ieee8021Q,
                semantics::VlanKind::Ieee8021Ad => NeighborVlanKind::Ieee8021Ad,
            },
            priority: tag.priority,
            drop_eligible: tag.drop_eligible,
            vlan_id: tag.vlan_id,
        })
        .collect())
}

fn arp_link_macs(packet: &Packet) -> (Option<MacAddress>, Option<MacAddress>) {
    let Some(layer) = packet
        .iter()
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
