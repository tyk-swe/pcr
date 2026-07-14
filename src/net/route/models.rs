use std::fmt;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::capture::{Frame, LinkType};
use crate::error::{Classification, Kind};
use crate::net::capture::CaptureStatistics;

/// Maximum explicit VLAN headers copied into a neighbor-discovery request.
pub(crate) const MAX_NEIGHBOR_VLAN_TAGS: usize = 8;

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
    pub(super) fn supports_layer2(self) -> bool {
        matches!(self, Self::Layer2 | Self::Layer2And3)
    }

    pub(super) fn supports_layer3(self) -> bool {
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
    pub link_type: LinkType,
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
    pub captured: Vec<Frame>,
    pub evidence_truncated: bool,
    pub capture_statistics: CaptureStatistics,
}
