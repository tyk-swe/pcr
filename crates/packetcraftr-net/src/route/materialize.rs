// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::{Error as LiveIoError, capture::CaptureStatistics};
use packetcraftr_capture::Frame;

fn materialize<N: NeighborResolver>(
    mut plan: PlannedRoute,
    resolver: &N,
) -> Result<MaterializedRoute, NeighborError> {
    let mut neighbor_resolution = None;
    if plan.needs_neighbor_resolution() {
        let target = plan
            .neighbor_target
            .ok_or_else(|| NeighborError::MissingNeighborTarget {
                interface: plan.route.interface.name.clone(),
            })?;
        let source = plan
            .neighbor_source
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

pub trait NeighborResolver: Send + Sync {
    /// Resolves synchronously. Custom implementations must bound blocking or
    /// support cancellation; callers can enforce outer deadlines only before
    /// and after this method returns.
    fn resolve_request(
        &self,
        request: &NeighborRequest,
    ) -> Result<NeighborResolution, NeighborError>;
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

pub(super) fn outer_ethernet_mac(packet: &Packet, field: &str) -> Option<MacAddress> {
    semantics::outer_layers(packet)
        .find(|layer| BuiltinProtocol::of(*layer) == Some(BuiltinProtocol::Ethernet))
        .and_then(|layer| layer.field(field))
        .and_then(|value| match value {
            FieldValue::Mac(value) if value != [0; 6] => Some(MacAddress(value)),
            _ => None,
        })
}

pub(super) fn extract_neighbor_vlan_tags(
    packet: &Packet,
) -> Result<Vec<NeighborVlanTag>, PlanError> {
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

pub(super) fn arp_link_macs(packet: &Packet) -> (Option<MacAddress>, Option<MacAddress>) {
    let Some(layer) = semantics::outer_layers(packet)
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

pub(super) fn multicast_mac(destination: IpAddr) -> Option<MacAddress> {
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
