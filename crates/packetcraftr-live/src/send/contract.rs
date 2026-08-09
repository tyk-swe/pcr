// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::IpAddr;

use thiserror::Error;

use packetcraftr_network::{
    Error as LiveIoError,
    neighbor::Error as NeighborError,
    route::{Error as PlanError, Materialized as MaterializedRoute, Options as PlanOptions},
    transmit::{Report as IoSendReport, TimingEvidence},
};
use packetcraftr_packet::build::{
    Error as BuildError, Options as BuildOptions, Result as BuiltPacket,
};
use packetcraftr_packet::error::{Classification, Classified, Kind};
use packetcraftr_packet::frame::{Frame, LinkType};

use super::super::Stats;
use super::super::policy::TrafficPolicyError;
use super::super::target::Error;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SendOptions {
    pub destination: Option<IpAddr>,
    pub plan: PlanOptions,
    pub build: BuildOptions,
    /// Second explicit opt-in required in addition to policy approval.
    pub allow_permissive_live: bool,
}

#[derive(Clone, Debug)]
pub struct SendReport {
    pub(crate) sent: SentPacket,
    pub(crate) stats: Stats,
}

/// Opaque successful transmission receipt. It binds the semantic build,
/// materialized route, exact provider-accepted bytes, and provider timing for
/// one send. No public constructor exists.
#[derive(Clone, Debug)]
pub struct SentPacket {
    built: BuiltPacket,
    route: MaterializedRoute,
    evidence: Frame,
    timing: TimingEvidence,
}

impl SentPacket {
    pub(crate) fn from_report(
        built: BuiltPacket,
        route: MaterializedRoute,
        report: &IoSendReport,
    ) -> Result<Self, LiveIoError> {
        let timing = report.validate_against(&built.bytes)?;
        let link_type = match route.plan.mode {
            packetcraftr_network::link::Mode::Layer2 => route.plan.route.link_type,
            packetcraftr_network::link::Mode::Layer3 => LinkType::RAW,
            packetcraftr_network::link::Mode::Auto => {
                return Err(LiveIoError::UnresolvedLinkMode);
            }
        };
        let captured_length = u32::try_from(report.wire_bytes().len()).map_err(|_| {
            LiveIoError::InvalidSendEvidence {
                message: "provider-accepted bytes exceed frame length range".to_owned(),
            }
        })?;
        let evidence = Frame::try_with_optional_timestamp(
            timing.output_wall_clock(),
            link_type,
            captured_length,
            captured_length,
            report.wire_bytes().clone(),
        )
        .map_err(|source| LiveIoError::InvalidSendEvidence {
            message: source.to_string(),
        })?;
        Ok(Self {
            built,
            route,
            evidence,
            timing,
        })
    }

    pub fn built(&self) -> &BuiltPacket {
        &self.built
    }

    pub fn packet(&self) -> &packetcraftr_packet::Packet {
        &self.built.packet
    }

    pub fn route(&self) -> &MaterializedRoute {
        &self.route
    }

    pub fn evidence(&self) -> &Frame {
        &self.evidence
    }

    pub fn wire_bytes(&self) -> &bytes::Bytes {
        self.evidence.bytes()
    }

    pub fn bytes_sent(&self) -> usize {
        self.evidence.bytes().len()
    }

    pub fn timing(&self) -> TimingEvidence {
        self.timing
    }

    pub fn freshness_at(&self) -> std::time::Instant {
        self.timing.freshness_at()
    }

    #[cfg(test)]
    pub(crate) fn for_test(bytes: bytes::Bytes, at: std::time::Instant) -> Self {
        Self::for_test_with_timing(bytes, TimingEvidence::commit(at, None))
    }

    #[cfg(test)]
    pub(crate) fn for_test_with_timing(bytes: bytes::Bytes, timing: TimingEvidence) -> Self {
        use packetcraftr_network::{
            interface::Id as InterfaceId,
            link::{Capability, Mode},
            route::{Decision, Materialized, Plan, Scope, SelectionReason},
        };

        let built = BuiltPacket {
            bytes: bytes.clone(),
            packet: packetcraftr_packet::Packet::new(),
            layout: Default::default(),
            diagnostics: Vec::new(),
            requires_live_opt_in: false,
        };
        let route = Materialized {
            plan: Plan {
                route: Decision {
                    interface: InterfaceId {
                        name: "fixture0".to_owned(),
                        index: 1,
                    },
                    source_mac: None,
                    selected_address: None,
                    preferred_source: None,
                    next_hop: None,
                    selection_reason: SelectionReason::InterfaceOnly,
                    destination_scope: Scope::Unspecified,
                    mtu: 1500,
                    capability: Capability::Layer3,
                    link_type: LinkType::RAW,
                },
                mode: Mode::Layer3,
                lookup_destination: None,
                final_destination: None,
                visited_destinations: Vec::new(),
                packet_source: None,
                neighbor_source: None,
                neighbor_target: None,
                destination_mac: None,
                source_mac: None,
                neighbor_vlan_tags: Vec::new(),
                synthesized_ethernet: false,
            },
            neighbor_resolution: None,
        };
        let report = IoSendReport::accepted(bytes, timing);
        Self::from_report(built, route, &report).expect("valid receipt fixture")
    }
}

impl SendReport {
    pub fn sent(&self) -> &SentPacket {
        &self.sent
    }

    pub fn stats(&self) -> &Stats {
        &self.stats
    }
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ClientError {
    #[error(transparent)]
    Target(#[from] Error),
    #[error(transparent)]
    Plan(#[from] PlanError),
    #[error(transparent)]
    Neighbor(#[from] NeighborError),
    #[error(transparent)]
    Build(#[from] BuildError),
    #[error(transparent)]
    Policy(#[from] TrafficPolicyError),
    #[error("permissively built packets require allow_permissive_live")]
    PermissiveLiveOptInRequired,
    #[error(transparent)]
    Io(#[from] LiveIoError),
    #[error("{operation}; capture shutdown also failed: {shutdown}")]
    OperationAndCaptureShutdown {
        operation: LiveIoError,
        shutdown: LiveIoError,
    },
    #[error("exchange packets selected different interfaces or link modes")]
    HeterogeneousExchangeRoute,
    #[error("packet template expansion failed: {message}")]
    Template { message: String },
    #[error("could not materialize {field} on layer {layer}: {message}")]
    PacketMaterialization {
        layer: usize,
        field: &'static str,
        message: String,
    },
    #[error(
        "network packet length {actual} exceeds route MTU {mtu}; apply an explicit fragmentation transform"
    )]
    PacketExceedsMtu { actual: usize, mtu: u32 },
    #[error("invalid exchange option {field}: {message}")]
    InvalidExchangeOption {
        field: &'static str,
        message: String,
    },
}

impl Classified for ClientError {
    fn classification(&self) -> Classification {
        match self {
            Self::Target(error) => error.classification(),
            Self::Plan(error) => error.classification(),
            Self::Neighbor(error) => error.classification(),
            Self::Build(_) => Classification::new(
                "packet.build",
                Kind::Packet,
                Some(
                    "correct the packet fields or select permissive mode with the required live opt-ins",
                ),
            ),
            Self::Policy(error) => error.classification(),
            Self::PermissiveLiveOptInRequired => Classification::new(
                "policy.permissive_live_opt_in",
                Kind::Policy,
                Some(
                    "set the explicit per-operation malformed-live opt-in in addition to policy approval",
                ),
            ),
            Self::Io(error) => error.classification(),
            Self::OperationAndCaptureShutdown { operation, .. } => operation.classification(),
            Self::HeterogeneousExchangeRoute => Classification::new(
                "cli.heterogeneous_exchange_route",
                Kind::Cli,
                Some("split the exchange so every packet uses the same interface and link mode"),
            ),
            Self::Template { .. } => Classification::new(
                "packet.template",
                Kind::Packet,
                Some("reduce or correct the bounded packet-template expansion"),
            ),
            Self::PacketMaterialization { .. } => Classification::new(
                "packet.materialization",
                Kind::Packet,
                Some(
                    "correct the route-dependent packet fields; post-build shape changes are rejected",
                ),
            ),
            Self::PacketExceedsMtu { .. } => Classification::new(
                "packet.mtu",
                Kind::Packet,
                Some("reduce the network packet or apply an explicit fragmentation transform"),
            ),
            Self::InvalidExchangeOption { .. } => Classification::new(
                "cli.exchange_limit",
                Kind::Cli,
                Some(
                    "use finite exchange timeout and retention limits no larger than the aggregate capture ceiling",
                ),
            ),
        }
    }

    fn causes(&self) -> Vec<String> {
        match self {
            Self::Target(error) => error.causes(),
            Self::Plan(error) => error.causes(),
            Self::Neighbor(error) => error.causes(),
            Self::Policy(error) => error.causes(),
            Self::Io(error) => error.causes(),
            Self::OperationAndCaptureShutdown {
                operation,
                shutdown,
            } => vec![operation.to_string(), shutdown.to_string()],
            _ => Vec::new(),
        }
    }
}
