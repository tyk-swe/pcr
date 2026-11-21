// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

use thiserror::Error;

use packetcraftr_core::error::{Classification, Classified, Coordinate, Kind};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Policy {
    pub allow_public_destinations: bool,
    /// Hostname resolution is a separate opt-in because a name has no stable
    /// address scope until after a resolver side effect.
    pub allow_hostname_resolution: bool,
    pub allow_permissive_packets: bool,
    pub allow_source_spoofing: bool,
    /// Exact address and CIDR constraints on destinations. An empty list adds
    /// no constraint; entries only narrow permission and never grant access
    /// that the other checks deny.
    pub allowed_destinations: Vec<DestinationConstraint>,
    pub denied_destinations: Vec<DestinationConstraint>,
    pub required_destination_groups: Vec<Vec<DestinationConstraint>>,
    pub max_packets_per_operation: u64,
    pub max_bytes_per_operation: u64,
    pub max_resolved_addresses: usize,
    /// The engagement Window an operation may be admitted in. Absent means
    /// no time bound. A present Window only ever denies admission outside
    /// itself and never grants what the other checks deny.
    pub window: Option<Window>,
}

/// One half-open engagement time interval in Unix seconds. The start bound
/// is included and the end bound is excluded, so an instant exactly at
/// `not_after_unix_seconds` is already outside the Window.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Window {
    pub not_before_unix_seconds: Option<u64>,
    pub not_after_unix_seconds: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WindowState {
    Before,
    Active,
    After,
}

impl WindowState {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Before => "before",
            Self::Active => "active",
            Self::After => "after",
        }
    }
}

impl Window {
    #[must_use]
    pub const fn state_at(self, unix_seconds: u64) -> WindowState {
        if let Some(start) = self.not_before_unix_seconds
            && unix_seconds < start
        {
            return WindowState::Before;
        }
        if let Some(end) = self.not_after_unix_seconds
            && unix_seconds >= end
        {
            return WindowState::After;
        }
        WindowState::Active
    }

    #[must_use]
    pub const fn contains_at(self, unix_seconds: u64) -> bool {
        matches!(self.state_at(unix_seconds), WindowState::Active)
    }

    /// The time both Windows allow. Disjoint Windows intersect to an empty
    /// Window that contains no instant, so narrowing fails closed.
    #[must_use]
    pub const fn intersect(self, other: Self) -> Self {
        let not_before_unix_seconds =
            match (self.not_before_unix_seconds, other.not_before_unix_seconds) {
                (Some(left), Some(right)) => Some(if left >= right { left } else { right }),
                (Some(value), None) | (None, Some(value)) => Some(value),
                (None, None) => None,
            };
        let not_after_unix_seconds =
            match (self.not_after_unix_seconds, other.not_after_unix_seconds) {
                (Some(left), Some(right)) => Some(if left <= right { left } else { right }),
                (Some(value), None) | (None, Some(value)) => Some(value),
                (None, None) => None,
            };
        Self {
            not_before_unix_seconds,
            not_after_unix_seconds,
        }
    }
}

pub const DEFAULT_MAX_PACKETS_PER_OPERATION: u64 = 10_000;
pub const DEFAULT_MAX_BYTES_PER_OPERATION: u64 = 256 * 1024 * 1024;
pub const DEFAULT_MAX_RESOLVED_ADDRESSES: usize = 64;
pub const MAX_RESOLVED_ADDRESSES: usize = 4_096;

pub const MAX_DESTINATION_CONSTRAINTS: usize = 1_024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DestinationConstraint {
    Exact(IpAddr),
    Network(crate::target::Network),
}

impl DestinationConstraint {
    /// Exact IPv4 and mapped IPv6 entries compare the same embedded address
    /// in either direction. Networks follow [`Network::contains`].
    ///
    /// [`Network::contains`]: crate::target::Network::contains
    pub fn contains(&self, address: IpAddr) -> bool {
        match *self {
            Self::Exact(expected) => expected.to_canonical() == address.to_canonical(),
            Self::Network(network) => network.contains(address),
        }
    }
}

impl fmt::Display for DestinationConstraint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Exact(address) => write!(f, "{address}"),
            Self::Network(network) => network.fmt(f),
        }
    }
}

impl FromStr for DestinationConstraint {
    type Err = Error;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let invalid = |reason: &str| Error::InvalidDestinationConstraint {
            value: input.to_owned(),
            reason: reason.to_owned(),
        };
        match input.split_once('/') {
            None => input
                .parse::<IpAddr>()
                .map(Self::Exact)
                .map_err(|_| invalid("expected an IP address or CIDR network")),
            Some((address, _)) => {
                let spelled = address
                    .parse::<IpAddr>()
                    .map_err(|_| invalid("expected an IP address before the prefix separator"))?;
                let network = input.parse::<crate::target::Network>().map_err(|_| {
                    invalid("expected a decimal prefix length no wider than the address family")
                })?;
                if network.address() != spelled {
                    return Err(invalid(
                        "network constraint must spell the canonical network address",
                    ));
                }
                Ok(Self::Network(network))
            }
        }
    }
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            allow_public_destinations: false,
            allow_hostname_resolution: false,
            allow_permissive_packets: false,
            allow_source_spoofing: false,
            allowed_destinations: Vec::new(),
            denied_destinations: Vec::new(),
            required_destination_groups: Vec::new(),
            max_packets_per_operation: DEFAULT_MAX_PACKETS_PER_OPERATION,
            max_bytes_per_operation: DEFAULT_MAX_BYTES_PER_OPERATION,
            max_resolved_addresses: DEFAULT_MAX_RESOLVED_ADDRESSES,
            window: None,
        }
    }
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    #[error("resolved-address limit {value} is invalid; expected 1..={maximum}")]
    InvalidAddressLimit { value: usize, maximum: usize },
    #[error("traffic policy denies public destination {destination}")]
    PublicDestination { destination: IpAddr },
    #[error(
        "traffic policy denies destination {destination} outside the configured allowlist: {constraints}"
    )]
    DestinationNotAllowed {
        destination: IpAddr,
        constraints: String,
    },
    #[error("destination constraint {value:?} is invalid: {reason}")]
    InvalidDestinationConstraint { value: String, reason: String },
    #[error("destination constraint count {actual} exceeds policy limit {maximum}")]
    DestinationConstraintLimit { actual: usize, maximum: usize },
    #[error("traffic policy denies destination {destination} excluded by {constraints}")]
    DestinationDenied {
        destination: IpAddr,
        constraints: String,
    },
    #[error("engagement scope document is invalid: {reason}")]
    InvalidScopeDocument { reason: String },
    #[error("traffic policy cannot authorize packet routing semantics: {reason}")]
    InvalidPacketSemantics {
        reason: String,
        #[source]
        source: Option<packetcraftr_core::protocol::semantics::Error>,
    },
    #[error("traffic policy cannot authorize wire bytes that do not form a frame")]
    WireFrame {
        #[source]
        source: packetcraftr_core::frame::Error,
    },
    #[error("traffic policy cannot authorize undecodable packet routing semantics")]
    UndecodableWire {
        #[source]
        source: packetcraftr_core::decode::Error,
    },
    #[error("traffic policy denies hostname resolution for {hostname}")]
    HostnameResolution { hostname: String },
    #[error("traffic policy denies permissively built packets")]
    PermissivePacket,
    #[error("permissively built packets require allow_permissive_live")]
    PermissiveLiveOptIn,
    #[error("traffic policy denies source {packet_source} that interface {interface} does not own")]
    SourceNotInterfaceOwned {
        packet_source: String,
        interface: String,
    },
    #[error("operation packet count {actual} exceeds policy limit {limit}")]
    PacketLimit { actual: u64, limit: u64 },
    #[error("operation byte count {actual} exceeds policy limit {limit}")]
    ByteLimit { actual: u64, limit: u64 },
    #[error("operation packet/socket traffic-unit count {actual} exceeds policy limit {limit}")]
    TrafficUnitLimit { actual: u64, limit: u64 },
    #[error("operation wire/application byte count {actual} exceeds policy limit {limit}")]
    TrafficByteLimit { actual: u64, limit: u64 },
    #[error(
        "traffic policy denies operation at unix time {now_unix_seconds} outside the engagement scope window"
    )]
    OutsideScopeWindow { now_unix_seconds: u64 },
}

const INVALID_PACKET_SEMANTICS: Classification = Classification::new(
    packetcraftr_core::error::Code::PolicyInvalidPacketSemantics,
    Kind::Policy,
    Some("repair malformed or unsupported route-bearing packet fields before live transmission"),
);

impl Classified for Error {
    fn classification(&self) -> Classification {
        let (code, remediation) = match self {
            // A malformed resolved-address bound is a caller request error and
            // shares the `cli.live_target` code with target resolution.
            Self::InvalidAddressLimit { .. } => (
                packetcraftr_core::error::Code::CliLiveTarget,
                "set the resolved-address limit to at least 1 and no more than the supported maximum",
            ),
            Self::PublicDestination { .. } => (
                packetcraftr_core::error::Code::PolicyPublicDestination,
                "explicitly authorize public destinations only for networks you are permitted to test",
            ),
            Self::DestinationNotAllowed { .. } => (
                packetcraftr_core::error::Code::PolicyDestinationNotAllowed,
                "permit the destination with an exact address or CIDR allowlist entry, or choose a permitted destination",
            ),
            Self::InvalidDestinationConstraint { .. } => (
                packetcraftr_core::error::Code::CliLiveTarget,
                "use an IP address or canonical CIDR network as the destination constraint",
            ),
            Self::DestinationConstraintLimit { .. } => (
                packetcraftr_core::error::Code::CliLiveTarget,
                "declare fewer destination constraints, covering adjacent hosts with one CIDR network where possible",
            ),
            Self::DestinationDenied { .. } => (
                packetcraftr_core::error::Code::PolicyDestinationNotAllowed,
                "choose a destination the engagement scope does not exclude, or amend the scope with approval",
            ),
            Self::InvalidScopeDocument { .. } => (
                packetcraftr_core::error::Code::CliLiveTarget,
                "provide a packetcraftr.scope/v1 or packetcraftr.scope/v2 JSON document with a label and IP or canonical CIDR destinations",
            ),
            Self::InvalidPacketSemantics { .. }
            | Self::WireFrame { .. }
            | Self::UndecodableWire { .. } => {
                return INVALID_PACKET_SEMANTICS;
            }
            Self::HostnameResolution { .. } => (
                packetcraftr_core::error::Code::PolicyHostnameResolution,
                "explicitly authorize hostname resolution, then independently authorize every resolved address",
            ),
            Self::PermissivePacket => (
                packetcraftr_core::error::Code::PolicyPermissivePacket,
                "authorize permissive live traffic in both build options and traffic policy",
            ),
            Self::PermissiveLiveOptIn => (
                packetcraftr_core::error::Code::PolicyPermissiveLiveOptIn,
                "set the explicit per-operation malformed-live opt-in in addition to policy approval",
            ),
            Self::SourceNotInterfaceOwned { .. } => (
                packetcraftr_core::error::Code::PolicySourceOwnership,
                "use an interface-owned source, select it with the route source option, or explicitly authorize source spoofing",
            ),
            Self::PacketLimit { .. } => (
                packetcraftr_core::error::Code::PolicyPacketLimit,
                "reduce the operation packet count or deliberately raise the configured traffic budget",
            ),
            Self::ByteLimit { .. } => (
                packetcraftr_core::error::Code::PolicyByteLimit,
                "reduce the operation byte count or deliberately raise the configured traffic budget",
            ),
            Self::TrafficUnitLimit { .. } => (
                packetcraftr_core::error::Code::PolicyTrafficUnitLimit,
                "reduce the connections, messages, or DNS attempts, or deliberately raise the packet/socket traffic-unit budget",
            ),
            Self::TrafficByteLimit { .. } => (
                packetcraftr_core::error::Code::PolicyTrafficByteLimit,
                "reduce the application or query bytes, or deliberately raise the wire/application byte budget",
            ),
            Self::OutsideScopeWindow { .. } => (
                packetcraftr_core::error::Code::PolicyScopeWindow,
                "run inside the engagement scope window, or amend the scope window with approval",
            ),
        };
        let kind = match self {
            Self::InvalidAddressLimit { .. }
            | Self::InvalidDestinationConstraint { .. }
            | Self::DestinationConstraintLimit { .. }
            | Self::InvalidScopeDocument { .. } => Kind::Usage,
            _ => Kind::Policy,
        };
        Classification::new(code, kind, Some(remediation))
    }

    fn context(&self) -> Option<Coordinate> {
        match self {
            Self::UndecodableWire { source } => source.context(),
            _ => None,
        }
    }
}
