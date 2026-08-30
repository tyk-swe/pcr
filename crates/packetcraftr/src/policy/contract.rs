// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::IpAddr;

use thiserror::Error;

use packetcraftr_core::error::{Classification, Classified, Kind};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Policy {
    pub allow_public_destinations: bool,
    /// Hostname resolution is a separate opt-in because a name has no stable
    /// address scope until after a resolver side effect.
    pub allow_hostname_resolution: bool,
    pub allow_permissive_packets: bool,
    /// Single opt-in for an explicit outer IP or Ethernet source the selected
    /// interface or final route does not own. Replay transmits captured
    /// sources verbatim and therefore applies this check after passive route
    /// selection and before transmission.
    pub allow_source_spoofing: bool,
    pub max_packets_per_operation: u64,
    pub max_bytes_per_operation: u64,
    pub max_resolved_addresses: usize,
}

pub const DEFAULT_MAX_RESOLVED_ADDRESSES: usize = 64;
pub const MAX_RESOLVED_ADDRESSES: usize = 4_096;

impl Default for Policy {
    fn default() -> Self {
        Self {
            allow_public_destinations: false,
            allow_hostname_resolution: false,
            allow_permissive_packets: false,
            allow_source_spoofing: false,
            max_packets_per_operation: 10_000,
            max_bytes_per_operation: 256 * 1024 * 1024,
            max_resolved_addresses: DEFAULT_MAX_RESOLVED_ADDRESSES,
        }
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    #[error("traffic policy denies public destination {destination}")]
    PublicDestination { destination: IpAddr },
    #[error("traffic policy cannot authorize packet routing semantics: {reason}")]
    InvalidPacketSemantics { reason: String },
    #[error("traffic policy denies hostname resolution for {hostname}")]
    HostnameResolution { hostname: String },
    #[error("traffic policy denies permissively built packets")]
    PermissivePacket,
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
}

impl Classified for Error {
    fn classification(&self) -> Classification {
        let (code, remediation) = match self {
            Self::PublicDestination { .. } => (
                "policy.public_destination",
                "explicitly authorize public destinations only for networks you are permitted to test",
            ),
            Self::InvalidPacketSemantics { .. } => (
                "policy.invalid_packet_semantics",
                "repair malformed or unsupported route-bearing packet fields before live transmission",
            ),
            Self::HostnameResolution { .. } => (
                "policy.hostname_resolution",
                "explicitly authorize hostname resolution, then independently authorize every resolved address",
            ),
            Self::PermissivePacket => (
                "policy.permissive_packet",
                "authorize permissive live traffic in both build options and traffic policy",
            ),
            Self::SourceNotInterfaceOwned { .. } => (
                "policy.source_ownership",
                "use an interface-owned source, select it with the route source option, or explicitly authorize source spoofing",
            ),
            Self::PacketLimit { .. } => (
                "policy.packet_limit",
                "reduce the operation packet count or deliberately raise the configured traffic budget",
            ),
            Self::ByteLimit { .. } => (
                "policy.byte_limit",
                "reduce the operation byte count or deliberately raise the configured traffic budget",
            ),
            Self::TrafficUnitLimit { .. } => (
                "policy.traffic_unit_limit",
                "reduce DNS attempts or deliberately raise the packet/socket traffic-unit budget",
            ),
            Self::TrafficByteLimit { .. } => (
                "policy.traffic_byte_limit",
                "reduce DNS attempts or query bytes, or deliberately raise the wire/application byte budget",
            ),
        };
        Classification::new(code, Kind::Policy, Some(remediation))
    }
}
