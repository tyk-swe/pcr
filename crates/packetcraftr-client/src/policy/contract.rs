// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::IpAddr;

use serde::Deserialize;
use thiserror::Error;

use packetcraftr_error::{Classification, Classified, Kind};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrafficPolicy {
    pub allow_public_destinations: bool,
    /// Hostname resolution is a separate opt-in because a name has no stable
    /// address scope until after a resolver side effect.
    pub allow_hostname_resolution: bool,
    pub allow_permissive_packets: bool,
    pub max_packets_per_operation: u64,
    pub max_bytes_per_operation: u64,
    pub max_resolved_addresses: usize,
}

pub const DEFAULT_MAX_RESOLVED_ADDRESSES: usize = 64;
pub const MAX_RESOLVED_ADDRESSES: usize = 4_096;

impl Default for TrafficPolicy {
    fn default() -> Self {
        Self {
            allow_public_destinations: false,
            allow_hostname_resolution: false,
            allow_permissive_packets: false,
            max_packets_per_operation: 10_000,
            max_bytes_per_operation: 256 * 1024 * 1024,
            max_resolved_addresses: DEFAULT_MAX_RESOLVED_ADDRESSES,
        }
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum TrafficPolicyError {
    #[error("traffic policy denies public destination {destination}")]
    PublicDestination { destination: IpAddr },
    #[error("traffic policy cannot authorize packet routing semantics: {reason}")]
    InvalidPacketSemantics { reason: String },
    #[error("traffic policy cannot authorize packet routing semantics: {reason}")]
    InvalidIpv4Options { reason: String },
    #[error("traffic policy denies hostname resolution for {hostname}")]
    HostnameResolution { hostname: String },
    #[error("traffic policy denies permissively built packets")]
    PermissivePacket,
    #[error("operation packet count {actual} exceeds policy limit {limit}")]
    PacketLimit { actual: u64, limit: u64 },
    #[error("operation byte count {actual} exceeds policy limit {limit}")]
    ByteLimit { actual: u64, limit: u64 },
}

impl Classified for TrafficPolicyError {
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
            Self::InvalidIpv4Options { .. } => (
                "policy.invalid_ipv4_options",
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
            Self::PacketLimit { .. } => (
                "policy.packet_limit",
                "reduce the operation packet count or deliberately raise the configured traffic budget",
            ),
            Self::ByteLimit { .. } => (
                "policy.byte_limit",
                "reduce the operation byte count or deliberately raise the configured traffic budget",
            ),
        };
        Classification::new(code, Kind::Policy, Some(remediation))
    }
}

/// A traffic policy as written in a configuration file.
///
/// Every field is optional and every omitted field falls back to the built-in
/// default, so a file can only describe what it deliberately states. Unknown
/// keys are rejected rather than ignored: a policy is a safety boundary, and a
/// typo in a gate name must not read as "gate not requested".
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrafficPolicyFile {
    pub allow_public_destinations: Option<bool>,
    pub allow_hostname_resolution: Option<bool>,
    pub allow_permissive_packets: Option<bool>,
    pub max_packets_per_operation: Option<u64>,
    pub max_bytes_per_operation: Option<u64>,
    pub max_resolved_addresses: Option<usize>,
}

/// Command-line values layered over a policy file.
///
/// The opt-in gates are `bool` rather than `Option<bool>` because a flag can
/// only request authorization: its absence means "not requested here", never
/// "deny what the file granted". The budgets are optional because absence and
/// an explicitly typed value are genuinely different there.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TrafficPolicyOverrides {
    pub allow_public_destinations: bool,
    pub allow_hostname_resolution: bool,
    pub allow_permissive_packets: bool,
    pub max_packets_per_operation: Option<u64>,
    pub max_bytes_per_operation: Option<u64>,
    pub max_resolved_addresses: Option<usize>,
}

impl TrafficPolicy {
    /// Resolves a policy from a file and command-line overrides.
    ///
    /// Precedence runs command line, then file, then built-in defaults.
    pub fn resolve(file: Option<TrafficPolicyFile>, overrides: TrafficPolicyOverrides) -> Self {
        let file = file.unwrap_or_default();
        let default = Self::default();
        Self {
            allow_public_destinations: overrides.allow_public_destinations
                || file.allow_public_destinations.unwrap_or(false),
            allow_hostname_resolution: overrides.allow_hostname_resolution
                || file.allow_hostname_resolution.unwrap_or(false),
            allow_permissive_packets: overrides.allow_permissive_packets
                || file.allow_permissive_packets.unwrap_or(false),
            max_packets_per_operation: overrides
                .max_packets_per_operation
                .or(file.max_packets_per_operation)
                .unwrap_or(default.max_packets_per_operation),
            max_bytes_per_operation: overrides
                .max_bytes_per_operation
                .or(file.max_bytes_per_operation)
                .unwrap_or(default.max_bytes_per_operation),
            max_resolved_addresses: overrides
                .max_resolved_addresses
                .or(file.max_resolved_addresses)
                .unwrap_or(default.max_resolved_addresses),
        }
    }
}

#[cfg(test)]
mod resolution_tests {
    use super::{TrafficPolicy, TrafficPolicyFile, TrafficPolicyOverrides};

    #[test]
    fn an_absent_file_and_absent_flags_resolve_to_the_defaults() {
        assert_eq!(
            TrafficPolicy::resolve(None, TrafficPolicyOverrides::default()),
            TrafficPolicy::default()
        );
    }

    #[test]
    fn a_file_supplies_what_the_command_line_did_not_state() {
        let policy = TrafficPolicy::resolve(
            Some(TrafficPolicyFile {
                allow_public_destinations: Some(true),
                max_packets_per_operation: Some(5),
                ..TrafficPolicyFile::default()
            }),
            TrafficPolicyOverrides::default(),
        );
        assert!(policy.allow_public_destinations);
        assert_eq!(policy.max_packets_per_operation, 5);
        // Everything the file left out keeps its built-in default.
        assert!(!policy.allow_hostname_resolution);
        assert_eq!(
            policy.max_bytes_per_operation,
            TrafficPolicy::default().max_bytes_per_operation
        );
    }

    #[test]
    fn command_line_budgets_win_over_the_file() {
        let policy = TrafficPolicy::resolve(
            Some(TrafficPolicyFile {
                max_packets_per_operation: Some(5),
                max_bytes_per_operation: Some(1024),
                max_resolved_addresses: Some(2),
                ..TrafficPolicyFile::default()
            }),
            TrafficPolicyOverrides {
                max_packets_per_operation: Some(7),
                max_resolved_addresses: Some(9),
                ..TrafficPolicyOverrides::default()
            },
        );
        assert_eq!(policy.max_packets_per_operation, 7);
        assert_eq!(policy.max_resolved_addresses, 9);
        // A budget the command line did not state still comes from the file.
        assert_eq!(policy.max_bytes_per_operation, 1024);
    }

    #[test]
    fn an_opt_in_flag_grants_but_never_revokes_what_a_file_granted() {
        // A flag can only request authorization, so its absence must not read
        // as a denial of what the operator wrote in the file.
        let from_file = TrafficPolicy::resolve(
            Some(TrafficPolicyFile {
                allow_hostname_resolution: Some(true),
                ..TrafficPolicyFile::default()
            }),
            TrafficPolicyOverrides::default(),
        );
        assert!(from_file.allow_hostname_resolution);

        let from_flag = TrafficPolicy::resolve(
            Some(TrafficPolicyFile {
                allow_hostname_resolution: Some(false),
                ..TrafficPolicyFile::default()
            }),
            TrafficPolicyOverrides {
                allow_hostname_resolution: true,
                ..TrafficPolicyOverrides::default()
            },
        );
        assert!(from_flag.allow_hostname_resolution);

        // A file that states nothing leaves every gate closed.
        let neither = TrafficPolicy::resolve(
            Some(TrafficPolicyFile::default()),
            TrafficPolicyOverrides::default(),
        );
        assert!(!neither.allow_public_destinations);
        assert!(!neither.allow_hostname_resolution);
        assert!(!neither.allow_permissive_packets);
    }
}
