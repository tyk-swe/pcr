// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

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
    /// Exact address and CIDR constraints on destinations. An empty list adds
    /// no constraint; entries only narrow permission and never grant access
    /// that the other checks deny.
    pub allowed_destinations: Vec<DestinationConstraint>,
    pub max_packets_per_operation: u64,
    pub max_bytes_per_operation: u64,
    pub max_resolved_addresses: usize,
}

pub const DEFAULT_MAX_RESOLVED_ADDRESSES: usize = 64;
pub const MAX_RESOLVED_ADDRESSES: usize = 4_096;

/// Maximum destination constraints accepted in a policy.
pub const MAX_DESTINATION_CONSTRAINTS: usize = 1_024;

/// An exact address or same-family CIDR constraint. `ADDR/PREFIX` must be a
/// canonical network (host bits are rejected); bare `ADDR` matches one host.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DestinationConstraint {
    Exact(IpAddr),
    /// Host bits are already masked by [`crate::target::Network::new`].
    Network(crate::target::Network),
}

impl DestinationConstraint {
    pub fn contains(&self, address: IpAddr) -> bool {
        match *self {
            Self::Exact(expected) => expected == address,
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
            max_packets_per_operation: 10_000,
            max_bytes_per_operation: 256 * 1024 * 1024,
            max_resolved_addresses: DEFAULT_MAX_RESOLVED_ADDRESSES,
        }
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
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
    #[error("traffic policy cannot authorize packet routing semantics: {reason}")]
    InvalidPacketSemantics {
        reason: String,
        /// The semantics traversal failure this refusal reports, when it
        /// came from the packet rather than from policy's own checks.
        #[source]
        source: Option<packetcraftr_core::packet::semantics::Error>,
    },
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

pub(crate) const INVALID_PACKET_SEMANTICS: Classification = Classification::new(
    "policy.invalid_packet_semantics",
    Kind::Policy,
    Some("repair malformed or unsupported route-bearing packet fields before live transmission"),
);

impl Classified for Error {
    fn classification(&self) -> Classification {
        let (code, remediation) = match self {
            // A malformed resolved-address bound is a caller request error and
            // shares the `cli.live_target` code with target resolution.
            Self::InvalidAddressLimit { .. } => (
                "cli.live_target",
                "set the resolved-address limit to at least 1 and no more than the supported maximum",
            ),
            Self::PublicDestination { .. } => (
                "policy.public_destination",
                "explicitly authorize public destinations only for networks you are permitted to test",
            ),
            Self::DestinationNotAllowed { .. } => (
                "policy.destination_not_allowed",
                "permit the destination with an exact address or CIDR allowlist entry, or choose a permitted destination",
            ),
            // Malformed destination constraints and a constraint list beyond
            // its bound are caller request errors, like the resolved-address
            // bound, and share the `cli.live_target` code with target input.
            Self::InvalidDestinationConstraint { .. } => (
                "cli.live_target",
                "use an IP address or canonical CIDR network as the destination constraint",
            ),
            Self::DestinationConstraintLimit { .. } => (
                "cli.live_target",
                "declare fewer destination constraints, covering adjacent hosts with one CIDR network where possible",
            ),
            Self::InvalidPacketSemantics { .. } => return INVALID_PACKET_SEMANTICS,
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
        let kind = match self {
            Self::InvalidAddressLimit { .. }
            | Self::InvalidDestinationConstraint { .. }
            | Self::DestinationConstraintLimit { .. } => Kind::Cli,
            _ => Kind::Policy,
        };
        Classification::new(code, kind, Some(remediation))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn constraint(input: &str) -> Result<DestinationConstraint, Error> {
        input.parse()
    }

    #[test]
    fn bare_addresses_parse_as_exact_constraints() {
        assert_eq!(
            constraint("192.0.2.9").expect("address parses"),
            DestinationConstraint::Exact(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9)))
        );
        assert_eq!(
            constraint("2001:db8::1").expect("address parses"),
            DestinationConstraint::Exact("2001:db8::1".parse::<IpAddr>().unwrap())
        );
    }

    #[test]
    fn cidr_constraints_match_the_masked_bits_only() {
        let v4 = constraint("192.0.2.0/24").expect("canonical network parses");
        assert!(v4.contains(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))));
        assert!(v4.contains(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 255))));
        assert!(!v4.contains(IpAddr::V4(Ipv4Addr::new(192, 0, 3, 1))));
        // A constraint never crosses address families.
        assert!(!v4.contains("2001:db8::1".parse().unwrap()));

        let v6 = constraint("2001:db8::/32").expect("canonical v6 network parses");
        assert!(v6.contains("2001:db8:ffff::1".parse().unwrap()));
        assert!(!v6.contains("2001:db9::1".parse().unwrap()));
        assert!(!v6.contains(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))));

        let hosts = constraint("192.0.2.9/32").expect("host prefix parses");
        assert!(hosts.contains(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9))));
        assert!(!hosts.contains(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 8))));

        let whole_family = constraint("0.0.0.0/0").expect("zero prefix parses");
        assert!(whole_family.contains(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 8))));
        assert!(!whole_family.contains("::1".parse().unwrap()));
    }

    #[test]
    fn malformed_and_noncanonical_constraints_are_rejected() {
        for input in [
            "",
            "not-an-address",
            "192.0.2.0/",
            "192.0.2.0/-1",
            "192.0.2.0/+24",
            "192.0.2.0/24x",
            "192.0.2.0/33",
            "2001:db8::/129",
            "192.0.2.1/24",
            "2001:db8::1/32",
            "/24",
            "192.0.2.0/24/8",
        ] {
            assert!(
                constraint(input).is_err(),
                "{input:?} must not parse as a constraint"
            );
        }
    }

    #[test]
    fn constraint_parse_errors_classify_as_target_input() {
        let error = constraint("192.0.2.1/24").expect_err("host bits must be spelled out");
        assert_eq!(error.classification().code, "cli.live_target");
        assert!(error.to_string().contains("canonical network"));
    }

    #[test]
    fn constraint_and_target_network_parsers_agree_on_cidr_text() {
        for input in ["10.0.0.0/8", "2001:db8::/32", "192.0.2.9/32", "::/0"] {
            let network = input
                .parse::<crate::target::Network>()
                .expect("target network parses");
            assert_eq!(
                input.parse::<DestinationConstraint>(),
                Ok(DestinationConstraint::Network(network)),
                "{input} must parse identically on both surfaces"
            );
        }
        let signed_prefix = "192.0.2.0/+24";
        assert!(signed_prefix.parse::<DestinationConstraint>().is_err());
        assert!(signed_prefix.parse::<crate::target::Network>().is_err());
    }

    #[test]
    fn constraint_display_round_trips_through_parse() {
        for input in ["192.0.2.9", "10.0.0.0/8", "2001:db8::/32", "::/0"] {
            let parsed = constraint(input).expect("constraint parses");
            assert_eq!(
                parsed.to_string().parse::<DestinationConstraint>().ok(),
                Some(parsed),
                "{input} must round-trip"
            );
        }
    }
}
