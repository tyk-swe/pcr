// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::{IpAddr, ToSocketAddrs};
use std::str::FromStr;

use serde::Serialize;
use thiserror::Error;

use packetcraftr_core::error::{Classification, Classified, Kind};

use super::super::policy::TrafficPolicyError;

/// Validated, canonical ASCII DNS hostname used by live target resolution.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct Hostname(String);

impl Hostname {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for Hostname {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for Hostname {
    type Err = TargetResolutionError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let hostname = value.strip_suffix('.').unwrap_or(value);
        let invalid = |reason| TargetResolutionError::InvalidHostname {
            hostname: value.to_owned(),
            reason,
        };
        if hostname.is_empty() {
            return Err(invalid("must not be empty"));
        }
        if !hostname.is_ascii() {
            return Err(invalid("must be an ASCII DNS hostname"));
        }
        if hostname.len() > 253 {
            return Err(invalid("exceeds the 253-byte DNS hostname limit"));
        }
        for label in hostname.split('.') {
            if label.is_empty() {
                return Err(invalid("contains an empty DNS label"));
            }
            if label.len() > 63 {
                return Err(invalid("contains a DNS label longer than 63 bytes"));
            }
            let bytes = label.as_bytes();
            if !bytes.first().is_some_and(u8::is_ascii_alphanumeric)
                || !bytes.last().is_some_and(u8::is_ascii_alphanumeric)
                || !bytes
                    .iter()
                    .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
            {
                return Err(invalid(
                    "labels must contain letters, digits, or interior hyphens",
                ));
            }
        }
        Ok(Self(hostname.to_ascii_lowercase()))
    }
}

/// Declared live destination before any hostname-resolution side effect.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum LiveTarget {
    Address(IpAddr),
    Hostname(Hostname),
}

impl FromStr for LiveTarget {
    type Err = TargetResolutionError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.parse::<IpAddr>() {
            Ok(address) => Ok(Self::Address(address)),
            Err(_) => value.parse::<Hostname>().map(Self::Hostname),
        }
    }
}

/// IP protocol version used when selecting one address from a resolved target.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IpVersion {
    V4,
    V6,
}

impl IpVersion {
    pub const fn label(self) -> &'static str {
        match self {
            Self::V4 => "IPv4",
            Self::V6 => "IPv6",
        }
    }

    const fn accepts(self, address: IpAddr) -> bool {
        matches!(
            (self, address),
            (Self::V4, IpAddr::V4(_)) | (Self::V6, IpAddr::V6(_))
        )
    }
}

/// A target whose declared hostname and every selected address have passed the
/// current traffic policy. Fields stay private so callers cannot forge this
/// authorization token.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ResolvedTarget {
    pub(crate) declared: LiveTarget,
    pub(crate) addresses: Vec<IpAddr>,
}

impl ResolvedTarget {
    pub fn declared(&self) -> &LiveTarget {
        &self.declared
    }

    pub fn addresses(&self) -> &[IpAddr] {
        &self.addresses
    }

    pub fn selected_address(&self) -> IpAddr {
        self.addresses[0]
    }

    pub fn address_for_version(&self, version: IpVersion) -> Option<IpAddr> {
        self.addresses
            .iter()
            .copied()
            .find(|address| version.accepts(*address))
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum TargetResolutionError {
    #[error("invalid hostname {hostname:?}: {reason}")]
    InvalidHostname {
        hostname: String,
        reason: &'static str,
    },
    #[error("resolved-address limit {value} is invalid; expected 1..={maximum}")]
    InvalidAddressLimit { value: usize, maximum: usize },
    #[error("hostname resolution for {hostname} failed: {message}")]
    Resolver { hostname: String, message: String },
    #[error("hostname {hostname} did not resolve to any addresses")]
    NoAddresses { hostname: String },
    #[error("hostname {hostname} resolved beyond the configured {limit}-address limit")]
    AddressLimit { hostname: String, limit: usize },
    #[error("resolved target has no {family} address compatible with the packet")]
    AddressFamilyUnavailable { family: &'static str },
    #[error(transparent)]
    Policy(#[from] TrafficPolicyError),
}

impl Classified for TargetResolutionError {
    fn classification(&self) -> Classification {
        match self {
            Self::InvalidHostname { .. } | Self::InvalidAddressLimit { .. } => Classification::new(
                "cli.live_target",
                Kind::Cli,
                Some("use a valid IP address or bounded ASCII DNS hostname"),
            ),
            Self::Resolver { .. } | Self::NoAddresses { .. } => Classification::new(
                "io.hostname_resolution",
                Kind::Io,
                Some(
                    "inspect resolver configuration and retry; no route lookup or transmission was attempted",
                ),
            ),
            Self::AddressLimit { .. } => Classification::new(
                "io.hostname_address_limit",
                Kind::Io,
                Some(
                    "reduce the resolver result set or deliberately raise the bounded address limit",
                ),
            ),
            Self::AddressFamilyUnavailable { .. } => Classification::new(
                "packet.target_address_family",
                Kind::Packet,
                Some("select a target address whose family matches the packet's IP layer"),
            ),
            Self::Policy(error) => error.classification(),
        }
    }

    fn causes(&self) -> Vec<String> {
        match self {
            Self::Policy(error) => error.causes(),
            _ => Vec::new(),
        }
    }
}

/// Injectable hostname resolver. Implementations must stop once `limit`
/// distinct addresses have been selected and report a typed overflow.
pub trait HostnameResolver: Send + Sync {
    fn resolve(
        &self,
        hostname: &Hostname,
        limit: usize,
    ) -> Result<Vec<IpAddr>, TargetResolutionError>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SystemHostnameResolver;

impl HostnameResolver for SystemHostnameResolver {
    fn resolve(
        &self,
        hostname: &Hostname,
        limit: usize,
    ) -> Result<Vec<IpAddr>, TargetResolutionError> {
        let resolved = (hostname.as_str(), 0).to_socket_addrs().map_err(|source| {
            TargetResolutionError::Resolver {
                hostname: hostname.to_string(),
                message: source.to_string(),
            }
        })?;
        let mut addresses = Vec::new();
        for address in resolved.map(|address| address.ip()) {
            if addresses.contains(&address) {
                continue;
            }
            if addresses.len() >= limit {
                return Err(TargetResolutionError::AddressLimit {
                    hostname: hostname.to_string(),
                    limit,
                });
            }
            addresses.push(address);
        }
        if addresses.is_empty() {
            return Err(TargetResolutionError::NoAddresses {
                hostname: hostname.to_string(),
            });
        }
        Ok(addresses)
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use packetcraftr_core::error::{Classified, Kind};

    use super::{Hostname, IpVersion, LiveTarget, ResolvedTarget, TargetResolutionError};
    use crate::policy::TrafficPolicyError;

    #[test]
    fn hostname_parsing_canonicalizes_ascii_case_and_one_trailing_dot() {
        let hostname = "WWW.Example.COM.".parse::<Hostname>().unwrap();
        assert_eq!(hostname.as_str(), "www.example.com");
        assert_eq!(hostname.to_string(), "www.example.com");
    }

    #[test]
    fn hostname_parsing_accepts_boundary_sized_labels_and_name() {
        let label = "a".repeat(63);
        let hostname = format!("{label}.{label}.{label}.{}", "b".repeat(61));
        assert_eq!(hostname.len(), 253);
        assert_eq!(hostname.parse::<Hostname>().unwrap().as_str(), hostname);
    }

    #[test]
    fn hostname_parsing_rejects_invalid_grammar_and_limits() {
        let invalid = [
            String::new(),
            ".".to_owned(),
            "éxample.test".to_owned(),
            "a..test".to_owned(),
            "-a.test".to_owned(),
            "a-.test".to_owned(),
            "a_b.test".to_owned(),
            format!("{}.test", "a".repeat(64)),
            "a".repeat(254),
        ];
        for hostname in invalid {
            let error = hostname.parse::<Hostname>().unwrap_err();
            assert!(matches!(
                error,
                TargetResolutionError::InvalidHostname { .. }
            ));
        }
    }

    #[test]
    fn live_target_prefers_ip_address_parsing_then_hostname_parsing() {
        assert_eq!(
            "192.0.2.1".parse::<LiveTarget>().unwrap(),
            LiveTarget::Address(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)))
        );
        assert!(matches!(
            "Example.Test".parse::<LiveTarget>().unwrap(),
            LiveTarget::Hostname(hostname) if hostname.as_str() == "example.test"
        ));
        assert!("not a hostname".parse::<LiveTarget>().is_err());
    }

    #[test]
    fn resolved_target_accessors_and_family_selection_preserve_order() {
        let first = IpAddr::V6(Ipv6Addr::LOCALHOST);
        let second = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let target = ResolvedTarget {
            declared: LiveTarget::Address(first),
            addresses: vec![first, second],
        };

        assert_eq!(target.declared(), &LiveTarget::Address(first));
        assert_eq!(target.addresses(), &[first, second]);
        assert_eq!(target.selected_address(), first);
        assert_eq!(target.address_for_version(IpVersion::V4), Some(second));
        assert_eq!(target.address_for_version(IpVersion::V6), Some(first));
        assert_eq!(IpVersion::V4.label(), "IPv4");
        assert_eq!(IpVersion::V6.label(), "IPv6");
    }

    #[test]
    fn unavailable_address_family_returns_none() {
        let address = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let target = ResolvedTarget {
            declared: LiveTarget::Address(address),
            addresses: vec![address],
        };
        assert_eq!(target.address_for_version(IpVersion::V6), None);
    }

    #[test]
    fn target_resolution_error_classifications_cover_every_family() {
        let cases = [
            (
                TargetResolutionError::InvalidHostname {
                    hostname: String::new(),
                    reason: "must not be empty",
                },
                "cli.live_target",
                Kind::Cli,
            ),
            (
                TargetResolutionError::InvalidAddressLimit {
                    value: 0,
                    maximum: 64,
                },
                "cli.live_target",
                Kind::Cli,
            ),
            (
                TargetResolutionError::Resolver {
                    hostname: "example.test".to_owned(),
                    message: "failed".to_owned(),
                },
                "io.hostname_resolution",
                Kind::Io,
            ),
            (
                TargetResolutionError::NoAddresses {
                    hostname: "example.test".to_owned(),
                },
                "io.hostname_resolution",
                Kind::Io,
            ),
            (
                TargetResolutionError::AddressLimit {
                    hostname: "example.test".to_owned(),
                    limit: 1,
                },
                "io.hostname_address_limit",
                Kind::Io,
            ),
            (
                TargetResolutionError::AddressFamilyUnavailable { family: "IPv6" },
                "packet.target_address_family",
                Kind::Packet,
            ),
            (
                TargetResolutionError::Policy(TrafficPolicyError::PublicDestination {
                    destination: "8.8.8.8".parse().unwrap(),
                }),
                "policy.public_destination",
                Kind::Policy,
            ),
        ];

        for (error, code, kind) in cases {
            let classification = error.classification();
            assert_eq!(classification.code, code);
            assert_eq!(classification.kind, kind);
            assert!(classification.remediation.is_some());
            assert!(!error.to_string().is_empty());
        }
    }
}
