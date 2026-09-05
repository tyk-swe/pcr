// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::{IpAddr, ToSocketAddrs};
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use packetcraftr_core::error::{Classification, Classified, Kind};

/// Validated, canonical ASCII DNS hostname used by live target resolution.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct Hostname(String);

impl<'de> Deserialize<'de> for Hostname {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

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
    type Err = Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let hostname = value.strip_suffix('.').unwrap_or(value);
        let invalid = |reason| Error::InvalidHostname {
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
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum Target {
    Address(IpAddr),
    Hostname(Hostname),
}

impl std::fmt::Display for Target {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Address(address) => address.fmt(formatter),
            Self::Hostname(hostname) => hostname.fmt(formatter),
        }
    }
}

impl FromStr for Target {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.parse::<IpAddr>() {
            Ok(address) => Ok(Self::Address(address)),
            Err(_) => value.parse::<Hostname>().map(Self::Hostname),
        }
    }
}

/// Address-family selection shared by target-oriented live operations.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Family {
    #[default]
    Any,
    Ipv4,
    Ipv6,
}

impl Family {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Any => "requested",
            Self::Ipv4 => "IPv4",
            Self::Ipv6 => "IPv6",
        }
    }

    pub(crate) const fn accepts(self, address: IpAddr) -> bool {
        match self {
            Self::Any => true,
            Self::Ipv4 => address.is_ipv4(),
            Self::Ipv6 => address.is_ipv6(),
        }
    }
}

/// Policy-authorized target with private fields that prevent forgery.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Authorized {
    pub(crate) declared: Target,
    pub(crate) addresses: Vec<IpAddr>,
}

impl Authorized {
    pub fn declared(&self) -> &Target {
        &self.declared
    }

    pub fn addresses(&self) -> &[IpAddr] {
        &self.addresses
    }

    #[expect(
        clippy::indexing_slicing,
        reason = "authorization only constructs `Authorized` with a non-empty address list"
    )]
    pub fn selected_address(&self) -> IpAddr {
        self.addresses[0]
    }

    pub fn address_for_family(&self, family: Family) -> Option<IpAddr> {
        self.addresses
            .iter()
            .copied()
            .find(|address| family.accepts(*address))
    }
}

/// A resolver refusal retains the system failure it was given, which is not
/// comparable, so these failures are matched on rather than equated.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    #[error("invalid hostname {hostname:?}: {reason}")]
    InvalidHostname {
        hostname: String,
        reason: &'static str,
    },
    #[error("hostname resolution for {hostname} failed")]
    Resolver {
        hostname: String,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    #[error("hostname {hostname} did not resolve to any addresses")]
    NoAddresses { hostname: String },
    #[error("hostname {hostname} resolved beyond the configured {limit}-address limit")]
    AddressLimit { hostname: String, limit: usize },
    #[error("resolved target has no {family} address compatible with the packet")]
    AddressFamilyUnavailable { family: &'static str },
    #[error(transparent)]
    Policy(#[from] crate::policy::Error),
}

impl Classified for Error {
    fn classification(&self) -> Classification {
        match self {
            Self::InvalidHostname { .. } => Classification::new(
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

    /// Walked from the retained `#[source]` chain, except for the transparent
    /// policy variant, whose own `Display` is already this error's message and
    /// which therefore delegates.
    fn causes(&self) -> Vec<String> {
        match self {
            Self::Policy(error) => error.causes(),
            error => packetcraftr_core::error::source_chain(error),
        }
    }
}

/// Injectable hostname resolver. Implementations must stop once `limit`
/// distinct addresses have been selected and report a typed overflow.
pub trait Resolver: Send + Sync {
    fn resolve(&self, hostname: &Hostname, limit: usize) -> Result<Vec<IpAddr>, Error>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SystemResolver;

impl Resolver for SystemResolver {
    fn resolve(&self, hostname: &Hostname, limit: usize) -> Result<Vec<IpAddr>, Error> {
        let resolved =
            (hostname.as_str(), 0)
                .to_socket_addrs()
                .map_err(|source| Error::Resolver {
                    hostname: hostname.to_string(),
                    source: Box::new(source),
                })?;
        let mut addresses = Vec::new();
        for address in resolved.map(|address| address.ip()) {
            if addresses.contains(&address) {
                continue;
            }
            if addresses.len() >= limit {
                return Err(Error::AddressLimit {
                    hostname: hostname.to_string(),
                    limit,
                });
            }
            addresses.push(address);
        }
        if addresses.is_empty() {
            return Err(Error::NoAddresses {
                hostname: hostname.to_string(),
            });
        }
        Ok(addresses)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
    use super::*;

    #[test]
    fn hostname_deserialization_validates_and_canonicalizes() {
        let name: Hostname = serde_json::from_str("\"EXAMPLE.COM.\"").unwrap();
        assert_eq!(name.as_str(), "example.com");
        for invalid in ["", "a..b", "-bad.example", "bad_.example", "é.example"] {
            assert!(serde_json::from_value::<Hostname>(serde_json::json!(invalid)).is_err());
        }
    }
}
