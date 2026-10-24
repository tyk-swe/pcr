// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::IpAddr;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use packetcraftr_core::error::{Classification, Classified, Kind};

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
        Ok(Self(value.to_ascii_lowercase()))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct Zone(String);

impl Zone {
    pub fn new(text: impl Into<String>) -> Result<Self, Error> {
        let text = text.into();
        let invalid = |reason| Error::InvalidZone {
            zone: text.clone(),
            reason,
        };
        if text.is_empty() {
            return Err(invalid("zone must not be empty"));
        }
        if text.len() > 128 {
            return Err(invalid("zone exceeds the 128-byte limit"));
        }
        if !text
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        {
            return Err(invalid(
                "zone must be ASCII letters, digits, '-', '_', or '.'",
            ));
        }
        if text.bytes().all(|byte| byte.is_ascii_digit()) {
            return match text.parse::<u32>() {
                Ok(0) => Err(invalid("numeric zone must be a nonzero interface index")),
                Ok(_) => Ok(Self(text)),
                Err(_) => Err(invalid("numeric zone is not a u32 interface index")),
            };
        }
        if matches!(text.as_bytes()[0], b'+' | b'-') {
            return Err(invalid("numeric-looking zones must be unsigned decimal"));
        }
        Ok(Self(text))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn index(&self) -> Option<u32> {
        self.0.parse::<u32>().ok().filter(|index| *index != 0)
    }
}

impl std::fmt::Display for Zone {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for Zone {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl<'de> Deserialize<'de> for Zone {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ScopedAddress {
    address: std::net::Ipv6Addr,
    zone: Zone,
}

impl ScopedAddress {
    pub fn new(address: std::net::Ipv6Addr, zone: Zone) -> Result<Self, Error> {
        if !address.is_unicast_link_local() {
            return Err(Error::InvalidScope {
                address: IpAddr::V6(address),
                reason: "a zone applies only to a unicast fe80::/10 address",
            });
        }
        Ok(Self { address, zone })
    }

    pub fn address(&self) -> std::net::Ipv6Addr {
        self.address
    }

    pub fn zone(&self) -> &Zone {
        &self.zone
    }
}

impl std::fmt::Display for ScopedAddress {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}%{}", self.address, self.zone)
    }
}

impl Serialize for ScopedAddress {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for ScopedAddress {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        let (address, zone) = text
            .split_once('%')
            .ok_or_else(|| serde::de::Error::custom("a scoped address needs a %zone"))?;
        let address = address
            .parse::<std::net::Ipv6Addr>()
            .map_err(serde::de::Error::custom)?;
        let zone = zone.parse::<Zone>().map_err(serde::de::Error::custom)?;
        Self::new(address, zone).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ResolvedZone {
    pub zone: Zone,
    pub interface: packetcraftr_netio::interface::Id,
}

impl ResolvedZone {
    pub(crate) fn retained_bytes(&self) -> usize {
        self.zone
            .as_str()
            .len()
            .saturating_add(self.interface.name.len())
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct SelectedAddress {
    pub address: IpAddr,
    pub scope: Option<ResolvedZone>,
}

impl SelectedAddress {
    pub fn new(address: IpAddr) -> Self {
        Self {
            address,
            scope: None,
        }
    }

    pub fn interface(&self) -> Option<&packetcraftr_netio::interface::Id> {
        self.scope.as_ref().map(|scope| &scope.interface)
    }

    pub fn identity(&self) -> (IpAddr, Option<&packetcraftr_netio::interface::Id>) {
        (self.address, self.interface())
    }

    pub(crate) fn key(&self) -> (IpAddr, Option<packetcraftr_netio::interface::Id>) {
        (self.address, self.interface().cloned())
    }

    pub(crate) fn scope_bytes(&self) -> usize {
        self.scope.as_ref().map_or(0, ResolvedZone::retained_bytes)
    }
}

impl PartialEq for SelectedAddress {
    fn eq(&self, other: &Self) -> bool {
        self.identity() == other.identity()
    }
}

impl Eq for SelectedAddress {}

impl std::hash::Hash for SelectedAddress {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.identity().hash(state);
    }
}

pub fn requires_scope(address: IpAddr) -> bool {
    matches!(address, IpAddr::V6(v6) if v6.is_unicast_link_local())
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum Target {
    Address(IpAddr),
    Hostname(Hostname),
    ScopedAddress(ScopedAddress),
}

impl std::fmt::Display for Target {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Address(address) => address.fmt(formatter),
            Self::Hostname(hostname) => hostname.fmt(formatter),
            Self::ScopedAddress(scoped) => scoped.fmt(formatter),
        }
    }
}

impl FromStr for Target {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.parse::<IpAddr>() {
            Ok(address) if requires_scope(address) => Err(Error::MissingScope { address }),
            Ok(address) => Ok(Self::Address(address)),
            Err(_) => match value
                .split_once('%')
                .and_then(|(address, zone)| Some((address.parse::<IpAddr>().ok()?, zone)))
            {
                Some((IpAddr::V6(address), zone)) => Ok(Self::ScopedAddress(ScopedAddress::new(
                    address,
                    zone.parse()?,
                )?)),
                Some((address @ IpAddr::V4(_), _)) => Err(Error::InvalidScope {
                    address,
                    reason: "a zone applies only to an IPv6 address",
                }),
                // `%` is never valid in a hostname, so the hostname parser
                // rejects any other zone-qualified text.
                None => value.parse::<Hostname>().map(Self::Hostname),
            },
        }
    }
}

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
    #[error("invalid zone {zone:?}: {reason}")]
    InvalidZone { zone: String, reason: &'static str },
    #[error("invalid scoped target {address}: {reason}")]
    InvalidScope {
        address: IpAddr,
        reason: &'static str,
    },
    #[error("link-local target {address} requires an explicit %zone scope")]
    MissingScope { address: IpAddr },
    #[error("zone {zone} did not resolve to any interface")]
    UnknownZone { zone: Zone },
    #[error("zone {zone} resolves to more than one interface")]
    AmbiguousZone { zone: Zone },
    #[error("zone resolution failed for {zone}")]
    ZoneResolution {
        zone: Zone,
        #[source]
        source: packetcraftr_netio::interface::Error,
    },
    #[error("zone {zone} resolved to an invalid interface identity: {interface:?}")]
    InvalidZoneInterface {
        zone: Zone,
        interface: packetcraftr_netio::interface::Id,
    },
    #[error("zone resolution is unavailable with this resolver")]
    ZoneCapability { zone: Zone },
    #[error(transparent)]
    Control(#[from] packetcraftr_core::error::BoundaryError),
    #[error(transparent)]
    Policy(#[from] crate::policy::Error),
}

impl Classified for Error {
    fn classification(&self) -> Classification {
        match self {
            Self::InvalidHostname { .. } => Classification::new(
                "cli.live_target",
                Kind::Usage,
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
            Self::InvalidZone { .. } | Self::InvalidScope { .. } => Classification::new(
                "cli.live_target",
                Kind::Usage,
                Some(
                    "qualify only unicast fe80::/10 addresses with a non-empty ASCII zone name or nonzero index",
                ),
            ),
            Self::MissingScope { .. } => Classification::new(
                "cli.live_target",
                Kind::Usage,
                Some("declare the link-local address with an explicit %zone scope"),
            ),
            Self::UnknownZone { .. } | Self::AmbiguousZone { .. } => Classification::new(
                "io.interface",
                Kind::Io,
                Some("use a zone naming exactly one current interface"),
            ),
            Self::InvalidZoneInterface { .. } => Classification::new(
                "io.interface",
                Kind::Io,
                Some(
                    "the zone resolver must return an interface with a non-empty name and nonzero index",
                ),
            ),
            Self::ZoneResolution {
                source: packetcraftr_netio::interface::Error::Discovery { .. },
                ..
            } => Classification::new(
                "io.interface",
                Kind::Io,
                Some("inspect interface enumeration and retry before any target traffic"),
            ),
            // A build without interface enumeration publishes its capability
            // failure, and an interrupted enumeration stays interrupted.
            Self::ZoneResolution { source, .. } => source.classification(),
            Self::ZoneCapability { .. } => Classification::new(
                "capability.zone_resolution",
                Kind::Capability,
                Some("use a resolver that can enumerate interfaces for scoped targets"),
            ),
            Self::Policy(error) => error.classification(),
            Self::Control(error) => error.classification(),
        }
    }

    fn causes(&self) -> Vec<String> {
        match self {
            Self::Policy(error) => error.causes(),
            error => packetcraftr_core::error::source_chain(error),
        }
    }
}
