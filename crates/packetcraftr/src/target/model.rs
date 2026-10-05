// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::{IpAddr, ToSocketAddrs};
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
        Ok(Self(hostname.to_ascii_lowercase()))
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

    pub fn identity(&self) -> (IpAddr, Option<&packetcraftr_netio::interface::Id>) {
        (
            self.address,
            self.scope.as_ref().map(|scope| &scope.interface),
        )
    }
}

impl PartialEq for SelectedAddress {
    fn eq(&self, other: &Self) -> bool {
        self.address == other.address
            && self.scope.as_ref().map(|scope| &scope.interface)
                == other.scope.as_ref().map(|scope| &scope.interface)
    }
}

impl Eq for SelectedAddress {}

impl std::hash::Hash for SelectedAddress {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.address.hash(state);
        self.scope
            .as_ref()
            .map(|scope| &scope.interface)
            .hash(state);
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
            Err(_) => {
                if let Some((address, zone)) = value.split_once('%') {
                    let address =
                        address
                            .parse::<std::net::Ipv6Addr>()
                            .map_err(|_| Error::InvalidScope {
                                address: value
                                    .parse::<IpAddr>()
                                    .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)),
                                reason: "a zone applies only to an IPv6 address",
                            })?;
                    return Ok(Self::ScopedAddress(ScopedAddress::new(
                        address,
                        zone.parse()?,
                    )?));
                }
                value.parse::<Hostname>().map(Self::Hostname)
            }
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

/// Policy-authorized target with private fields that prevent forgery.
#[derive(Clone, Debug, Serialize)]
pub struct Authorized {
    pub(crate) declared: Target,
    pub(crate) selected: Vec<SelectedAddress>,
}

impl Authorized {
    pub fn declared(&self) -> &Target {
        &self.declared
    }

    pub fn addresses(&self) -> Vec<IpAddr> {
        self.selected
            .iter()
            .map(|selected| selected.address)
            .collect()
    }

    pub fn selected(&self) -> &[SelectedAddress] {
        &self.selected
    }

    // authorization only constructs `Authorized` with a non-empty address list
    pub fn selected_address(&self) -> IpAddr {
        self.selected[0].address
    }

    pub fn address_for_family(&self, family: Family) -> Option<IpAddr> {
        self.selected
            .iter()
            .map(|selected| selected.address)
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
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    #[error("zone {zone} resolved to an invalid interface identity: {interface:?}")]
    InvalidZoneInterface {
        zone: Zone,
        interface: packetcraftr_netio::interface::Id,
    },
    #[error("zone resolution is unavailable with this resolver")]
    ZoneCapability { zone: Zone },
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
            Self::ZoneResolution { .. } => Classification::new(
                "io.interface",
                Kind::Io,
                Some("inspect interface enumeration and retry before any target traffic"),
            ),
            Self::ZoneCapability { .. } => Classification::new(
                "capability.zone_resolution",
                Kind::Capability,
                Some("use a resolver that can enumerate interfaces for scoped targets"),
            ),
            Self::Policy(error) => error.classification(),
        }
    }

    fn causes(&self) -> Vec<String> {
        match self {
            Self::Policy(error) => error.causes(),
            error => packetcraftr_core::error::source_chain(error),
        }
    }
}

/// Injectable hostname resolver. Implementations must stop once `limit`
/// distinct addresses have been selected and report a typed overflow.
/// Resolution is synchronous. Implementations own their I/O timeout; an
/// operation deadline can stop subsequent work but cannot interrupt this call.
pub trait Resolver: Send + Sync {
    fn resolve(&self, hostname: &Hostname, limit: usize) -> Result<Vec<IpAddr>, Error>;

    fn resolve_zone(
        &self,
        zone: &Zone,
        _deadline: &packetcraftr_core::budget::Deadline,
    ) -> Result<packetcraftr_netio::interface::Id, Error> {
        Err(Error::ZoneCapability { zone: zone.clone() })
    }
}

pub(crate) trait ResolveTarget {
    fn resolve_and_authorize(
        &mut self,
        target: &Target,
        deadline: &packetcraftr_core::budget::Deadline,
    ) -> Result<Authorized, packetcraftr_core::error::BoundaryError>;
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
        distinct_addresses(hostname, resolved.map(|address| address.ip()), limit)
    }

    fn resolve_zone(
        &self,
        zone: &Zone,
        deadline: &packetcraftr_core::budget::Deadline,
    ) -> Result<packetcraftr_netio::interface::Id, Error> {
        use packetcraftr_netio::interface::Provider as _;
        let interfaces = packetcraftr_netio::interface::SystemProvider
            .interfaces(deadline)
            .map_err(|source| Error::ZoneResolution {
                zone: zone.clone(),
                source: Box::new(source),
            })?;
        resolve_zone_from(zone, interfaces.into_iter().map(|info| info.id))
    }
}

pub(crate) fn resolve_zone_from(
    zone: &Zone,
    interfaces: impl IntoIterator<Item = packetcraftr_netio::interface::Id>,
) -> Result<packetcraftr_netio::interface::Id, Error> {
    let mut matches = interfaces.into_iter().filter(|id| match zone.index() {
        Some(index) => id.index == index,
        None => id.name == zone.as_str(),
    });
    let resolved = matches
        .next()
        .ok_or_else(|| Error::UnknownZone { zone: zone.clone() })?;
    if matches.next().is_some() {
        return Err(Error::AmbiguousZone { zone: zone.clone() });
    }
    valid_zone_interface(zone, resolved)
}

pub(crate) fn valid_zone_interface(
    zone: &Zone,
    interface: packetcraftr_netio::interface::Id,
) -> Result<packetcraftr_netio::interface::Id, Error> {
    if interface.index == 0 || interface.name.is_empty() {
        return Err(Error::InvalidZoneInterface {
            zone: zone.clone(),
            interface,
        });
    }
    Ok(interface)
}

/// Keeps each address in first-seen order. Only distinct addresses count
/// toward `limit`.
pub(crate) fn distinct_addresses(
    hostname: &Hostname,
    resolved: impl IntoIterator<Item = IpAddr>,
    limit: usize,
) -> Result<Vec<IpAddr>, Error> {
    let mut addresses = Vec::new();
    for address in resolved {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn distinct_addresses_are_bounded_and_ordered_by_first_sighting() {
        let name: Hostname = "example.test".parse().unwrap();
        let [a, b, c]: [IpAddr; 3] =
            ["192.0.2.1", "192.0.2.2", "2001:db8::3"].map(|s| s.parse().unwrap());

        assert_eq!(
            distinct_addresses(&name, [b, a, b, a], 2).unwrap(),
            [b, a],
            "repeats neither reorder the answer nor count toward the limit"
        );
        assert!(matches!(
            distinct_addresses(&name, [a, b, c], 2),
            Err(Error::AddressLimit { hostname, limit: 2 }) if hostname == "example.test"
        ));
        assert!(matches!(
            distinct_addresses(&name, [], 2),
            Err(Error::NoAddresses { hostname }) if hostname == "example.test"
        ));
    }
}

#[cfg(test)]
mod scoped_tests {
    use std::net::Ipv6Addr;
    use std::str::FromStr;

    use crate::target::Specification;

    use super::*;

    #[test]
    fn zone_names_and_indices_parse() {
        assert_eq!(Zone::from_str("eth0").expect("name").as_str(), "eth0");
        assert_eq!(Zone::from_str("42").expect("index").as_str(), "42");
        assert_eq!(Zone::from_str("0en0").expect("alnum name").as_str(), "0en0");
        for invalid in ["", "0", "00", "-1", " ", "eth 0", "en\u{00e9}0"] {
            assert!(Zone::from_str(invalid).is_err(), "{invalid:?} parsed");
        }
        let too_long = "x".repeat(129);
        assert!(Zone::from_str(&too_long).is_err());
        assert!(Zone::from_str(&"x".repeat(128)).is_ok());
        assert!(Zone::from_str("4294967296").is_err(), "index > u32::MAX");
    }

    #[test]
    fn zones_serde_round_trip_and_validate() {
        let zone = Zone::from_str("eth0").expect("zone");
        let json = serde_json::to_string(&zone).expect("serialize");
        assert_eq!(
            serde_json::from_str::<Zone>(&json).expect("deserialize"),
            zone
        );
        assert!(serde_json::from_str::<Zone>("\"\"").is_err());
        assert!(serde_json::from_str::<Zone>("\"0\"").is_err());
        assert!(serde_json::from_str::<Zone>("42").is_err(), "non-string");
    }

    #[test]
    fn scoped_addresses_require_a_valid_link_local_target() {
        let address = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        let zone = Zone::from_str("eth0").expect("zone");
        let scoped = ScopedAddress::new(address, zone.clone()).expect("scoped");
        assert_eq!(scoped.address(), address);
        assert_eq!(scoped.zone(), &zone);
        for invalid in [
            Ipv6Addr::LOCALHOST,
            Ipv6Addr::UNSPECIFIED,
            "ff02::1".parse().unwrap(),
            "2001:db8::1".parse().unwrap(),
        ] {
            assert!(
                ScopedAddress::new(invalid, zone.clone()).is_err(),
                "{invalid}"
            );
        }
    }

    #[test]
    fn targets_parse_scoped_forms() {
        let parsed = Target::from_str("fe80::1%eth0").expect("scoped");
        let Target::ScopedAddress(scoped) = &parsed else {
            panic!("expected ScopedAddress, got {parsed:?}");
        };
        assert_eq!(scoped.zone().as_str(), "eth0");
        assert_eq!(parsed.to_string(), "fe80::1%eth0");
        assert_eq!(
            Target::from_str("fe80::1%1").expect("zone index"),
            Target::from_str("fe80::1%1").expect("scoped")
        );
        assert!(Target::from_str("fe80::1%").is_err(), "empty zone");
        assert!(Target::from_str("fe80::1%0").is_err(), "zero zone");
        assert!(Target::from_str("fe80::1%eth0/10").is_err(), "suffix");
        assert!(Target::from_str("192.0.2.1%eth0").is_err(), "v4 scope");
        assert!(
            Target::from_str("2001:db8::1%eth0").is_err(),
            "global scope"
        );
        assert!(
            Target::from_str("host.invalid%eth0").is_err(),
            "hostname scope"
        );
    }

    #[test]
    fn link_local_addresses_refuse_to_parse_unscoped() {
        for bare in ["fe80::1", "fe80:0:0:0:0202:b3ff:fe1e:8329"] {
            assert!(
                matches!(Target::from_str(bare), Err(Error::MissingScope { .. })),
                "{bare}"
            );
        }
    }

    #[test]
    fn scoped_targets_round_trip_through_serde_with_validation() {
        let target = Target::from_str("fe80::1%eth0").expect("target");
        let json = serde_json::to_string(&target).expect("serialize");
        assert_eq!(
            serde_json::from_str::<Target>(&json).expect("deserialize"),
            target
        );
        assert!(serde_json::from_str::<Target>("\"fe80::1\"").is_err());
        assert!(serde_json::from_str::<Target>("\"fe80::1%0\"").is_err());
        let scoped = ScopedAddress::new(
            Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1),
            Zone::from_str("eth0").unwrap(),
        )
        .expect("scoped");
        let json = serde_json::to_string(&scoped).expect("serialize");
        assert_eq!(
            serde_json::from_str::<ScopedAddress>(&json).expect("deserialize"),
            scoped
        );
        assert!(
            serde_json::from_str::<ScopedAddress>(
                "{\"address\":\"2001:db8::1\",\"zone\":\"eth0\"}"
            )
            .is_err()
        );
    }

    #[test]
    fn specifications_reject_link_local_cidrs_and_scoped_networks() {
        assert!(Specification::from_str("fe80::1%eth0").is_ok());
        assert!(Specification::from_str("fe80::/10").is_err());
        assert!(Specification::from_str("fe80::1/128%eth0").is_err());
    }
}
