// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Explicit finite target sets, without discovery or I/O.

use super::Target;
use packetcraftr_core::error::{Classification, Classified, Kind};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    str::FromStr,
};

pub(crate) const MAX_CANDIDATES: usize = 100_000;
const MAX_SPECIFICATIONS: usize = 4096;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Network {
    address: IpAddr,
    prefix: u8,
}
impl Network {
    pub fn new(address: IpAddr, prefix: u8) -> Result<Self, SelectionError> {
        let bits = if address.is_ipv4() { 32 } else { 128 };
        if prefix > bits {
            return Err(SelectionError::Network {
                value: format!("{address}/{prefix}"),
            });
        }
        let value = match address {
            IpAddr::V4(a) => u128::from(u32::from(a)),
            IpAddr::V6(a) => u128::from(a),
        };
        let mask = if prefix == 0 {
            0
        } else {
            u128::MAX << (bits - prefix)
        };
        let network = value & mask;
        Ok(Self {
            address: if address.is_ipv4() {
                IpAddr::V4(Ipv4Addr::from(network as u32))
            } else {
                IpAddr::V6(Ipv6Addr::from(network))
            },
            prefix,
        })
    }
    pub fn address(&self) -> IpAddr {
        self.address
    }
    pub fn prefix(&self) -> u8 {
        self.prefix
    }
    pub fn contains(&self, address: IpAddr) -> bool {
        address.is_ipv4() == self.address.is_ipv4()
            && Self::new(address, self.prefix).is_ok_and(|network| network == *self)
    }
    pub fn cardinality(&self, maximum: usize) -> Result<usize, SelectionError> {
        let bits = if self.address.is_ipv4() { 32u32 } else { 128 };
        let count = 1u128
            .checked_shl(bits - u32::from(self.prefix))
            .and_then(|count| usize::try_from(count).ok())
            .filter(|count| *count <= maximum)
            .ok_or(SelectionError::Limit {
                field: "target_candidates",
                limit: maximum,
            })?;
        Ok(count)
    }
    /// Rejects an oversized network before creating its iterator.
    pub fn addresses(
        &self,
        maximum: usize,
    ) -> Result<impl ExactSizeIterator<Item = IpAddr>, SelectionError> {
        let count = self.cardinality(maximum)?;
        let address = self.address;
        let start = match address {
            IpAddr::V4(a) => u128::from(u32::from(a)),
            IpAddr::V6(a) => u128::from(a),
        };
        Ok((0..count).map(move |offset| {
            let value = start + offset as u128;
            if address.is_ipv4() {
                IpAddr::V4(Ipv4Addr::from(value as u32))
            } else {
                IpAddr::V6(Ipv6Addr::from(value))
            }
        }))
    }
}
impl fmt::Display for Network {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.address, self.prefix)
    }
}
impl FromStr for Network {
    type Err = SelectionError;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let invalid = || SelectionError::Network {
            value: value.chars().take(256).collect(),
        };
        let (address, prefix) = value
            .split_once('/')
            .map_or((value, None), |(address, prefix)| (address, Some(prefix)));
        let address: IpAddr = address.parse().map_err(|_| invalid())?;
        let prefix = prefix
            .map(|prefix| prefix.parse::<u8>().map_err(|_| invalid()))
            .transpose()?
            .unwrap_or(if address.is_ipv4() { 32 } else { 128 });
        Self::new(address, prefix)
    }
}
impl Serialize for Network {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}
impl<'de> Deserialize<'de> for Network {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum Specification {
    Target(Target),
    Network(Network),
}
impl From<Target> for Specification {
    fn from(target: Target) -> Self {
        Self::Target(target)
    }
}
impl FromStr for Specification {
    type Err = SelectionError;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.contains('/') {
            value.parse().map(Self::Network)
        } else {
            value
                .parse()
                .map(Self::Target)
                .map_err(SelectionError::Target)
        }
    }
}
impl fmt::Display for Specification {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Target(target) => target.fmt(f),
            Self::Network(network) => network.fmt(f),
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Selection {
    pub include: Vec<Specification>,
    pub exclude: Vec<Network>,
}
impl From<Target> for Selection {
    fn from(target: Target) -> Self {
        Self {
            include: vec![target.into()],
            exclude: Vec::new(),
        }
    }
}
impl Selection {
    /// Bounds specification count and numeric expansion before any hostname work.
    pub fn validate(&self) -> Result<(), SelectionError> {
        if self.include.is_empty() {
            return Err(SelectionError::Empty);
        }
        if self.include.len() > MAX_SPECIFICATIONS || self.exclude.len() > MAX_SPECIFICATIONS {
            return Err(SelectionError::Limit {
                field: "target_specifications",
                limit: MAX_SPECIFICATIONS,
            });
        }
        let mut remaining = MAX_CANDIDATES;
        let mut seen = HashSet::new();
        for target in &self.include {
            if !seen.insert(target) {
                continue;
            }
            let count = match target {
                Specification::Target(_) => 1,
                Specification::Network(network) => network.cardinality(remaining)?,
            };
            remaining = remaining.checked_sub(count).ok_or(SelectionError::Limit {
                field: "target_candidates",
                limit: MAX_CANDIDATES,
            })?;
        }
        Ok(())
    }
    pub fn excludes(&self, address: IpAddr) -> bool {
        self.exclude.iter().any(|network| network.contains(address))
    }
}
impl fmt::Display for Selection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, target) in self.include.iter().enumerate() {
            if index != 0 {
                f.write_str(",")?;
            }
            target.fmt(f)?;
        }
        for network in &self.exclude {
            write!(f, ",!{network}")?;
        }
        Ok(())
    }
}
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SelectionError {
    #[error("target selection is empty")]
    Empty,
    #[error("invalid numeric address or CIDR {value:?}")]
    Network { value: String },
    #[error("target selection exceeds {field}={limit}")]
    Limit { field: &'static str, limit: usize },
    #[error(transparent)]
    Target(#[from] super::Error),
}
impl Classified for SelectionError {
    fn classification(&self) -> Classification {
        match self {
            Self::Target(source) => source.classification(),
            _ => Classification::new(
                "cli.target_selection",
                Kind::Cli,
                Some("supply explicit bounded host/IP/CIDR targets and numeric exclusions"),
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn networks_normalize_host_bits_and_bound_expansion_before_iteration() {
        let network: Network = "192.0.2.7/30".parse().unwrap();
        assert_eq!(network.to_string(), "192.0.2.4/30");
        assert_eq!(
            network
                .addresses(4)
                .unwrap()
                .map(|a| a.to_string())
                .collect::<Vec<_>>(),
            ["192.0.2.4", "192.0.2.5", "192.0.2.6", "192.0.2.7"]
        );
        assert!(network.addresses(3).is_err());
        for input in ["::/0", "2001:db8::/64", "0.0.0.0/0"] {
            assert!(
                input
                    .parse::<Network>()
                    .unwrap()
                    .addresses(MAX_CANDIDATES)
                    .is_err()
            );
        }
        assert_eq!(
            "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128"
                .parse::<Network>()
                .unwrap()
                .addresses(1)
                .unwrap()
                .count(),
            1
        );
        assert!("192.0.2.1/33".parse::<Network>().is_err());
        assert!(!network.contains("2001:db8::1".parse().unwrap()));
    }
}
