// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::{Error, HeaderRewrite, RewriteLimits};
use crate::{
    error::{Classification, Classified, Kind},
    frame::Frame,
    protocol::headers::LinkHeader,
};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    str::FromStr,
};

pub const MAX_CIDR_MAPS: usize = 64;
#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub enum CidrError {
    #[error("CIDR maps use OLD_PREFIX=NEW_PREFIX with equal address families and prefix widths")]
    Syntax,
    #[error("CIDR prefix has nonzero host bits")]
    HostBits,
    #[error("CIDR mapping source ranges overlap")]
    Overlap,
    #[error("CIDR maps exceed the limit of {MAX_CIDR_MAPS}")]
    Limit,
}
impl Classified for CidrError {
    fn classification(&self) -> Classification {
        Classification::new(
            "cli.cidr_map",
            Kind::Usage,
            Some("use at most 64 nonoverlapping equal-width network-prefix maps"),
        )
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CidrMap {
    old: IpAddr,
    new: IpAddr,
    prefix: u8,
}
impl CidrMap {
    pub fn new(old: IpAddr, new: IpAddr, prefix: u8) -> Result<Self, CidrError> {
        if old.is_ipv4() != new.is_ipv4() || prefix > width(old) {
            return Err(CidrError::Syntax);
        }
        let mask = mask(old, prefix);
        if numeric(old) & !mask != 0 || numeric(new) & !mask != 0 {
            return Err(CidrError::HostBits);
        }
        Ok(Self { old, new, prefix })
    }
    pub fn source(&self) -> IpAddr {
        self.old
    }
    pub fn destination(&self) -> IpAddr {
        self.new
    }
    pub fn prefix_length(&self) -> u8 {
        self.prefix
    }
    pub fn remap(&self, address: IpAddr) -> Option<IpAddr> {
        if address.is_ipv4() != self.old.is_ipv4() {
            return None;
        }
        let mask = mask(address, self.prefix);
        if numeric(address) & mask != numeric(self.old) {
            return None;
        }
        let mapped = numeric(self.new) | (numeric(address) & !mask);
        Some(if address.is_ipv4() {
            IpAddr::V4(Ipv4Addr::from(mapped as u32))
        } else {
            IpAddr::V6(Ipv6Addr::from(mapped))
        })
    }
    fn overlaps(&self, other: &Self) -> bool {
        self.old.is_ipv4() == other.old.is_ipv4()
            && numeric(self.old) & mask(self.old, self.prefix.min(other.prefix))
                == numeric(other.old) & mask(other.old, self.prefix.min(other.prefix))
    }
}
impl FromStr for CidrMap {
    type Err = CidrError;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (old, new) = value.split_once('=').ok_or(CidrError::Syntax)?;
        let parse = |v: &str| {
            let (address, prefix) = v.split_once('/').ok_or(CidrError::Syntax)?;
            Ok::<_, CidrError>((
                address.parse::<IpAddr>().map_err(|_| CidrError::Syntax)?,
                prefix.parse::<u8>().map_err(|_| CidrError::Syntax)?,
            ))
        };
        let (old, old_prefix) = parse(old)?;
        let (new, new_prefix) = parse(new)?;
        if old_prefix != new_prefix {
            return Err(CidrError::Syntax);
        }
        Self::new(old, new, old_prefix)
    }
}
fn numeric(ip: IpAddr) -> u128 {
    match ip {
        IpAddr::V4(v) => u128::from(u32::from(v)),
        IpAddr::V6(v) => u128::from(v),
    }
}
fn width(ip: IpAddr) -> u8 {
    if ip.is_ipv4() { 32 } else { 128 }
}
fn mask(ip: IpAddr, prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        let bits = width(ip);
        (u128::MAX << (bits - prefix))
            & if bits == 32 {
                u128::from(u32::MAX)
            } else {
                u128::MAX
            }
    }
}
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CidrRemap {
    pub source: Vec<CidrMap>,
    pub destination: Vec<CidrMap>,
}
impl CidrRemap {
    pub fn validate(&self) -> Result<(), CidrError> {
        if self.source.len().saturating_add(self.destination.len()) > MAX_CIDR_MAPS {
            return Err(CidrError::Limit);
        }
        for maps in [&self.source, &self.destination] {
            for (index, map) in maps.iter().enumerate() {
                if maps[index + 1..].iter().any(|other| map.overlaps(other)) {
                    return Err(CidrError::Overlap);
                }
            }
        }
        Ok(())
    }
}
/// Apply source/destination CIDR maps to the original outer addresses, then apply
/// fixed header overrides, repairing checksums through the ordinary rewrite path.
pub fn rewrite_with_cidr_maps(
    frame: &Frame,
    patch: &HeaderRewrite,
    maps: &CidrRemap,
    limits: RewriteLimits,
) -> Result<Frame, Error> {
    maps.validate()?;
    if maps.source.is_empty() && maps.destination.is_empty() {
        return super::rewrite(frame, patch, limits);
    }
    let Some(link) = LinkHeader::walk(frame.link_type, frame.bytes())? else {
        return super::rewrite(frame, patch, limits);
    };
    let Some(ip) = link.walk_ip(frame.bytes())? else {
        return super::rewrite(frame, patch, limits);
    };
    let (source, destination) = ip.addresses(&frame.bytes()[link.network_offset()..])?;
    let mut merged = patch.clone();
    if merged.source_ip.is_none() {
        merged.source_ip = maps.source.iter().find_map(|map| map.remap(source));
    }
    if merged.destination_ip.is_none() {
        merged.destination_ip = maps
            .destination
            .iter()
            .find_map(|map| map.remap(destination));
    }
    super::rewrite(frame, &merged, limits)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn preserves_host_bits_for_both_families_and_zero_width() {
        for (map, input, output) in [
            (
                "192.0.2.0/24=198.51.100.0/24",
                "192.0.2.42",
                "198.51.100.42",
            ),
            (
                "2001:db8::/32=2001:db9::/32",
                "2001:db8:1::42",
                "2001:db9:1::42",
            ),
            ("0.0.0.0/0=0.0.0.0/0", "192.0.2.42", "192.0.2.42"),
        ] {
            assert_eq!(
                map.parse::<CidrMap>()
                    .unwrap()
                    .remap(input.parse().unwrap()),
                Some(output.parse().unwrap())
            );
        }
    }
    #[test]
    fn rejects_overlap_families_widths_and_host_bits() {
        assert!("192.0.2.0/24=2001:db8::/24".parse::<CidrMap>().is_err());
        assert!("192.0.2.0/24=198.51.100.0/25".parse::<CidrMap>().is_err());
        assert!("192.0.2.1/24=198.51.100.0/24".parse::<CidrMap>().is_err());
        let maps = CidrRemap {
            source: vec![
                "192.0.2.0/24=198.51.100.0/24".parse().unwrap(),
                "192.0.2.128/25=198.51.100.128/25".parse().unwrap(),
            ],
            destination: vec![],
        };
        assert_eq!(maps.validate(), Err(CidrError::Overlap));
    }
}
