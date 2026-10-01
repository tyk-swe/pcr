// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Many-to-many IP and MAC address remapping through the header rewrite path.

use std::collections::HashMap;
use std::net::IpAddr;
use std::str::FromStr;

use super::{Error, HeaderRewrite, InvalidInput, Limit, RewriteLimits, rewrite};
use crate::frame::{Frame, LinkType};
use crate::packet::MacAddress;
use crate::protocol::headers::{Ipv4Header, Ipv6Header, LinkHeader};

/// The most entries an address map holds, across IP and MAC mappings.
pub const MAX_ADDRESS_MAP_ENTRIES: usize = 4096;

/// One `OLD=NEW` IP mapping: a single address, or equal-length prefixes whose
/// host bits carry over, so `192.0.2.0/24=198.51.100.0/24` turns `192.0.2.7`
/// into `198.51.100.7`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IpMapping {
    old: IpAddr,
    new: IpAddr,
    prefix_length: u8,
}

impl IpMapping {
    pub const fn old(&self) -> IpAddr {
        self.old
    }

    pub const fn replacement(&self) -> IpAddr {
        self.new
    }

    pub const fn prefix_length(&self) -> u8 {
        self.prefix_length
    }

    fn bits(&self) -> u8 {
        if self.old.is_ipv4() { 32 } else { 128 }
    }
}

/// An address with an optional prefix length; a missing one covers every bit.
fn parse_side(text: &str) -> Result<(IpAddr, u8), Error> {
    let (address, length) = match text.split_once('/') {
        Some((address, length)) => (address, Some(length)),
        None => (text, None),
    };
    let address = address
        .parse::<IpAddr>()
        .map_err(|_| Error::Invalid(InvalidInput::AddressMapAddress))?;
    let bits = if address.is_ipv4() { 32 } else { 128 };
    let length = match length {
        None => bits,
        Some(digits) => {
            if digits.is_empty() || !digits.bytes().all(|digit| digit.is_ascii_digit()) {
                return Err(Error::Invalid(InvalidInput::AddressMapPrefix));
            }
            digits
                .parse::<u8>()
                .ok()
                .filter(|length| *length <= bits)
                .ok_or(Error::Invalid(InvalidInput::AddressMapPrefix))?
        }
    };
    Ok((address, length))
}

impl FromStr for IpMapping {
    type Err = Error;

    /// Parses `OLD=NEW` where each side is an address or `address/prefix`.
    fn from_str(text: &str) -> Result<Self, Error> {
        let (old, new) = text
            .split_once('=')
            .ok_or(Error::Invalid(InvalidInput::AddressMapSyntax))?;
        let ((old, old_length), (new, new_length)) = (parse_side(old)?, parse_side(new)?);
        if old.is_ipv4() != new.is_ipv4() {
            return Err(Error::Invalid(InvalidInput::AddressMapFamilies));
        }
        if old_length != new_length {
            return Err(Error::Invalid(InvalidInput::AddressMapPrefix));
        }
        let mapping = Self {
            old,
            new,
            prefix_length: old_length,
        };
        let host = !mask(mapping.prefix_length, mapping.bits());
        if numeric(old) & host != 0 || numeric(new) & host != 0 {
            return Err(Error::Invalid(InvalidInput::AddressMapHostBits));
        }
        Ok(mapping)
    }
}

/// One `OLD=NEW` Ethernet address mapping.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MacMapping {
    old: MacAddress,
    new: MacAddress,
}

impl MacMapping {
    pub const fn old(&self) -> MacAddress {
        self.old
    }

    pub const fn replacement(&self) -> MacAddress {
        self.new
    }
}

impl FromStr for MacMapping {
    type Err = Error;

    /// Parses `OLD=NEW` where each side is a MAC address.
    fn from_str(text: &str) -> Result<Self, Error> {
        let (old, new) = text
            .split_once('=')
            .ok_or(Error::Invalid(InvalidInput::AddressMapSyntax))?;
        let mac = |text: &str| {
            text.parse::<MacAddress>()
                .map_err(|_| Error::Invalid(InvalidInput::AddressMapAddress))
        };
        Ok(Self {
            old: mac(old)?,
            new: mac(new)?,
        })
    }
}

fn numeric(address: IpAddr) -> u128 {
    match address {
        IpAddr::V4(address) => u128::from(u32::from(address)),
        IpAddr::V6(address) => u128::from(address),
    }
}

fn address(value: u128, ipv4: bool) -> IpAddr {
    if ipv4 {
        IpAddr::from(u32::try_from(value).unwrap_or_default().to_be_bytes())
    } else {
        IpAddr::from(value.to_be_bytes())
    }
}

/// The leading `length` bits of a `bits`-wide address.
fn mask(length: u8, bits: u8) -> u128 {
    let width = if bits == 32 {
        u32::MAX.into()
    } else {
        u128::MAX
    };
    width & !width.checked_shr(length.into()).unwrap_or(0)
}

/// Prefixes of one family, grouped by length so a lookup probes each distinct
/// length once instead of scanning every entry.
#[derive(Clone, Debug, Default)]
struct PrefixTable {
    ipv4: bool,
    by_length: Vec<(u8, HashMap<u128, u128>)>,
}

impl PrefixTable {
    fn insert(&mut self, mapping: &IpMapping) {
        let table = match self
            .by_length
            .iter_mut()
            .find(|(length, _)| *length == mapping.prefix_length)
        {
            Some((_, table)) => table,
            None => {
                self.by_length.push((mapping.prefix_length, HashMap::new()));
                &mut self.by_length.last_mut().expect("just pushed").1
            }
        };
        table.insert(numeric(mapping.old), numeric(mapping.new));
    }

    fn lookup(&self, value: u128) -> Option<IpAddr> {
        let bits = if self.ipv4 { 32 } else { 128 };
        self.by_length.iter().find_map(|(length, table)| {
            let network = mask(*length, bits);
            table
                .get(&(value & network))
                .map(|new| address(new | (value & !network), self.ipv4))
        })
    }
}

/// A validated table of IP and MAC remappings. Each frame's outer source and
/// destination are looked up independently; a match is applied through
/// [`rewrite`], which repairs lengths and checksums, and everything else
/// passes through unchanged.
#[derive(Clone, Debug)]
pub struct AddressMap {
    ipv4: PrefixTable,
    ipv6: PrefixTable,
    macs: HashMap<MacAddress, MacAddress>,
}

impl AddressMap {
    /// Builds the table, refusing more than [`MAX_ADDRESS_MAP_ENTRIES`] entries
    /// and IP prefixes of one family that overlap, repeated sources included.
    pub fn new(ips: &[IpMapping], macs: &[MacMapping]) -> Result<Self, Error> {
        if ips.len().saturating_add(macs.len()) > MAX_ADDRESS_MAP_ENTRIES {
            return Err(Error::Limit {
                field: Limit::AddressMapEntries,
                limit: MAX_ADDRESS_MAP_ENTRIES,
            });
        }
        let mut map = Self {
            ipv4: PrefixTable {
                ipv4: true,
                ..PrefixTable::default()
            },
            ipv6: PrefixTable::default(),
            macs: HashMap::new(),
        };
        for (index, mapping) in ips.iter().enumerate() {
            let overlaps = ips[..index].iter().any(|earlier| {
                earlier.old.is_ipv4() == mapping.old.is_ipv4() && {
                    let shorter = earlier.prefix_length.min(mapping.prefix_length);
                    let network = mask(shorter, mapping.bits());
                    numeric(earlier.old) & network == numeric(mapping.old) & network
                }
            });
            if overlaps {
                return Err(Error::Invalid(InvalidInput::AddressMapOverlap));
            }
            if mapping.old.is_ipv4() {
                map.ipv4.insert(mapping);
            } else {
                map.ipv6.insert(mapping);
            }
        }
        for mapping in macs {
            if map.macs.insert(mapping.old, mapping.new).is_some() {
                return Err(Error::Invalid(InvalidInput::AddressMapOverlap));
            }
        }
        // Longest prefixes first; overlap is refused, so at most one matches.
        for table in [&mut map.ipv4, &mut map.ipv6] {
            table
                .by_length
                .sort_unstable_by_key(|(length, _)| std::cmp::Reverse(*length));
        }
        Ok(map)
    }

    /// Remaps the matching addresses of `frame`. Looking addresses up only
    /// reads bytes, so a frame the lookup cannot place (no Ethernet or outer
    /// IP header, or one cut short by the capture) matches nothing and is
    /// returned unchanged; a frame that does match must pass every
    /// [`rewrite`] check and checksum repair, like the fixed address edits.
    pub fn apply(&self, frame: &Frame, limits: RewriteLimits) -> Result<Frame, Error> {
        let mut patch = HeaderRewrite::default();
        let bytes = frame.bytes();
        if frame.link_type == LinkType::ETHERNET && bytes.len() >= 12 {
            let mac = |octets: &[u8]| {
                let octets: [u8; 6] = octets.try_into().ok()?;
                self.macs.get(&MacAddress(octets)).map(|new| new.0)
            };
            patch.destination_mac = mac(&bytes[..6]);
            patch.source_mac = mac(&bytes[6..12]);
        }
        if let Some(ip) = outer_ip(frame) {
            let (table, source, destination) = match ip[0] >> 4 {
                4 if ip.len() >= Ipv4Header::MIN_LENGTH => {
                    (&self.ipv4, Ipv4Header::SOURCE, Ipv4Header::DESTINATION)
                }
                6 if ip.len() >= Ipv6Header::LENGTH => {
                    (&self.ipv6, Ipv6Header::SOURCE, Ipv6Header::DESTINATION)
                }
                _ => return rewrite(frame, &patch, limits),
            };
            patch.source_ip = table.lookup(read(ip, source));
            patch.destination_ip = table.lookup(read(ip, destination));
        }
        rewrite(frame, &patch, limits)
    }
}

/// The bytes from the outer IP header on, when the link header announces IP
/// and agrees with the version nibble.
fn outer_ip(frame: &Frame) -> Option<&[u8]> {
    let link = LinkHeader::walk(frame.link_type, frame.bytes()).ok()??;
    if !link.carries_ip() {
        return None;
    }
    let ip = frame.bytes().get(link.network_offset()..)?;
    let version = ip.first()? >> 4;
    link.announced_ip_version()
        .is_none_or(|announced| announced == version)
        .then_some(ip)
}

fn read(ip: &[u8], range: std::ops::Range<usize>) -> u128 {
    ip[range]
        .iter()
        .fold(0, |value, byte| (value << 8) | u128::from(*byte))
}
