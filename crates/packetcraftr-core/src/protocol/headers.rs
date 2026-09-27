// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! One bounded walker over raw link, VLAN, and IP header bytes.
//!
//! [`Ipv4Header::walk_prefix`] and [`Ipv6Header::walk_prefix`] cover inputs
//! that hold only the datagram's start, such as the quote inside an ICMP
//! error, and [`Ipv6ExtensionChain`] walks an extension chain directly.
//!
//! ```
//! use packetcraftr_core::{
//!     frame::LinkType,
//!     protocol::headers::{IpHeader, LinkHeader},
//! };
//!
//! let mut frame = vec![0; 12];
//! frame.extend_from_slice(&[0x81, 0x00, 0x20, 0x07, 0x86, 0xdd]); // VLAN 7, IPv6
//! frame.extend_from_slice(&[0x60, 0, 0, 0, 0, 8, 0, 64]); // payload 8, Hop-by-Hop
//! frame.extend_from_slice(&[0; 32]); // addresses
//! frame.extend_from_slice(&[58, 0, 1, 4, 0, 0, 0, 0]); // Hop-by-Hop -> ICMPv6
//!
//! let link = LinkHeader::walk(LinkType::ETHERNET, &frame)?.expect("Ethernet");
//! assert_eq!(link.network_offset(), 18);
//! let Some(IpHeader::V6(ipv6)) = link.walk_ip(&frame)? else {
//!     panic!("IPv6")
//! };
//! assert_eq!(ipv6.extensions().len(), 1);
//! assert_eq!(ipv6.upper_layer(), (58, 48));
//! # Ok::<(), packetcraftr_core::protocol::headers::Error>(())
//! ```

use std::fmt;
use std::ops::Range;

use crate::error::{Classification, Classified, Kind};
use crate::frame::LinkType;
use crate::packet::{MacAddress, VlanKind, VlanTag};

use super::BuiltinProtocol;
use super::network::ip_protocol;

pub const MAX_VLAN_DEPTH: usize = 64;
pub const MAX_IPV6_EXTENSIONS: usize = 64;

pub(crate) const fn is_walkable_ipv6_extension(next_header: u8) -> bool {
    matches!(
        next_header,
        ip_protocol::HOP_BY_HOP
            | ip_protocol::ROUTING
            | ip_protocol::AH
            | ip_protocol::DESTINATION_OPTIONS
    )
}

pub(crate) fn ipv6_extension_header_length(next_header: u8, encoded_length: u8) -> Option<usize> {
    match next_header {
        ip_protocol::HOP_BY_HOP | ip_protocol::ROUTING | ip_protocol::DESTINATION_OPTIONS => {
            usize::from(encoded_length)
                .checked_add(1)
                .and_then(|units| units.checked_mul(8))
        }
        ip_protocol::AH => usize::from(encoded_length)
            .checked_add(2)
            .and_then(|words| words.checked_mul(4))
            .filter(|length| *length >= 12),
        _ => None,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Header {
    Ethernet,
    Vlan,
    Ip,
    Ipv4,
    Ipv4Option,
    Ipv6,
    Ipv6Extension,
    Ipv6Option,
}

impl Header {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ethernet => "Ethernet header",
            Self::Vlan => "VLAN tag",
            Self::Ip => "IP header",
            Self::Ipv4 => "IPv4 header",
            Self::Ipv4Option => "IPv4 option",
            Self::Ipv6 => "IPv6 header",
            Self::Ipv6Extension => "IPv6 extension header",
            Self::Ipv6Option => "IPv6 option",
        }
    }
}

impl fmt::Display for Header {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("truncated {0}")]
    Truncated(Header),
    #[error("invalid {0} length")]
    Length(Header),
    #[error("{header} depth exceeds {limit}")]
    Depth { header: Header, limit: usize },
    #[error("unknown IP version {0}")]
    UnknownIpVersion(u8),
    #[error("link announces IPv{expected} but the IP header is version {found}")]
    IpVersionMismatch { expected: u8, found: u8 },
    #[error("IPv6 jumbograms are not walked")]
    Jumbogram,
}

impl Classified for Error {
    fn classification(&self) -> Classification {
        match self {
            Self::Jumbogram => Classification::new(
                "packet.transform_unsupported",
                Kind::Packet,
                Some("inspect the documented transform boundaries"),
            ),
            Self::Depth { .. } => Classification::new(
                "policy.transform_limit",
                Kind::Policy,
                Some("raise a finite transform limit or reduce the input"),
            ),
            Self::Truncated(_)
            | Self::Length(_)
            | Self::UnknownIpVersion(_)
            | Self::IpVersionMismatch { .. } => Classification::new(
                "packet.transform_input",
                Kind::Packet,
                Some("supply a complete supported datagram"),
            ),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LinkHeader {
    Ethernet(EthernetHeader),
    RawIp { version: Option<u8> },
}

impl LinkHeader {
    pub fn walk(link_type: LinkType, frame: &[u8]) -> Result<Option<Self>, Error> {
        if link_type == LinkType::ETHERNET {
            return EthernetHeader::walk(frame).map(|header| Some(Self::Ethernet(header)));
        }
        if !link_type.is_raw_ip() {
            return Ok(None);
        }
        let version = match link_type.root_protocol() {
            Some(BuiltinProtocol::Ipv4) => Some(4),
            Some(BuiltinProtocol::Ipv6) => Some(6),
            _ => None,
        };
        Ok(Some(Self::RawIp { version }))
    }

    pub fn network_offset(&self) -> usize {
        match self {
            Self::Ethernet(ethernet) => ethernet.payload_offset(),
            Self::RawIp { .. } => 0,
        }
    }

    pub fn carries_ip(&self) -> bool {
        match self {
            Self::Ethernet(ethernet) => ethernet.ip_version().is_some(),
            Self::RawIp { .. } => true,
        }
    }

    pub fn announced_ip_version(&self) -> Option<u8> {
        match self {
            Self::Ethernet(ethernet) => ethernet.ip_version(),
            Self::RawIp { version } => *version,
        }
    }

    pub fn walk_ip(&self, frame: &[u8]) -> Result<Option<IpHeader>, Error> {
        if !self.carries_ip() {
            return Ok(None);
        }
        let ip = frame
            .get(self.network_offset()..)
            .ok_or(Error::Truncated(Header::Ip))?;
        if let (Some(expected), Some(found)) = (
            self.announced_ip_version(),
            ip.first().map(|byte| byte >> 4),
        ) && expected != found
        {
            return Err(Error::IpVersionMismatch { expected, found });
        }
        IpHeader::walk(ip).map(Some)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EthernetHeader {
    destination: MacAddress,
    source: MacAddress,
    vlan_tags: Vec<VlanTag>,
    ether_type: u16,
}

impl EthernetHeader {
    pub const LENGTH: usize = 14;
    pub const VLAN_TAG_LENGTH: usize = 4;

    pub fn walk(frame: &[u8]) -> Result<Self, Error> {
        let header = frame
            .first_chunk::<{ Self::LENGTH }>()
            .ok_or(Error::Truncated(Header::Ethernet))?;
        let mut destination = [0; 6];
        destination.copy_from_slice(&header[..6]);
        let mut source = [0; 6];
        source.copy_from_slice(&header[6..12]);
        let mut ether_type = u16::from_be_bytes([header[12], header[13]]);
        let mut vlan_tags = Vec::new();
        while let Some(kind) = VlanKind::from_ether_type(ether_type) {
            if vlan_tags.len() == MAX_VLAN_DEPTH {
                return Err(Error::Depth {
                    header: Header::Vlan,
                    limit: MAX_VLAN_DEPTH,
                });
            }
            let offset = Self::LENGTH + vlan_tags.len() * Self::VLAN_TAG_LENGTH;
            let tag = frame
                .get(offset..)
                .and_then(<[u8]>::first_chunk::<{ Self::VLAN_TAG_LENGTH }>)
                .ok_or(Error::Truncated(Header::Vlan))?;
            vlan_tags.push(VlanTag::from_tci(
                kind,
                u16::from_be_bytes([tag[0], tag[1]]),
            ));
            ether_type = u16::from_be_bytes([tag[2], tag[3]]);
        }
        Ok(Self {
            destination: MacAddress(destination),
            source: MacAddress(source),
            vlan_tags,
            ether_type,
        })
    }

    pub fn destination(&self) -> MacAddress {
        self.destination
    }

    pub fn source(&self) -> MacAddress {
        self.source
    }

    pub fn vlan_tags(&self) -> &[VlanTag] {
        &self.vlan_tags
    }

    pub fn ether_type(&self) -> u16 {
        self.ether_type
    }

    pub fn payload_offset(&self) -> usize {
        Self::LENGTH + self.vlan_tags.len() * Self::VLAN_TAG_LENGTH
    }

    fn ip_version(&self) -> Option<u8> {
        match self.ether_type {
            0x0800 => Some(4),
            0x86dd => Some(6),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IpHeader {
    V4(Ipv4Header),
    V6(Ipv6Header),
}

impl IpHeader {
    pub fn walk(ip: &[u8]) -> Result<Self, Error> {
        match ip.first().map(|byte| byte >> 4) {
            None => Err(Error::Truncated(Header::Ip)),
            Some(4) => Ipv4Header::walk(ip).map(Self::V4),
            Some(6) => Ipv6Header::walk(ip).map(Self::V6),
            Some(version) => Err(Error::UnknownIpVersion(version)),
        }
    }

    pub fn version(&self) -> u8 {
        match self {
            Self::V4(_) => 4,
            Self::V6(_) => 6,
        }
    }

    pub fn datagram_length(&self) -> usize {
        match self {
            Self::V4(header) => header.total_length(),
            Self::V6(header) => header.datagram_length(),
        }
    }

    pub fn is_fragment(&self) -> bool {
        match self {
            Self::V4(header) => header.is_fragment(),
            Self::V6(header) => header.is_fragment(),
        }
    }

    pub fn upper_layer(&self) -> (u8, usize) {
        match self {
            Self::V4(header) => (header.protocol(), header.header_length()),
            Self::V6(header) => header.upper_layer(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ipv4Header {
    header_length: usize,
    total_length: usize,
    identification: u16,
    flags_and_offset: u16,
    protocol: u8,
}

impl Ipv4Header {
    pub const MIN_LENGTH: usize = 20;
    pub const CHECKSUM: Range<usize> = 10..12;
    pub const SOURCE: Range<usize> = 12..16;
    pub const DESTINATION: Range<usize> = 16..20;

    pub fn walk(ip: &[u8]) -> Result<Self, Error> {
        Self::walk_lengths(ip, false)
    }

    /// Walks the IPv4 header at the start of `ip`, which may be only the
    /// header's prefix: the declared total length may exceed `ip`, as in the
    /// datagram an ICMP error quotes. The header itself, including options,
    /// must still fit.
    pub fn walk_prefix(ip: &[u8]) -> Result<Self, Error> {
        Self::walk_lengths(ip, true)
    }

    fn walk_lengths(ip: &[u8], prefix: bool) -> Result<Self, Error> {
        let fixed = ip
            .first_chunk::<{ Self::MIN_LENGTH }>()
            .ok_or(Error::Truncated(Header::Ipv4))?;
        if fixed[0] >> 4 != 4 {
            return Err(Error::IpVersionMismatch {
                expected: 4,
                found: fixed[0] >> 4,
            });
        }
        let header_length = usize::from(fixed[0] & 0x0f) * 4;
        let total_length = usize::from(u16::from_be_bytes([fixed[2], fixed[3]]));
        if header_length < Self::MIN_LENGTH || total_length < header_length {
            return Err(Error::Length(Header::Ipv4));
        }
        if header_length > ip.len() || !prefix && total_length > ip.len() {
            return Err(Error::Truncated(Header::Ipv4));
        }
        Ok(Self {
            header_length,
            total_length,
            identification: u16::from_be_bytes([fixed[4], fixed[5]]),
            flags_and_offset: u16::from_be_bytes([fixed[6], fixed[7]]),
            protocol: fixed[9],
        })
    }

    pub fn header_length(&self) -> usize {
        self.header_length
    }

    pub fn total_length(&self) -> usize {
        self.total_length
    }

    pub fn identification(&self) -> u16 {
        self.identification
    }

    pub fn flags_and_offset(&self) -> u16 {
        self.flags_and_offset
    }

    pub fn reserved_flag(&self) -> bool {
        self.flags_and_offset & 0x8000 != 0
    }

    pub fn dont_fragment(&self) -> bool {
        self.flags_and_offset & 0x4000 != 0
    }

    pub fn is_fragment(&self) -> bool {
        self.flags_and_offset & 0x3fff != 0
    }

    pub fn protocol(&self) -> u8 {
        self.protocol
    }

    pub fn options<'a>(&self, ip: &'a [u8]) -> Ipv4Options<'a> {
        Ipv4Options {
            header: &ip[..self.header_length.min(ip.len())],
            cursor: Self::MIN_LENGTH,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IpOption {
    pub kind: u8,
    pub range: Range<usize>,
}

#[derive(Clone, Debug)]
pub struct Ipv4Options<'a> {
    header: &'a [u8],
    cursor: usize,
}

impl Iterator for Ipv4Options<'_> {
    type Item = Result<IpOption, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        const END_OF_OPTIONS: u8 = 0;
        const NO_OPERATION: u8 = 1;
        let start = self.cursor;
        let kind = *self.header.get(start)?;
        let length = match kind {
            END_OF_OPTIONS => {
                self.cursor = self.header.len();
                return None;
            }
            NO_OPERATION => 1,
            _ => match self.header.get(start + 1) {
                None => {
                    self.cursor = self.header.len();
                    return Some(Err(Error::Truncated(Header::Ipv4Option)));
                }
                Some(&length) => usize::from(length),
            },
        };
        if kind != NO_OPERATION && length < 2 || start + length > self.header.len() {
            self.cursor = self.header.len();
            return Some(Err(Error::Length(Header::Ipv4Option)));
        }
        self.cursor = start + length;
        Some(Ok(IpOption {
            kind,
            range: start..start + length,
        }))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ipv6Header {
    payload_length: usize,
    next_header: u8,
    extensions: Vec<Ipv6Extension>,
    upper_layer: u8,
    upper_layer_offset: usize,
}

impl Ipv6Header {
    pub const LENGTH: usize = 40;
    pub const SOURCE: Range<usize> = 8..24;
    pub const DESTINATION: Range<usize> = 24..40;

    pub fn walk(ip: &[u8]) -> Result<Self, Error> {
        let (payload_length, next_header) = Self::walk_fixed(ip)?;
        let datagram = ip
            .get(..Self::LENGTH + payload_length)
            .ok_or(Error::Truncated(Header::Ipv6))?;
        Self::walk_chain(datagram, payload_length, next_header)
    }

    /// Walks the IPv6 header at the start of `ip` and its extension chain,
    /// which may be only the datagram's prefix: the declared payload length
    /// may exceed `ip`, as in the datagram an ICMP error quotes. Every
    /// extension header must still fit in the bytes that are present; the
    /// chain otherwise follows [`walk`](Self::walk).
    pub fn walk_prefix(ip: &[u8]) -> Result<Self, Error> {
        let (payload_length, next_header) = Self::walk_fixed(ip)?;
        let datagram = &ip[..(Self::LENGTH + payload_length).min(ip.len())];
        Self::walk_chain(datagram, payload_length, next_header)
    }

    fn walk_fixed(ip: &[u8]) -> Result<(usize, u8), Error> {
        let fixed = ip
            .first_chunk::<{ Self::LENGTH }>()
            .ok_or(Error::Truncated(Header::Ipv6))?;
        if fixed[0] >> 4 != 6 {
            return Err(Error::IpVersionMismatch {
                expected: 6,
                found: fixed[0] >> 4,
            });
        }
        let payload_length = usize::from(u16::from_be_bytes([fixed[4], fixed[5]]));
        let next_header = fixed[6];
        if payload_length == 0 && next_header != ip_protocol::NO_NEXT_HEADER {
            return Err(Error::Jumbogram);
        }
        Ok((payload_length, next_header))
    }

    fn walk_chain(datagram: &[u8], payload_length: usize, next_header: u8) -> Result<Self, Error> {
        let mut extensions = Vec::new();
        let mut chain = Ipv6ExtensionChain::new(datagram, Self::LENGTH, next_header);
        while chain.at_header() {
            if extensions.len() == MAX_IPV6_EXTENSIONS {
                return Err(Error::Depth {
                    header: Header::Ipv6Extension,
                    limit: MAX_IPV6_EXTENSIONS,
                });
            }
            let extension = match chain.next() {
                Some(extension) => extension?,
                None => break,
            };
            extensions.push(extension);
        }
        let (upper_layer, upper_layer_offset) = chain.position();
        Ok(Self {
            payload_length,
            next_header,
            extensions,
            upper_layer,
            upper_layer_offset,
        })
    }

    pub fn payload_length(&self) -> usize {
        self.payload_length
    }

    pub fn datagram_length(&self) -> usize {
        Self::LENGTH + self.payload_length
    }

    pub fn next_header(&self) -> u8 {
        self.next_header
    }

    pub fn extensions(&self) -> &[Ipv6Extension] {
        &self.extensions
    }

    pub fn is_fragment(&self) -> bool {
        self.extensions.iter().any(Ipv6Extension::is_fragment)
    }

    pub fn upper_layer(&self) -> (u8, usize) {
        (self.upper_layer, self.upper_layer_offset)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ipv6Extension {
    protocol: u8,
    offset: usize,
    length: usize,
    next_header: u8,
    fragment: Option<u16>,
}

impl Ipv6Extension {
    pub fn protocol(&self) -> u8 {
        self.protocol
    }

    /// Where the header sits, counted from the start of the walked bytes
    /// (the IPv6 header start for [`Ipv6Header`] walks).
    pub fn range(&self) -> Range<usize> {
        self.offset..self.offset + self.length
    }

    pub fn next_header(&self) -> u8 {
        self.next_header
    }

    /// For a Fragment header, the offset and flags word as it appears on
    /// the wire (mirrors [`Ipv4Header::flags_and_offset`]).
    pub fn fragment_offset_and_flags(&self) -> Option<u16> {
        self.fragment
    }

    /// For a Fragment header, the fragment offset in 8-byte units.
    pub fn fragment_offset(&self) -> Option<u16> {
        self.fragment.map(|word| word >> 3)
    }

    pub fn more_fragments(&self) -> Option<bool> {
        self.fragment.map(|word| word & 1 != 0)
    }

    pub fn is_fragment(&self) -> bool {
        self.fragment.is_some_and(|word| word & 0xfff9 != 0)
    }

    pub fn options<'a>(&self, ip: &'a [u8]) -> Ipv6Options<'a> {
        let carries_options = matches!(
            self.protocol,
            ip_protocol::HOP_BY_HOP | ip_protocol::DESTINATION_OPTIONS
        );
        let end = if carries_options {
            (self.offset + self.length).min(ip.len())
        } else {
            0
        };
        Ipv6Options {
            ip: &ip[..end],
            cursor: self.offset + 2,
        }
    }
}

/// Iterator over one IPv6 extension-header chain in `bytes`. Each step
/// reports the Hop-by-Hop, Routing, Fragment, AH, or Destination Options
/// header the position stands at; the walk ends at the first other Next
/// Header value, and behind a Fragment header with a nonzero offset — the
/// bytes there continue an earlier fragment, not another header. It yields
/// an error once and then ends.
///
/// There is no count bound: the slice bounds the chain. [`Ipv6Header`]
/// walks apply [`MAX_IPV6_EXTENSIONS`] on top.
#[derive(Clone, Debug)]
pub struct Ipv6ExtensionChain<'a> {
    bytes: &'a [u8],
    protocol: u8,
    offset: usize,
    done: bool,
}

impl<'a> Ipv6ExtensionChain<'a> {
    /// Starts a walk at `offset` in `bytes`, where the header announced by
    /// `next_header` begins.
    pub fn new(bytes: &'a [u8], offset: usize, next_header: u8) -> Self {
        Self {
            bytes,
            protocol: next_header,
            offset,
            done: false,
        }
    }

    /// The Next Header value the walk stands at and the offset where the
    /// header or upper layer it announces starts.
    pub fn position(&self) -> (u8, usize) {
        (self.protocol, self.offset)
    }

    fn at_header(&self) -> bool {
        !self.done
            && (self.protocol == ip_protocol::FRAGMENT || is_walkable_ipv6_extension(self.protocol))
    }
}

impl Iterator for Ipv6ExtensionChain<'_> {
    type Item = Result<Ipv6Extension, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if !self.at_header() {
            return None;
        }
        let step = (|| {
            let prefix = self
                .bytes
                .get(self.offset..)
                .and_then(<[u8]>::first_chunk::<2>)
                .ok_or(Error::Truncated(Header::Ipv6Extension))?;
            let length = if self.protocol == ip_protocol::FRAGMENT {
                8
            } else {
                ipv6_extension_header_length(self.protocol, prefix[1])
                    .ok_or(Error::Length(Header::Ipv6Extension))?
            };
            let header = self
                .bytes
                .get(self.offset..self.offset + length)
                .ok_or(Error::Truncated(Header::Ipv6Extension))?;
            let fragment = (self.protocol == ip_protocol::FRAGMENT)
                .then(|| u16::from_be_bytes([header[2], header[3]]));
            Ok(Ipv6Extension {
                protocol: self.protocol,
                offset: self.offset,
                length,
                next_header: header[0],
                fragment,
            })
        })();
        match step {
            Ok(extension) => {
                self.offset += extension.length;
                self.protocol = extension.next_header;
                self.done = extension.fragment_offset().is_some_and(|units| units != 0);
                Some(Ok(extension))
            }
            Err(error) => {
                self.done = true;
                Some(Err(error))
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct Ipv6Options<'a> {
    ip: &'a [u8],
    cursor: usize,
}

impl Iterator for Ipv6Options<'_> {
    type Item = Result<IpOption, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        const PAD1: u8 = 0;
        let start = self.cursor;
        let kind = *self.ip.get(start)?;
        let length = if kind == PAD1 {
            1
        } else {
            match self.ip.get(start + 1) {
                None => {
                    self.cursor = self.ip.len();
                    return Some(Err(Error::Truncated(Header::Ipv6Option)));
                }
                Some(&length) => usize::from(length) + 2,
            }
        };
        if start + length > self.ip.len() {
            self.cursor = self.ip.len();
            return Some(Err(Error::Length(Header::Ipv6Option)));
        }
        self.cursor = start + length;
        Some(Ok(IpOption {
            kind,
            range: start..start + length,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ipv4(options: &[u8], payload: usize) -> Vec<u8> {
        let header = 20 + options.len();
        let total = u16::try_from(header + payload).unwrap();
        let mut ip = vec![0x40 | (header / 4) as u8, 0];
        ip.extend_from_slice(&total.to_be_bytes());
        ip.extend_from_slice(&[0x12, 0x34, 0x20, 0x00, 64, 17, 0, 0]);
        ip.extend_from_slice(&[192, 0, 2, 1, 198, 51, 100, 2]);
        ip.extend_from_slice(options);
        ip.resize(header + payload, 0xaa);
        ip
    }

    fn ipv6(next_header: u8, chain: &[u8], upper: usize) -> Vec<u8> {
        let payload = u16::try_from(chain.len() + upper).unwrap();
        let mut ip = vec![0x60, 0, 0, 0];
        ip.extend_from_slice(&payload.to_be_bytes());
        ip.extend_from_slice(&[next_header, 64]);
        ip.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8]);
        ip.resize(40, 0);
        ip.extend_from_slice(chain);
        ip.resize(40 + chain.len() + upper, 0xbb);
        ip
    }

    #[test]
    fn ethernet_walk_reports_every_tag_and_the_inner_ether_type() {
        let mut frame = vec![2, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0, 2, 0x88, 0xa8];
        frame.extend_from_slice(&[0xb0, 0x64, 0x81, 0x00, 0x20, 0xc8, 0x08, 0x06, 0xff]);
        let ethernet = EthernetHeader::walk(&frame).unwrap();
        assert_eq!(ethernet.destination(), MacAddress([2, 0, 0, 0, 0, 1]));
        assert_eq!(ethernet.source(), MacAddress([2, 0, 0, 0, 0, 2]));
        assert_eq!(
            ethernet.vlan_tags(),
            [
                VlanTag {
                    kind: VlanKind::Ieee8021Ad,
                    priority: 5,
                    drop_eligible: true,
                    vlan_id: 100,
                },
                VlanTag {
                    kind: VlanKind::Ieee8021Q,
                    priority: 1,
                    drop_eligible: false,
                    vlan_id: 200,
                },
            ]
        );
        assert_eq!(ethernet.vlan_tags()[0].tci(), 0xb064);
        assert_eq!(ethernet.ether_type(), 0x0806);
        assert_eq!(ethernet.payload_offset(), 22);

        let link = LinkHeader::Ethernet(ethernet);
        assert!(!link.carries_ip());
        assert_eq!(link.walk_ip(&frame), Ok(None));
    }

    #[test]
    fn ethernet_walk_bounds_truncation_and_tag_depth() {
        assert_eq!(
            EthernetHeader::walk(&[0; 13]),
            Err(Error::Truncated(Header::Ethernet))
        );
        let mut frame = vec![0; 12];
        frame.extend_from_slice(&[0x81, 0x00, 0, 1]);
        assert_eq!(
            EthernetHeader::walk(&frame),
            Err(Error::Truncated(Header::Vlan))
        );
        let mut deep = vec![0; 12];
        for _ in 0..MAX_VLAN_DEPTH {
            deep.extend_from_slice(&[0x81, 0x00, 0, 1]);
        }
        deep.extend_from_slice(&[0x08, 0x00]);
        assert_eq!(
            EthernetHeader::walk(&deep).unwrap().vlan_tags().len(),
            MAX_VLAN_DEPTH
        );
        let mut deeper = deep[..deep.len() - 2].to_vec();
        deeper.extend_from_slice(&[0x81, 0x00, 0, 1, 0x08, 0x00]);
        assert_eq!(
            EthernetHeader::walk(&deeper),
            Err(Error::Depth {
                header: Header::Vlan,
                limit: MAX_VLAN_DEPTH,
            })
        );
    }

    #[test]
    fn link_types_choose_the_framing_and_announced_version() {
        let ip = ipv4(&[], 4);
        for (link_type, version) in [
            (LinkType::RAW, None),
            (LinkType::BSD_RAW, None),
            (LinkType::IPV4, Some(4)),
            (LinkType::IPV6, Some(6)),
        ] {
            let link = LinkHeader::walk(link_type, &ip).unwrap().unwrap();
            assert_eq!(link, LinkHeader::RawIp { version });
            assert_eq!(link.network_offset(), 0);
        }
        assert_eq!(LinkHeader::walk(LinkType::LINUX_SLL, &ip), Ok(None));
        let raw_ipv6 = LinkHeader::walk(LinkType::IPV6, &ip).unwrap().unwrap();
        assert_eq!(
            raw_ipv6.walk_ip(&ip),
            Err(Error::IpVersionMismatch {
                expected: 6,
                found: 4,
            })
        );
        let mut ethernet = vec![0; 12];
        ethernet.extend_from_slice(&[0x86, 0xdd]);
        ethernet.extend_from_slice(&ip);
        let link = LinkHeader::walk(LinkType::ETHERNET, &ethernet)
            .unwrap()
            .unwrap();
        assert_eq!(link.announced_ip_version(), Some(6));
        assert!(matches!(
            link.walk_ip(&ethernet),
            Err(Error::IpVersionMismatch { .. })
        ));
        assert_eq!(IpHeader::walk(&[]), Err(Error::Truncated(Header::Ip)));
        assert_eq!(IpHeader::walk(&[0x50]), Err(Error::UnknownIpVersion(5)));
    }

    #[test]
    fn ipv4_walk_checks_lengths_and_reads_flags_and_options() {
        let options = [0x83, 7, 4, 192, 0, 2, 9, 1, 0x44, 4, 5, 0, 0, 0, 0, 0];
        let mut ip = ipv4(&options, 8);
        ip.extend_from_slice(&[0xee; 3]);
        let IpHeader::V4(header) = IpHeader::walk(&ip).unwrap() else {
            panic!("IPv4")
        };
        assert_eq!(header.header_length(), 36);
        assert_eq!(header.total_length(), 44);
        assert_eq!(header.identification(), 0x1234);
        assert!(header.is_fragment());
        assert!(!header.dont_fragment() && !header.reserved_flag());
        assert_eq!(header.protocol(), 17);
        let options = header.options(&ip).collect::<Result<Vec<_>, _>>().unwrap();
        assert_eq!(
            options,
            [
                IpOption {
                    kind: 0x83,
                    range: 20..27,
                },
                IpOption {
                    kind: 1,
                    range: 27..28,
                },
                IpOption {
                    kind: 0x44,
                    range: 28..32,
                },
            ]
        );

        let mut short = ipv4(&[], 0);
        short[0] = 0x44;
        assert_eq!(Ipv4Header::walk(&short), Err(Error::Length(Header::Ipv4)));
        let mut long = ipv4(&[], 4);
        long[3] += 1;
        assert_eq!(Ipv4Header::walk(&long), Err(Error::Truncated(Header::Ipv4)));
        for bad in [[0x07, 1, 0, 0], [0x07, 5, 0, 0]] {
            let ip = ipv4(&bad, 0);
            let header = Ipv4Header::walk(&ip).unwrap();
            assert_eq!(
                header.options(&ip).collect::<Vec<_>>(),
                [Err(Error::Length(Header::Ipv4Option))]
            );
        }
        let ip = ipv4(&[1, 1, 1, 0x07], 0);
        let header = Ipv4Header::walk(&ip).unwrap();
        assert_eq!(
            header.options(&ip).last(),
            Some(Err(Error::Truncated(Header::Ipv4Option)))
        );
    }

    #[test]
    fn ipv6_walk_steps_over_the_extension_chain_to_the_upper_layer() {
        let chain = [
            60, 0, 1, 0, 0xc9, 2, 0, 0, // Hop-by-Hop: PadN, then Home Address type
            51, 0, 0, 0, 0, 0, 0, 0, // Destination Options
            44, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, // AH, 12 bytes
            6, 0, 0, 0, 0, 0, 0, 7, // atomic Fragment
        ];
        let ip = ipv6(0, &chain, 20);
        let IpHeader::V6(header) = IpHeader::walk(&ip).unwrap() else {
            panic!("IPv6")
        };
        let protocols = header
            .extensions()
            .iter()
            .map(|extension| (extension.protocol(), extension.range()))
            .collect::<Vec<_>>();
        assert_eq!(
            protocols,
            [(0, 40..48), (60, 48..56), (51, 56..68), (44, 68..76)]
        );
        assert_eq!(header.upper_layer(), (6, 76));
        assert!(!header.is_fragment());
        assert_eq!(header.extensions()[3].fragment_offset(), Some(0));
        let options = header.extensions()[0]
            .options(&ip)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(
            options,
            [
                IpOption {
                    kind: 1,
                    range: 42..44,
                },
                IpOption {
                    kind: 0xc9,
                    range: 44..48,
                },
            ]
        );
        assert_eq!(header.extensions()[2].options(&ip).count(), 0);
    }

    #[test]
    fn ipv6_walk_stops_behind_a_later_fragment_and_bounds_the_chain() {
        let ip = ipv6(44, &[60, 0, 0x05, 0x01, 0, 0, 0, 9], 16);
        let header = Ipv6Header::walk(&ip).unwrap();
        assert!(header.is_fragment());
        assert_eq!(header.extensions()[0].fragment_offset(), Some(160));
        assert_eq!(header.extensions()[0].more_fragments(), Some(true));
        assert_eq!(header.upper_layer(), (60, 48));

        let first = Ipv6Header::walk(&ipv6(44, &[17, 0, 0, 1, 0, 0, 0, 9], 8)).unwrap();
        assert!(first.is_fragment());
        assert_eq!(first.upper_layer(), (17, 48));

        let mut chain = Vec::new();
        for _ in 0..MAX_IPV6_EXTENSIONS {
            chain.extend_from_slice(&[60, 0, 1, 4, 0, 0, 0, 0]);
        }
        let ip = ipv6(60, &chain, 0);
        assert_eq!(
            Ipv6Header::walk(&ip),
            Err(Error::Depth {
                header: Header::Ipv6Extension,
                limit: MAX_IPV6_EXTENSIONS,
            })
        );
        *chain.last_chunk_mut::<8>().unwrap() = [59, 0, 1, 4, 0, 0, 0, 0];
        let ip = ipv6(60, &chain, 0);
        assert_eq!(
            Ipv6Header::walk(&ip).unwrap().extensions().len(),
            MAX_IPV6_EXTENSIONS
        );
    }

    #[test]
    fn ipv6_walk_rejects_truncation_jumbograms_and_bad_option_lengths() {
        assert_eq!(
            Ipv6Header::walk(&[0x60; 39]),
            Err(Error::Truncated(Header::Ipv6))
        );
        assert_eq!(Ipv6Header::walk(&ipv6(0, &[], 0)), Err(Error::Jumbogram));
        assert!(Ipv6Header::walk(&ipv6(59, &[], 0)).is_ok());
        let mut long = ipv6(17, &[], 8);
        long.truncate(47);
        assert_eq!(Ipv6Header::walk(&long), Err(Error::Truncated(Header::Ipv6)));
        assert_eq!(
            Ipv6Header::walk(&ipv6(0, &[17, 1, 0, 0, 0, 0, 0, 0], 0)),
            Err(Error::Truncated(Header::Ipv6Extension))
        );
        assert_eq!(
            Ipv6Header::walk(&ipv6(51, &[17, 0, 0, 0, 0, 0, 0, 0], 0)),
            Err(Error::Length(Header::Ipv6Extension))
        );
        let ip = ipv6(60, &[17, 0, 1, 5, 0, 0, 0, 0], 0);
        let header = Ipv6Header::walk(&ip).unwrap();
        assert_eq!(
            header.extensions()[0].options(&ip).collect::<Vec<_>>(),
            [Err(Error::Length(Header::Ipv6Option))]
        );
    }

    #[test]
    fn ipv4_walk_prefix_accepts_a_truncated_datagram_but_not_truncated_options() {
        let mut ip = ipv4(&[1, 1, 1, 1], 64);
        let declared = ip.len();
        ip.truncate(36);
        assert_eq!(Ipv4Header::walk(&ip), Err(Error::Truncated(Header::Ipv4)));
        let header = Ipv4Header::walk_prefix(&ip).unwrap();
        assert_eq!(header.header_length(), 24);
        assert_eq!(header.total_length(), declared);

        ip.truncate(23);
        assert_eq!(
            Ipv4Header::walk_prefix(&ip),
            Err(Error::Truncated(Header::Ipv4))
        );
    }

    #[test]
    fn ipv6_walk_prefix_walks_the_chain_inside_a_truncated_datagram() {
        let chain = [17, 0, 1, 4, 0, 0, 0, 0]; // Hop-by-Hop -> UDP
        let mut ip = ipv6(0, &chain, 64);
        ip.truncate(40 + chain.len());
        assert_eq!(Ipv6Header::walk(&ip), Err(Error::Truncated(Header::Ipv6)));
        let header = Ipv6Header::walk_prefix(&ip).unwrap();
        assert_eq!(header.extensions().len(), 1);
        assert_eq!(header.extensions()[0].range(), 40..48);
        assert_eq!(header.upper_layer(), (17, 48));
        assert_eq!(header.datagram_length(), 40 + chain.len() + 64);

        ip.truncate(43);
        assert_eq!(
            Ipv6Header::walk_prefix(&ip),
            Err(Error::Truncated(Header::Ipv6Extension))
        );
    }

    #[test]
    fn ipv6_extension_chain_walks_from_any_offset_and_reports_its_position() {
        let mut bytes = vec![0xaa; 20];
        bytes.extend_from_slice(&[51, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]); // AH -> AH
        bytes.extend_from_slice(&[6, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]); // AH -> TCP
        let mut chain = Ipv6ExtensionChain::new(&bytes, 20, ip_protocol::AH);
        assert_eq!(chain.position(), (ip_protocol::AH, 20));
        let first = chain.next().unwrap().unwrap();
        assert_eq!(first.range(), 20..32);
        assert_eq!(chain.position(), (ip_protocol::AH, 32));
        let second = chain.next().unwrap().unwrap();
        assert_eq!(second.range(), 32..44);
        assert_eq!(chain.position(), (6, 44));
        assert_eq!(chain.next(), None);
    }

    #[test]
    fn ipv6_extension_chain_yields_one_error_then_ends() {
        let bytes = [17, 0, 1, 4, 0, 0, 0]; // truncated Hop-by-Hop
        let mut chain = Ipv6ExtensionChain::new(&bytes, 0, ip_protocol::HOP_BY_HOP);
        assert_eq!(
            chain.next(),
            Some(Err(Error::Truncated(Header::Ipv6Extension)))
        );
        assert_eq!(chain.position(), (ip_protocol::HOP_BY_HOP, 0));
        assert_eq!(chain.next(), None);
        assert_eq!(chain.next(), None);
    }

    #[test]
    fn ipv6_extension_chain_stops_behind_a_later_fragment() {
        // A non-initial fragment announces Hop-by-Hop, but the bytes behind
        // it continue an earlier fragment and must not walk as a header.
        let mut bytes = vec![0xaa; 8];
        bytes.extend_from_slice(&[0, 0, 0, 0x09, 0, 0, 0, 0]); // Fragment -> Hop-by-Hop, offset 1
        bytes.extend_from_slice(&[6, 0, 0, 0, 0, 0, 0, 0]); // fragment data
        let mut chain = Ipv6ExtensionChain::new(&bytes, 8, ip_protocol::FRAGMENT);
        let fragment = chain.next().unwrap().unwrap();
        assert_eq!(fragment.range(), 8..16);
        assert_eq!(fragment.fragment_offset(), Some(1));
        assert_eq!(chain.position(), (ip_protocol::HOP_BY_HOP, 16));
        assert_eq!(chain.next(), None);
        assert_eq!(chain.position(), (ip_protocol::HOP_BY_HOP, 16));
    }

    #[test]
    fn fragment_offset_and_flags_returns_the_wire_word() {
        let ip = ipv6(44, &[17, 0, 0x05, 0x01, 0, 0, 0, 9], 8);
        let header = Ipv6Header::walk(&ip).unwrap();
        let fragment = header.extensions()[0];
        assert_eq!(fragment.fragment_offset_and_flags(), Some(0x0501));
        assert_eq!(fragment.fragment_offset(), Some(160));
        assert_eq!(fragment.more_fragments(), Some(true));
        assert_eq!(header.extensions()[0].protocol(), ip_protocol::FRAGMENT);

        let chain = [17, 0, 1, 4, 0, 0, 0, 0];
        let header = Ipv6Header::walk(&ipv6(0, &chain, 8)).unwrap();
        assert_eq!(header.extensions()[0].fragment_offset_and_flags(), None);
    }

    #[test]
    fn walk_failures_classify_as_transform_failures() {
        let code = |error: Error| error.classification().code;
        assert_eq!(code(Error::Jumbogram), "packet.transform_unsupported");
        assert_eq!(
            code(Error::Depth {
                header: Header::Vlan,
                limit: MAX_VLAN_DEPTH
            }),
            "policy.transform_limit"
        );
        assert_eq!(
            code(Error::Truncated(Header::Ipv4)),
            "packet.transform_input"
        );
        assert_eq!(
            code(Error::IpVersionMismatch {
                expected: 4,
                found: 6
            }),
            "packet.transform_input"
        );
    }
}
