// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Neighbor Discovery (RFC 4861) neighbor, router and redirect messages.
//! ```
//! use packetcraftr_core::{
//!     packet::MacAddress,
//!     protocol::network::ndp::{MessageOption, NeighborSolicitation},
//! };
//!
//! let solicitation = NeighborSolicitation {
//!     reserved: 0,
//!     target: "2001:db8::2".parse()?,
//!     options: vec![MessageOption::source_link_layer(MacAddress([2, 0, 0, 0, 0, 1]))],
//! };
//! let icmp = solicitation.to_icmpv6()?;
//! assert_eq!(icmp.icmp_type, 135);
//! assert_eq!(NeighborSolicitation::decode(&icmp.body)?, solicitation);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

use std::net::Ipv6Addr;

use bytes::Bytes;

use crate::field::WireValue;
use crate::packet::MacAddress;

use super::Icmpv6;

pub const ROUTER_SOLICITATION: u8 = 133;
pub const ROUTER_ADVERTISEMENT: u8 = 134;
pub const NEIGHBOR_SOLICITATION: u8 = 135;
pub const NEIGHBOR_ADVERTISEMENT: u8 = 136;
pub const REDIRECT: u8 = 137;
pub const SOURCE_LINK_LAYER_ADDRESS: u8 = 1;
pub const TARGET_LINK_LAYER_ADDRESS: u8 = 2;
pub const PREFIX_INFORMATION: u8 = 3;
pub const REDIRECTED_HEADER: u8 = 4;
pub const MTU: u8 = 5;
pub const ROUTE_INFORMATION: u8 = 24;
pub const RDNSS: u8 = 25;

const FIXED_LENGTH: usize = 20;
const ROUTER_SOLICITATION_LENGTH: usize = 4;
const ROUTER_ADVERTISEMENT_LENGTH: usize = 12;
const REDIRECT_LENGTH: usize = 36;
/// Options are sized in units of eight octets.
const OPTION_UNIT: usize = 8;
const OPTION_HEADER_LENGTH: usize = 2;
const ROUTER_FLAG: u32 = 1 << 31;
const SOLICITED_FLAG: u32 = 1 << 30;
const OVERRIDE_FLAG: u32 = 1 << 29;
const ADVERTISEMENT_RESERVED: u32 = OVERRIDE_FLAG - 1;
const MANAGED_FLAG: u8 = 0x80;
const OTHER_FLAG: u8 = 0x40;
const HOME_AGENT_FLAG: u8 = 0x20;
const PREFERENCE_SHIFT: u32 = 3;
const PREFERENCE_MASK: u8 = 0b11;
const PROXY_FLAG: u8 = 0x04;
const ROUTER_RESERVED_MASK: u8 = 0b11;
const ON_LINK_FLAG: u8 = 0x80;
const AUTONOMOUS_FLAG: u8 = 0x40;
const ROUTER_ADDRESS_FLAG: u8 = 0x20;
const PREFIX_RESERVED_MASK: u8 = 0x1f;
/// Route Information keeps its reserved bits where they sit on the wire,
/// either side of the two preference bits.
const ROUTE_RESERVED_MASK: u8 = !(PREFERENCE_MASK << PREFERENCE_SHIFT);
const REDIRECTED_RESERVED_LENGTH: usize = 6;
const PREFIX_INFORMATION_UNITS: u8 = 4;
const PREFIX_INFORMATION_VALUE: usize = 30;
const MTU_VALUE: usize = 6;
const ROUTE_FIXED_VALUE: usize = 6;
const RDNSS_FIXED_VALUE: usize = 6;

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("NDP message body is {actual} bytes; expected at least {FIXED_LENGTH}")]
    Truncated { actual: usize },
    #[error("NDP option at body byte {offset} has zero length")]
    ZeroLengthOption { offset: usize },
    #[error("NDP option at body byte {offset} runs past the end of the message")]
    OptionOverrun { offset: usize },
    #[error("NDP option value of {length} bytes does not fill whole 8-octet units")]
    OptionLength { length: usize },
    #[error("NDP advertisement reserved bits {value:#x} do not fit in 29 bits")]
    Reserved { value: u32 },
    #[error("NDP message body is {actual} bytes; expected at least {expected}")]
    TruncatedMessage { expected: usize, actual: usize },
    #[error("NDP {field} value {value:#x} does not fit its bit width")]
    FieldRange { field: &'static str, value: u64 },
    #[error("NDP option {kind} holds {length} value bytes, which its layout cannot carry")]
    OptionValue { kind: u8, length: usize },
}

impl crate::error::Classified for Error {
    fn classification(&self) -> crate::error::Classification {
        crate::error::Classification::new(
            "packet.codec",
            crate::error::Kind::Packet,
            Some("correct the layer bytes or field values the codec refused"),
        )
    }
}

/// A Neighbor Discovery option. Options whose kind is not modelled, or whose
/// length does not fit the layout their kind defines, stay [`Other`] so the
/// bytes re-encode exactly.
///
/// [`Other`]: MessageOption::Other
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum MessageOption {
    SourceLinkLayerAddress(Bytes),
    TargetLinkLayerAddress(Bytes),
    PrefixInformation(PrefixInformation),
    RedirectedHeader(RedirectedHeader),
    Mtu(MtuOption),
    RouteInformation(RouteInformation),
    Rdnss(Rdnss),
    Other { kind: u8, value: Bytes },
}

/// Prefix Information option (type 3), including the router-address flag of
/// RFC 6275.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrefixInformation {
    pub prefix_length: u8,
    pub on_link: bool,
    pub autonomous: bool,
    pub router_address: bool,
    /// The five reserved bits that follow the flags.
    pub reserved: u8,
    pub valid_lifetime: u32,
    pub preferred_lifetime: u32,
    pub reserved2: u32,
    pub prefix: Ipv6Addr,
}

/// Redirected Header option (type 4): six reserved bytes and as much of the
/// redirected packet as fits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RedirectedHeader {
    pub reserved: [u8; REDIRECTED_RESERVED_LENGTH],
    pub packet: Bytes,
}

/// MTU option (type 5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MtuOption {
    pub reserved: u16,
    pub mtu: u32,
}

/// Route Information option (type 24, RFC 4191).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteInformation {
    pub prefix_length: u8,
    /// The two route preference bits.
    pub preference: u8,
    /// Reserved bits at their wire positions in the flags octet.
    pub reserved: u8,
    pub route_lifetime: u32,
    /// The prefix bytes as sent: none, eight or sixteen.
    pub prefix: Bytes,
}

/// Recursive DNS Server option (type 25, RFC 8106).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rdnss {
    pub reserved: u16,
    pub lifetime: u32,
    pub servers: Vec<Ipv6Addr>,
}

impl MessageOption {
    pub fn source_link_layer(address: MacAddress) -> Self {
        Self::SourceLinkLayerAddress(Bytes::copy_from_slice(&address.0))
    }

    pub fn target_link_layer(address: MacAddress) -> Self {
        Self::TargetLinkLayerAddress(Bytes::copy_from_slice(&address.0))
    }

    pub fn kind(&self) -> u8 {
        match self {
            Self::SourceLinkLayerAddress(_) => SOURCE_LINK_LAYER_ADDRESS,
            Self::TargetLinkLayerAddress(_) => TARGET_LINK_LAYER_ADDRESS,
            Self::PrefixInformation(_) => PREFIX_INFORMATION,
            Self::RedirectedHeader(_) => REDIRECTED_HEADER,
            Self::Mtu(_) => MTU,
            Self::RouteInformation(_) => ROUTE_INFORMATION,
            Self::Rdnss(_) => RDNSS,
            Self::Other { kind, .. } => *kind,
        }
    }

    /// The option bytes after the two-octet kind and length header.
    pub fn value(&self) -> Bytes {
        match self {
            Self::SourceLinkLayerAddress(value)
            | Self::TargetLinkLayerAddress(value)
            | Self::Other { value, .. } => value.clone(),
            Self::PrefixInformation(option) => option.value(),
            Self::RedirectedHeader(option) => option.value(),
            Self::Mtu(option) => option.value(),
            Self::RouteInformation(option) => option.value(),
            Self::Rdnss(option) => option.value(),
        }
    }

    pub fn ethernet_address(&self) -> Option<MacAddress> {
        match self {
            Self::SourceLinkLayerAddress(value) | Self::TargetLinkLayerAddress(value) => {
                <[u8; 6]>::try_from(value.as_ref()).ok().map(MacAddress)
            }
            _ => None,
        }
    }

    fn encode(&self, body: &mut Vec<u8>) -> Result<(), Error> {
        self.check()?;
        let value = self.value();
        let length = OPTION_HEADER_LENGTH
            .checked_add(value.len())
            .filter(|length| length % OPTION_UNIT == 0)
            .and_then(|length| u8::try_from(length / OPTION_UNIT).ok())
            .ok_or(Error::OptionLength {
                length: value.len(),
            })?;
        body.extend_from_slice(&[self.kind(), length]);
        body.extend_from_slice(&value);
        Ok(())
    }

    fn check(&self) -> Result<(), Error> {
        match self {
            Self::PrefixInformation(option) if option.reserved > PREFIX_RESERVED_MASK => {
                Err(field_range("prefix information reserved", option.reserved))
            }
            Self::RouteInformation(option) => {
                if option.preference > PREFERENCE_MASK {
                    return Err(field_range("route preference", option.preference));
                }
                if option.reserved & !ROUTE_RESERVED_MASK != 0 {
                    return Err(field_range("route information reserved", option.reserved));
                }
                // RFC 4191 ties the option's length to the prefix it carries.
                let Some(expected) = route_prefix_bytes(option.prefix_length) else {
                    return Err(field_range("route prefix length", option.prefix_length));
                };
                if option.prefix.len() != expected {
                    return Err(Error::OptionValue {
                        kind: ROUTE_INFORMATION,
                        length: option.prefix.len(),
                    });
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    /// Reads a typed option from `value`, the bytes after the header of an
    /// option `units` eight-octet units long. A layout the kind does not
    /// define is kept as the generic form.
    fn from_wire(kind: u8, units: u8, value: &[u8]) -> Self {
        let typed = match kind {
            SOURCE_LINK_LAYER_ADDRESS => {
                return Self::SourceLinkLayerAddress(Bytes::copy_from_slice(value));
            }
            TARGET_LINK_LAYER_ADDRESS => {
                return Self::TargetLinkLayerAddress(Bytes::copy_from_slice(value));
            }
            PREFIX_INFORMATION if units == PREFIX_INFORMATION_UNITS => {
                PrefixInformation::from_value(value).map(Self::PrefixInformation)
            }
            REDIRECTED_HEADER => RedirectedHeader::from_value(value).map(Self::RedirectedHeader),
            MTU if value.len() == MTU_VALUE => MtuOption::from_value(value).map(Self::Mtu),
            ROUTE_INFORMATION if matches!(units, 1..=3) => {
                RouteInformation::from_value(value).map(Self::RouteInformation)
            }
            RDNSS if units >= 3 && units % 2 == 1 => Rdnss::from_value(value).map(Self::Rdnss),
            _ => None,
        };
        typed.unwrap_or_else(|| Self::Other {
            kind,
            value: Bytes::copy_from_slice(value),
        })
    }
}

fn field_range(field: &'static str, value: impl Into<u64>) -> Error {
    Error::FieldRange {
        field,
        value: value.into(),
    }
}

/// The prefix byte count a Route Information option reserves for a prefix
/// length, or `None` when the length exceeds the option's wire layout.
fn route_prefix_bytes(prefix_length: u8) -> Option<usize> {
    match prefix_length {
        0 => Some(0),
        1..=64 => Some(8),
        65..=128 => Some(16),
        _ => None,
    }
}

impl PrefixInformation {
    fn from_value(value: &[u8]) -> Option<Self> {
        let value = value.first_chunk::<PREFIX_INFORMATION_VALUE>()?;
        Some(Self {
            prefix_length: value[0],
            on_link: value[1] & ON_LINK_FLAG != 0,
            autonomous: value[1] & AUTONOMOUS_FLAG != 0,
            router_address: value[1] & ROUTER_ADDRESS_FLAG != 0,
            reserved: value[1] & PREFIX_RESERVED_MASK,
            valid_lifetime: u32::from_be_bytes([value[2], value[3], value[4], value[5]]),
            preferred_lifetime: u32::from_be_bytes([value[6], value[7], value[8], value[9]]),
            reserved2: u32::from_be_bytes([value[10], value[11], value[12], value[13]]),
            prefix: Ipv6Addr::from(<[u8; 16]>::try_from(&value[14..]).ok()?),
        })
    }

    fn value(&self) -> Bytes {
        let flag = |set: bool, bit: u8| if set { bit } else { 0 };
        let flags = flag(self.on_link, ON_LINK_FLAG)
            | flag(self.autonomous, AUTONOMOUS_FLAG)
            | flag(self.router_address, ROUTER_ADDRESS_FLAG)
            | self.reserved;
        let mut value = Vec::with_capacity(PREFIX_INFORMATION_VALUE);
        value.extend_from_slice(&[self.prefix_length, flags]);
        value.extend_from_slice(&self.valid_lifetime.to_be_bytes());
        value.extend_from_slice(&self.preferred_lifetime.to_be_bytes());
        value.extend_from_slice(&self.reserved2.to_be_bytes());
        value.extend_from_slice(&self.prefix.octets());
        Bytes::from(value)
    }
}

impl RedirectedHeader {
    fn from_value(value: &[u8]) -> Option<Self> {
        let (reserved, packet) = value.split_first_chunk::<REDIRECTED_RESERVED_LENGTH>()?;
        Some(Self {
            reserved: *reserved,
            packet: Bytes::copy_from_slice(packet),
        })
    }

    fn value(&self) -> Bytes {
        let mut value = Vec::with_capacity(REDIRECTED_RESERVED_LENGTH + self.packet.len());
        value.extend_from_slice(&self.reserved);
        value.extend_from_slice(&self.packet);
        Bytes::from(value)
    }
}

impl MtuOption {
    fn from_value(value: &[u8]) -> Option<Self> {
        let value = value.first_chunk::<MTU_VALUE>()?;
        Some(Self {
            reserved: u16::from_be_bytes([value[0], value[1]]),
            mtu: u32::from_be_bytes([value[2], value[3], value[4], value[5]]),
        })
    }

    fn value(&self) -> Bytes {
        let mut value = Vec::with_capacity(MTU_VALUE);
        value.extend_from_slice(&self.reserved.to_be_bytes());
        value.extend_from_slice(&self.mtu.to_be_bytes());
        Bytes::from(value)
    }
}

impl RouteInformation {
    fn from_value(value: &[u8]) -> Option<Self> {
        let (fixed, prefix) = value.split_first_chunk::<ROUTE_FIXED_VALUE>()?;
        // Only a canonical layout decodes typed: a noncanonical option stays
        // generic so the message re-encodes to its captured bytes.
        if route_prefix_bytes(fixed[0]) != Some(prefix.len()) {
            return None;
        }
        Some(Self {
            prefix_length: fixed[0],
            preference: fixed[1] >> PREFERENCE_SHIFT & PREFERENCE_MASK,
            reserved: fixed[1] & ROUTE_RESERVED_MASK,
            route_lifetime: u32::from_be_bytes([fixed[2], fixed[3], fixed[4], fixed[5]]),
            prefix: Bytes::copy_from_slice(prefix),
        })
    }

    fn value(&self) -> Bytes {
        let flags = self.preference << PREFERENCE_SHIFT | self.reserved;
        let mut value = Vec::with_capacity(ROUTE_FIXED_VALUE + self.prefix.len());
        value.extend_from_slice(&[self.prefix_length, flags]);
        value.extend_from_slice(&self.route_lifetime.to_be_bytes());
        value.extend_from_slice(&self.prefix);
        Bytes::from(value)
    }
}

impl Rdnss {
    fn from_value(value: &[u8]) -> Option<Self> {
        let (fixed, servers) = value.split_first_chunk::<RDNSS_FIXED_VALUE>()?;
        let (servers, rest) = servers.as_chunks::<16>();
        if !rest.is_empty() {
            return None;
        }
        Some(Self {
            reserved: u16::from_be_bytes([fixed[0], fixed[1]]),
            lifetime: u32::from_be_bytes([fixed[2], fixed[3], fixed[4], fixed[5]]),
            servers: servers.iter().copied().map(Ipv6Addr::from).collect(),
        })
    }

    fn value(&self) -> Bytes {
        let mut value = Vec::with_capacity(
            RDNSS_FIXED_VALUE.saturating_add(self.servers.len().saturating_mul(16)),
        );
        value.extend_from_slice(&self.reserved.to_be_bytes());
        value.extend_from_slice(&self.lifetime.to_be_bytes());
        for server in &self.servers {
            value.extend_from_slice(&server.octets());
        }
        Bytes::from(value)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouterSolicitation {
    pub reserved: u32,
    pub options: Vec<MessageOption>,
}

impl RouterSolicitation {
    pub fn decode(body: &[u8]) -> Result<Self, Error> {
        let Some((reserved, rest)) = body.split_first_chunk::<ROUTER_SOLICITATION_LENGTH>() else {
            return Err(truncated_message(ROUTER_SOLICITATION_LENGTH, body.len()));
        };
        Ok(Self {
            reserved: u32::from_be_bytes(*reserved),
            options: decode_options(rest, ROUTER_SOLICITATION_LENGTH)?,
        })
    }

    pub fn encode(&self) -> Result<Bytes, Error> {
        let mut body = Vec::with_capacity(ROUTER_SOLICITATION_LENGTH);
        body.extend_from_slice(&self.reserved.to_be_bytes());
        encode_options(&mut body, &self.options)?;
        Ok(Bytes::from(body))
    }

    pub fn to_icmpv6(&self) -> Result<Icmpv6, Error> {
        Ok(icmpv6(ROUTER_SOLICITATION, self.encode()?))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouterAdvertisement {
    pub cur_hop_limit: u8,
    pub managed: bool,
    pub other: bool,
    pub home_agent: bool,
    /// The two default router preference bits.
    pub preference: u8,
    pub proxy: bool,
    /// The two reserved bits at the bottom of the flags octet.
    pub reserved: u8,
    pub router_lifetime: u16,
    pub reachable_time: u32,
    pub retrans_timer: u32,
    pub options: Vec<MessageOption>,
}

impl RouterAdvertisement {
    pub fn decode(body: &[u8]) -> Result<Self, Error> {
        let Some((fixed, rest)) = body.split_first_chunk::<ROUTER_ADVERTISEMENT_LENGTH>() else {
            return Err(truncated_message(ROUTER_ADVERTISEMENT_LENGTH, body.len()));
        };
        let flags = fixed[1];
        Ok(Self {
            cur_hop_limit: fixed[0],
            managed: flags & MANAGED_FLAG != 0,
            other: flags & OTHER_FLAG != 0,
            home_agent: flags & HOME_AGENT_FLAG != 0,
            preference: flags >> PREFERENCE_SHIFT & PREFERENCE_MASK,
            proxy: flags & PROXY_FLAG != 0,
            reserved: flags & ROUTER_RESERVED_MASK,
            router_lifetime: u16::from_be_bytes([fixed[2], fixed[3]]),
            reachable_time: u32::from_be_bytes([fixed[4], fixed[5], fixed[6], fixed[7]]),
            retrans_timer: u32::from_be_bytes([fixed[8], fixed[9], fixed[10], fixed[11]]),
            options: decode_options(rest, ROUTER_ADVERTISEMENT_LENGTH)?,
        })
    }

    pub fn encode(&self) -> Result<Bytes, Error> {
        if self.preference > PREFERENCE_MASK {
            return Err(field_range("router preference", self.preference));
        }
        if self.reserved > ROUTER_RESERVED_MASK {
            return Err(field_range("router advertisement reserved", self.reserved));
        }
        let flag = |set: bool, bit: u8| if set { bit } else { 0 };
        let flags = flag(self.managed, MANAGED_FLAG)
            | flag(self.other, OTHER_FLAG)
            | flag(self.home_agent, HOME_AGENT_FLAG)
            | self.preference << PREFERENCE_SHIFT
            | flag(self.proxy, PROXY_FLAG)
            | self.reserved;
        let mut body = Vec::with_capacity(ROUTER_ADVERTISEMENT_LENGTH);
        body.extend_from_slice(&[self.cur_hop_limit, flags]);
        body.extend_from_slice(&self.router_lifetime.to_be_bytes());
        body.extend_from_slice(&self.reachable_time.to_be_bytes());
        body.extend_from_slice(&self.retrans_timer.to_be_bytes());
        encode_options(&mut body, &self.options)?;
        Ok(Bytes::from(body))
    }

    pub fn to_icmpv6(&self) -> Result<Icmpv6, Error> {
        Ok(icmpv6(ROUTER_ADVERTISEMENT, self.encode()?))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Redirect {
    pub reserved: u32,
    pub target: Ipv6Addr,
    pub destination: Ipv6Addr,
    pub options: Vec<MessageOption>,
}

impl Redirect {
    pub fn decode(body: &[u8]) -> Result<Self, Error> {
        let Some((fixed, rest)) = body.split_first_chunk::<REDIRECT_LENGTH>() else {
            return Err(truncated_message(REDIRECT_LENGTH, body.len()));
        };
        let address = |start: usize| {
            let mut octets = [0; 16];
            octets.copy_from_slice(&fixed[start..start + 16]);
            Ipv6Addr::from(octets)
        };
        Ok(Self {
            reserved: u32::from_be_bytes([fixed[0], fixed[1], fixed[2], fixed[3]]),
            target: address(4),
            destination: address(20),
            options: decode_options(rest, REDIRECT_LENGTH)?,
        })
    }

    pub fn encode(&self) -> Result<Bytes, Error> {
        let mut body = Vec::with_capacity(REDIRECT_LENGTH);
        body.extend_from_slice(&self.reserved.to_be_bytes());
        body.extend_from_slice(&self.target.octets());
        body.extend_from_slice(&self.destination.octets());
        encode_options(&mut body, &self.options)?;
        Ok(Bytes::from(body))
    }

    pub fn to_icmpv6(&self) -> Result<Icmpv6, Error> {
        Ok(icmpv6(REDIRECT, self.encode()?))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NeighborSolicitation {
    pub reserved: u32,
    pub target: Ipv6Addr,
    pub options: Vec<MessageOption>,
}

impl NeighborSolicitation {
    pub fn decode(body: &[u8]) -> Result<Self, Error> {
        let (word, target, options) = decode_fixed(body)?;
        Ok(Self {
            reserved: word,
            target,
            options,
        })
    }

    pub fn encode(&self) -> Result<Bytes, Error> {
        encode_fixed(self.reserved, self.target, &self.options)
    }

    pub fn to_icmpv6(&self) -> Result<Icmpv6, Error> {
        Ok(icmpv6(NEIGHBOR_SOLICITATION, self.encode()?))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NeighborAdvertisement {
    pub router: bool,
    pub solicited: bool,
    pub override_address: bool,
    pub reserved: u32,
    pub target: Ipv6Addr,
    pub options: Vec<MessageOption>,
}

impl NeighborAdvertisement {
    pub fn decode(body: &[u8]) -> Result<Self, Error> {
        let (word, target, options) = decode_fixed(body)?;
        Ok(Self {
            router: word & ROUTER_FLAG != 0,
            solicited: word & SOLICITED_FLAG != 0,
            override_address: word & OVERRIDE_FLAG != 0,
            reserved: word & ADVERTISEMENT_RESERVED,
            target,
            options,
        })
    }

    pub fn encode(&self) -> Result<Bytes, Error> {
        if self.reserved > ADVERTISEMENT_RESERVED {
            return Err(Error::Reserved {
                value: self.reserved,
            });
        }
        let flag = |set: bool, bit: u32| if set { bit } else { 0 };
        let word = flag(self.router, ROUTER_FLAG)
            | flag(self.solicited, SOLICITED_FLAG)
            | flag(self.override_address, OVERRIDE_FLAG)
            | self.reserved;
        encode_fixed(word, self.target, &self.options)
    }

    pub fn to_icmpv6(&self) -> Result<Icmpv6, Error> {
        Ok(icmpv6(NEIGHBOR_ADVERTISEMENT, self.encode()?))
    }
}

pub fn solicited_node_multicast(target: Ipv6Addr) -> Ipv6Addr {
    const PREFIX: u128 = 0xff02_0000_0000_0000_0000_0001_ff00_0000;
    Ipv6Addr::from(PREFIX | (u128::from(target) & 0x00ff_ffff))
}

fn icmpv6(icmp_type: u8, body: Bytes) -> Icmpv6 {
    Icmpv6 {
        icmp_type,
        code: 0,
        checksum: WireValue::Auto,
        body,
    }
}

fn truncated_message(expected: usize, actual: usize) -> Error {
    Error::TruncatedMessage { expected, actual }
}

fn decode_fixed(body: &[u8]) -> Result<(u32, Ipv6Addr, Vec<MessageOption>), Error> {
    let Some((fixed, rest)) = body.split_first_chunk::<FIXED_LENGTH>() else {
        return Err(Error::Truncated { actual: body.len() });
    };
    let word = u32::from_be_bytes([fixed[0], fixed[1], fixed[2], fixed[3]]);
    let mut target = [0; 16];
    target.copy_from_slice(&fixed[4..]);
    let options = decode_options(rest, FIXED_LENGTH)?;
    Ok((word, Ipv6Addr::from(target), options))
}

/// `offset` is where `rest` starts in the message body.
fn decode_options(mut rest: &[u8], mut offset: usize) -> Result<Vec<MessageOption>, Error> {
    let mut options = Vec::new();
    while let Some(&[kind, units]) = rest.first_chunk::<OPTION_HEADER_LENGTH>() {
        let length = usize::from(units) * OPTION_UNIT;
        if length == 0 {
            return Err(Error::ZeroLengthOption { offset });
        }
        let Some((option, next)) = rest.split_at_checked(length) else {
            return Err(Error::OptionOverrun { offset });
        };
        options.push(MessageOption::from_wire(
            kind,
            units,
            &option[OPTION_HEADER_LENGTH..],
        ));
        offset += length;
        rest = next;
    }
    if !rest.is_empty() {
        return Err(Error::OptionOverrun { offset });
    }
    Ok(options)
}

fn encode_options(body: &mut Vec<u8>, options: &[MessageOption]) -> Result<(), Error> {
    for option in options {
        option.encode(body)?;
    }
    Ok(())
}

fn encode_fixed(word: u32, target: Ipv6Addr, options: &[MessageOption]) -> Result<Bytes, Error> {
    let mut body = Vec::with_capacity(FIXED_LENGTH);
    body.extend_from_slice(&word.to_be_bytes());
    body.extend_from_slice(&target.octets());
    encode_options(&mut body, options)?;
    Ok(Bytes::from(body))
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAC: MacAddress = MacAddress([0x02, 0, 0, 0, 0, 1]);

    fn target() -> Ipv6Addr {
        "2001:db8::abcd".parse().expect("target")
    }

    #[test]
    fn solicitation_body_carries_target_and_source_link_layer_option() {
        let solicitation = NeighborSolicitation {
            reserved: 0,
            target: target(),
            options: vec![MessageOption::source_link_layer(MAC)],
        };
        let body = solicitation.encode().expect("solicitation encodes");

        let mut expected = vec![0, 0, 0, 0];
        expected.extend_from_slice(&target().octets());
        expected.extend_from_slice(&[1, 1, 0x02, 0, 0, 0, 0, 1]);
        assert_eq!(body.as_ref(), expected);
        assert_eq!(NeighborSolicitation::decode(&body), Ok(solicitation));
    }

    #[test]
    fn advertisement_flags_reserved_bits_and_unknown_options_round_trip() {
        let mut body = vec![0b1010_0000, 0, 0x12, 0x34];
        body.extend_from_slice(&target().octets());
        body.extend_from_slice(&[2, 1, 0x02, 0, 0, 0, 0, 2]);
        body.extend_from_slice(&[99, 2, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14]);

        let advertisement = NeighborAdvertisement::decode(&body).expect("advertisement decodes");
        assert!(advertisement.router && !advertisement.solicited);
        assert!(advertisement.override_address);
        assert_eq!(advertisement.reserved, 0x1234);
        assert_eq!(
            advertisement.options[0].ethernet_address(),
            Some(MacAddress([0x02, 0, 0, 0, 0, 2]))
        );
        assert_eq!(advertisement.options[1].kind(), 99);
        assert_eq!(advertisement.options[1].value().len(), 14);
        assert_eq!(
            advertisement.encode().expect("re-encodes").as_ref(),
            body,
            "a decoded body re-encodes byte for byte"
        );
    }

    #[test]
    fn malformed_bodies_and_options_are_refused() {
        let mut body = vec![0x40, 0, 0, 0];
        body.extend_from_slice(&target().octets());
        assert_eq!(
            NeighborAdvertisement::decode(&body[..19]),
            Err(Error::Truncated { actual: 19 })
        );

        let mut zero_length = body.clone();
        zero_length.extend_from_slice(&[2, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(
            NeighborAdvertisement::decode(&zero_length),
            Err(Error::ZeroLengthOption { offset: 20 })
        );

        let mut overrun = body.clone();
        overrun.extend_from_slice(&[2, 2, 0, 0, 0, 0, 0, 0]);
        assert_eq!(
            NeighborAdvertisement::decode(&overrun),
            Err(Error::OptionOverrun { offset: 20 })
        );

        let mut dangling = body;
        dangling.push(2);
        assert_eq!(
            NeighborAdvertisement::decode(&dangling),
            Err(Error::OptionOverrun { offset: 20 })
        );
    }

    #[test]
    fn unencodable_values_are_refused() {
        let odd = NeighborSolicitation {
            reserved: 0,
            target: target(),
            options: vec![MessageOption::SourceLinkLayerAddress(Bytes::from_static(
                &[0; 5],
            ))],
        };
        assert_eq!(odd.encode(), Err(Error::OptionLength { length: 5 }));

        let oversized = NeighborAdvertisement {
            router: false,
            solicited: true,
            override_address: false,
            reserved: 1 << 29,
            target: target(),
            options: Vec::new(),
        };
        assert_eq!(oversized.encode(), Err(Error::Reserved { value: 1 << 29 }));
        let error = oversized.encode().expect_err("reserved overflow");
        assert_eq!(
            crate::error::Classified::classification(&error).code,
            "packet.codec"
        );
    }

    #[test]
    fn solicited_node_group_keeps_the_low_24_target_bits() {
        assert_eq!(
            solicited_node_multicast(target()),
            "ff02::1:ff00:abcd".parse::<Ipv6Addr>().expect("group")
        );
        assert_eq!(
            solicited_node_multicast("fe80::1234:5678:9abc:def0".parse().expect("target")),
            "ff02::1:ffbc:def0".parse::<Ipv6Addr>().expect("group")
        );
    }

    fn router_advertisement_bytes() -> Vec<u8> {
        // hop limit 64; M, O and proxy set, preference 0b10, reserved bits 0b11
        let mut body = vec![64, 0b1101_0111, 0x07, 0x08];
        body.extend_from_slice(&30_000_u32.to_be_bytes());
        body.extend_from_slice(&1_000_u32.to_be_bytes());
        // prefix information: /64, on-link and autonomous, reserved bits kept
        body.extend_from_slice(&[3, 4, 64, 0b1101_0101]);
        body.extend_from_slice(&86_400_u32.to_be_bytes());
        body.extend_from_slice(&14_400_u32.to_be_bytes());
        body.extend_from_slice(&0xdead_beef_u32.to_be_bytes());
        body.extend_from_slice(&"2001:db8:1::".parse::<Ipv6Addr>().expect("prefix").octets());
        body.extend_from_slice(&[5, 1, 0xab, 0xcd, 0, 0, 0x05, 0xdc]);
        body.extend_from_slice(&[25, 3, 0x12, 0x34]);
        body.extend_from_slice(&600_u32.to_be_bytes());
        body.extend_from_slice(&"2001:db8::53".parse::<Ipv6Addr>().expect("server").octets());
        // route information: /32, preference 0b11 with reserved bits either side
        body.extend_from_slice(&[24, 2, 32, 0b1111_1101]);
        body.extend_from_slice(&1_800_u32.to_be_bytes());
        body.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0]);
        body
    }

    #[test]
    fn router_advertisement_with_typed_options_round_trips_every_bit() {
        let body = router_advertisement_bytes();
        let advertisement = RouterAdvertisement::decode(&body).expect("advertisement decodes");

        assert_eq!(advertisement.cur_hop_limit, 64);
        assert!(advertisement.managed && advertisement.other && advertisement.proxy);
        assert!(!advertisement.home_agent);
        assert_eq!(advertisement.preference, 0b10);
        assert_eq!(advertisement.reserved, 0b11);
        assert_eq!(advertisement.router_lifetime, 0x0708);
        assert_eq!(advertisement.reachable_time, 30_000);
        assert_eq!(advertisement.retrans_timer, 1_000);
        assert_eq!(
            advertisement.options[0],
            MessageOption::PrefixInformation(PrefixInformation {
                prefix_length: 64,
                on_link: true,
                autonomous: true,
                router_address: false,
                reserved: 0b1_0101,
                valid_lifetime: 86_400,
                preferred_lifetime: 14_400,
                reserved2: 0xdead_beef,
                prefix: "2001:db8:1::".parse().expect("prefix"),
            })
        );
        assert_eq!(
            advertisement.options[1],
            MessageOption::Mtu(MtuOption {
                reserved: 0xabcd,
                mtu: 1500,
            })
        );
        assert_eq!(
            advertisement.options[2],
            MessageOption::Rdnss(Rdnss {
                reserved: 0x1234,
                lifetime: 600,
                servers: vec!["2001:db8::53".parse().expect("server")],
            })
        );
        let MessageOption::RouteInformation(route) = &advertisement.options[3] else {
            panic!("expected route information");
        };
        assert_eq!((route.prefix_length, route.preference), (32, 0b11));
        assert_eq!(route.reserved, 0b1110_0101);
        assert_eq!(route.prefix.len(), 8);

        assert_eq!(advertisement.encode().expect("re-encodes").as_ref(), body);
        let icmp = advertisement.to_icmpv6().expect("icmpv6");
        assert_eq!(icmp.icmp_type, ROUTER_ADVERTISEMENT);
        assert_eq!(icmp.body.as_ref(), body);
    }

    #[test]
    fn router_solicitation_and_redirect_round_trip_with_their_options() {
        let solicitation = RouterSolicitation {
            reserved: 0x0102_0304,
            options: vec![MessageOption::source_link_layer(MAC)],
        };
        let body = solicitation.encode().expect("solicitation encodes");
        assert_eq!(
            body.as_ref(),
            [1, 2, 3, 4, 1, 1, 0x02, 0, 0, 0, 0, 1].as_slice()
        );
        assert_eq!(RouterSolicitation::decode(&body), Ok(solicitation.clone()));
        assert_eq!(
            solicitation.to_icmpv6().expect("icmpv6").icmp_type,
            ROUTER_SOLICITATION
        );

        let redirect = Redirect {
            reserved: 0,
            target: "fe80::1".parse().expect("target"),
            destination: "2001:db8::99".parse().expect("destination"),
            options: vec![
                MessageOption::target_link_layer(MAC),
                MessageOption::RedirectedHeader(RedirectedHeader {
                    reserved: [0, 0, 0, 0, 0xaa, 0xbb],
                    packet: Bytes::from_static(&[0x60; 16]),
                }),
                MessageOption::Other {
                    kind: 99,
                    value: Bytes::from_static(&[7; 6]),
                },
            ],
        };
        let body = redirect.encode().expect("redirect encodes");
        assert_eq!(body.len(), REDIRECT_LENGTH + 8 + 24 + 8);
        let decoded = Redirect::decode(&body).expect("redirect decodes");
        assert_eq!(decoded, redirect);
        assert_eq!(decoded.options[2].kind(), 99);
        assert_eq!(redirect.to_icmpv6().expect("icmpv6").icmp_type, REDIRECT);
    }

    #[test]
    fn known_options_with_foreign_lengths_stay_generic() {
        // an MTU option two units long and an RDNSS option with a partial address
        let mut body = vec![0, 0, 0, 0];
        body.extend_from_slice(&[5, 2, 0, 0, 0, 0, 5, 220, 1, 1, 1, 1, 1, 1, 1, 1]);
        body.extend_from_slice(&[25, 2, 0, 0, 0, 0, 1, 44, 9, 9, 9, 9, 9, 9, 9, 9]);
        let solicitation = RouterSolicitation::decode(&body).expect("decodes");
        assert!(
            solicitation
                .options
                .iter()
                .all(|option| matches!(option, MessageOption::Other { .. }))
        );
        assert_eq!(solicitation.encode().expect("re-encodes").as_ref(), body);
    }

    #[test]
    fn router_messages_refuse_truncation_and_malformed_options() {
        assert_eq!(
            RouterSolicitation::decode(&[0; 3]),
            Err(Error::TruncatedMessage {
                expected: 4,
                actual: 3
            })
        );
        let body = router_advertisement_bytes();
        assert_eq!(
            RouterAdvertisement::decode(&body[..11]),
            Err(Error::TruncatedMessage {
                expected: 12,
                actual: 11
            })
        );
        assert_eq!(
            Redirect::decode(&[0; 35]),
            Err(Error::TruncatedMessage {
                expected: 36,
                actual: 35
            })
        );

        let mut zero_length = body[..12].to_vec();
        zero_length.extend_from_slice(&[5, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(
            RouterAdvertisement::decode(&zero_length),
            Err(Error::ZeroLengthOption { offset: 12 })
        );

        let mut overrun = vec![0; 4];
        overrun.extend_from_slice(&[24, 3, 0, 0, 0, 0, 0, 0]);
        assert_eq!(
            RouterSolicitation::decode(&overrun),
            Err(Error::OptionOverrun { offset: 4 })
        );

        let mut dangling = body[..12].to_vec();
        dangling.push(5);
        assert_eq!(
            RouterAdvertisement::decode(&dangling),
            Err(Error::OptionOverrun { offset: 12 })
        );
    }

    #[test]
    fn router_values_that_do_not_fit_their_bits_are_refused() {
        fn advertisement(edit: impl Fn(&mut RouterAdvertisement)) -> Result<Bytes, Error> {
            let mut advertisement =
                RouterAdvertisement::decode(&router_advertisement_bytes()).expect("decodes");
            edit(&mut advertisement);
            advertisement.encode()
        }
        assert_eq!(
            advertisement(|message| message.preference = 4),
            Err(Error::FieldRange {
                field: "router preference",
                value: 4
            })
        );
        assert_eq!(
            advertisement(|message| message.reserved = 4),
            Err(Error::FieldRange {
                field: "router advertisement reserved",
                value: 4
            })
        );
        assert_eq!(
            advertisement(|message| {
                let MessageOption::PrefixInformation(prefix) = &mut message.options[0] else {
                    unreachable!("first option is the prefix");
                };
                prefix.reserved = 0x20;
            }),
            Err(Error::FieldRange {
                field: "prefix information reserved",
                value: 0x20
            })
        );
        assert_eq!(
            advertisement(|message| {
                let MessageOption::RouteInformation(route) = &mut message.options[3] else {
                    unreachable!("last option is the route");
                };
                route.reserved = PREFERENCE_MASK << PREFERENCE_SHIFT;
            }),
            Err(Error::FieldRange {
                field: "route information reserved",
                value: 0x18
            })
        );
        assert_eq!(
            advertisement(|message| {
                let MessageOption::RouteInformation(route) = &mut message.options[3] else {
                    unreachable!("last option is the route");
                };
                route.prefix = Bytes::from_static(&[0; 5]);
            }),
            Err(Error::OptionValue {
                kind: ROUTE_INFORMATION,
                length: 5
            })
        );
        // the fixture's /32 carries eight prefix bytes; the declared width and
        // the bytes must agree on the RFC 4191 layout
        assert_eq!(
            advertisement(|message| {
                let MessageOption::RouteInformation(route) = &mut message.options[3] else {
                    unreachable!("last option is the route");
                };
                route.prefix_length = 129;
            }),
            Err(Error::FieldRange {
                field: "route prefix length",
                value: 129
            })
        );
        for (prefix_length, length) in [(0, 8), (64, 0), (65, 8), (32, 16)] {
            assert_eq!(
                advertisement(|message| {
                    let MessageOption::RouteInformation(route) = &mut message.options[3] else {
                        unreachable!("last option is the route");
                    };
                    route.prefix_length = prefix_length;
                    route.prefix = Bytes::from(vec![0; length]);
                }),
                Err(Error::OptionValue {
                    kind: ROUTE_INFORMATION,
                    length
                })
            );
        }
    }

    #[test]
    fn noncanonical_route_options_stay_generic_and_reencode() {
        let route = |prefix_length: u8, width: usize| {
            let mut value = vec![prefix_length, 0x10];
            value.extend_from_slice(&7u32.to_be_bytes());
            value.extend_from_slice(&vec![0xAB; width]);
            let units = u8::try_from((value.len() + OPTION_HEADER_LENGTH) / OPTION_UNIT)
                .expect("route option units");
            (
                MessageOption::from_wire(ROUTE_INFORMATION, units, &value),
                Bytes::from(value),
            )
        };
        // A declared width that agrees with its prefix length decodes typed.
        for (prefix_length, width) in [(0, 0), (1, 8), (64, 8), (65, 16), (128, 16)] {
            let (option, _) = route(prefix_length, width);
            assert!(
                matches!(option, MessageOption::RouteInformation(_)),
                "{prefix_length}/{width} decodes typed: {option:?}"
            );
        }
        // Any other layout, including an out-of-range prefix length, stays
        // generic and carries its bytes back out unchanged.
        for (prefix_length, width) in [(0, 8), (64, 0), (65, 8), (32, 16), (129, 16)] {
            let (option, value) = route(prefix_length, width);
            match option {
                MessageOption::Other { kind, value: kept } => {
                    assert_eq!(kind, ROUTE_INFORMATION);
                    assert_eq!(kept, value, "{prefix_length}/{width} keeps its bytes");
                }
                _ => panic!("{prefix_length}/{width} stays generic: {option:?}"),
            }
        }
    }
}
