// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Neighbor Discovery (RFC 4861) solicitation and advertisement messages.
//!
//! The [`Icmpv6`] layer keeps its body verbatim. These models type the body
//! of a Neighbor Solicitation or Neighbor Advertisement and its options, so
//! neighbor discovery builds and checks them without hand-written bytes.
//! They are not registered layers: dissection still reports an NDP message
//! as an ICMPv6 layer with an opaque body, and these models read or produce
//! that body.
//!
//! Decoding keeps every wire value: reserved bits, option order, and options
//! of unknown kind. Encoding a decoded message reproduces its body byte for
//! byte.
//!
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

/// ICMPv6 type of a Neighbor Solicitation.
pub const NEIGHBOR_SOLICITATION: u8 = 135;
/// ICMPv6 type of a Neighbor Advertisement.
pub const NEIGHBOR_ADVERTISEMENT: u8 = 136;
/// Option kind of a Source Link-Layer Address option.
pub const SOURCE_LINK_LAYER_ADDRESS: u8 = 1;
/// Option kind of a Target Link-Layer Address option.
pub const TARGET_LINK_LAYER_ADDRESS: u8 = 2;

/// Bytes of a solicitation or advertisement body before its options: the
/// flags or reserved word and the target address.
const FIXED_LENGTH: usize = 20;
/// Options are sized in units of eight octets.
const OPTION_UNIT: usize = 8;
/// An option's kind and length octets.
const OPTION_HEADER_LENGTH: usize = 2;
const ROUTER_FLAG: u32 = 1 << 31;
const SOLICITED_FLAG: u32 = 1 << 30;
const OVERRIDE_FLAG: u32 = 1 << 29;
/// The advertisement bits after its three flags.
const ADVERTISEMENT_RESERVED: u32 = OVERRIDE_FLAG - 1;

/// A solicitation or advertisement body the codec cannot read or write.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("NDP message body is {actual} bytes; expected at least {FIXED_LENGTH}")]
    Truncated { actual: usize },
    #[error("NDP option at body byte {offset} has zero length")]
    ZeroLengthOption { offset: usize },
    #[error("NDP option at body byte {offset} runs past the end of the message")]
    OptionOverrun { offset: usize },
    /// An option's kind, length, and value must fill whole eight-octet units,
    /// at most 255 of them.
    #[error("NDP option value of {length} bytes does not fill whole 8-octet units")]
    OptionLength { length: usize },
    #[error("NDP advertisement reserved bits {value:#x} do not fit in 29 bits")]
    Reserved { value: u32 },
}

/// One Neighbor Discovery option, with its value after the kind and length
/// octets.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MessageOption {
    /// The sender's link-layer address, padded to whole option units.
    SourceLinkLayerAddress(Bytes),
    /// The advertised target's link-layer address, padded to whole option
    /// units.
    TargetLinkLayerAddress(Bytes),
    /// An option of any other kind, kept verbatim.
    Other { kind: u8, value: Bytes },
}

impl MessageOption {
    /// A Source Link-Layer Address option carrying an Ethernet address.
    pub fn source_link_layer(address: MacAddress) -> Self {
        Self::SourceLinkLayerAddress(Bytes::copy_from_slice(&address.0))
    }

    /// A Target Link-Layer Address option carrying an Ethernet address.
    pub fn target_link_layer(address: MacAddress) -> Self {
        Self::TargetLinkLayerAddress(Bytes::copy_from_slice(&address.0))
    }

    /// The option kind octet.
    pub fn kind(&self) -> u8 {
        match self {
            Self::SourceLinkLayerAddress(_) => SOURCE_LINK_LAYER_ADDRESS,
            Self::TargetLinkLayerAddress(_) => TARGET_LINK_LAYER_ADDRESS,
            Self::Other { kind, .. } => *kind,
        }
    }

    /// The option value after the kind and length octets.
    pub fn value(&self) -> &Bytes {
        match self {
            Self::SourceLinkLayerAddress(value)
            | Self::TargetLinkLayerAddress(value)
            | Self::Other { value, .. } => value,
        }
    }

    /// The Ethernet address a link-layer address option carries: `None` for
    /// other options and for values that are not exactly six bytes, which is
    /// the one-unit option RFC 2464 defines for Ethernet.
    pub fn ethernet_address(&self) -> Option<MacAddress> {
        match self {
            Self::SourceLinkLayerAddress(value) | Self::TargetLinkLayerAddress(value) => {
                <[u8; 6]>::try_from(value.as_ref()).ok().map(MacAddress)
            }
            Self::Other { .. } => None,
        }
    }

    fn encode(&self, body: &mut Vec<u8>) -> Result<(), Error> {
        let value = self.value();
        let length = OPTION_HEADER_LENGTH
            .checked_add(value.len())
            .filter(|length| length % OPTION_UNIT == 0)
            .and_then(|length| u8::try_from(length / OPTION_UNIT).ok())
            .ok_or(Error::OptionLength {
                length: value.len(),
            })?;
        body.extend_from_slice(&[self.kind(), length]);
        body.extend_from_slice(value);
        Ok(())
    }
}

/// A Neighbor Solicitation body (ICMPv6 type 135).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NeighborSolicitation {
    pub reserved: u32,
    pub target: Ipv6Addr,
    pub options: Vec<MessageOption>,
}

impl NeighborSolicitation {
    /// Reads a solicitation from an ICMPv6 body.
    pub fn decode(body: &[u8]) -> Result<Self, Error> {
        let (word, target, options) = decode_fixed(body)?;
        Ok(Self {
            reserved: word,
            target,
            options,
        })
    }

    /// The ICMPv6 body.
    pub fn encode(&self) -> Result<Bytes, Error> {
        encode_fixed(self.reserved, self.target, &self.options)
    }

    /// An ICMPv6 layer of type 135 and code 0 carrying this body, with the
    /// checksum left for the builder to compute.
    pub fn to_icmpv6(&self) -> Result<Icmpv6, Error> {
        Ok(icmpv6(NEIGHBOR_SOLICITATION, self.encode()?))
    }
}

/// A Neighbor Advertisement body (ICMPv6 type 136).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NeighborAdvertisement {
    pub router: bool,
    pub solicited: bool,
    pub override_address: bool,
    /// The 29 bits after the three flags.
    pub reserved: u32,
    pub target: Ipv6Addr,
    pub options: Vec<MessageOption>,
}

impl NeighborAdvertisement {
    /// Reads an advertisement from an ICMPv6 body.
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

    /// The ICMPv6 body.
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

    /// An ICMPv6 layer of type 136 and code 0 carrying this body, with the
    /// checksum left for the builder to compute.
    pub fn to_icmpv6(&self) -> Result<Icmpv6, Error> {
        Ok(icmpv6(NEIGHBOR_ADVERTISEMENT, self.encode()?))
    }
}

/// The solicited-node multicast group (RFC 4291 section 2.7.1) a Neighbor
/// Solicitation for `target` is sent to: `ff02::1:ff00:0/104` plus the low
/// 24 bits of the target.
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

fn decode_fixed(body: &[u8]) -> Result<(u32, Ipv6Addr, Vec<MessageOption>), Error> {
    let Some((fixed, mut rest)) = body.split_first_chunk::<FIXED_LENGTH>() else {
        return Err(Error::Truncated { actual: body.len() });
    };
    let word = u32::from_be_bytes([fixed[0], fixed[1], fixed[2], fixed[3]]);
    let mut target = [0; 16];
    target.copy_from_slice(&fixed[4..]);
    let mut options = Vec::new();
    let mut offset = FIXED_LENGTH;
    while let Some(&[kind, units]) = rest.first_chunk::<OPTION_HEADER_LENGTH>() {
        let length = usize::from(units) * OPTION_UNIT;
        if length == 0 {
            return Err(Error::ZeroLengthOption { offset });
        }
        let Some((option, next)) = rest.split_at_checked(length) else {
            return Err(Error::OptionOverrun { offset });
        };
        let value = Bytes::copy_from_slice(&option[OPTION_HEADER_LENGTH..]);
        options.push(match kind {
            SOURCE_LINK_LAYER_ADDRESS => MessageOption::SourceLinkLayerAddress(value),
            TARGET_LINK_LAYER_ADDRESS => MessageOption::TargetLinkLayerAddress(value),
            kind => MessageOption::Other { kind, value },
        });
        offset += length;
        rest = next;
    }
    if !rest.is_empty() {
        return Err(Error::OptionOverrun { offset });
    }
    Ok((word, Ipv6Addr::from(target), options))
}

fn encode_fixed(word: u32, target: Ipv6Addr, options: &[MessageOption]) -> Result<Bytes, Error> {
    let mut body = Vec::with_capacity(FIXED_LENGTH);
    body.extend_from_slice(&word.to_be_bytes());
    body.extend_from_slice(&target.octets());
    for option in options {
        option.encode(&mut body)?;
    }
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
}
