// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded DHCP fixture construction and lossless option inspection.
//! This module performs no address configuration, discovery, or server workflow.
//!
//! DHCPv4 and DHCPv6 each keep their model, codec, and reflection in `v4`
//! and `v6`; both share [`Limits`], [`Error`], and the codec helpers in `codec`.

mod codec;
mod v4;
mod v6;

pub(crate) use v4::Dhcpv4Codec;
pub use v4::{Dhcpv4, Option4, Value4};
pub(crate) use v6::Dhcpv6Codec;
pub use v6::{Dhcpv6, Duid, Option6, Value6};

#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub max_message_bytes: usize,
    pub max_options: usize,
    pub max_nesting: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_message_bytes: 65_535,
            max_options: 512,
            max_nesting: 8,
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("DHCP exceeds {0} limit")]
    Limit(Limit),
    #[error("DHCP truncated at byte {offset}: need {needed}, have {available}")]
    Truncated {
        offset: usize,
        needed: usize,
        available: usize,
    },
    #[error("invalid DHCP value: {0}")]
    Invalid(&'static str),
}
/// The DHCP bound an [`Error::Limit`] exceeds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Limit {
    MessageBytes,
    EncodedBytes,
    OptionCount,
    OptionNesting,
    RelayNesting,
    DuidBytes,
    Ipv4OptionAddresses,
    Dhcpv4OptionBytes,
    Dhcpv6OptionBytes,
}

impl std::fmt::Display for Limit {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::MessageBytes => "message bytes",
            Self::EncodedBytes => "encoded bytes",
            Self::OptionCount => "option count",
            Self::OptionNesting => "option nesting",
            Self::RelayNesting => "relay nesting",
            Self::DuidBytes => "DUID bytes",
            Self::Ipv4OptionAddresses => "IPv4 option addresses",
            Self::Dhcpv4OptionBytes => "DHCPv4 option bytes",
            Self::Dhcpv6OptionBytes => "DHCPv6 option bytes",
        })
    }
}

impl crate::error::Classified for Error {
    fn classification(&self) -> crate::error::Classification {
        use crate::error::{Classification, Kind};
        match self {
            Self::Limit(_) => Classification::new("policy.dhcp_limit", Kind::Policy, None),
            _ => Classification::new("packet.dhcp", Kind::Packet, None),
        }
    }
}
