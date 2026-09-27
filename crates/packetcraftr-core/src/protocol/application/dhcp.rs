// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! This module performs no address configuration, discovery, or server workflow.

mod codec;
mod v4;
mod v6;

pub(crate) use v4::Dhcpv4Codec;
pub use v4::{Dhcpv4, Option4, Value4};
pub(crate) use v6::Dhcpv6Codec;
pub use v6::{Dhcpv6, Duid, Option6, Value6};

pub const MAX_MESSAGE_BYTES: usize = 65_535;
pub const MAX_OPTIONS: usize = 4_096;
pub const MAX_NESTING: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    pub max_message_bytes: usize,
    /// Options counted across every nesting level, at most [`MAX_OPTIONS`].
    pub max_options: usize,
    /// Encapsulated option and relay depth, at most [`MAX_NESTING`].
    pub max_nesting: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_message_bytes: MAX_MESSAGE_BYTES,
            max_options: 512,
            max_nesting: MAX_NESTING,
        }
    }
}
impl Limits {
    pub fn validate(&self) -> Result<(), Error> {
        for (limit, value, maximum) in [
            (
                Limit::MessageBytes,
                self.max_message_bytes,
                MAX_MESSAGE_BYTES,
            ),
            (Limit::OptionCount, self.max_options, MAX_OPTIONS),
            (Limit::OptionNesting, self.max_nesting, MAX_NESTING),
        ] {
            if value > maximum {
                return Err(Error::InvalidLimit {
                    limit,
                    value,
                    maximum,
                });
            }
        }
        Ok(())
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
    #[error("DHCP {limit} limit {value} exceeds the maximum of {maximum}")]
    InvalidLimit {
        limit: Limit,
        value: usize,
        maximum: usize,
    },
}
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
            Self::Limit(_) | Self::InvalidLimit { .. } => {
                Classification::new("policy.dhcp_limit", Kind::Policy, None)
            }
            _ => Classification::new("packet.dhcp", Kind::Packet, None),
        }
    }
}
