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

/// Largest accepted [`Limits::max_message_bytes`]: one UDP payload.
pub const MAX_MESSAGE_BYTES: usize = 65_535;
/// Largest accepted [`Limits::max_options`].
pub const MAX_OPTIONS: usize = 4_096;
/// Largest accepted [`Limits::max_nesting`].
pub const MAX_NESTING: usize = 8;

/// Ceilings for decoding or encoding one DHCP message. Each is at most its
/// `MAX_*` constant; [`Limits::validate`] refuses a larger one rather than
/// lowering it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// At most [`MAX_MESSAGE_BYTES`].
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
    /// Rejects a ceiling above its `MAX_*` constant.
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
    /// A configured [`Limits`] field above its ceiling.
    #[error("DHCP {limit} limit {value} exceeds the maximum of {maximum}")]
    InvalidLimit {
        limit: Limit,
        value: usize,
        maximum: usize,
    },
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
            Self::Limit(_) | Self::InvalidLimit { .. } => {
                Classification::new("policy.dhcp_limit", Kind::Policy, None)
            }
            _ => Classification::new("packet.dhcp", Kind::Packet, None),
        }
    }
}
