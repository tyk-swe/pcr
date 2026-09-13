// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded DHCP fixture construction and lossless option inspection.
//! This module performs no address configuration, discovery, or server workflow.
mod codec;
mod v4;
mod v6;
pub(crate) use codec::{Dhcpv4Codec, Dhcpv6Codec};
pub use v4::{Dhcpv4, Option4, Value4};
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
    Limit(&'static str),
    #[error("DHCP truncated at byte {offset}: need {needed}, have {available}")]
    Truncated {
        offset: usize,
        needed: usize,
        available: usize,
    },
    #[error("invalid DHCP value: {0}")]
    Invalid(&'static str),
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
struct Budget {
    limits: Limits,
    options: usize,
}
impl Budget {
    fn new(limits: Limits, length: usize) -> Result<Self, Error> {
        let limits = Limits {
            max_message_bytes: limits.max_message_bytes.min(65_535),
            max_options: limits.max_options.min(4096),
            max_nesting: limits.max_nesting.min(8),
        };
        if length > limits.max_message_bytes {
            return Err(Error::Limit("message bytes"));
        }
        Ok(Self { limits, options: 0 })
    }
    fn option(&mut self, depth: usize) -> Result<(), Error> {
        if depth > self.limits.max_nesting {
            return Err(Error::Limit("option nesting"));
        }
        if self.options >= self.limits.max_options {
            return Err(Error::Limit("option count"));
        }
        self.options += 1;
        Ok(())
    }
}
fn take(bytes: &[u8], offset: usize, length: usize) -> Result<&[u8], Error> {
    bytes
        .get(offset..offset.saturating_add(length))
        .ok_or(Error::Truncated {
            offset,
            needed: length,
            available: bytes.len().saturating_sub(offset),
        })
}
fn u16_at(bytes: &[u8], offset: usize) -> Result<u16, Error> {
    Ok(u16::from_be_bytes(
        take(bytes, offset, 2)?.try_into().expect("two bytes"),
    ))
}
fn u32_at(bytes: &[u8], offset: usize) -> Result<u32, Error> {
    Ok(u32::from_be_bytes(
        take(bytes, offset, 4)?.try_into().expect("four bytes"),
    ))
}
fn extend(output: &mut Vec<u8>, bytes: &[u8], maximum: usize) -> Result<(), Error> {
    if output.len().saturating_add(bytes.len()) > maximum {
        return Err(Error::Limit("encoded bytes"));
    }
    output.extend_from_slice(bytes);
    Ok(())
}
