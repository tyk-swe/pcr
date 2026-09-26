// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Explicit, bounded transformations of complete packet bytes.

mod fields;
mod fragment;
mod rewrite;
pub use fields::{
    ChangeOrigin, ChecksumMode, FieldAssignment, FieldChange, FieldEdit, FieldEditOutcome,
    FieldEdits, MAX_FIELD_ASSIGNMENTS,
};
pub use fragment::{FragmentOptions, fragment};
pub use rewrite::{HeaderRewrite, RewriteLimits, VlanRewrite, rewrite};

use crate::error::{Classification, Classified, Kind};

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("invalid packet transform input: {0}")]
    Invalid(&'static str),
    #[error("unsupported packet transform: {0}")]
    Unsupported(&'static str),
    #[error("packet transform exceeds {field}={limit}")]
    Limit { field: &'static str, limit: usize },
    #[error(transparent)]
    Frame(#[from] crate::frame::Error),
    #[error(transparent)]
    Decode(#[from] crate::decode::Error),
    #[error("packet transform checksum failed")]
    Checksum(#[source] crate::codec::Error),
}

impl Classified for Error {
    fn classification(&self) -> Classification {
        match self {
            Self::Frame(source) => source.classification(),
            Self::Decode(source) => source.classification(),
            Self::Invalid(_) => Classification::new(
                "packet.transform_input",
                Kind::Packet,
                Some("supply a complete supported datagram"),
            ),
            Self::Unsupported(_) => Classification::new(
                "packet.transform_unsupported",
                Kind::Packet,
                Some("inspect the documented transform boundaries"),
            ),
            Self::Limit { .. } => Classification::new(
                "policy.transform_limit",
                Kind::Policy,
                Some("raise a finite transform limit or reduce the input"),
            ),
            Self::Checksum(_) => Classification::new(
                "packet.transform_checksum",
                Kind::Packet,
                Some("supply a complete datagram the checksum can cover"),
            ),
        }
    }
}

/// Skips 802.1Q/802.1ad tags after the Ethernet addresses, returning the
/// payload offset and its EtherType. `u16_at` bounds-checks each read, so every
/// caller keeps its own truncation error.
fn ethernet_payload(
    bytes: &[u8],
    u16_at: fn(&[u8], usize) -> Result<u16, Error>,
) -> Result<(usize, u16), Error> {
    let mut offset = 14;
    let mut kind = u16_at(bytes, 12)?;
    let mut vlans = 0;
    while matches!(kind, 0x8100 | 0x88a8) {
        if vlans >= 64 {
            return Err(Error::Limit {
                field: "VLAN depth",
                limit: 64,
            });
        }
        kind = u16_at(bytes, offset + 2)?;
        offset += 4;
        vlans += 1;
    }
    Ok((offset, kind))
}
