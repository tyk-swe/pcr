// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Explicit, bounded transformations of complete packet bytes.
//!
//! Transforms take captured frames, whose bytes a codec round trip does not
//! reproduce in general: malformed and unknown bytes, link trailers,
//! non-canonical option and length encodings, and stale checksums in layers
//! the edit does not touch would all be re-encoded. So, per ADR 0004, no
//! transform re-encodes a frame. Each one copies the captured bytes and
//! changes only the bytes its edit names:
//!
//! - [`FieldEdits`] locates fields through the codecs' decoded layout.
//! - [`rewrite`] and [`fragment`] locate the link, VLAN, and IP headers with
//!   the shared [`protocol::headers`](crate::protocol::headers) walker.
//!
//! Every byte-level edit says which faithfulness gap it avoids.

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
use crate::protocol::headers::{self, IpHeader};
use crate::protocol::network::ip_protocol;

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
    /// The link, VLAN, or IP headers the transform edits could not be walked.
    #[error(transparent)]
    Header(#[from] headers::Error),
}

impl Classified for Error {
    fn classification(&self) -> Classification {
        match self {
            Self::Frame(source) => source.classification(),
            Self::Decode(source) => source.classification(),
            Self::Header(source) => source.classification(),
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
            Self::Invalid(_) => Classification::new(
                "packet.transform_input",
                Kind::Packet,
                Some("supply a complete supported datagram"),
            ),
            Self::Checksum(_) => Classification::new(
                "packet.transform_checksum",
                Kind::Packet,
                Some("supply a complete datagram the checksum can cover"),
            ),
        }
    }
}

/// Refuses a datagram whose transport pseudo-header an in-place edit cannot
/// recompute. An incomplete fragment hides the rest of the segment, and IPv4
/// source routing, an IPv6 routing header, or a Home Address option changes
/// which addresses the pseudo-header covers.
fn ensure_checksum_coverage(ip: &[u8], header: &IpHeader) -> Result<(), Error> {
    const LOOSE_SOURCE_ROUTE: u8 = 131;
    const STRICT_SOURCE_ROUTE: u8 = 137;
    const HOME_ADDRESS: u8 = 201;
    if header.is_fragment() {
        return Err(Error::Unsupported(
            "checksum-covered edits require a reassembled datagram",
        ));
    }
    match header {
        IpHeader::V4(ipv4) => {
            for option in ipv4.options(ip) {
                if matches!(option?.kind, LOOSE_SOURCE_ROUTE | STRICT_SOURCE_ROUTE) {
                    return Err(Error::Unsupported(
                        "IPv4 source routing changes checksum destinations",
                    ));
                }
            }
        }
        IpHeader::V6(ipv6) => {
            for extension in ipv6.extensions() {
                if extension.protocol() == ip_protocol::ROUTING {
                    return Err(Error::Unsupported(
                        "IPv6 routing header changes checksum destinations",
                    ));
                }
                for option in extension.options(ip) {
                    if option?.kind == HOME_ADDRESS {
                        return Err(Error::Unsupported(
                            "IPv6 Home Address option changes checksum sources",
                        ));
                    }
                }
            }
        }
    }
    Ok(())
}
