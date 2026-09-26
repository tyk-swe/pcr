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
//! - [`rewrite()`] and [`fragment()`] locate the link, VLAN, and IP headers with
//!   the shared [`protocol::headers`](crate::protocol::headers) walker.
//!
//! Every byte-level edit says which faithfulness gap it avoids.

mod error;
mod fields;
mod fragment;
mod rewrite;
pub use error::{Error, InvalidInput, Limit, Unsupported};
pub use fields::{
    ChangeOrigin, ChecksumMode, FieldAssignment, FieldChange, FieldEdit, FieldEditOutcome,
    FieldEdits, MAX_FIELD_ASSIGNMENTS,
};
pub use fragment::{FragmentOptions, fragment};
pub use rewrite::{HeaderRewrite, RewriteLimits, VlanRewrite, rewrite};

use crate::protocol::headers::IpHeader;
use crate::protocol::network::ip_protocol;

/// Refuses a datagram whose transport pseudo-header an in-place edit cannot
/// recompute. An incomplete fragment hides the rest of the segment, and IPv4
/// source routing, an IPv6 routing header, or a Home Address option changes
/// which addresses the pseudo-header covers.
fn ensure_checksum_coverage(ip: &[u8], header: &IpHeader) -> Result<(), Error> {
    const LOOSE_SOURCE_ROUTE: u8 = 131;
    const STRICT_SOURCE_ROUTE: u8 = 137;
    const HOME_ADDRESS: u8 = 201;
    if header.is_fragment() {
        return Err(Error::Unsupported(Unsupported::ChecksumOverFragment));
    }
    match header {
        IpHeader::V4(ipv4) => {
            for option in ipv4.options(ip) {
                if matches!(option?.kind, LOOSE_SOURCE_ROUTE | STRICT_SOURCE_ROUTE) {
                    return Err(Error::Unsupported(Unsupported::Ipv4SourceRoute));
                }
            }
        }
        IpHeader::V6(ipv6) => {
            for extension in ipv6.extensions() {
                if extension.protocol() == ip_protocol::ROUTING {
                    return Err(Error::Unsupported(Unsupported::Ipv6RoutingHeader));
                }
                for option in extension.options(ip) {
                    if option?.kind == HOME_ADDRESS {
                        return Err(Error::Unsupported(Unsupported::Ipv6HomeAddress));
                    }
                }
            }
        }
    }
    Ok(())
}
