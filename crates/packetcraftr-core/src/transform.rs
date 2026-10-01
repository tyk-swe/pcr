// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Explicit, bounded transformations of complete packet bytes.

mod address_map;
mod error;
mod fields;
mod fragment;
mod rewrite;
pub mod rules;
pub use address_map::{AddressMap, IpMapping, MAX_ADDRESS_MAP_ENTRIES, MacMapping};
pub use error::{Error, InvalidInput, Limit, Unsupported};
pub use fields::{
    ChangeOrigin, ChecksumMode, FieldAssignment, FieldChange, FieldEditOutcome, FieldEdits,
    MAX_FIELD_ASSIGNMENTS,
};
pub use fragment::{FragmentOptions, fragment, fragment_link_type};
pub use rewrite::{HeaderRewrite, RewriteLimits, VlanRewrite, rewrite};

use std::net::IpAddr;
use std::ops::Range;

use crate::protocol::headers::IpHeader;
use crate::protocol::network::ip_protocol;
use crate::protocol::{network_from_addresses, transport_checksum};

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

/// Recomputes the checksum at `field` over `segment`, the exact covered bytes,
/// and returns the value written. An IPv4 UDP checksum of zero stays disabled
/// and returns `None`.
fn repair_checksum(
    segment: &mut [u8],
    field: Range<usize>,
    protocol: u8,
    name: &'static str,
    (source, destination): (IpAddr, IpAddr),
) -> Result<Option<u16>, Error> {
    let udp = protocol == ip_protocol::UDP;
    if udp && source.is_ipv4() && segment[field.clone()] == [0, 0] {
        return Ok(None);
    }
    segment[field.clone()].fill(0);
    let mut value = transport_checksum(
        name,
        network_from_addresses(source, destination),
        protocol,
        segment,
    )
    .map_err(Error::Checksum)?;
    if udp && value == 0 {
        value = 0xffff;
    }
    segment[field].copy_from_slice(&value.to_be_bytes());
    Ok(Some(value))
}
