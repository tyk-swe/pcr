// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Network-layer protocol models.

mod envelope;
mod igmp;
mod ipv4;
mod ipv6;
mod raw_ip;

/// IANA IP protocol numbers that codecs and analyzers refer to by name.
pub mod ip_protocol {
    pub const HOP_BY_HOP: u8 = 0;
    pub const TCP: u8 = 6;
    pub const UDP: u8 = 17;
    pub const ROUTING: u8 = 43;
    pub const FRAGMENT: u8 = 44;
    pub const AH: u8 = 51;
    pub const DESTINATION_OPTIONS: u8 = 60;
}

pub(crate) use envelope::{
    ipv6_extension_header_length, is_walkable_ipv6_extension, resolve_envelope,
};
pub use igmp::Igmp;
pub(crate) use igmp::IgmpCodec;
pub use ipv4::Ipv4;
pub(crate) use ipv4::Ipv4Codec;
pub use ipv6::Ipv6;
pub(crate) use ipv6::Ipv6Codec;
pub(crate) use raw_ip::RawIpCodec;
