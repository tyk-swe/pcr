// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Built-in codec and capture-root capability information.
//!
//! [`BUILTIN_PROTOCOLS`] distinguishes construction, dissection, exact round
//! trips, response matching, and decode-only support. [`BUILTIN_CAPTURE_ROOTS`]
//! lists the default registry's numeric capture bindings.

use crate::protocol::BuiltinProtocol;
use crate::protocol_catalog::builtin_protocol_catalog;

/// One built-in codec row in the stable protocol contract.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Protocol {
    pub protocol: &'static str,
    pub aliases: &'static [&'static str],
    pub build: bool,
    pub dissect: bool,
    /// Whether encoding a decoded layer reproduces its wire bytes exactly.
    /// False for a codec that cannot encode at all.
    pub exact_round_trip: bool,
    pub matcher: bool,
    pub decode_only: bool,
}

/// One numeric DLT/LINKTYPE binding in the default registry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CaptureRoot {
    pub link_type: u32,
    pub protocol: &'static str,
}

macro_rules! define_protocol_support {
    ($(
        $variant:ident {
            canonical: $canonical:literal,
            aliases: [$($alias:literal),* $(,)?],
            constructible: $constructible:literal,
            exact_round_trip: $exact_round_trip:literal,
            matcher: $matcher:ident,
            codec: $codec:ident
        }
    )*) => {
        /// Every codec registered by [`crate::protocol::builtin::registry`], in
        /// stable manifest order.
        pub const BUILTIN_PROTOCOLS: &[Protocol] = &[$(
            Protocol {
                protocol: $canonical,
                aliases: &[$($alias),*],
                build: $constructible,
                dissect: true,
                exact_round_trip: $exact_round_trip,
                matcher: BuiltinProtocol::$variant.has_matcher(),
                decode_only: !$constructible,
            }
        ),*];
    };
}

builtin_protocol_catalog!(define_protocol_support);

const fn capture_root(link_type: u32, protocol: BuiltinProtocol) -> CaptureRoot {
    CaptureRoot {
        link_type,
        protocol: protocol.as_str(),
    }
}

/// Every numeric capture root registered by the default built-in module.
///
/// Capture topology remains separate from identity metadata, but every edge is
/// typed so a protocol rename cannot silently leave a string binding behind.
pub const BUILTIN_CAPTURE_ROOTS: &[CaptureRoot] = &[
    capture_root(crate::frame::LinkType::NULL.0, BuiltinProtocol::BsdNull),
    capture_root(
        crate::frame::LinkType::ETHERNET.0,
        BuiltinProtocol::Ethernet,
    ),
    capture_root(crate::frame::LinkType::BSD_RAW.0, BuiltinProtocol::RawIp),
    capture_root(crate::frame::LinkType::RAW.0, BuiltinProtocol::RawIp),
    capture_root(crate::frame::LinkType::LOOP.0, BuiltinProtocol::BsdLoop),
    capture_root(
        crate::frame::LinkType::LINUX_SLL.0,
        BuiltinProtocol::LinuxSll,
    ),
    capture_root(crate::frame::LinkType::IPV4.0, BuiltinProtocol::Ipv4),
    capture_root(crate::frame::LinkType::IPV6.0, BuiltinProtocol::Ipv6),
    capture_root(
        crate::frame::LinkType::LINUX_SLL2.0,
        BuiltinProtocol::LinuxSll2,
    ),
];
