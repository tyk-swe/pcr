// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Public built-in codec and capture-root capability tables.

use serde::Serialize;

use packetcraftr_packet::semantics::{BuiltinProtocol, builtin_protocol_catalog};

/// One built-in codec row in the stable protocol contract.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct ProtocolSupport {
    pub protocol: &'static str,
    pub aliases: &'static [&'static str],
    pub build: bool,
    pub dissect: bool,
    pub exact_round_trip: bool,
    pub matcher: bool,
    pub decode_only: bool,
}

/// Byte-order rule applied by a registered capture root.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureRootByteOrder {
    /// A captured host-order field is detected and preserved as little or big endian.
    CapturedHost,
    /// Multi-byte header fields use network byte order.
    Network,
    /// The encapsulated protocol defines its own byte order.
    ProtocolDefined,
}

/// One numeric DLT/LINKTYPE binding in the default registry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct CaptureRootSupport {
    pub link_type: u32,
    pub protocol: &'static str,
    pub byte_order: CaptureRootByteOrder,
    pub exact_round_trip: bool,
}

/// The alias list a built-in codec advertises for its own protocol.
///
/// Every caller passes the `protocol_id` of the codec it is implementing, so
/// an unknown name means this manifest has drifted from [`BuiltinProtocol`].
/// Panicking is deliberate: returning an empty slice would silently drop the
/// aliases the registry resolves names through, and the drift would surface
/// later as a name that no longer parses.
/// `manifest_matches_the_default_registry_exactly` below asserts the same
/// correspondence at test time.
pub(crate) fn aliases(protocol: &str) -> &'static [&'static str] {
    BuiltinProtocol::from_name(protocol)
        .map(BuiltinProtocol::aliases)
        .unwrap_or_else(|| panic!("missing built-in protocol support for {protocol}"))
}

macro_rules! define_protocol_support {
    ($(
        $variant:ident {
            canonical: $canonical:literal,
            aliases: [$($alias:literal),* $(,)?],
            constructible: $constructible:literal,
            dissect: $dissect:literal,
            exact_round_trip: $exact_round_trip:literal,
            matcher: $matcher:ident,
            codec: $codec:ident
        }
    )*) => {
        /// Every codec registered by [`crate::builtin::Module`], in
        /// stable manifest order.
        pub const BUILTIN_PROTOCOLS: &[ProtocolSupport] = &[$(
            ProtocolSupport {
                protocol: $canonical,
                aliases: &[$($alias),*],
                build: $constructible,
                dissect: $dissect,
                exact_round_trip: $exact_round_trip,
                matcher: define_protocol_support!(@matcher $matcher),
                decode_only: !$constructible,
            }
        ),*];
    };
    (@matcher none) => { false };
    (@matcher reverse_flow) => { true };
    (@matcher echo_v4) => { true };
    (@matcher echo_v6) => { true };
}

builtin_protocol_catalog!(define_protocol_support);

const fn capture_root(
    link_type: u32,
    protocol: BuiltinProtocol,
    byte_order: CaptureRootByteOrder,
) -> CaptureRootSupport {
    CaptureRootSupport {
        link_type,
        protocol: protocol.as_str(),
        byte_order,
        exact_round_trip: true,
    }
}

/// Every numeric capture root registered by the default built-in module.
///
/// Capture topology remains separate from identity metadata, but every edge is
/// typed so a protocol rename cannot silently leave a string binding behind.
pub const BUILTIN_CAPTURE_ROOTS: &[CaptureRootSupport] = &[
    capture_root(
        packetcraftr_core::frame::LinkType::NULL.0,
        BuiltinProtocol::BsdNull,
        CaptureRootByteOrder::CapturedHost,
    ),
    capture_root(
        packetcraftr_core::frame::LinkType::ETHERNET.0,
        BuiltinProtocol::Ethernet,
        CaptureRootByteOrder::ProtocolDefined,
    ),
    capture_root(
        packetcraftr_core::frame::LinkType::BSD_RAW.0,
        BuiltinProtocol::RawIp,
        CaptureRootByteOrder::ProtocolDefined,
    ),
    capture_root(
        packetcraftr_core::frame::LinkType::RAW.0,
        BuiltinProtocol::RawIp,
        CaptureRootByteOrder::ProtocolDefined,
    ),
    capture_root(
        packetcraftr_core::frame::LinkType::LOOP.0,
        BuiltinProtocol::BsdLoop,
        CaptureRootByteOrder::Network,
    ),
    capture_root(
        packetcraftr_core::frame::LinkType::LINUX_SLL.0,
        BuiltinProtocol::LinuxSll,
        CaptureRootByteOrder::Network,
    ),
    capture_root(
        packetcraftr_core::frame::LinkType::IPV4.0,
        BuiltinProtocol::Ipv4,
        CaptureRootByteOrder::ProtocolDefined,
    ),
    capture_root(
        packetcraftr_core::frame::LinkType::IPV6.0,
        BuiltinProtocol::Ipv6,
        CaptureRootByteOrder::ProtocolDefined,
    ),
    capture_root(
        packetcraftr_core::frame::LinkType::LINUX_SLL2.0,
        BuiltinProtocol::LinuxSll2,
        CaptureRootByteOrder::Network,
    ),
];

#[cfg(test)]
mod tests;
