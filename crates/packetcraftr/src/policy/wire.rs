// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::{Error, Policy};
use bytes::Bytes;
use packetcraftr_core::{
    build::BuiltPacket,
    codec::Mode,
    decode::Dissector,
    frame::{Frame, LinkType},
};

/// Whether transmitting `built` needs the permissive-live opt-in: it was
/// built permissively, contains a malformed layer, or carries a trailer after
/// a network payload that a receiver may parse differently.
#[must_use]
pub fn requires_live_opt_in(built: &BuiltPacket) -> bool {
    built.mode == Mode::Permissive || built.contains_malformed() || built.contains_network_trailer()
}

/// Requires both the per-operation opt-in and the policy's permissive-live
/// allowance, reporting the missing opt-in first.
pub(crate) fn authorize_permissive_live(
    policy: &Policy,
    allow_permissive_live: bool,
) -> Result<(), Error> {
    if !allow_permissive_live {
        return Err(Error::PermissiveLiveOptIn);
    }
    if !policy.allow_permissive_packets {
        return Err(Error::PermissivePacket);
    }
    Ok(())
}

/// Decodes exact wire bytes with the trusted built-in registry.
///
/// Bytes about to be transmitted have no capture time, interface, or original
/// length, so the caller passes only the link type and the bytes.
pub(crate) fn decode_wire(
    link_type: LinkType,
    bytes: &Bytes,
) -> Result<packetcraftr_core::decode::DecodedPacket, Error> {
    let unsupported = |reason| Error::InvalidPacketSemantics {
        reason,
        source: None,
    };
    let registry = packetcraftr_core::protocol::builtin::registry();
    if registry.root_for_link_type(link_type).is_none() {
        return Err(unsupported(format!(
            "trusted wire authorization does not support link type {}",
            link_type.0
        )));
    }
    let frame = Frame::without_timestamp(link_type, bytes.clone())
        .map_err(|source| unsupported(source.to_string()))?;
    Dissector::new(registry)
        .decode(frame, packetcraftr_core::decode::Options::default())
        .map_err(|source| Error::UndecodableWire { source })
}

/// Decodes exact wire bytes with the trusted registry and applies destination
/// policy, returning the trusted decode so a later route-aware source check
/// can reuse it instead of decoding again.
/// Caller registries remain outside this policy trust boundary. A decode
/// failure is [`Error::UndecodableWire`], which callers may reclassify in
/// their own vocabulary.
pub(crate) fn authorize_wire_destinations(
    policy: &Policy,
    link_type: LinkType,
    bytes: &Bytes,
) -> Result<packetcraftr_core::decode::DecodedPacket, Error> {
    let decoded = decode_wire(link_type, bytes)?;
    policy.authorize_packet_destinations(&decoded.packet)?;
    Ok(decoded)
}

/// Applies route-dependent source policy to a packet the trusted registry
/// already decoded from the wire bytes.
pub(crate) fn authorize_wire_sources(
    policy: &Policy,
    decoded: &packetcraftr_core::decode::DecodedPacket,
    route: &crate::route::Plan,
) -> Result<(), Error> {
    policy.authorize_packet_sources(&decoded.packet, route)
}

/// Applies destination (and, given a route, source) policy to the packet the
/// trusted registry decodes from the bytes that will actually reach the wire.
/// Caller registries remain outside this policy trust boundary. A decode
/// failure is [`Error::UndecodableWire`], which callers may reclassify in
/// their own vocabulary.
pub(crate) fn authorize_wire(
    policy: &Policy,
    link_type: LinkType,
    bytes: &Bytes,
    route: Option<&crate::route::Plan>,
) -> Result<(), Error> {
    let decoded = authorize_wire_destinations(policy, link_type, bytes)?;
    if let Some(route) = route {
        authorize_wire_sources(policy, &decoded, route)?;
    }
    Ok(())
}

impl Policy {
    /// Authorizes the destinations a built packet declares, plus the two
    /// permissive-live approvals when the build needed them.
    pub(crate) fn authorize_built_packet(
        &self,
        built: &BuiltPacket,
        allow_permissive_live: bool,
    ) -> Result<(), Error> {
        self.authorize_packet_destinations(&built.packet)?;
        if requires_live_opt_in(built) {
            authorize_permissive_live(self, allow_permissive_live)?;
        }
        Ok(())
    }
}
