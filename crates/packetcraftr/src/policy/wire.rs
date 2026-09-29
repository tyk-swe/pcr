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

#[must_use]
pub fn requires_live_opt_in(built: &BuiltPacket) -> bool {
    built.mode == Mode::Permissive || built.contains_malformed() || built.contains_network_trailer()
}

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
        .map_err(|source| Error::WireFrame { source })?;
    Dissector::new(registry)
        .decode(frame, packetcraftr_core::decode::Options::default())
        .map_err(|source| Error::UndecodableWire { source })
}

/// Caller registries remain outside this policy trust boundary.
pub(crate) fn authorize_wire_destinations(
    policy: &Policy,
    link_type: LinkType,
    bytes: &Bytes,
) -> Result<packetcraftr_core::decode::DecodedPacket, Error> {
    let decoded = decode_wire(link_type, bytes)?;
    policy.authorize_packet_destinations(&decoded.packet)?;
    Ok(decoded)
}

pub(crate) fn authorize_wire(
    policy: &Policy,
    link_type: LinkType,
    bytes: &Bytes,
    route: &crate::route::Plan,
) -> Result<(), Error> {
    let decoded = authorize_wire_destinations(policy, link_type, bytes)?;
    policy.authorize_packet_sources(&decoded.packet, route)
}

impl Policy {
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
