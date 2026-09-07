// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Exact built-in wire interpretation at active side-effect boundaries.

use super::Policy;
use crate::Error;
use bytes::Bytes;
use packetcraftr_core::{
    build::BuiltPacket,
    decode::Dissector,
    frame::{Frame, LinkType},
};
use packetcraftr_netio::{Error as LiveIoError, link::Mode as LinkMode};

/// Which of the two permissive-live approvals is missing.
///
/// Callers that phrase the refusal in their own words (replay names the capture
/// bytes and the CLI flag) match on this instead of restating the check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PermissiveLiveDenial {
    /// The caller did not pass the per-operation opt-in for this run.
    OperationOptIn,
    /// The traffic policy does not stand behind permissively built bytes.
    PolicyApproval,
}

/// The two independent approvals permissively built bytes need before they can
/// reach the wire: the per-operation opt-in the caller passes for this run, and
/// the traffic policy's own standing allowance.
pub(crate) fn check_permissive_live(
    policy: &crate::policy::Policy,
    allow_permissive_live: bool,
) -> Result<(), PermissiveLiveDenial> {
    if !allow_permissive_live {
        return Err(PermissiveLiveDenial::OperationOptIn);
    }
    if !policy.allow_permissive_packets {
        return Err(PermissiveLiveDenial::PolicyApproval);
    }
    Ok(())
}

/// [`check_permissive_live`] phrased as the workflow error every caller but
/// replay reports.
pub(crate) fn authorize_permissive_live(
    policy: &crate::policy::Policy,
    allow_permissive_live: bool,
) -> Result<(), Error> {
    check_permissive_live(policy, allow_permissive_live).map_err(|denial| match denial {
        PermissiveLiveDenial::OperationOptIn => Error::PermissiveLiveOptInRequired,
        PermissiveLiveDenial::PolicyApproval => crate::policy::Error::PermissivePacket.into(),
    })
}

/// Why the final wire bytes were refused: they did not decode, or they
/// decoded to packets the policy does not permit.
#[derive(Debug)]
pub(crate) enum WireAuthorizationError {
    Decode(packetcraftr_core::decode::Error),
    Policy(crate::policy::Error),
}

/// Decodes exact wire bytes with the trusted built-in registry.
///
/// Bytes about to be transmitted have no capture time, interface, or original
/// length, so the caller passes only the link type and the bytes.
pub(crate) fn decode_wire(
    link_type: LinkType,
    bytes: &Bytes,
) -> Result<packetcraftr_core::decode::DecodedPacket, WireAuthorizationError> {
    let unsupported = |reason| {
        WireAuthorizationError::Policy(crate::policy::Error::InvalidPacketSemantics { reason })
    };
    let registry = packetcraftr_core::protocol::builtin::registry();
    if registry.root_for_link_type(link_type.0).is_none() {
        return Err(unsupported(format!(
            "trusted wire authorization does not support link type {}",
            link_type.0
        )));
    }
    let frame = Frame::without_timestamp(link_type, bytes.clone())
        .map_err(|source| unsupported(source.to_string()))?;
    Dissector::new(registry)
        .decode(frame, packetcraftr_core::decode::Options::default())
        .map_err(WireAuthorizationError::Decode)
}

/// Applies destination (and, given a route, source) policy to the packet the
/// trusted registry decodes from the bytes that will actually reach the wire.
/// Caller registries remain outside this policy trust boundary. Callers
/// classify decode failures in their own vocabulary.
pub(crate) fn authorize_wire(
    policy: &crate::policy::Policy,
    link_type: LinkType,
    bytes: &Bytes,
    route: Option<&packetcraftr_netio::route::Plan>,
) -> Result<(), WireAuthorizationError> {
    let decoded = decode_wire(link_type, bytes)?;
    policy
        .authorize_packet_destinations(&decoded.packet)
        .map_err(WireAuthorizationError::Policy)?;
    if let Some(route) = route {
        policy
            .authorize_packet_sources(&decoded.packet, route)
            .map_err(WireAuthorizationError::Policy)?;
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
        if built.requires_live_opt_in {
            authorize_permissive_live(self, allow_permissive_live)?;
        }
        Ok(())
    }

    /// Authorizes the exact bytes that would reach the wire against the route
    /// that was selected for them, decoding them with the trusted registry.
    pub(crate) fn authorize_built_wire(
        &self,
        built: &BuiltPacket,
        route: &packetcraftr_netio::route::Plan,
    ) -> Result<(), Error> {
        let link_type = match route.mode {
            LinkMode::Layer2 => route.decision.link_type,
            LinkMode::Layer3 => LinkType::RAW,
            LinkMode::Auto => return Err(LiveIoError::UnresolvedLinkMode.into()),
        };
        authorize_wire(self, link_type, &built.bytes, Some(route)).map_err(|error| match error {
            WireAuthorizationError::Decode(source) => Error::Wire(source),
            WireAuthorizationError::Policy(source) => Error::Policy(source),
        })
    }
}
