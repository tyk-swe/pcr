// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Policy and exact-byte authorization before replay performs live I/O.

use std::sync::Arc;

use packetcraftr_core::error::Classification;
use packetcraftr_core::frame::Frame;
use packetcraftr_core::{build, decode, registry::Registry};
use packetcraftr_netio::link::Mode;

use crate::BoundaryError;

use super::super::model::{AuthorizationContext, Authorizer};
use super::super::wire::replay_network_envelope;

/// Validates complete capture evidence, applies policy to raw routing destinations
/// before I/O, and requires an exact decode/build round trip.
pub struct SystemAuthorizer {
    policy: crate::policy::Policy,
    registry: Arc<Registry>,
    allow_permissive_live: bool,
}

impl SystemAuthorizer {
    /// # Panics
    ///
    /// Panics if the statically defined built-in protocol registry is invalid.
    pub fn new(policy: crate::policy::Policy, allow_permissive_live: bool) -> Self {
        Self {
            policy,
            registry: Arc::new(
                packetcraftr_core::protocol::builtin::registry()
                    .expect("the built-in protocol registry must be valid"),
            ),
            allow_permissive_live,
        }
    }

    pub(in crate::replay) fn authorize_frame(
        &self,
        frame: &Frame,
        mode: Mode,
    ) -> Result<(), BoundaryError> {
        validate_complete_frame(frame)?;
        self.validate_link_type(frame)?;
        validate_network_frame(frame, mode)?;
        let decoded = self.decode_frame(frame)?;
        self.policy
            .authorize_packet_destinations(&decoded.packet)
            .map_err(BoundaryError::from_error)?;
        let rebuilt = self.rebuild_frame(&decoded)?;
        self.validate_rebuild(frame, &rebuilt)
    }

    fn validate_link_type(&self, frame: &Frame) -> Result<(), BoundaryError> {
        self.policy
            .authorize_link_type(frame.link_type, &self.registry, "replay")
            .map_err(BoundaryError::from_error)
    }

    fn decode_frame(&self, frame: &Frame) -> Result<decode::DecodedPacket, BoundaryError> {
        decode::Dissector::new(Arc::clone(&self.registry))
            .decode(frame.clone(), decode::Options::default())
            .map_err(BoundaryError::from_error)
    }

    fn rebuild_frame(
        &self,
        decoded: &decode::DecodedPacket,
    ) -> Result<build::BuiltPacket, BoundaryError> {
        build::Builder::new(Arc::clone(&self.registry))
            .build(
                decoded.packet.clone(),
                build::Context::default(),
                build::Options {
                    mode: build::Mode::Permissive,
                    ..build::Options::default()
                },
            )
            .map_err(|source| {
                BoundaryError::with_source(
                    format!("captured frame cannot be rebuilt exactly: {source}"),
                    Classification::new(
                        "packet.replay_rebuild",
                        Some(
                            "repair the capture so its decoded layers rebuild the exact submitted bytes",
                        ),
                    ),
                    Vec::new(),
                    source,
                )
            })
    }

    fn validate_rebuild(
        &self,
        frame: &Frame,
        rebuilt: &build::BuiltPacket,
    ) -> Result<(), BoundaryError> {
        if rebuilt.bytes != frame.bytes() {
            return Err(BoundaryError::new(
                "captured frame did not reproduce the exact source bytes",
                Classification::new(
                    "internal.replay_rebuild",
                    Some(
                        "do not replay bytes whose codec round trip changed the authoritative capture",
                    ),
                ),
                Vec::new(),
            ));
        }
        self.policy
            .authorize_permissive(rebuilt.requires_live_opt_in, self.allow_permissive_live)
            .map_err(BoundaryError::from_error)
    }
}

fn validate_complete_frame(frame: &Frame) -> Result<(), BoundaryError> {
    if frame.captured_length() == frame.original_length() {
        return Ok(());
    }
    Err(BoundaryError::new(
        format!(
            "captured frame contains {} of {} original wire bytes",
            frame.captured_length(),
            frame.original_length()
        ),
        Classification::new(
            "packet.replay_truncated",
            Some("replay only complete captured frames whose captured and original lengths match"),
        ),
        Vec::new(),
    ))
}

fn validate_network_frame(frame: &Frame, mode: Mode) -> Result<(), BoundaryError> {
    if mode != Mode::Layer3 {
        return Ok(());
    }
    replay_network_envelope(frame).map_err(|source| {
        BoundaryError::with_source(
            source.to_string(),
            Classification::new(
                "packet.replay_network",
                Some("repair the raw IP header or capture link type before live replay"),
            ),
            Vec::new(),
            source,
        )
    })?;
    Ok(())
}

impl Authorizer for SystemAuthorizer {
    fn authorize_operation(
        &mut self,
        context: AuthorizationContext,
        frame: &Frame,
        mode: Mode,
    ) -> Result<(), BoundaryError> {
        self.policy
            .authorize_operation(context.packets, context.wire_bytes)
            .map_err(BoundaryError::from_error)?;
        self.authorize_frame(frame, mode)
    }
}
