// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Policy and exact-byte authorization before replay performs live I/O.

use std::sync::Arc;

use packetcraftr_capture::Frame;
use packetcraftr_core::error::{Classification, Kind};
use packetcraftr_net::link::LinkMode;
use packetcraftr_packet::{
    build::{Builder, Context as BuildContext, Mode as BuildMode, Options as BuildOptions},
    decode::{Decoder, Options as DecodeOptions},
    registry::ProtocolRegistry,
};

use crate::BoundaryError;

use super::super::model::{ReplayAuthorizationContext, ReplayAuthorizer};
use super::super::wire::replay_network_envelope;

/// Production replay authorizer. It checks complete capture evidence, applies
/// the traffic policy to raw routing destinations before any I/O, and requires
/// an exact decode/build round trip.
pub struct SystemAuthorizer {
    policy: packetcraftr_client::policy::Policy,
    registry: Arc<ProtocolRegistry>,
    allow_malformed_live: bool,
}

impl SystemAuthorizer {
    /// # Panics
    ///
    /// Panics if the statically defined built-in protocol registry is invalid.
    pub fn new(policy: packetcraftr_client::policy::Policy, allow_malformed_live: bool) -> Self {
        Self {
            policy,
            registry: Arc::new(
                packetcraftr_protocol::builtin::registry()
                    .expect("the built-in protocol registry must be valid"),
            ),
            allow_malformed_live,
        }
    }

    pub(in crate::replay) fn authorize_frame(
        &self,
        frame: &Frame,
        mode: LinkMode,
    ) -> Result<(), BoundaryError> {
        if frame.captured_length() != frame.original_length() {
            return Err(BoundaryError::new(
                format!(
                    "captured frame contains {} of {} original wire bytes",
                    frame.captured_length(),
                    frame.original_length()
                ),
                Classification::new(
                    "packet.replay_truncated",
                    Kind::Packet,
                    Some(
                        "replay only complete captured frames whose captured and original lengths match",
                    ),
                ),
                Vec::new(),
            ));
        }
        if self
            .registry
            .root_for_link_type(frame.link_type.0)
            .is_none()
        {
            return Err(BoundaryError::from_error(
                packetcraftr_client::policy::Error::InvalidPacketSemantics {
                    reason: format!(
                        "replay authorization does not support link type {}",
                        frame.link_type.0
                    ),
                },
            ));
        }
        if mode == LinkMode::Layer3 {
            replay_network_envelope(frame).map_err(|source| {
                BoundaryError::with_source(
                    source.to_string(),
                    Classification::new(
                        "packet.replay_network",
                        Kind::Packet,
                        Some("repair the raw IP header or capture link type before live replay"),
                    ),
                    Vec::new(),
                    source,
                )
            })?;
        }
        let decoded = Decoder::new(Arc::clone(&self.registry))
            .decode(frame.clone(), DecodeOptions::default())
            .map_err(|source| {
                BoundaryError::with_source(
                    source.to_string(),
                    Classification::new(
                        "packet.decode",
                        Kind::Packet,
                        Some("repair the frame or link type before authorizing live replay"),
                    ),
                    Vec::new(),
                    source,
                )
            })?;
        self.policy
            .authorize_packet_destinations(&decoded.packet)
            .map_err(BoundaryError::from_error)?;
        let rebuilt = Builder::new(Arc::clone(&self.registry))
            .build(
                decoded.packet.clone(),
                BuildContext::default(),
                BuildOptions {
                    mode: BuildMode::Permissive,
                    ..BuildOptions::default()
                },
            )
            .map_err(|source| {
                BoundaryError::with_source(
                    format!("captured frame cannot be rebuilt exactly: {source}"),
                    Classification::new(
                        "packet.replay_rebuild",
                        Kind::Packet,
                        Some(
                            "repair the capture so its decoded layers rebuild the exact submitted bytes",
                        ),
                    ),
                    Vec::new(),
                    source,
                )
            })?;
        if rebuilt.bytes != frame.bytes() {
            return Err(BoundaryError::new(
                "captured frame did not reproduce the exact source bytes",
                Classification::new(
                    "internal.replay_rebuild",
                    Kind::Internal,
                    Some(
                        "do not replay bytes whose codec round trip changed the authoritative capture",
                    ),
                ),
                Vec::new(),
            ));
        }
        if rebuilt.requires_live_opt_in && !self.allow_malformed_live {
            return Err(BoundaryError::new(
                "permissive or malformed captured bytes require --allow-malformed-live",
                Classification::new(
                    "policy.permissive_live_opt_in",
                    Kind::Policy,
                    Some(
                        "set the per-operation malformed-live opt-in in addition to policy approval",
                    ),
                ),
                Vec::new(),
            ));
        }
        if rebuilt.requires_live_opt_in && !self.policy.allow_permissive_packets {
            return Err(BoundaryError::from_error(
                packetcraftr_client::policy::Error::PermissivePacket,
            ));
        }
        Ok(())
    }
}

impl ReplayAuthorizer for SystemAuthorizer {
    fn authorize_operation(
        &mut self,
        context: ReplayAuthorizationContext,
        frame: &Frame,
        mode: LinkMode,
    ) -> Result<(), BoundaryError> {
        self.policy
            .authorize_operation(context.packets, context.wire_bytes)
            .map_err(BoundaryError::from_error)?;
        self.authorize_frame(frame, mode)
    }
}
