// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Production replay authorizer. It checks complete capture evidence, applies
//! the traffic policy to raw routing destinations before any I/O, and requires
//! an exact decode/build round trip.

use std::sync::Arc;

use packetcraftr_policy::TrafficPolicy;

use super::wire::{ReplayWireDestinations, replay_network_envelope, replay_wire_destinations};
use super::{
    BuildContext, BuildMode, BuildOptions, Builder, Classification, DecodeOptions, Decoder, Frame,
    Kind, LinkMode, ProtocolRegistry, ReplayAuthorizationContext, ReplayAuthorizer,
};
use crate::BoundaryError;

pub struct SystemAuthorizer {
    policy: TrafficPolicy,
    registry: Arc<ProtocolRegistry>,
    allow_malformed_live: bool,
}

impl SystemAuthorizer {
    pub fn new(
        policy: TrafficPolicy,
        registry: Arc<ProtocolRegistry>,
        allow_malformed_live: bool,
    ) -> Self {
        Self {
            policy,
            registry,
            allow_malformed_live,
        }
    }

    pub(super) fn authorize_frame(
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
        let ReplayWireDestinations {
            addresses,
            has_unsupported_routing_header,
        } = replay_wire_destinations(frame).map_err(|source| {
            BoundaryError::with_source(
                source.to_string(),
                Classification::new(
                    "packet.replay_packet_semantics",
                    Kind::Packet,
                    Some("repair malformed route-bearing packet fields before live replay"),
                ),
                Vec::new(),
                source,
            )
        })?;
        for destination in addresses {
            self.policy
                .authorize_destination(destination)
                .map_err(BoundaryError::from_error)?;
        }
        if has_unsupported_routing_header {
            return Err(BoundaryError::new(
                "captured IPv6 packet uses an unsupported routing header",
                Classification::new(
                    "capability.replay_routing_header",
                    Kind::Capability,
                    Some(
                        "replay only typed RFC 8754 Segment Routing Headers; unsupported routing types cannot be policy-authorized safely",
                    ),
                ),
                Vec::new(),
            ));
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
                packetcraftr_policy::TrafficPolicyError::PermissivePacket,
            ));
        }
        self.policy
            .authorize_packet_destinations(&decoded.packet)
            .map_err(BoundaryError::from_error)
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
