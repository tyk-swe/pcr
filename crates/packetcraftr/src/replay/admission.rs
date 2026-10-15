// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;

use packetcraftr_core::error::{Classification, Kind};
use packetcraftr_core::frame::Frame;
use packetcraftr_core::{build, codec, decode, registry::Registry};
use packetcraftr_netio::link::Mode;

use crate::policy::{
    Operation, WireLimits, authorize_permissive_live, authorize_wire, authorize_wire_destinations,
};
use packetcraftr_core::error::BoundaryError;

use super::evidence::network_envelope;

/// Replay's two admission steps for one captured frame: `admit_frame` checks
/// limits and exact bytes before route work, and `authorize_final_wire` applies
/// source policy to the final route before delay or transmission.
pub(crate) trait ReplayAdmission {
    fn admit_frame(
        &mut self,
        limits: WireLimits,
        frame: &Frame,
        mode: Mode,
    ) -> Result<(), BoundaryError>;

    fn authorize_final_wire(
        &mut self,
        frame: &Frame,
        route: &crate::route::Plan,
    ) -> Result<(), BoundaryError>;
}

pub(super) struct FrameAdmission<'c> {
    policy: &'c crate::policy::Policy,
    registry: Arc<Registry>,
    allow_permissive_live: bool,
    wire_decode: Option<decode::DecodedPacket>,
}

impl<'c> FrameAdmission<'c> {
    /// Destination policy is applied through an independent built-in decoder.
    pub(super) fn new(
        policy: &'c crate::policy::Policy,
        registry: Arc<Registry>,
        allow_permissive_live: bool,
    ) -> Self {
        Self {
            policy,
            registry,
            allow_permissive_live,
            wire_decode: None,
        }
    }

    fn authorize_frame(&mut self, frame: &Frame, mode: Mode) -> Result<(), BoundaryError> {
        validate_complete_frame(frame)?;
        self.validate_link_type(frame)?;
        validate_network_frame(frame, mode)?;
        let trusted = authorize_wire_destinations(self.policy, frame.link_type, frame.bytes())
            .map_err(wire_error)?;
        let decoded = self.decode_frame(frame)?;
        let rebuilt = self.rebuild_frame(&decoded)?;
        self.validate_rebuild(frame, &rebuilt)?;
        self.wire_decode = Some(trusted);
        Ok(())
    }

    fn validate_link_type(&self, frame: &Frame) -> Result<(), BoundaryError> {
        if self.registry.root_for_link_type(frame.link_type).is_some() {
            return Ok(());
        }
        Err(BoundaryError::from_error(
            crate::policy::Error::InvalidPacketSemantics {
                reason: format!(
                    "replay authorization does not support link type {}",
                    frame.link_type.0
                ),
                source: None,
            },
        ))
    }

    fn decode_frame(&self, frame: &Frame) -> Result<decode::DecodedPacket, BoundaryError> {
        decode::Dissector::new(Arc::clone(&self.registry))
            .decode(frame.clone(), decode::Options::default())
            .map_err(decode_error)
    }

    fn rebuild_frame(
        &self,
        decoded: &decode::DecodedPacket,
    ) -> Result<build::BuiltPacket, BoundaryError> {
        build::Builder::new(Arc::clone(&self.registry))
            .build(
                decoded.packet.clone(),
                codec::Addresses::default(),
                build::Options {
                    mode: codec::Mode::Permissive,
                    ..build::Options::default()
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
                    packetcraftr_core::error::source_chain(&source),
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
                    Kind::Internal,
                    Some(
                        "do not replay bytes whose codec round trip changed the authoritative capture",
                    ),
                ),
                Vec::new(),
            ));
        }
        if crate::policy::requires_live_opt_in(rebuilt) {
            authorize_permissive_live(self.policy, self.allow_permissive_live)
                .map_err(permissive_live_error)?;
        }
        Ok(())
    }
}

fn wire_error(error: crate::policy::Error) -> BoundaryError {
    match error {
        crate::policy::Error::UndecodableWire { source } => decode_error(source),
        error => BoundaryError::from_error(error),
    }
}

fn decode_error(source: decode::Error) -> BoundaryError {
    BoundaryError::with_source(
        source.to_string(),
        Classification::new(
            "packet.decode",
            Kind::Packet,
            Some("repair the frame or link type before authorizing live replay"),
        ),
        packetcraftr_core::error::source_chain(&source),
        source,
    )
}

fn permissive_live_error(error: crate::policy::Error) -> BoundaryError {
    match error {
        crate::policy::Error::PermissiveLiveOptIn => BoundaryError::new(
            "permissive or malformed captured bytes require --allow-malformed-live",
            Classification::new(
                "policy.permissive_live_opt_in",
                Kind::Policy,
                Some("set the per-operation malformed-live opt-in in addition to policy approval"),
            ),
            Vec::new(),
        ),
        error => BoundaryError::from_error(error),
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
            Kind::Packet,
            Some("replay only complete captured frames whose captured and original lengths match"),
        ),
        Vec::new(),
    ))
}

fn validate_network_frame(frame: &Frame, mode: Mode) -> Result<(), BoundaryError> {
    if mode != Mode::Layer3 {
        return Ok(());
    }
    network_envelope(frame).map_err(|source| {
        BoundaryError::with_source(
            source.to_string(),
            Classification::new(
                "packet.replay_network",
                Kind::Packet,
                Some("repair the raw IP header or capture link type before live replay"),
            ),
            packetcraftr_core::error::source_chain(&source),
            source,
        )
    })?;
    Ok(())
}

impl ReplayAdmission for FrameAdmission<'_> {
    fn admit_frame(
        &mut self,
        limits: WireLimits,
        frame: &Frame,
        mode: Mode,
    ) -> Result<(), BoundaryError> {
        self.policy
            .authorize(Operation::Wire(limits))
            .map_err(BoundaryError::from_error)?;
        self.authorize_frame(frame, mode)
    }

    fn authorize_final_wire(
        &mut self,
        frame: &Frame,
        route: &crate::route::Plan,
    ) -> Result<(), BoundaryError> {
        match self.wire_decode.take() {
            Some(decoded)
                if decoded.frame.link_type == frame.link_type
                    && decoded.frame.bytes() == frame.bytes() =>
            {
                self.policy
                    .authorize_packet_sources(&decoded.packet, route)
                    .map_err(wire_error)
            }
            _ => authorize_wire(self.policy, frame.link_type, frame.bytes(), route)
                .map_err(wire_error),
        }
    }
}
