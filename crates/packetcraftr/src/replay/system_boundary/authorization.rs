// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Policy and exact-byte authorization before replay performs live I/O.

use std::sync::Arc;

use packetcraftr_core::error::{Classification, Kind};
use packetcraftr_core::frame::Frame;
use packetcraftr_core::{build, decode, registry::Registry};
use packetcraftr_netio::link::Mode;

use crate::BoundaryError;

use crate::authorization::{Authorizer, Operation, authorize_permissive_live};

use super::super::wire::replay_network_envelope;

/// Validates complete capture evidence, applies policy to raw routing destinations
/// before I/O, and requires an exact decode/build round trip.
pub struct SystemAuthorizer {
    policy: crate::policy::Policy,
    registry: Arc<Registry>,
    allow_malformed_live: bool,
}

impl SystemAuthorizer {
    /// # Panics
    ///
    /// Panics if the statically defined built-in protocol registry is invalid.
    pub fn new(policy: crate::policy::Policy, allow_malformed_live: bool) -> Self {
        Self {
            policy,
            registry: Arc::new(
                packetcraftr_core::protocol::builtin::registry()
                    .expect("the built-in protocol registry must be valid"),
            ),
            allow_malformed_live,
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
        if self
            .registry
            .root_for_link_type(frame.link_type.0)
            .is_some()
        {
            return Ok(());
        }
        Err(BoundaryError::from_error(
            crate::policy::Error::InvalidPacketSemantics {
                reason: format!(
                    "replay authorization does not support link type {}",
                    frame.link_type.0
                ),
            },
        ))
    }

    fn decode_frame(&self, frame: &Frame) -> Result<decode::DecodedPacket, BoundaryError> {
        decode::Dissector::new(Arc::clone(&self.registry))
            .decode(frame.clone(), decode::Options::default())
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
            })
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
                        Kind::Packet,
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
                    Kind::Internal,
                    Some(
                        "do not replay bytes whose codec round trip changed the authoritative capture",
                    ),
                ),
                Vec::new(),
            ));
        }
        if rebuilt.requires_live_opt_in {
            authorize_permissive_live(&self.policy, self.allow_malformed_live)
                .map_err(BoundaryError::from_error)?;
        }
        Ok(())
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
    Ok(())
}

impl Authorizer for SystemAuthorizer {
    fn authorize_operation(&mut self, operation: Operation<'_>) -> Result<(), BoundaryError> {
        self.policy
            .authorize_operation(operation.packets, operation.wire_bytes)
            .map_err(BoundaryError::from_error)?;
        let Some((frame, mode)) = operation.frame else {
            return Ok(());
        };
        self.authorize_frame(frame, mode)
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::sync::Arc;
    use std::time::UNIX_EPOCH;

    use packetcraftr_core::Packet;
    use packetcraftr_core::build::{Builder, BuiltPacket};
    use packetcraftr_core::error::Classified;
    use packetcraftr_core::protocol::{icmp::Icmpv4, network::Ipv4};

    use super::*;

    fn built_ipv4(reserved_flag: bool) -> BuiltPacket {
        let mut packet = Packet::new();
        packet
            .push(Ipv4 {
                source: Ipv4Addr::new(192, 0, 2, 1),
                destination: Ipv4Addr::new(192, 0, 2, 2),
                reserved_flag,
                ..Ipv4::default()
            })
            .push(Icmpv4::default());
        Builder::new(Arc::new(
            packetcraftr_core::protocol::builtin::registry().expect("built-in registry"),
        ))
        .build(
            packet,
            build::Context::default(),
            build::Options {
                mode: if reserved_flag {
                    build::Mode::Permissive
                } else {
                    build::Mode::Strict
                },
                ..build::Options::default()
            },
        )
        .expect("fixture packet builds")
    }

    fn raw_frame(built: &BuiltPacket) -> Frame {
        Frame::new(
            UNIX_EPOCH,
            packetcraftr_core::frame::LinkType::RAW,
            built.bytes.clone(),
        )
        .expect("bounded raw frame")
    }

    #[test]
    fn exact_complete_documentation_frame_is_authorized_with_replay_opt_ins() {
        let built = built_ipv4(false);
        assert!(!built.requires_live_opt_in);
        let frame = raw_frame(&built);
        let inspecting_authorizer = SystemAuthorizer::new(crate::policy::Policy::default(), false);
        let decoded = inspecting_authorizer
            .decode_frame(&frame)
            .expect("fixture decodes");
        let rebuilt = inspecting_authorizer
            .rebuild_frame(&decoded)
            .expect("fixture rebuilds");
        assert!(rebuilt.requires_live_opt_in);
        assert!(decoded.diagnostics.is_empty());
        assert!(rebuilt.diagnostics.is_empty());

        let policy = crate::policy::Policy {
            allow_permissive_packets: true,
            ..crate::policy::Policy::default()
        };
        SystemAuthorizer::new(policy, true)
            .authorize_frame(&frame, Mode::Layer3)
            .expect("exact replay with both explicit live approvals");
    }

    #[test]
    fn operation_budgets_fail_before_frame_decoding_or_interface_work() {
        let invalid_frame = Frame::new(
            UNIX_EPOCH,
            packetcraftr_core::frame::LinkType(65_535),
            vec![0_u8],
        )
        .expect("bounded fixture frame");
        let policy = crate::policy::Policy {
            max_packets_per_operation: 1,
            max_bytes_per_operation: 2,
            ..crate::policy::Policy::default()
        };
        let mut authorizer = SystemAuthorizer::new(policy, false);

        let packet_error = authorizer
            .authorize_operation(Operation {
                packets: 2,
                wire_bytes: 1,
                frame: Some((&invalid_frame, Mode::Layer2)),
                ..Operation::default()
            })
            .expect_err("packet budget must fail first");
        assert_eq!(packet_error.classification().code, "policy.packet_limit");

        let byte_error = authorizer
            .authorize_operation(Operation {
                packets: 1,
                wire_bytes: 3,
                frame: Some((&invalid_frame, Mode::Layer2)),
                ..Operation::default()
            })
            .expect_err("byte budget must fail before unsupported link type");
        assert_eq!(byte_error.classification().code, "policy.byte_limit");
    }

    #[test]
    fn incomplete_unsupported_and_non_network_frames_fail_with_stable_classification() {
        let truncated = Frame::try_with_lengths(
            UNIX_EPOCH,
            packetcraftr_core::frame::LinkType::RAW,
            1,
            2,
            vec![0x45_u8],
        )
        .expect("valid truncated capture record");
        let authorizer = SystemAuthorizer::new(crate::policy::Policy::default(), false);
        let error = authorizer
            .authorize_frame(&truncated, Mode::Layer3)
            .expect_err("truncated evidence cannot be replayed");
        assert_eq!(error.classification().code, "packet.replay_truncated");

        let unsupported = Frame::new(
            UNIX_EPOCH,
            packetcraftr_core::frame::LinkType(65_535),
            vec![0_u8],
        )
        .expect("bounded fixture frame");
        let error = authorizer
            .authorize_frame(&unsupported, Mode::Layer2)
            .expect_err("unknown live link type cannot be authorized");
        assert_eq!(
            error.classification().code,
            "policy.invalid_packet_semantics"
        );

        let ethernet_bytes = vec![0_u8; 14];
        let ethernet = Frame::new(
            UNIX_EPOCH,
            packetcraftr_core::frame::LinkType::ETHERNET,
            ethernet_bytes,
        )
        .expect("bounded Ethernet frame");
        let error = authorizer
            .authorize_frame(&ethernet, Mode::Layer3)
            .expect_err("Ethernet bytes are not a raw network envelope");
        assert_eq!(error.classification().code, "packet.replay_network");
    }

    #[test]
    fn permissive_capture_requires_both_live_opt_ins() {
        let built = built_ipv4(true);
        assert!(built.requires_live_opt_in);
        let frame = raw_frame(&built);

        let missing_operation_opt_in =
            SystemAuthorizer::new(crate::policy::Policy::default(), false)
                .authorize_frame(&frame, Mode::Layer3)
                .expect_err("operation opt-in is mandatory");
        assert_eq!(
            missing_operation_opt_in.classification().code,
            "policy.permissive_live_opt_in"
        );

        let missing_policy_opt_in = SystemAuthorizer::new(crate::policy::Policy::default(), true)
            .authorize_frame(&frame, Mode::Layer3)
            .expect_err("policy opt-in is independently mandatory");
        assert_eq!(
            missing_policy_opt_in.classification().code,
            "policy.permissive_packet"
        );

        let policy = crate::policy::Policy {
            allow_permissive_packets: true,
            ..crate::policy::Policy::default()
        };
        SystemAuthorizer::new(policy, true)
            .authorize_frame(&frame, Mode::Layer3)
            .expect("both explicit approvals authorize the exact malformed bytes");
    }

    #[test]
    fn rebuilt_bytes_must_match_the_authoritative_capture_exactly() {
        let built = built_ipv4(false);
        let different_frame = Frame::new(
            UNIX_EPOCH,
            packetcraftr_core::frame::LinkType::RAW,
            vec![0_u8; built.bytes.len()],
        )
        .expect("same-width fixture frame");
        let authorizer = SystemAuthorizer::new(crate::policy::Policy::default(), false);

        let error = authorizer
            .validate_rebuild(&different_frame, &built)
            .expect_err("semantic rebuild cannot substitute different bytes");
        assert_eq!(error.classification().code, "internal.replay_rebuild");
    }
}
