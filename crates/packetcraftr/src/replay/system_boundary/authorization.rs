// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Policy and exact-byte authorization before replay performs live I/O.

use std::sync::Arc;

use packetcraftr_core::error::{Classification, Kind};
use packetcraftr_core::frame::Frame;
use packetcraftr_core::{build, decode, registry::Registry};
use packetcraftr_netio::link::Mode;

use crate::BoundaryError;

use crate::authorization::{
    Authorizer, Operation, PermissiveLiveDenial, WireAuthorizationError, authorize_wire,
    check_permissive_live, unsupported_operation,
};

use crate::replay::wire::replay_network_envelope;

/// Validates complete capture evidence, applies policy to raw routing destinations
/// before I/O, and requires an exact decode/build round trip.
pub struct SystemAuthorizer {
    policy: crate::policy::Policy,
    registry: Arc<Registry>,
    allow_malformed_live: bool,
}

impl SystemAuthorizer {
    /// Uses `registry` for the caller's normal decode/rebuild round trip.
    /// Destination policy is applied through an independent built-in decoder.
    pub fn new(
        registry: Arc<Registry>,
        policy: crate::policy::Policy,
        allow_malformed_live: bool,
    ) -> Self {
        Self {
            policy,
            registry,
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
        authorize_wire(&self.policy, frame.link_type, frame.bytes(), None).map_err(|error| {
            match error {
                WireAuthorizationError::Decode(source) => decode_error(source),
                WireAuthorizationError::Policy(error) => BoundaryError::from_error(error),
            }
        })?;
        let decoded = self.decode_frame(frame)?;
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
            .map_err(decode_error)
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
            check_permissive_live(&self.policy, self.allow_malformed_live)
                .map_err(permissive_live_error)?;
        }
        Ok(())
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
        Vec::new(),
        source,
    )
}

/// Replay reports the missing opt-in in its own words: it refuses captured
/// bytes, not a packet it built, and it names the flag that unblocks them.
fn permissive_live_error(denial: PermissiveLiveDenial) -> BoundaryError {
    match denial {
        PermissiveLiveDenial::OperationOptIn => BoundaryError::new(
            "permissive or malformed captured bytes require --allow-malformed-live",
            Classification::new(
                "policy.permissive_live_opt_in",
                Kind::Policy,
                Some("set the per-operation malformed-live opt-in in addition to policy approval"),
            ),
            Vec::new(),
        ),
        PermissiveLiveDenial::PolicyApproval => {
            BoundaryError::from_error(crate::policy::Error::PermissivePacket)
        }
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
    /// Budgets are checked before the frame is decoded or rebuilt, so a
    /// request that exceeds policy never reaches the expensive round trip.
    /// Shapes without an exact frame are rejected: replay cannot be
    /// authorized from a budget or a declared packet list.
    fn authorize_operation(&mut self, operation: Operation<'_>) -> Result<(), BoundaryError> {
        let budget = operation.budget();
        self.policy
            .authorize_operation(budget.packets(), budget.wire_bytes())
            .map_err(BoundaryError::from_error)?;
        match operation {
            Operation::Replay(replay) => self.authorize_frame(replay.frame(), replay.mode()),
            Operation::Budgeted(_) | Operation::Dns(_) | Operation::Declared(_) => Err(
                unsupported_operation("the replay system authorizer", &operation),
            ),
        }
    }

    fn authorize_final_wire(
        &mut self,
        frame: &Frame,
        route: &packetcraftr_netio::route::Plan,
    ) -> Result<(), BoundaryError> {
        authorize_wire(&self.policy, frame.link_type, frame.bytes(), Some(route)).map_err(|error| {
            match error {
                WireAuthorizationError::Decode(source) => decode_error(source),
                WireAuthorizationError::Policy(error) => BoundaryError::from_error(error),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;
    use std::time::UNIX_EPOCH;

    use packetcraftr_core::Packet;
    use packetcraftr_core::build::{Builder, BuiltPacket};
    use packetcraftr_core::codec::{
        DecodedLayerValue, EncodedLayer, LayerCodec, LayerDecodeContext, LayerEncodeContext,
    };
    use packetcraftr_core::error::Classified;
    use packetcraftr_core::field::FieldValue;
    use packetcraftr_core::frame::LinkType;
    use packetcraftr_core::layer::{Layer, Raw, raw_layout};
    use packetcraftr_core::protocol::{icmp::Icmpv4, link::Ethernet, network::Ipv4};
    use packetcraftr_netio::interface::Id as InterfaceId;
    use packetcraftr_netio::link::{Capability as LinkCapability, MacAddress};
    use packetcraftr_netio::route::{Decision, Plan, Scope, SelectionReason};

    use super::*;
    use crate::authorization::{DeclaredPackets, PermissiveLive, ReplayFrame, WireBudget};

    fn registry() -> Arc<Registry> {
        packetcraftr_core::protocol::builtin::registry()
    }

    /// A caller codec that preserves every root byte while exposing no IP
    /// semantics to consumers of its decoded packet.
    #[derive(Clone, Copy, Debug)]
    struct OpaqueRawCodec;

    impl LayerCodec for OpaqueRawCodec {
        fn protocol_id(&self) -> &'static packetcraftr_core::layer::Id {
            static PROTOCOL: std::sync::OnceLock<packetcraftr_core::layer::Id> =
                std::sync::OnceLock::new();
            PROTOCOL.get_or_init(|| "raw".into())
        }

        fn encode(
            &self,
            layer: &dyn Layer,
            _payload: &[u8],
            _context: &LayerEncodeContext<'_>,
        ) -> Result<EncodedLayer, packetcraftr_core::codec::Error> {
            let raw = layer.as_any().downcast_ref::<Raw>().ok_or_else(|| {
                packetcraftr_core::codec::Error::WrongLayer {
                    expected: "raw".into(),
                    actual: layer.protocol_id().clone(),
                }
            })?;
            let mut encoded = EncodedLayer::header(raw.bytes.to_vec(), Box::new(raw.clone()));
            encoded.fields = raw_layout(raw.bytes.len());
            Ok(encoded)
        }

        fn decode(
            &self,
            input: &[u8],
            _context: &LayerDecodeContext<'_>,
        ) -> Result<DecodedLayerValue, packetcraftr_core::codec::Error> {
            let mut decoded =
                DecodedLayerValue::terminal(Box::new(Raw::new(input.to_vec())), input.len());
            decoded.fields = raw_layout(input.len());
            Ok(decoded)
        }

        fn make_layer(
            &self,
            _fields: &BTreeMap<String, FieldValue>,
        ) -> Result<Box<dyn Layer>, packetcraftr_core::codec::Error> {
            Ok(Box::new(Raw::default()))
        }
    }

    fn opaque_raw_registry() -> Arc<Registry> {
        let mut builder = Registry::builder();
        builder
            .register_codec(OpaqueRawCodec, &[])
            .expect("opaque codec registration");
        builder
            .bind_link_type(LinkType::RAW.0, "raw")
            .expect("opaque raw root binding");
        Arc::new(builder.build().expect("opaque registry"))
    }

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
        Builder::new(registry())
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

    fn ethernet_frame(source_mac: [u8; 6], source_ip: Ipv4Addr) -> Frame {
        let mut packet = Packet::new();
        packet
            .push(Ethernet {
                source: source_mac,
                destination: [0x02, 0, 0, 0, 0, 2],
                ..Ethernet::default()
            })
            .push(Ipv4 {
                source: source_ip,
                destination: Ipv4Addr::new(192, 0, 2, 2),
                ..Ipv4::default()
            })
            .push(Icmpv4::default());
        let built = Builder::new(registry())
            .build(packet, build::Context::default(), build::Options::default())
            .expect("Ethernet replay fixture builds");
        Frame::new(UNIX_EPOCH, LinkType::ETHERNET, built.bytes)
            .expect("bounded Ethernet replay fixture")
    }

    fn replay_route(mode: Mode, link_type: LinkType, selected_source: Ipv4Addr) -> Plan {
        let source_mac = MacAddress([0x02, 0, 0, 0, 0, 1]);
        Plan {
            decision: Decision {
                interface: InterfaceId {
                    name: "fixture0".to_owned(),
                    index: 7,
                },
                source_mac: Some(source_mac),
                selected_source: Some(IpAddr::V4(selected_source)),
                preferred_source: None,
                next_hop: None,
                selection_reason: SelectionReason::InterfaceOnly,
                destination_scope: Scope::Link,
                mtu: 1_500,
                capability: LinkCapability::Layer2AndLayer3,
                link_type,
            },
            mode,
            lookup_destination: None,
            final_destination: None,
            visited_destinations: Vec::new(),
            packet_source: Some(IpAddr::V4(selected_source)),
            neighbor_source: None,
            neighbor_target: None,
            destination_mac: None,
            source_mac: Some(source_mac),
            neighbor_vlan_tags: Vec::new(),
            synthesized_ethernet: false,
        }
    }

    #[test]
    fn exact_complete_documentation_frame_is_authorized_with_replay_opt_ins() {
        let built = built_ipv4(false);
        assert!(!built.requires_live_opt_in);
        let frame = raw_frame(&built);
        let inspecting_authorizer =
            SystemAuthorizer::new(registry(), crate::policy::Policy::default(), false);
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
        SystemAuthorizer::new(registry(), policy, true)
            .authorize_frame(&frame, Mode::Layer3)
            .expect("exact replay with both explicit live approvals");
    }

    #[test]
    fn final_wire_replay_rejects_foreign_raw_ip_source_unless_explicitly_allowed() {
        let frame = raw_frame(&built_ipv4(false));
        let route = replay_route(Mode::Layer3, LinkType::RAW, Ipv4Addr::new(192, 0, 2, 99));

        let error = SystemAuthorizer::new(registry(), crate::policy::Policy::default(), false)
            .authorize_final_wire(&frame, &route)
            .expect_err("foreign raw IP source must be rejected by default");
        assert_eq!(error.classification().code, "policy.source_ownership");

        let policy = crate::policy::Policy {
            allow_source_spoofing: true,
            ..crate::policy::Policy::default()
        };
        SystemAuthorizer::new(registry(), policy, false)
            .authorize_final_wire(&frame, &route)
            .expect("explicit source-spoofing approval permits the raw IP source");
    }

    #[test]
    fn final_wire_replay_rejects_foreign_ethernet_source_unless_explicitly_allowed() {
        let frame = ethernet_frame([0x02, 0, 0, 0, 0, 9], Ipv4Addr::new(192, 0, 2, 1));
        let route = replay_route(
            Mode::Layer2,
            LinkType::ETHERNET,
            Ipv4Addr::new(192, 0, 2, 1),
        );

        let error = SystemAuthorizer::new(registry(), crate::policy::Policy::default(), false)
            .authorize_final_wire(&frame, &route)
            .expect_err("foreign Ethernet source must be rejected by default");
        assert_eq!(error.classification().code, "policy.source_ownership");

        let policy = crate::policy::Policy {
            allow_source_spoofing: true,
            ..crate::policy::Policy::default()
        };
        SystemAuthorizer::new(registry(), policy, false)
            .authorize_final_wire(&frame, &route)
            .expect("explicit source-spoofing approval permits the Ethernet source");
    }

    #[test]
    fn final_wire_replay_does_not_replace_an_unspecified_captured_source() {
        let frame = ethernet_frame([0x02, 0, 0, 0, 0, 1], Ipv4Addr::UNSPECIFIED);
        let mut route = replay_route(
            Mode::Layer2,
            LinkType::ETHERNET,
            Ipv4Addr::new(192, 0, 2, 1),
        );
        route.packet_source = None;

        let error = SystemAuthorizer::new(registry(), crate::policy::Policy::default(), false)
            .authorize_final_wire(&frame, &route)
            .expect_err("the exact unspecified source requires spoofing approval");
        assert_eq!(error.classification().code, "policy.source_ownership");
    }

    #[test]
    fn final_wire_replay_does_not_replace_a_zero_captured_source_mac() {
        let frame = ethernet_frame([0; 6], Ipv4Addr::new(192, 0, 2, 1));
        let mut route = replay_route(
            Mode::Layer2,
            LinkType::ETHERNET,
            Ipv4Addr::new(192, 0, 2, 1),
        );
        route.source_mac = None;

        let error = SystemAuthorizer::new(registry(), crate::policy::Policy::default(), false)
            .authorize_final_wire(&frame, &route)
            .expect_err("the exact zero source MAC requires spoofing approval");
        assert_eq!(error.classification().code, "policy.source_ownership");
    }

    #[test]
    fn final_wire_replay_accepts_a_secondary_selected_interface_ip_source() {
        let secondary = Ipv4Addr::new(192, 0, 2, 9);
        let frame = ethernet_frame([0x02, 0, 0, 0, 0, 1], secondary);
        let mut route = replay_route(
            Mode::Layer2,
            LinkType::ETHERNET,
            Ipv4Addr::new(192, 0, 2, 1),
        );
        route.decision.preferred_source = Some(IpAddr::V4(secondary));

        SystemAuthorizer::new(registry(), crate::policy::Policy::default(), false)
            .authorize_final_wire(&frame, &route)
            .expect("an IP source owned by the selected interface is not spoofing");
    }

    #[test]
    fn caller_codec_cannot_hide_a_public_destination_from_replay_policy() {
        let mut packet = Packet::new();
        packet
            .push(Ipv4 {
                source: Ipv4Addr::new(192, 0, 2, 1),
                destination: Ipv4Addr::new(224, 0, 0, 251),
                ..Ipv4::default()
            })
            .push(Icmpv4::default());
        let built = Builder::new(registry())
            .build(packet, build::Context::default(), build::Options::default())
            .expect("public-destination fixture builds");
        let frame = raw_frame(&built);
        let policy = crate::policy::Policy {
            allow_permissive_packets: true,
            ..crate::policy::Policy::default()
        };
        let authorizer = SystemAuthorizer::new(opaque_raw_registry(), policy, true);

        let caller_decoded = authorizer
            .decode_frame(&frame)
            .expect("caller codec decodes the root opaquely");
        assert_eq!(caller_decoded.packet.len(), 1);
        assert!(
            caller_decoded
                .packet
                .layer(0)
                .is_some_and(|layer| layer.as_any().is::<Raw>())
        );
        let caller_rebuilt = authorizer
            .rebuild_frame(&caller_decoded)
            .expect("caller codec rebuilds its opaque layer");
        authorizer
            .validate_rebuild(&frame, &caller_rebuilt)
            .expect("caller codec round trip is exact");

        let error = authorizer
            .authorize_frame(&frame, Mode::Layer3)
            .expect_err("trusted policy decoding must still see the public destination");
        assert_eq!(error.classification().code, "policy.public_destination");
        assert!(error.to_string().contains("224.0.0.251"));
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
        let mut authorizer = SystemAuthorizer::new(registry(), policy, false);

        let packet_error = authorizer
            .authorize_operation(Operation::Replay(ReplayFrame::new(
                WireBudget::new(2, 1),
                &invalid_frame,
                Mode::Layer2,
            )))
            .expect_err("packet budget must fail first");
        assert_eq!(packet_error.classification().code, "policy.packet_limit");

        let byte_error = authorizer
            .authorize_operation(Operation::Replay(ReplayFrame::new(
                WireBudget::new(1, 3),
                &invalid_frame,
                Mode::Layer2,
            )))
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
        let authorizer = SystemAuthorizer::new(registry(), crate::policy::Policy::default(), false);
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
            SystemAuthorizer::new(registry(), crate::policy::Policy::default(), false)
                .authorize_frame(&frame, Mode::Layer3)
                .expect_err("operation opt-in is mandatory");
        assert_eq!(
            missing_operation_opt_in.classification().code,
            "policy.permissive_live_opt_in"
        );

        let missing_policy_opt_in =
            SystemAuthorizer::new(registry(), crate::policy::Policy::default(), true)
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
        SystemAuthorizer::new(registry(), policy, true)
            .authorize_frame(&frame, Mode::Layer3)
            .expect("both explicit approvals authorize the exact malformed bytes");
    }

    #[test]
    fn the_missing_replay_opt_in_keeps_its_published_message_and_remediation() {
        let frame = raw_frame(&built_ipv4(true));

        let error = SystemAuthorizer::new(registry(), crate::policy::Policy::default(), false)
            .authorize_frame(&frame, Mode::Layer3)
            .expect_err("operation opt-in is mandatory");

        assert_eq!(
            error.to_string(),
            "permissive or malformed captured bytes require --allow-malformed-live"
        );
        assert_eq!(
            error.classification().remediation,
            Some("set the per-operation malformed-live opt-in in addition to policy approval")
        );
    }

    #[test]
    fn replay_authorization_refuses_an_operation_with_no_frame() {
        let mut authorizer =
            SystemAuthorizer::new(registry(), crate::policy::Policy::default(), false);

        let error = authorizer
            .authorize_operation(Operation::Budgeted(WireBudget::new(1, 1)))
            .expect_err("a frameless replay operation cannot be authorized");

        assert_eq!(error.classification().kind, Kind::Internal);
        assert_eq!(
            error.classification().code,
            "internal.unsupported_operation"
        );

        let declared = authorizer
            .authorize_operation(Operation::Declared(DeclaredPackets::new(
                WireBudget::new(1, 1),
                &[],
                None,
                PermissiveLive::NotRequired,
            )))
            .expect_err("a declared-packet list is not an exact frame");
        assert_eq!(
            declared.classification().code,
            "internal.unsupported_operation"
        );
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
        let authorizer = SystemAuthorizer::new(registry(), crate::policy::Policy::default(), false);

        let error = authorizer
            .validate_rebuild(&different_frame, &built)
            .expect_err("semantic rebuild cannot substitute different bytes");
        assert_eq!(error.classification().code, "internal.replay_rebuild");
    }
}
