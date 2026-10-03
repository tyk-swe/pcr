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
                codec::Context::default(),
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

#[cfg(test)]
mod tests {
    #![allow(dead_code)]

    use std::collections::BTreeMap;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;
    use std::time::UNIX_EPOCH;

    use bytes::Bytes;
    use packetcraftr_core::build::{Builder, BuiltPacket};
    use packetcraftr_core::codec::{
        DecodedLayer, EncodedLayer, LayerCodec, LayerDecodeContext, LayerEncodeContext,
    };
    use packetcraftr_core::error::Classified;
    use packetcraftr_core::field::FieldValue;
    use packetcraftr_core::frame::LinkType;
    use packetcraftr_core::layer::{Layer, Raw};
    use packetcraftr_core::packet::MacAddress;
    use packetcraftr_core::packet::Packet;
    use packetcraftr_core::protocol::network::{Icmpv4, Ipv4};
    use packetcraftr_netio::interface::Id as InterfaceId;
    use packetcraftr_netio::link::Capability as LinkCapability;
    use packetcraftr_netio::route::{Decision, Scope, SelectionReason};

    use crate::route::Plan;

    use super::*;

    fn registry() -> Arc<Registry> {
        packetcraftr_core::protocol::builtin::registry()
    }

    fn frame_admission(
        registry: Arc<Registry>,
        policy: crate::policy::Policy,
        allow_permissive_live: bool,
    ) -> FrameAdmission<'static> {
        let policy = Box::leak(Box::new(policy));
        FrameAdmission::new(policy, registry, allow_permissive_live)
    }

    #[derive(Clone, Copy, Debug)]
    struct OpaqueRawCodec;

    impl LayerCodec for OpaqueRawCodec {
        fn protocol_id(&self) -> &'static packetcraftr_core::layer::Id {
            const PROTOCOL: &packetcraftr_core::layer::Id =
                &packetcraftr_core::layer::Id::new("raw");
            PROTOCOL
        }

        fn encode(
            &self,
            layer: &dyn Layer,
            _payload: &[u8],
            _context: &LayerEncodeContext<'_>,
        ) -> Result<EncodedLayer, packetcraftr_core::codec::Error> {
            let raw = layer.downcast_ref::<Raw>().ok_or_else(|| {
                packetcraftr_core::codec::Error::WrongLayer {
                    expected: "raw".into(),
                    actual: *layer.protocol_id(),
                }
            })?;
            let mut encoded = EncodedLayer::header(raw.bytes.to_vec(), Box::new(raw.clone()));
            encoded.fields = Raw::layout(raw.bytes.len());
            Ok(encoded)
        }

        fn decode(
            &self,
            input: Bytes,
            _context: &LayerDecodeContext<'_>,
        ) -> Result<DecodedLayer, packetcraftr_core::codec::Error> {
            let mut decoded =
                DecodedLayer::terminal(Box::new(Raw::new(input.clone())), input.len());
            decoded.fields = Raw::layout(input.len());
            Ok(decoded)
        }

        fn make_layer(
            &self,
            _fields: &BTreeMap<String, FieldValue>,
        ) -> Result<Box<dyn Layer>, packetcraftr_core::codec::Error> {
            Ok(Box::new(Raw::default()))
        }
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
                codec::Context::default(),
                build::Options {
                    mode: if reserved_flag {
                        codec::Mode::Permissive
                    } else {
                        codec::Mode::Strict
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
    fn final_wire_reuses_the_trusted_decode_from_frame_authorization() {
        let frame = raw_frame(&built_ipv4(false));
        let route = replay_route(Mode::Layer3, LinkType::RAW, Ipv4Addr::new(192, 0, 2, 99));
        let policy = crate::policy::Policy {
            allow_permissive_packets: true,
            ..crate::policy::Policy::default()
        };
        let mut authorizer = frame_admission(registry(), policy, true);
        authorizer
            .authorize_frame(&frame, Mode::Layer3)
            .expect("the frame authorizes before route planning");

        let error = authorizer
            .authorize_final_wire(&frame, &route)
            .expect_err("the retained decode still checks the captured source");
        assert_eq!(error.classification().code, "policy.source_ownership");

        let policy = crate::policy::Policy {
            allow_permissive_packets: true,
            allow_source_spoofing: true,
            ..crate::policy::Policy::default()
        };
        let mut authorizer = frame_admission(registry(), policy, true);
        authorizer
            .authorize_frame(&frame, Mode::Layer3)
            .expect("the frame authorizes before route planning");
        authorizer
            .authorize_final_wire(&frame, &route)
            .expect("the retained decode permits an approved source");
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
        let mut authorizer = frame_admission(registry(), policy, false);

        let packet_error = authorizer
            .admit_frame(WireLimits::new(2, 1), &invalid_frame, Mode::Layer2)
            .expect_err("packet budget must fail first");
        assert_eq!(packet_error.classification().code, "policy.packet_limit");

        let byte_error = authorizer
            .admit_frame(WireLimits::new(1, 3), &invalid_frame, Mode::Layer2)
            .expect_err("byte budget must fail before unsupported link type");
        assert_eq!(byte_error.classification().code, "policy.byte_limit");
    }
}
