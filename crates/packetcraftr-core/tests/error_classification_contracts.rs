// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
// Test code indexes fixtures and counts by hand; the fail-closed lints are
// for library paths.
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

//! Every public error variant renders a stable, non-empty message and, where
//! the type is classified, carries the code and kind the CLI contract relies on.

use std::net::Ipv6Addr;

use packetcraftr_core::codec;
use packetcraftr_core::decode::{Dissector, Options as DecodeOptions};
use packetcraftr_core::error::{Classified, Kind};
use packetcraftr_core::frame::{Error as FrameError, Frame, LinkType};
use packetcraftr_core::layer::{FieldError, Id, Malformed};
use packetcraftr_core::packet::semantics::{Error as SemanticsError, live_destinations};
use packetcraftr_core::{build, decode, registry};

fn ipv4() -> Id {
    Id::new("ipv4")
}

fn tcp() -> Id {
    Id::new("tcp")
}

fn field_error() -> FieldError {
    FieldError::MissingRequired {
        protocol: ipv4(),
        field: "destination".to_owned(),
    }
}

/// A message is "stable-looking" when it names the failing thing without
/// leaking debug formatting of the enum itself.
fn assert_message_is_stable(message: &str, variant: &str) {
    assert!(!message.is_empty(), "{variant} must render a message");
    assert!(
        !message.contains(variant),
        "{variant} must render prose, not its variant name: {message}"
    );
    assert!(
        !message.contains("{ ") && !message.contains(" }"),
        "{variant} must not leak debug struct formatting: {message}"
    );
}

#[test]
fn every_build_error_variant_renders_and_classifies_stably() {
    let cases: Vec<(&str, build::Error, &str, Kind)> = vec![
        (
            "EmptyPacket",
            build::Error::EmptyPacket,
            "packet.empty",
            Kind::Packet,
        ),
        (
            "LayerLimit",
            build::Error::LayerLimit {
                actual: 9,
                limit: 8,
            },
            "policy.build_resource_limit",
            Kind::Policy,
        ),
        (
            "PacketSizeLimit",
            build::Error::PacketSizeLimit {
                actual: 65_536,
                limit: 65_535,
            },
            "policy.build_resource_limit",
            Kind::Policy,
        ),
        (
            "MissingCodec",
            build::Error::MissingCodec {
                index: 1,
                protocol: Id::new("mystery"),
            },
            "packet.missing_codec",
            Kind::Packet,
        ),
        (
            "InvalidLayer",
            build::Error::InvalidLayer {
                index: 0,
                protocol: ipv4(),
                source: field_error(),
            },
            "packet.invalid_layer",
            Kind::Packet,
        ),
        (
            "UnboundLayers",
            build::Error::UnboundLayers {
                parent: tcp(),
                child: ipv4(),
            },
            "packet.unbound_layers",
            Kind::Packet,
        ),
        (
            "Codec",
            build::Error::Codec {
                index: 0,
                protocol: ipv4(),
                source: codec::Error::Invalid {
                    protocol: ipv4(),
                    message: "options exceed the 40-byte IPv4 limit".to_owned(),
                },
            },
            "packet.codec",
            Kind::Packet,
        ),
        (
            "LengthOverflow",
            build::Error::LengthOverflow,
            "packet.length_overflow",
            Kind::Packet,
        ),
        (
            "AllocationFailure",
            build::Error::AllocationFailure {
                requested: usize::MAX,
            },
            "policy.build_resource_limit",
            Kind::Policy,
        ),
        (
            "MaterializedProtocolMismatch",
            build::Error::MaterializedProtocolMismatch {
                protocol: ipv4(),
                actual: tcp(),
            },
            "internal.codec_contract",
            Kind::Internal,
        ),
        (
            "InvalidCodecLayout",
            build::Error::InvalidCodecLayout { protocol: ipv4() },
            "internal.codec_contract",
            Kind::Internal,
        ),
        (
            "InvalidPaddingBoundary",
            build::Error::InvalidPaddingBoundary {
                index: 2,
                outside_layer: 5,
            },
            "packet.padding_boundary",
            Kind::Packet,
        ),
        (
            "PaddingWithoutLinkLayer",
            build::Error::PaddingWithoutLinkLayer { index: 0 },
            "packet.padding_boundary",
            Kind::Packet,
        ),
    ];

    for (variant, error, code, kind) in cases {
        assert_message_is_stable(&error.to_string(), variant);
        let classification = error.classification();
        assert_eq!(classification.code, code, "{variant}");
        assert_eq!(classification.kind, kind, "{variant}");
        assert!(
            classification.remediation.is_some(),
            "{variant} must carry remediation"
        );
    }
}

#[test]
fn every_decode_error_variant_renders_and_classifies_stably() {
    let cases: Vec<(&str, decode::Error, &str, Kind)> = vec![
        (
            "PacketSizeLimit",
            decode::Error::PacketSizeLimit {
                actual: 70_000,
                limit: 65_535,
            },
            "policy.decode_resource_limit",
            Kind::Policy,
        ),
        (
            "LayerLimit",
            decode::Error::LayerLimit { limit: 0 },
            "policy.decode_resource_limit",
            Kind::Policy,
        ),
        (
            "MissingRootCodec",
            decode::Error::MissingRootCodec {
                protocol: Id::new("linktype_999"),
            },
            "packet.missing_codec",
            Kind::Packet,
        ),
        (
            "InvalidCodecCursor",
            decode::Error::InvalidCodecCursor { protocol: ipv4() },
            "internal.codec_contract",
            Kind::Internal,
        ),
        (
            "InvalidCodecLayout",
            decode::Error::InvalidCodecLayout { protocol: ipv4() },
            "internal.codec_contract",
            Kind::Internal,
        ),
        (
            "CodecLayerMismatch",
            decode::Error::CodecLayerMismatch {
                protocol: ipv4(),
                actual: tcp(),
            },
            "internal.codec_contract",
            Kind::Internal,
        ),
        (
            "InvalidLayer",
            decode::Error::InvalidLayer {
                protocol: ipv4(),
                source: field_error(),
            },
            "internal.codec_contract",
            Kind::Internal,
        ),
        (
            "InvalidFrame",
            decode::Error::InvalidFrame(FrameError::CapturedLengthMismatch {
                declared: 4,
                actual: 3,
            }),
            FrameError::CapturedLengthMismatch {
                declared: 4,
                actual: 3,
            }
            .classification()
            .code,
            FrameError::CapturedLengthMismatch {
                declared: 4,
                actual: 3,
            }
            .classification()
            .kind,
        ),
    ];

    for (variant, error, code, kind) in cases {
        assert_message_is_stable(&error.to_string(), variant);
        let classification = error.classification();
        assert_eq!(classification.code, code, "{variant}");
        assert_eq!(classification.kind, kind, "{variant}");
    }
}

#[test]
fn registry_duplicate_alias_and_matcher_errors_name_the_conflict() {
    let alias = registry::Error::DuplicateAlias {
        alias: "ip".to_owned(),
        existing: ipv4(),
    };
    assert_message_is_stable(&alias.to_string(), "DuplicateAlias");
    assert!(alias.to_string().contains("alias ip"));
    assert!(alias.to_string().contains("ipv4"));

    let matcher = registry::Error::DuplicateMatcher { protocol: tcp() };
    assert_message_is_stable(&matcher.to_string(), "DuplicateMatcher");
    assert!(matcher.to_string().contains("matcher for tcp"));
}

#[test]
fn every_semantics_error_variant_renders_a_stable_refusal() {
    let header: Ipv6Addr = "2001:db8::1".parse().expect("fixture address");
    let active: Ipv6Addr = "2001:db8::2".parse().expect("fixture address");
    let cases: Vec<(&str, SemanticsError, &str)> = vec![
        (
            "Field",
            SemanticsError::Field {
                protocol: Id::new("arp"),
                field: "target_protocol",
                reason: "is missing",
            },
            "field target_protocol on layer arp is missing",
        ),
        (
            "NonAtomicFragment",
            SemanticsError::NonAtomicFragment { protocol: ipv4() },
            "non-atomic ipv4 fragment may hide a live destination",
        ),
        (
            "MalformedMayHideDestination",
            SemanticsError::MalformedMayHideDestination {
                protocol: "ipv4".to_owned(),
                reason: "truncated ipv4 layer".to_owned(),
            },
            "malformed ipv4 layer may hide a live destination: truncated ipv4 layer",
        ),
        (
            "UnknownProtocolRouteField",
            SemanticsError::UnknownProtocolRouteField {
                protocol: Id::new("route_mimic"),
                field: "destination",
            },
            "unknown protocol route_mimic exposes route-bearing field destination",
        ),
        (
            "LayerIndexOutOfRange",
            SemanticsError::LayerIndexOutOfRange,
            "IP layer index is outside the packet",
        ),
        (
            "DuplicateSegmentRoutingHeader",
            SemanticsError::DuplicateSegmentRoutingHeader,
            "more than one SRH",
        ),
        (
            "DetachedSegmentRoutingHeader",
            SemanticsError::DetachedSegmentRoutingHeader,
            "SRH is not in a contiguous typed extension chain",
        ),
        (
            "SegmentCount",
            SemanticsError::SegmentCount,
            "SRH requires 1..=127 IPv6 segments",
        ),
        (
            "SegmentCountUnrepresentable",
            SemanticsError::SegmentCountUnrepresentable,
            "SRH segment count cannot be represented",
        ),
        (
            "SegmentLastEntry",
            SemanticsError::SegmentLastEntry {
                last_entry: 3,
                expected: 1,
            },
            "SRH last_entry 3 does not match segment-list index 1",
        ),
        (
            "SegmentsLeft",
            SemanticsError::SegmentsLeft {
                segments_left: 2,
                last_entry: 1,
            },
            "SRH segments_left 2 exceeds last_entry 1",
        ),
        (
            "SegmentFlags",
            SemanticsError::SegmentFlags,
            "unsupported SRH flags are non-zero",
        ),
        (
            "SegmentDestinationMismatch",
            SemanticsError::SegmentDestinationMismatch { header, active },
            "IPv6 header destination 2001:db8::1 does not match active SRH segment 2001:db8::2",
        ),
        (
            "Ipv4OptionsTooLong",
            SemanticsError::Ipv4OptionsTooLong,
            "IPv4 option bytes exceed the 40-byte header limit",
        ),
        (
            "Ipv4OptionMissingLength",
            SemanticsError::Ipv4OptionMissingLength,
            "IPv4 option is missing its length byte",
        ),
        (
            "Ipv4OptionLength",
            SemanticsError::Ipv4OptionLength {
                option: 7,
                length: 1,
            },
            "IPv4 option 7 has invalid length 1",
        ),
        (
            "Ipv4OptionTruncated",
            SemanticsError::Ipv4OptionTruncated { option: 7 },
            "IPv4 option 7 is truncated",
        ),
        (
            "Ipv4SourceRouteLength",
            SemanticsError::Ipv4SourceRouteLength {
                option: 131,
                length: 4,
            },
            "IPv4 source-route option 131 has invalid length 4",
        ),
        (
            "Ipv4SourceRoutePointer",
            SemanticsError::Ipv4SourceRoutePointer {
                option: 131,
                pointer: 3,
            },
            "IPv4 source-route option 131 has invalid pointer 3",
        ),
    ];

    for (variant, error, expected) in cases {
        let message = error.to_string();
        assert_message_is_stable(&message, variant);
        assert!(message.contains(expected), "{variant}: {message}");
        assert_eq!(error.clone(), error, "{variant} must compare by value");
    }
}

/// An Ethernet frame carrying an IPv4 header whose IHL promises 8 option
/// bytes that the wire does not carry. The trusted decoder cannot see the
/// options, so it cannot know whether they source-route the datagram elsewhere.
fn ethernet_ipv4_with_truncated_options() -> Vec<u8> {
    vec![
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x08, 0x00, 0x47,
        0x00, 0x00, 0x14, 0x00, 0x01, 0x00, 0x00, 0x40, 0xfd, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x05,
        0x0a, 0x00, 0x00, 0x02,
    ]
}

#[test]
fn ipv4_wire_with_truncated_options_may_hide_a_destination() {
    let frame =
        Frame::without_timestamp(LinkType::ETHERNET, ethernet_ipv4_with_truncated_options())
            .expect("fixture frame");
    let decoded = Dissector::new(packetcraftr_core::protocol::builtin::registry())
        .decode(frame, DecodeOptions::default())
        .expect("a malformed header decodes to a malformed layer, not a decode failure");

    let malformed = decoded
        .packet
        .iter()
        .find_map(|layer| layer.as_any().downcast_ref::<Malformed>())
        .expect("the truncated IPv4 header must decode as a malformed layer");
    assert_eq!(malformed.intended_protocol.as_deref(), Some("ipv4"));

    let error = live_destinations(&decoded.packet)
        .expect_err("a malformed IPv4 layer must not be authorized on its outer header");
    assert!(
        matches!(
            &error,
            SemanticsError::MalformedMayHideDestination { protocol, reason }
                if protocol == "ipv4" && reason == &malformed.reason
        ),
        "{error:?}"
    );
}
