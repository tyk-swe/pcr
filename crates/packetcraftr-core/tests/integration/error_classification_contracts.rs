// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr_core::analysis::{self, Constraint};
use packetcraftr_core::codec;
use packetcraftr_core::error::{BoundaryError, Classified, Kind};
use packetcraftr_core::field;
use packetcraftr_core::frame::Error as FrameError;
use packetcraftr_core::layer::Id;
use packetcraftr_core::{build, decode};

fn ipv4() -> Id {
    Id::new("ipv4")
}

fn tcp() -> Id {
    Id::new("tcp")
}

fn field_error() -> field::Error {
    field::Error::MissingRequired {
        protocol: ipv4(),
        field: "destination".to_owned(),
    }
}

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
fn every_build_error_renders_class_stably() {
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
fn every_decode_error_renders_class_stably() {
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
            "packet.frame_metadata",
            Kind::Packet,
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
fn analysis_errors_class_distinct() {
    let invalid = analysis::Error::InvalidLimit {
        field: "max_flows",
        value: 0,
        reason: Constraint::NonZero,
    };
    assert_eq!(invalid.classification().kind, Kind::Usage);
    let stream = analysis::Error::StreamLimit {
        number: 2,
        limit: 1,
    };
    assert_eq!(stream.classification().kind, Kind::Policy);
    let malformed = analysis::Error::Reassembly {
        number: 3,
        source: analysis::reassembly::tcp::Malformed::ConflictingFinalSequence {
            existing_offset: 1,
            new_offset: 2,
        }
        .into(),
    };
    assert_eq!(malformed.classification().kind, Kind::Packet);
    assert_eq!(malformed.causes().len(), 1);
    let bounded = analysis::Error::Reassembly {
        number: 3,
        source: analysis::reassembly::tcp::Resource::FlowByteLimit { limit: 8 }.into(),
    };
    assert_eq!(bounded.classification().kind, Kind::Policy);
    let tcp_remediation = bounded
        .classification()
        .remediation
        .expect("TCP resource failures have remediation");
    assert!(tcp_remediation.contains("trim or pre-filter the capture"));
    assert!(tcp_remediation.contains("--max-tcp-*"));
    let bounded_ip = analysis::Error::IpReassembly {
        number: 3,
        source: analysis::reassembly::ip::Resource::AggregateMemoryLimit { limit: 8 }.into(),
    };
    let remediation = bounded_ip
        .classification()
        .remediation
        .expect("IP resource failures have remediation");
    assert!(remediation.contains("trim or pre-filter the capture"));
    assert!(remediation.contains("--max-ip-*"));
    let inconsistent = analysis::Error::IpReassembly {
        number: 4,
        source: analysis::reassembly::ip::Error::Inconsistent {
            reason: "retained datagram family disagrees with its key",
        },
    };
    assert_eq!(inconsistent.classification().kind, Kind::Internal);
    assert_eq!(inconsistent.classification().code, "internal.ip_reassembly");
    let bounded_scope = analysis::Error::Scope {
        number: 3,
        source: analysis::scope::Error::Limit { limit: 8 },
    };
    assert_eq!(bounded_scope.classification().kind, Kind::Policy);
    for source in [
        analysis::scope::Error::Unknown { scope: 7 },
        analysis::scope::Error::ReplayMismatch { scope: 7 },
    ] {
        let invariant = analysis::Error::Scope { number: 3, source };
        assert_eq!(invariant.classification().kind, Kind::Internal);
        assert_eq!(
            invariant.classification().code,
            "internal.scope_composition"
        );
    }
    let sink = analysis::Error::Sink {
        number: 4,
        source: BoundaryError::execution_validation("bad sink", "test.sink", "repair it"),
    };
    assert_eq!(sink.classification().code, "test.sink");
    assert_eq!(sink.to_string(), "analysis consumer failed at frame 4");
    assert_eq!(sink.causes(), ["bad sink"]);
}
