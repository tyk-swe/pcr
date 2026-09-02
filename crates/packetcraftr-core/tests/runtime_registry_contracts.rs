// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
// Test code indexes fixtures and counts by hand; the fail-closed lints are
// for library paths.
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

//! Contracts for registry queries, build/decode bounds, and binding conflicts.

mod common;

use bytes::Bytes;
use common::probe::{
    Child, ChildCodec, PROBE_LINK_TYPE, Probe, ProbeCodec, probe_registry, structure,
};
use packetcraftr_core::frame::{Frame, LinkType};
use packetcraftr_core::layer::{Malformed, Raw, raw_layout};
use packetcraftr_core::layout::ByteRange;
use packetcraftr_core::registry::{Discriminator, FilterFieldBinding};
use packetcraftr_core::{Packet, build, decode};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

fn decode_probe(
    registry: &Arc<packetcraftr_core::registry::Registry>,
    bytes: impl Into<Bytes>,
    options: decode::Options,
) -> Result<decode::DecodedPacket, decode::Error> {
    let frame = Frame::new(SystemTime::UNIX_EPOCH, PROBE_LINK_TYPE, bytes)?;
    decode::Dissector::new(Arc::clone(registry)).decode(frame, options)
}

fn assert_registry_queries(registry: &packetcraftr_core::registry::Registry) {
    assert_eq!(
        registry
            .protocol_named(" P ")
            .map(|protocol| protocol.as_str()),
        Some("probe")
    );
    assert!(registry.codec_named("P").is_some());
    assert_eq!(
        registry
            .root_for_link_type(777)
            .map(|protocol| protocol.as_str()),
        Some("probe")
    );
    assert_eq!(
        registry
            .child_for("probe", Discriminator(7))
            .map(|protocol| protocol.as_str()),
        Some("child")
    );
    assert_eq!(
        registry.discriminator_for("probe", "child"),
        Some(Discriminator(7))
    );
    assert_eq!(registry.protocols().len(), 2);
    assert!(format!("{registry:?}").contains("binding_count"));
}

fn build_and_decode_probe(
    registry: &Arc<packetcraftr_core::registry::Registry>,
) -> (build::Builder, decode::DecodedPacket) {
    let mut packet = Packet::new();
    packet.push(Probe {
        value: 9,
        ..Probe::default()
    });
    packet.push(Child { value: 4 });
    let builder = build::Builder::new(Arc::clone(registry));
    let built = builder
        .build(packet, build::Context::default(), build::Options::default())
        .expect("bound packet builds");
    assert_eq!(built.bytes.as_ref(), &[9, 4]);
    assert_eq!(built.layout.layers.len(), 2);
    assert_eq!(
        built.layout.layer(1).expect("child layout").range,
        ByteRange::new(1, 2)
    );
    assert_eq!(built.packet.encoded_payload_length(0), Some(1));
    assert_eq!(built.packet.encoded_payload_length(1), Some(0));
    assert_eq!(built.diagnostics[0].layer, Some(0));

    let decoded = decode_probe(registry, built.bytes.clone(), decode::Options::default())
        .expect("bound packet decodes");
    assert_eq!(decoded.packet.len(), 2);
    assert_eq!(decoded.original.as_ref(), &[9, 4]);
    assert_eq!(decoded.layout.layers.len(), 2);
    assert_eq!(decoded.packet.encoded_payload_length(0), Some(1));
    assert_eq!(decoded.packet.encoded_payload_length(1), Some(0));
    assert_eq!(decoded.diagnostics.len(), 1);
    (builder, decoded)
}

fn assert_failed_packet_lookups(decoded: decode::DecodedPacket) {
    let before_failed_lookups = decoded.packet.clone();
    let mut failed_lookups = decoded.packet;
    assert!(failed_lookups.get_mut::<Raw>().is_none());
    assert!(failed_lookups.layer_mut(99).is_none());
    assert!(matches!(
        failed_lookups.insert(99, Probe::default()),
        Err(packetcraftr_core::PacketError::IndexOutOfBounds { index: 99, len: 2 })
    ));
    assert!(matches!(
        failed_lookups.replace(99, Probe::default()),
        Err(packetcraftr_core::PacketError::IndexOutOfBounds { index: 99, len: 2 })
    ));
    assert!(matches!(
        failed_lookups.remove(99),
        Err(packetcraftr_core::PacketError::IndexOutOfBounds { index: 99, len: 2 })
    ));
    assert_eq!(
        structure(&failed_lookups),
        structure(&before_failed_lookups)
    );
    assert_eq!(
        failed_lookups.encoded_payload_length(0),
        before_failed_lookups.encoded_payload_length(0)
    );
    assert_eq!(
        failed_lookups.encoded_payload_length(1),
        before_failed_lookups.encoded_payload_length(1)
    );
}

fn assert_root_decode_behavior(registry: &Arc<packetcraftr_core::registry::Registry>) {
    let frame = Frame::new(
        SystemTime::UNIX_EPOCH + Duration::from_secs(5),
        LinkType(777),
        vec![7, 3],
    )
    .expect("frame");
    assert_eq!(
        decode::Dissector::new(Arc::clone(registry))
            .decode(frame, decode::Options::default())
            .expect("root lookup")
            .packet
            .len(),
        2
    );
    let unsupported = Frame::new(SystemTime::UNIX_EPOCH, LinkType(778), vec![1, 2]).expect("frame");
    let raw = decode::Dissector::new(Arc::clone(registry))
        .decode(unsupported, decode::Options::default())
        .expect("unsupported roots become raw packets");
    assert_eq!(
        raw.packet.get::<Raw>().map(|raw| raw.bytes.as_ref()),
        Some(&[1, 2][..])
    );
    assert_eq!(raw.packet.encoded_payload_length(0), Some(0));
    assert_eq!(raw.layout.layers.len(), 1);
    assert_eq!(raw.layout.layers[0].range, ByteRange::new(0, 2));
    assert_eq!(raw.layout.layers[0].fields, raw_layout(2));
    assert_eq!(raw.diagnostics[0].code, "decode.unsupported_link_type");
}

fn assert_build_decode_limits(
    registry: &Arc<packetcraftr_core::registry::Registry>,
    builder: &build::Builder,
) {
    assert!(matches!(
        builder.build(
            Packet::new(),
            build::Context::default(),
            build::Options::default()
        ),
        Err(build::Error::EmptyPacket)
    ));
    let mut one = Packet::new();
    one.push(Probe::default());
    assert!(matches!(
        builder.build(
            one.clone(),
            build::Context::default(),
            build::Options {
                max_layers: 0,
                ..build::Options::default()
            },
        ),
        Err(build::Error::LayerLimit {
            actual: 1,
            limit: 0
        })
    ));
    assert!(matches!(
        builder.build(
            one,
            build::Context::default(),
            build::Options {
                max_packet_size: 0,
                ..build::Options::default()
            },
        ),
        Err(build::Error::PacketSizeLimit { .. })
    ));
    assert!(matches!(
        decode_probe(
            registry,
            vec![1],
            decode::Options {
                max_layers: 0,
                ..decode::Options::default()
            },
        ),
        Err(decode::Error::LayerLimit { limit: 0 })
    ));
    assert!(matches!(
        decode_probe(
            registry,
            vec![1, 2],
            decode::Options {
                max_packet_size: 1,
                ..decode::Options::default()
            },
        ),
        Err(decode::Error::PacketSizeLimit { .. })
    ));
    let malformed = decode_probe(registry, Vec::<u8>::new(), decode::Options::default())
        .expect("codec errors are preserved as malformed layers");
    assert!(malformed.packet.get::<Malformed>().is_some());
    assert_eq!(malformed.diagnostics[0].code, "decode.malformed_layer");
}

#[test]
fn registry_build_decode_and_error_paths_are_bounded() {
    let registry = Arc::new(probe_registry());
    assert_registry_queries(&registry);
    let (builder, decoded) = build_and_decode_probe(&registry);

    assert_failed_packet_lookups(decoded);
    assert_root_decode_behavior(&registry);
    assert_build_decode_limits(&registry, &builder);
}

fn assert_registry_binding_conflicts() {
    let mut duplicate = packetcraftr_core::registry::Builder::new();
    duplicate
        .register_codec(ProbeCodec, &["p"])
        .expect("first codec");
    assert!(matches!(
        duplicate.register_codec(ProbeCodec, &["p"]),
        Err(packetcraftr_core::registry::Error::DuplicateProtocol { .. })
    ));

    let mut roots = packetcraftr_core::registry::Builder::new();
    roots.bind_link_type(1, "probe").expect("first root");
    assert!(matches!(
        roots.bind_link_type(1, "child"),
        Err(packetcraftr_core::registry::Error::DuplicateLinkType { link_type: 1 })
    ));
    assert!(matches!(
        roots.build(),
        Err(packetcraftr_core::registry::Error::UnknownProtocol { .. })
    ));

    let mut bindings = packetcraftr_core::registry::Builder::new();
    bindings.register_codec(ProbeCodec, &["p"]).expect("probe");
    bindings.register_codec(ChildCodec, &[]).expect("child");
    bindings.bind("probe", 7, "child", 1).expect("binding");
    assert!(matches!(
        bindings.bind("probe", 7, "probe", 1),
        Err(packetcraftr_core::registry::Error::BindingConflict {
            discriminator: 7,
            priority: 1,
            ..
        })
    ));
    assert!(matches!(
        bindings.bind("probe", 7, "child", 2),
        Err(packetcraftr_core::registry::Error::BindingConflict { .. })
    ));
}

fn assert_filter_field_binding_conflicts() {
    let mut invalid = packetcraftr_core::registry::Builder::new();
    assert!(matches!(
        invalid.bind_filter_field(
            "empty",
            FilterFieldBinding::Either {
                protocol: "probe".into(),
                fields: &[]
            },
        ),
        Err(packetcraftr_core::registry::Error::InvalidFilterField { .. })
    ));
    assert!(matches!(
        invalid.bind_filter_field(
            "zero",
            FilterFieldBinding::Bits {
                protocol: "probe".into(),
                field: "value",
                mask: 0,
                shift: 0
            },
        ),
        Err(packetcraftr_core::registry::Error::InvalidFilterField { .. })
    ));
    assert!(matches!(
        invalid.bind_filter_field(
            "shift",
            FilterFieldBinding::Bits {
                protocol: "probe".into(),
                field: "value",
                mask: 1,
                shift: 64
            },
        ),
        Err(packetcraftr_core::registry::Error::InvalidFilterField { .. })
    ));

    let mut canonical = packetcraftr_core::registry::Builder::new();
    canonical.register_codec(ProbeCodec, &["p"]).expect("probe");
    canonical
        .bind_filter_field(
            "probe.value",
            FilterFieldBinding::Direct {
                protocol: "probe".into(),
                field: "value",
            },
        )
        .expect("staged binding");
    assert!(matches!(
        canonical.build(),
        Err(packetcraftr_core::registry::Error::DuplicateFilterField { .. })
    ));

    let mut unknown = packetcraftr_core::registry::Builder::new();
    unknown.register_codec(ProbeCodec, &["p"]).expect("probe");
    unknown
        .bind_filter_field(
            "probe.nope",
            FilterFieldBinding::Direct {
                protocol: "probe".into(),
                field: "nope",
            },
        )
        .expect("staged binding");
    assert!(matches!(
        unknown.build(),
        Err(packetcraftr_core::registry::Error::UnknownFilterField { .. })
    ));

    let mut wrong_kind = packetcraftr_core::registry::Builder::new();
    wrong_kind
        .register_codec(ProbeCodec, &["p"])
        .expect("probe");
    wrong_kind
        .bind_filter_field(
            "probe.label.flag",
            FilterFieldBinding::Bits {
                protocol: "probe".into(),
                field: "label",
                mask: 1,
                shift: 0,
            },
        )
        .expect("staged binding");
    assert!(matches!(
        wrong_kind.build(),
        Err(packetcraftr_core::registry::Error::InvalidFilterField { .. })
    ));
}

#[test]
fn registry_rejects_alias_binding_and_filter_contract_conflicts() {
    assert_registry_binding_conflicts();
    assert_filter_field_binding_conflicts();
}
