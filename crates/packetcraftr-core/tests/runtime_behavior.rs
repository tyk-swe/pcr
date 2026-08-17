// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use packetcraftr_core::codec::{
    DecodedLayerValue, EncodedLayer, LayerCodec, LayerDecodeContext, LayerEncodeContext,
};
use packetcraftr_core::diagnostic::Diagnostic;
use packetcraftr_core::field::{FieldValue, WireValue};
use packetcraftr_core::frame::{Frame, LinkType};
use packetcraftr_core::layer::{
    FieldError, Layer, Malformed, Padding, Raw, malformed_layout, padding_layout, raw_layout,
};
use packetcraftr_core::layout::{ByteRange, FieldLayout};
use packetcraftr_core::registry::{Discriminator, FilterFieldBinding};
use packetcraftr_core::{Packet, build, decode, document, expression, reflective_layer, template};

include!("common/runtime_fixture.rs");

fn assert_failed_packet_mutations(packet: &mut Packet) {
    let before_failed_mutations = packet.clone();
    assert!(
        packet
            .layer_mut(0)
            .and_then(|layer| layer.as_any_mut().downcast_mut::<Probe>())
            .is_none()
    );
    assert!(packet.layer_mut(99).is_none());
    assert!(packet.get_mut::<Raw>().is_none());
    assert!(packet.by_protocol_mut(&"absent".into()).is_none());
    assert!(matches!(
        packet.replace(99, Child::default()),
        Err(packetcraftr_core::Error::IndexOutOfBounds { index: 99, len: 4 })
    ));
    assert!(packet.structurally_eq(&before_failed_mutations));
    assert_eq!(packet.get::<Child>().map(|child| child.value), Some(10));
}

#[test]
fn packet_mutation_reflection_and_boundaries_are_consistent() {
    let mut packet = Packet::with_capacity(4);
    assert!(packet.is_empty());
    packet.push(Probe::default()).push(Probe {
        value: 2,
        ..Probe::default()
    });
    assert_eq!(packet.len(), 2);
    assert_eq!(packet.get_all::<Probe>().count(), 2);
    assert_eq!(
        packet
            .all_by_protocol(&packetcraftr_core::layer::Id::new("probe"))
            .count(),
        2
    );
    assert_eq!(
        packet
            .iter()
            .next_back()
            .and_then(|layer| layer.field("value")),
        Some(2_u8.into())
    );

    packet.push(Padding::after_layer(vec![0xaa], 1));
    packet
        .insert(0, Child::default())
        .expect("insertion should shift an existing padding boundary");
    assert_eq!(
        packet
            .get::<Padding>()
            .and_then(|padding| padding.outside_layer),
        Some(2)
    );
    assert!(matches!(
        packet.insert(9, Raw::default()),
        Err(packetcraftr_core::Error::IndexOutOfBounds { index: 9, len: 4 })
    ));

    let removed = packet
        .replace(0, Child { value: 9 })
        .expect("replace layer");
    assert_eq!(removed.protocol_id().as_str(), "child");
    packet
        .layer_mut(0)
        .and_then(|layer| layer.as_any_mut().downcast_mut::<Child>())
        .expect("child layer at index 0")
        .value = 10;
    assert_failed_packet_mutations(&mut packet);

    assert!(matches!(
        packet.remove(2),
        Err(packetcraftr_core::Error::PaddingBoundaryRemoval { index: 2 })
    ));
    packet.remove(3).expect("padding itself can be removed");
    assert_eq!(packet.len(), 3);
    assert!(matches!(
        packet.remove(8),
        Err(packetcraftr_core::Error::IndexOutOfBounds { index: 8, len: 3 })
    ));

    packet
        .edit(&"probe".into(), "probe_value", 42_u8.into())
        .expect("edit reflected value");
    assert_eq!(
        packet
            .by_protocol(&"probe".into())
            .and_then(|layer| layer.field("probe_value")),
        Some(42_u8.into())
    );
    let before_failed_edits = packet.clone();
    assert!(packet.by_protocol_mut(&"absent".into()).is_none());
    assert!(matches!(
        packet.edit(&"absent".into(), "value", 1_u8.into()),
        Err(packetcraftr_core::Error::ProtocolNotFound { .. })
    ));
    assert!(matches!(
        packet.edit(&"probe".into(), "unknown", 1_u8.into()),
        Err(packetcraftr_core::Error::Field(
            FieldError::UnknownField { .. }
        ))
    ));
    assert!(matches!(
        packet.edit(&"probe".into(), "value", FieldValue::Unsigned(256)),
        Err(packetcraftr_core::Error::Field(
            FieldError::OutOfRange { .. }
        ))
    ));
    assert!(packet.structurally_eq(&before_failed_edits));

    let clone = packet.clone();
    assert!(packet.structurally_eq(&clone));
    packet.get_mut::<Probe>().expect("probe layer").value = 43;
    assert!(!packet.structurally_eq(&clone));
    assert!(format!("{packet:?}").contains("Probe"));

    let collected: Packet = [Child { value: 1 }, Child { value: 2 }]
        .into_iter()
        .collect();
    assert_eq!(collected.len(), 2);
}

#[test]
fn reflected_fields_cover_supported_types_and_fail_closed() {
    let mut layer = Probe::default();
    layer.set_field("enabled", true.into()).expect("bool");
    layer.set_field("label", "renamed".into()).expect("text");
    layer
        .set_field("bytes", vec![1, 2, 3].into())
        .expect("bytes");
    layer
        .set_field("ipv4", "192.0.2.4".into())
        .expect("IPv4 text");
    layer
        .set_field("ipv6", "2001:db8::4".into())
        .expect("IPv6 text");
    layer
        .set_field("mac", "00-11-22-33-44-55".into())
        .expect("MAC text");
    layer
        .set_field("token", FieldValue::Bytes(Bytes::from_static(b"12345678")))
        .expect("eight-byte token");
    layer
        .set_field("wire", "AUTO".into())
        .expect("auto wire value");
    assert_eq!(
        layer.field("wire"),
        Some(FieldValue::Text("auto".to_owned()))
    );
    layer
        .set_field("wire", 65_535_u64.into())
        .expect("exact wire value");
    assert_eq!(layer.wire.exact(), Some(&65_535));
    layer
        .set_field("wire", FieldValue::Bytes(Bytes::from_static(b"raw")))
        .expect("raw wire value");

    assert!(matches!(
        layer.set_field("enabled", 1_u8.into()),
        Err(FieldError::WrongType {
            expected: "bool",
            ..
        })
    ));
    assert!(matches!(
        layer.set_field("ipv4", "not-an-address".into()),
        Err(FieldError::WrongType {
            expected: "ipv4",
            ..
        })
    ));
    assert!(matches!(
        layer.set_field("ipv6", false.into()),
        Err(FieldError::WrongType {
            expected: "ipv6",
            ..
        })
    ));
    assert!(matches!(
        layer.set_field("mac", "00:11:22".into()),
        Err(FieldError::WrongType {
            expected: "mac address",
            ..
        })
    ));
    assert!(matches!(
        layer.set_field("token", vec![1, 2].into()),
        Err(FieldError::WrongType {
            expected: "eight bytes",
            ..
        })
    ));
    assert!(matches!(
        layer.set_field("wire", "manual".into()),
        Err(FieldError::WrongType {
            expected: "unsigned, bytes, or 'auto'",
            ..
        })
    ));

    let schema = layer.schema();
    assert_eq!(schema.name, "Probe");
    assert_eq!(schema.fields.len(), 9);
    layer
        .validate_required_fields()
        .expect("all required getters produce values");
    assert_eq!(
        probe_layout(),
        vec![FieldLayout {
            name: "value".to_owned(),
            range: ByteRange::new(0, 1)
        }]
    );
    assert_eq!(raw_layout(3)[0].range, ByteRange::new(0, 3));
    assert_eq!(padding_layout(2)[0].range, ByteRange::new(0, 2));
    assert_eq!(malformed_layout(4)[0].range, ByteRange::new(0, 4));
}

#[test]
fn field_values_raw_layers_and_diagnostics_have_stable_views() {
    let values = [
        FieldValue::Bool(true),
        FieldValue::Unsigned(7),
        FieldValue::Signed(-3),
        FieldValue::Text("text".to_owned()),
        FieldValue::Bytes(Bytes::from_static(&[0xab, 0xcd])),
        FieldValue::Ipv4(Ipv4Addr::LOCALHOST),
        FieldValue::Ipv6(Ipv6Addr::LOCALHOST),
        FieldValue::Mac([0, 1, 2, 3, 4, 5]),
        FieldValue::List(vec![1_u8.into(), "two".into()]),
    ];
    let rendered = values.iter().map(ToString::to_string).collect::<Vec<_>>();
    assert_eq!(
        rendered,
        [
            "true",
            "7",
            "-3",
            "text",
            "abcd",
            "127.0.0.1",
            "::1",
            "00:01:02:03:04:05",
            "1,two"
        ]
    );
    assert_eq!(values[1].as_u64(), Some(7));
    assert_eq!(values[0].as_bool(), Some(true));
    assert_eq!(values[0].as_u64(), None);
    assert_eq!(values[1].as_bool(), None);
    let serialized = serde_json::to_string(&values[4]).expect("serialize bytes field");
    assert_eq!(
        serde_json::from_str::<FieldValue>(&serialized).expect("deserialize bytes field"),
        values[4]
    );

    let mut raw = Raw::new(vec![1, 2]);
    assert_eq!(raw.field("bytes"), Some(vec![1, 2].into()));
    raw.set_field("bytes", vec![3].into())
        .expect("edit raw bytes");
    let mut padding = Padding::new(vec![0, 0]);
    assert_eq!(padding.field("outside_layer"), None);
    padding
        .set_field("outside_layer", 4_u8.into())
        .expect("set boundary");
    assert_eq!(padding.outside_layer, Some(4));
    assert!(matches!(
        padding.set_field("outside_layer", false.into()),
        Err(FieldError::WrongType { .. })
    ));
    let mut malformed = Malformed::new(None, vec![0xff], "bad header");
    malformed
        .set_field("protocol", "ipv4".into())
        .expect("set intended protocol");
    malformed
        .set_field("reason", "truncated".into())
        .expect("set reason");
    assert_eq!(
        malformed
            .intended_protocol
            .as_ref()
            .map(packetcraftr_core::layer::Id::as_str),
        Some("ipv4")
    );

    let mut diagnostics = Vec::new();
    packetcraftr_core::diagnostic::push_once(
        &mut diagnostics,
        Diagnostic::info("once", "first")
            .at_layer(2)
            .at_field("value"),
    );
    packetcraftr_core::diagnostic::push_once(
        &mut diagnostics,
        Diagnostic::error("once", "duplicate"),
    );
    packetcraftr_core::diagnostic::push_once(
        &mut diagnostics,
        Diagnostic::warning("other", "kept"),
    );
    assert_eq!(diagnostics.len(), 2);
    assert_eq!(
        diagnostics[0].severity,
        packetcraftr_core::diagnostic::Severity::Info
    );
    assert_eq!(diagnostics[0].layer, Some(2));
    assert_eq!(diagnostics[0].field.as_deref(), Some("value"));
    assert_eq!(
        diagnostics[1].severity,
        packetcraftr_core::diagnostic::Severity::Warning
    );
}

#[test]
fn templates_expand_cartesian_axes_and_report_limits_and_edit_errors() {
    let mut base = Packet::new();
    base.push(Probe::default());
    let template = template::Template::new(base)
        .axis(0, "value", vec![10_u8.into(), 11_u8.into()])
        .axis(
            0,
            "label",
            vec![
                FieldValue::Text("label-0".to_owned()),
                FieldValue::Text("label-1".to_owned()),
            ],
        );
    assert_eq!(template.expansion_len().expect("bounded product"), 4);
    assert!(matches!(
        template.expand(3),
        Err(template::Error::ExpansionLimit {
            requested: 4,
            limit: 3
        })
    ));
    let expanded = template
        .expand(4)
        .expect("within limit")
        .collect::<Result<Vec<_>, _>>()
        .expect("valid edits");
    let pairs = expanded
        .iter()
        .map(|packet| {
            let layer = packet.get::<Probe>().expect("probe");
            (layer.value, layer.label.as_str())
        })
        .collect::<Vec<_>>();
    assert_eq!(
        pairs,
        [
            (10, "label-0"),
            (10, "label-1"),
            (11, "label-0"),
            (11, "label-1")
        ]
    );

    let empty = template::Template::new(Packet::new()).axis(0, "value", Vec::new());
    assert_eq!(empty.expansion_len().expect("empty range"), 0);
    assert_eq!(empty.expand(0).expect("empty expansion").len(), 0);

    let bad_index = template::Template::new(Packet::new()).axis(1, "value", vec![1_u8.into()]);
    assert!(matches!(
        bad_index.expand(1).expect("one ordinal").next(),
        Some(Err(template::Error::LayerIndex { index: 1, len: 0 }))
    ));
    let mut packet = Packet::new();
    packet.push(Probe::default());
    let bad_field = template::Template::new(packet).axis(0, "missing", vec![1_u8.into()]);
    assert!(matches!(
        bad_field.expand(1).expect("one ordinal").next(),
        Some(Err(template::Error::Field { layer: 0, .. }))
    ));
}

fn parse_expression_fixture(registry: &packetcraftr_core::registry::Registry) -> Packet {
    let expression = concat!(
        "p(value=0x2a,enabled=true,label=\"hello\\nworld\",bytes=ignored,",
        "ipv4=192.0.2.1,ipv6=2001:db8::1,mac=00-11-22-33-44-55,",
        "token=ignored,wire=auto)"
    );
    let error = expression::parse(expression, registry, expression::Options::default())
        .expect_err("incompatible custom byte fields should be rejected by the codec");
    assert!(matches!(error, expression::Error::Layer { layer: 0, .. }));

    let packet = expression::parse(
        "probe(value=42,enabled=true,label=hello,ipv4=192.0.2.1,ipv6=2001:db8::1,mac=00:11:22:33:44:55,wire=auto)",
        registry,
        expression::Options::default(),
    )
    .expect("valid expression");
    let probe = packet.get::<Probe>().expect("probe layer");
    assert_eq!(probe.value, 42);
    assert!(probe.enabled);
    assert_eq!(probe.ipv4, Ipv4Addr::new(192, 0, 2, 1));

    assert_eq!(
        packetcraftr_core::protocol::raw::parse_hex("0x01:ab-CD 20").expect("hex"),
        Bytes::from_static(&[1, 0xab, 0xcd, 0x20])
    );
    assert!(packetcraftr_core::protocol::raw::parse_hex("abc").is_err());
    assert!(packetcraftr_core::protocol::raw::parse_hex("zz").is_err());
    for source in ["", "probe(", "/probe", "probe(value=1,value=2)", "unknown"] {
        assert!(
            expression::parse(source, registry, expression::Options::default()).is_err(),
            "{source}"
        );
    }
    assert!(matches!(
        expression::parse(
            "probe",
            registry,
            expression::Options {
                max_bytes: 4,
                ..expression::Options::default()
            },
        ),
        Err(expression::Error::SizeLimit { .. })
    ));
    assert!(matches!(
        expression::parse(
            "probe/probe",
            registry,
            expression::Options {
                max_layers: 1,
                ..expression::Options::default()
            },
        ),
        Err(expression::Error::LayerLimit { limit: 1 })
    ));
    assert!(matches!(
        expression::parse(
            "probe",
            registry,
            expression::Options {
                max_nesting: expression::MAX_EXPRESSION_NESTING + 1,
                ..expression::Options::default()
            },
        ),
        Err(expression::Error::InvalidNestingLimit { .. })
    ));
    packet
}

#[test]
fn expressions_and_documents_round_trip_and_enforce_resource_bounds() {
    let registry = registry();
    let packet = parse_expression_fixture(&registry);
    let document = document::Packet::from_packet(&packet);
    document.validate_schema().expect("current schema");
    let json = document.to_json_pretty().expect("JSON serialization");
    let yaml = document.to_yaml().expect("YAML serialization");
    let from_json =
        document::Packet::parse(&json, document::Format::Json, json.len()).expect("JSON parse");
    let from_yaml =
        document::Packet::parse(&yaml, document::Format::Yaml, yaml.len()).expect("YAML parse");
    assert_eq!(from_json, document);
    assert_eq!(from_yaml, document);
    assert!(
        document
            .to_packet(&registry, 1)
            .expect("document conversion")
            .structurally_eq(&packet)
    );

    let mut wrong_schema = document.clone();
    wrong_schema.schema = "future".to_owned();
    assert!(matches!(
        wrong_schema.validate_schema(),
        Err(document::Error::Schema { .. })
    ));
    assert!(matches!(
        document.to_packet(&registry, 0),
        Err(document::Error::LayerLimit { limit: 0 })
    ));
    let unknown = document::Packet {
        schema: document::PACKET_DOCUMENT_SCHEMA_V1.to_owned(),
        layers: vec![document::Layer {
            protocol: "absent".to_owned(),
            fields: BTreeMap::new(),
        }],
    };
    assert!(matches!(
        unknown.to_packet(&registry, 1),
        Err(document::Error::UnknownProtocol { .. })
    ));
    assert!(matches!(
        document::Packet::parse_with_nesting_limit(
            &json,
            document::Format::Json,
            json.len(),
            document::MAX_DOCUMENT_NESTING + 1,
        ),
        Err(document::Error::InvalidLimit { .. })
    ));
    assert!(document::Packet::parse("{} trailing", document::Format::Json, 20).is_err());
    assert!(document::Packet::parse("---\n{}\n---\n{}", document::Format::Yaml, 20).is_err());
}

fn assert_registry_queries(registry: &packetcraftr_core::registry::Registry) {
    assert_eq!(
        registry
            .protocol_named(" P ")
            .map(packetcraftr_core::layer::Id::as_str),
        Some("probe")
    );
    assert!(registry.codec_named("P").is_some());
    assert_eq!(
        registry
            .root_for_link_type(777)
            .map(packetcraftr_core::layer::Id::as_str),
        Some("probe")
    );
    assert_eq!(
        registry
            .child_for("probe", Discriminator(7))
            .map(packetcraftr_core::layer::Id::as_str),
        Some("child")
    );
    assert_eq!(
        registry.discriminator_for("probe", "child"),
        Some(Discriminator(7))
    );
    assert_eq!(registry.protocols().len(), 2);
    assert_eq!(registry.link_type_roots().len(), 1);
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

    let decoded = decode::Dissector::new(Arc::clone(registry))
        .decode_with_root(
            built.bytes.clone(),
            "probe".into(),
            decode::Options::default(),
        )
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
    assert!(failed_lookups.by_protocol_mut(&"absent".into()).is_none());
    assert!(failed_lookups.layer_mut(99).is_none());
    assert!(matches!(
        failed_lookups.insert_boxed(99, Box::new(Probe::default())),
        Err(packetcraftr_core::Error::IndexOutOfBounds { index: 99, len: 2 })
    ));
    assert!(matches!(
        failed_lookups.replace_boxed(99, Box::new(Probe::default())),
        Err(packetcraftr_core::Error::IndexOutOfBounds { index: 99, len: 2 })
    ));
    assert!(matches!(
        failed_lookups.remove(99),
        Err(packetcraftr_core::Error::IndexOutOfBounds { index: 99, len: 2 })
    ));
    assert!(failed_lookups.structurally_eq(&before_failed_lookups));
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
        decode::Dissector::new(Arc::clone(registry)).decode_with_root(
            vec![1],
            "probe".into(),
            decode::Options {
                max_layers: 0,
                ..decode::Options::default()
            },
        ),
        Err(decode::Error::LayerLimit { limit: 0 })
    ));
    assert!(matches!(
        decode::Dissector::new(Arc::clone(registry)).decode_with_root(
            vec![1, 2],
            "probe".into(),
            decode::Options {
                max_packet_size: 1,
                ..decode::Options::default()
            },
        ),
        Err(decode::Error::PacketSizeLimit { .. })
    ));
    assert!(matches!(
        decode::Dissector::new(Arc::clone(registry)).decode_with_root(
            vec![1],
            "missing".into(),
            decode::Options::default(),
        ),
        Err(decode::Error::MissingRootCodec { .. })
    ));
    let malformed = decode::Dissector::new(Arc::clone(registry))
        .decode_with_root(Vec::<u8>::new(), "probe".into(), decode::Options::default())
        .expect("codec errors are preserved as malformed layers");
    assert!(malformed.packet.get::<Malformed>().is_some());
    assert_eq!(malformed.diagnostics[0].code, "decode.malformed_layer");
}

#[test]
fn registry_build_decode_and_error_paths_are_bounded() {
    let registry = Arc::new(registry());
    assert_registry_queries(&registry);
    let (builder, decoded) = build_and_decode_probe(&registry);

    assert_failed_packet_lookups(decoded);
    assert_root_decode_behavior(&registry);
    assert_build_decode_limits(&registry, &builder);
}

fn assert_registry_binding_conflicts() {
    let mut duplicate = packetcraftr_core::registry::Builder::new();
    duplicate.register_codec(ProbeCodec).expect("first codec");
    assert!(matches!(
        duplicate.register_codec(ProbeCodec),
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
    bindings.register_codec(ProbeCodec).expect("probe");
    bindings.register_codec(ChildCodec).expect("child");
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
    canonical.register_codec(ProbeCodec).expect("probe");
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
    unknown.register_codec(ProbeCodec).expect("probe");
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
    wrong_kind.register_codec(ProbeCodec).expect("probe");
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
