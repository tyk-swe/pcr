// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use packetcraftr_core::frame::{Frame, LinkType};
use packetcraftr_packet::codec::{
    Codec, DecodeContext, Decoded, EncodeContext, Encoded, Error as CodecError,
};
use packetcraftr_packet::diagnostic::{Diagnostic, Severity, push_diagnostic_once};
use packetcraftr_packet::field::{FieldValue, WireValue};
use packetcraftr_packet::layer::{
    FieldError, Layer, Malformed, Padding, ProtocolId, Raw, malformed_layout, padding_layout,
    raw_layout,
};
use packetcraftr_packet::layout::{Field, Range};
use packetcraftr_packet::registry::{
    Builder as RegistryBuilder, Discriminator, Error as RegistryError,
};
use packetcraftr_packet::{
    Packet, build, decode, document, expression, reflective_layer, template,
};

#[derive(Clone, Debug, PartialEq, Eq)]
struct Probe {
    value: u8,
    enabled: bool,
    label: String,
    bytes: Bytes,
    ipv4: Ipv4Addr,
    ipv6: Ipv6Addr,
    mac: [u8; 6],
    token: [u8; 8],
    wire: WireValue<u16>,
}

impl Default for Probe {
    fn default() -> Self {
        Self {
            value: 1,
            enabled: false,
            label: "probe".to_owned(),
            bytes: Bytes::new(),
            ipv4: Ipv4Addr::UNSPECIFIED,
            ipv6: Ipv6Addr::UNSPECIFIED,
            mac: [0; 6],
            token: [0; 8],
            wire: WireValue::Auto,
        }
    }
}

reflective_layer! {
    fn probe_schema() => { protocol: ProtocolId::new("probe"), name: "Probe" }
    impl Probe {
        "value" => {
            kind: Unsigned, derived: false, required: true,
            description: "One-byte probe value",
            get |layer| Some(packetcraftr_packet::layer::reflect_get(&layer.value)),
            set |layer, value, name| packetcraftr_packet::layer::reflect_set(
                &mut layer.value, probe_schema(), name, value
            ),
            layout: (0, 1)
        },
        "enabled" => {
            kind: Bool, derived: false, required: true,
            description: "Probe flag",
            get |layer| Some(packetcraftr_packet::layer::reflect_get(&layer.enabled)),
            set |layer, value, name| packetcraftr_packet::layer::reflect_set(
                &mut layer.enabled, probe_schema(), name, value
            )
        },
        "label" => {
            kind: Text, derived: false, required: true,
            description: "Probe label",
            get |layer| Some(packetcraftr_packet::layer::reflect_get(&layer.label)),
            set |layer, value, name| packetcraftr_packet::layer::reflect_set(
                &mut layer.label, probe_schema(), name, value
            )
        },
        "bytes" => {
            kind: Bytes, derived: false, required: false,
            description: "Probe bytes",
            get |layer| Some(packetcraftr_packet::layer::reflect_get(&layer.bytes)),
            set |layer, value, name| packetcraftr_packet::layer::reflect_set(
                &mut layer.bytes, probe_schema(), name, value
            )
        },
        "ipv4" => {
            kind: Ipv4, derived: false, required: true,
            description: "Probe IPv4 address",
            get |layer| Some(packetcraftr_packet::layer::reflect_get(&layer.ipv4)),
            set |layer, value, name| packetcraftr_packet::layer::reflect_set(
                &mut layer.ipv4, probe_schema(), name, value
            )
        },
        "ipv6" => {
            kind: Ipv6, derived: false, required: true,
            description: "Probe IPv6 address",
            get |layer| Some(packetcraftr_packet::layer::reflect_get(&layer.ipv6)),
            set |layer, value, name| packetcraftr_packet::layer::reflect_set(
                &mut layer.ipv6, probe_schema(), name, value
            )
        },
        "mac" => {
            kind: Mac, derived: false, required: true,
            description: "Probe MAC address",
            get |layer| Some(packetcraftr_packet::layer::reflect_get(&layer.mac)),
            set |layer, value, name| packetcraftr_packet::layer::reflect_set(
                &mut layer.mac, probe_schema(), name, value
            )
        },
        "token" => {
            kind: Bytes, derived: false, required: true,
            description: "Eight-byte token",
            get |layer| Some(packetcraftr_packet::layer::reflect_get(&layer.token)),
            set |layer, value, name| packetcraftr_packet::layer::reflect_set(
                &mut layer.token, probe_schema(), name, value
            )
        },
        "wire" => {
            kind: Unsigned, derived: true, required: true,
            description: "Derived wire value",
            get |layer| Some(packetcraftr_packet::layer::reflect_get(&layer.wire)),
            set |layer, value, name| packetcraftr_packet::layer::reflect_set(
                &mut layer.wire, probe_schema(), name, value
            )
        }
    }
    layout fn probe_layout();
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Child {
    value: u8,
}

reflective_layer! {
    fn child_schema() => { protocol: ProtocolId::new("child"), name: "Child" }
    impl Child {
        "value" => {
            kind: Unsigned, derived: false, required: true,
            description: "Child value",
            get |layer| Some(packetcraftr_packet::layer::reflect_get(&layer.value)),
            set |layer, value, name| packetcraftr_packet::layer::reflect_set(
                &mut layer.value, child_schema(), name, value
            ),
            layout: (0, 1)
        }
    }
    layout fn child_layout();
}

#[derive(Clone, Copy, Debug)]
struct ProbeCodec;

impl Codec for ProbeCodec {
    fn protocol_id(&self) -> ProtocolId {
        "probe".into()
    }

    fn aliases(&self) -> &'static [&'static str] {
        &["p"]
    }

    fn encode(
        &self,
        layer: &dyn Layer,
        _payload: &[u8],
        _context: &EncodeContext<'_>,
    ) -> Result<Encoded, CodecError> {
        let probe =
            layer
                .as_any()
                .downcast_ref::<Probe>()
                .ok_or_else(|| CodecError::WrongLayer {
                    expected: "probe".into(),
                    actual: layer.protocol_id().clone(),
                })?;
        let mut encoded = Encoded::header(vec![probe.value], Box::new(probe.clone()));
        encoded.fields = probe_layout();
        encoded
            .diagnostics
            .push(Diagnostic::info("probe.encoded", "encoded probe"));
        Ok(encoded)
    }

    fn decode(&self, input: &[u8], _context: &DecodeContext<'_>) -> Result<Decoded, CodecError> {
        let Some(value) = input.first().copied() else {
            return Err(CodecError::Truncated {
                protocol: "probe".into(),
                needed: 1,
                available: 0,
            });
        };
        let payload_len = input.len() - 1;
        Ok(Decoded {
            layer: Box::new(Probe {
                value,
                ..Probe::default()
            }),
            consumed: 1,
            payload_offset: 1,
            payload_len,
            next: (payload_len != 0)
                .then_some(Discriminator(7))
                .into_iter()
                .collect(),
            fields: probe_layout(),
            diagnostics: vec![Diagnostic::warning("probe.decoded", "decoded probe")],
            stop: payload_len == 0,
            network: None,
        })
    }

    fn make_layer(
        &self,
        fields: &BTreeMap<String, FieldValue>,
    ) -> Result<Box<dyn Layer>, CodecError> {
        let mut layer = Probe::default();
        for (name, value) in fields {
            layer.set_field(name, value.clone())?;
        }
        Ok(Box::new(layer))
    }
}

#[derive(Clone, Copy, Debug)]
struct ChildCodec;

impl Codec for ChildCodec {
    fn protocol_id(&self) -> ProtocolId {
        "child".into()
    }

    fn encode(
        &self,
        layer: &dyn Layer,
        _payload: &[u8],
        _context: &EncodeContext<'_>,
    ) -> Result<Encoded, CodecError> {
        let child =
            layer
                .as_any()
                .downcast_ref::<Child>()
                .ok_or_else(|| CodecError::WrongLayer {
                    expected: "child".into(),
                    actual: layer.protocol_id().clone(),
                })?;
        let mut encoded = Encoded::header(vec![child.value], Box::new(child.clone()));
        encoded.fields = child_layout();
        Ok(encoded)
    }

    fn decode(&self, input: &[u8], _context: &DecodeContext<'_>) -> Result<Decoded, CodecError> {
        let value = input
            .first()
            .copied()
            .ok_or_else(|| CodecError::Truncated {
                protocol: "child".into(),
                needed: 1,
                available: 0,
            })?;
        let mut decoded = Decoded::terminal(Box::new(Child { value }), 1);
        decoded.fields = child_layout();
        Ok(decoded)
    }

    fn make_layer(
        &self,
        fields: &BTreeMap<String, FieldValue>,
    ) -> Result<Box<dyn Layer>, CodecError> {
        let mut layer = Child::default();
        for (name, value) in fields {
            layer.set_field(name, value.clone())?;
        }
        Ok(Box::new(layer))
    }
}

fn registry() -> packetcraftr_packet::registry::Registry {
    let mut builder = RegistryBuilder::new();
    builder.register_codec(ProbeCodec).expect("register probe");
    builder.register_codec(ChildCodec).expect("register child");
    builder.bind_link_type(777, "probe").expect("bind root");
    builder.bind("probe", 7, "child", 10).expect("bind child");
    builder.build().expect("valid test registry")
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
    assert_eq!(packet.all_by_protocol(&ProtocolId::new("probe")).count(), 2);
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
        Err(packetcraftr_packet::Error::IndexOutOfBounds { index: 9, len: 4 })
    ));

    let removed = packet
        .replace(0, Child { value: 9 })
        .expect("replace layer");
    assert_eq!(removed.protocol_id().as_str(), "child");
    assert!(packet.mutate_fixed_width_layer::<Child>(0, |child| child.value = 10));
    assert!(!packet.mutate_fixed_width_layer::<Probe>(0, |_| {}));
    assert!(!packet.mutate_fixed_width_layer::<Child>(99, |_| {}));
    assert_eq!(packet.get::<Child>().map(|child| child.value), Some(10));

    assert!(matches!(
        packet.remove(2),
        Err(packetcraftr_packet::Error::PaddingBoundaryRemoval { index: 2 })
    ));
    packet.remove(3).expect("padding itself can be removed");
    assert_eq!(packet.len(), 3);
    assert!(matches!(
        packet.remove(8),
        Err(packetcraftr_packet::Error::IndexOutOfBounds { index: 8, len: 3 })
    ));

    packet
        .edit(&"probe".into(), "value", 42_u8.into())
        .expect("edit reflected value");
    assert_eq!(
        packet
            .by_protocol(&"probe".into())
            .and_then(|layer| layer.field("value")),
        Some(42_u8.into())
    );
    assert!(packet.by_protocol_mut(&"absent".into()).is_none());
    assert!(matches!(
        packet.edit(&"absent".into(), "value", 1_u8.into()),
        Err(packetcraftr_packet::Error::ProtocolNotFound { .. })
    ));
    assert!(matches!(
        packet.edit(&"probe".into(), "unknown", 1_u8.into()),
        Err(packetcraftr_packet::Error::Field(
            FieldError::UnknownField { .. }
        ))
    ));
    assert!(matches!(
        packet.edit(&"probe".into(), "value", FieldValue::Unsigned(256)),
        Err(packetcraftr_packet::Error::Field(
            FieldError::OutOfRange { .. }
        ))
    ));

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
        vec![Field {
            name: "value".to_owned(),
            range: Range::new(0, 1)
        }]
    );
    assert_eq!(raw_layout(3)[0].range, Range::new(0, 3));
    assert_eq!(padding_layout(2)[0].range, Range::new(0, 2));
    assert_eq!(malformed_layout(4)[0].range, Range::new(0, 4));
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
        malformed.intended_protocol.as_ref().map(ProtocolId::as_str),
        Some("ipv4")
    );

    let mut diagnostics = Vec::new();
    push_diagnostic_once(
        &mut diagnostics,
        Diagnostic::info("once", "first")
            .at_layer(2)
            .at_field("value"),
    );
    push_diagnostic_once(&mut diagnostics, Diagnostic::error("once", "duplicate"));
    push_diagnostic_once(&mut diagnostics, Diagnostic::warning("other", "kept"));
    assert_eq!(diagnostics.len(), 2);
    assert_eq!(diagnostics[0].severity, Severity::Info);
    assert_eq!(diagnostics[0].layer, Some(2));
    assert_eq!(diagnostics[0].field.as_deref(), Some("value"));
    assert_eq!(diagnostics[1].severity, Severity::Warning);
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

#[test]
fn expressions_and_documents_round_trip_and_enforce_resource_bounds() {
    let registry = registry();
    let expression = concat!(
        "p(value=0x2a,enabled=true,label=\"hello\\nworld\",bytes=ignored,",
        "ipv4=192.0.2.1,ipv6=2001:db8::1,mac=00-11-22-33-44-55,",
        "token=ignored,wire=auto)"
    );
    let error = expression::parse(expression, &registry, expression::Options::default())
        .expect_err("incompatible custom byte fields should be rejected by the codec");
    assert!(matches!(error, expression::Error::Layer { layer: 0, .. }));

    let packet = expression::parse(
        "probe(value=42,enabled=true,label=hello,ipv4=192.0.2.1,ipv6=2001:db8::1,mac=00:11:22:33:44:55,wire=auto)",
        &registry,
        expression::Options::default(),
    )
    .expect("valid expression");
    let probe = packet.get::<Probe>().expect("probe layer");
    assert_eq!(probe.value, 42);
    assert!(probe.enabled);
    assert_eq!(probe.ipv4, Ipv4Addr::new(192, 0, 2, 1));

    assert_eq!(
        expression::decode_hex("0x01:ab-CD 20").expect("hex"),
        Bytes::from_static(&[1, 0xab, 0xcd, 0x20])
    );
    assert!(expression::decode_hex("abc").is_err());
    assert!(expression::decode_hex("zz").is_err());
    for source in ["", "probe(", "/probe", "probe(value=1,value=2)", "unknown"] {
        assert!(
            expression::parse(source, &registry, expression::Options::default()).is_err(),
            "{source}"
        );
    }
    assert!(matches!(
        expression::parse(
            "probe",
            &registry,
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
            &registry,
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
            &registry,
            expression::Options {
                max_nesting: expression::MAX_EXPRESSION_NESTING + 1,
                ..expression::Options::default()
            },
        ),
        Err(expression::Error::InvalidNestingLimit { .. })
    ));

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
        document::Packet::parse_with_limits(
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

#[test]
fn registry_build_decode_and_error_paths_are_bounded() {
    let registry = Arc::new(registry());
    assert_eq!(
        registry.protocol_named(" P ").map(ProtocolId::as_str),
        Some("probe")
    );
    assert!(registry.codec_named("P").is_some());
    assert_eq!(
        registry.root_for_link_type(777).map(ProtocolId::as_str),
        Some("probe")
    );
    assert_eq!(
        registry
            .child_for("probe", Discriminator(7))
            .map(ProtocolId::as_str),
        Some("child")
    );
    assert_eq!(
        registry.discriminator_for("probe", "child"),
        Some(Discriminator(7))
    );
    assert_eq!(registry.protocols().len(), 2);
    assert_eq!(registry.link_type_roots().len(), 1);
    assert!(format!("{registry:?}").contains("binding_count"));

    let mut packet = Packet::new();
    packet.push(Probe {
        value: 9,
        ..Probe::default()
    });
    packet.push(Child { value: 4 });
    let builder = build::Builder::new(Arc::clone(&registry));
    let built = builder
        .build(packet, build::Context::default(), build::Options::default())
        .expect("bound packet builds");
    assert_eq!(built.bytes.as_ref(), &[9, 4]);
    assert_eq!(built.layout.layers.len(), 2);
    assert_eq!(
        built.layout.layer(1).expect("child layout").range,
        Range::new(1, 2)
    );
    assert_eq!(built.packet.encoded_payload_length(0), Some(1));
    assert_eq!(built.packet.encoded_payload_length(1), Some(0));
    assert_eq!(built.diagnostics[0].layer, Some(0));

    let decoded = decode::Decoder::new(Arc::clone(&registry))
        .decode_with_root(
            built.bytes.clone(),
            "probe".into(),
            decode::Options::default(),
        )
        .expect("bound packet decodes");
    assert_eq!(decoded.packet.len(), 2);
    assert_eq!(decoded.original.as_ref(), &[9, 4]);
    assert_eq!(decoded.layout.layers.len(), 2);
    assert_eq!(decoded.diagnostics.len(), 1);

    let frame = Frame::new(
        SystemTime::UNIX_EPOCH + Duration::from_secs(5),
        LinkType(777),
        vec![7, 3],
    )
    .expect("frame");
    assert_eq!(
        decode::Decoder::new(Arc::clone(&registry))
            .decode(frame, decode::Options::default())
            .expect("root lookup")
            .packet
            .len(),
        2
    );
    let unsupported = Frame::new(SystemTime::UNIX_EPOCH, LinkType(778), vec![1, 2]).expect("frame");
    let raw = decode::Decoder::new(Arc::clone(&registry))
        .decode(unsupported, decode::Options::default())
        .expect("unsupported roots become raw packets");
    assert_eq!(
        raw.packet.get::<Raw>().map(|raw| raw.bytes.as_ref()),
        Some(&[1, 2][..])
    );
    assert_eq!(raw.diagnostics[0].code, "decode.unsupported_link_type");

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
        decode::Decoder::new(Arc::clone(&registry)).decode_with_root(
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
        decode::Decoder::new(Arc::clone(&registry)).decode_with_root(
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
        decode::Decoder::new(Arc::clone(&registry)).decode_with_root(
            vec![1],
            "missing".into(),
            decode::Options::default(),
        ),
        Err(decode::Error::MissingRootCodec { .. })
    ));
    let malformed = decode::Decoder::new(registry)
        .decode_with_root(Vec::<u8>::new(), "probe".into(), decode::Options::default())
        .expect("codec errors are preserved as malformed layers");
    assert!(malformed.packet.get::<Malformed>().is_some());
    assert_eq!(malformed.diagnostics[0].code, "decode.malformed_layer");
}

#[test]
fn registry_rejects_alias_binding_and_filter_contract_conflicts() {
    let mut duplicate = RegistryBuilder::new();
    duplicate.register_codec(ProbeCodec).expect("first codec");
    assert!(matches!(
        duplicate.register_codec(ProbeCodec),
        Err(RegistryError::DuplicateProtocol { .. })
    ));

    let mut roots = RegistryBuilder::new();
    roots.bind_link_type(1, "probe").expect("first root");
    assert!(matches!(
        roots.bind_link_type(1, "child"),
        Err(RegistryError::DuplicateLinkType { link_type: 1 })
    ));
    assert!(matches!(
        roots.build(),
        Err(RegistryError::UnknownProtocol { .. })
    ));

    let mut bindings = RegistryBuilder::new();
    bindings.register_codec(ProbeCodec).expect("probe");
    bindings.register_codec(ChildCodec).expect("child");
    bindings.bind("probe", 7, "child", 1).expect("binding");
    assert!(matches!(
        bindings.bind("probe", 7, "probe", 1),
        Err(RegistryError::BindingConflict {
            discriminator: 7,
            priority: 1,
            ..
        })
    ));
    assert!(matches!(
        bindings.bind("probe", 7, "child", 2),
        Err(RegistryError::BindingConflict { .. })
    ));

    use packetcraftr_packet::registry::FilterFieldBinding;
    let mut invalid = RegistryBuilder::new();
    assert!(matches!(
        invalid.bind_filter_field(
            "empty",
            FilterFieldBinding::Either {
                protocol: "probe".into(),
                fields: &[]
            },
        ),
        Err(RegistryError::InvalidFilterField { .. })
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
        Err(RegistryError::InvalidFilterField { .. })
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
        Err(RegistryError::InvalidFilterField { .. })
    ));

    let mut canonical = RegistryBuilder::new();
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
        Err(RegistryError::DuplicateFilterField { .. })
    ));

    let mut unknown = RegistryBuilder::new();
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
        Err(RegistryError::UnknownFilterField { .. })
    ));

    let mut wrong_kind = RegistryBuilder::new();
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
        Err(RegistryError::InvalidFilterField { .. })
    ));
}
