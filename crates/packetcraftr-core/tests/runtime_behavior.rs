// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
// Test code indexes fixtures and counts by hand; the fail-closed lints are
// for library paths.
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

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
    fn probe_schema() => { protocol: packetcraftr_core::layer::Id::new("probe"), name: "Probe" }
    impl Probe {
        "value" | "probe_value" => {
            kind: Unsigned, tier: Required,
            description: "One-byte probe value",
            reflect: value,
            layout: (0, 1)
        },
        "enabled" => {
            kind: Bool, tier: Required,
            description: "Probe flag",
            get |layer| Some(packetcraftr_core::layer::reflect_get(&layer.enabled)),
            set |layer, value, name| packetcraftr_core::layer::reflect_set(
                &mut layer.enabled, probe_schema(), name, value
            )
        },
        "label" => {
            kind: Text, tier: Required,
            description: "Probe label",
            get |layer| Some(packetcraftr_core::layer::reflect_get(&layer.label)),
            set |layer, value, name| packetcraftr_core::layer::reflect_set(
                &mut layer.label, probe_schema(), name, value
            )
        },
        "bytes" => {
            kind: Bytes, tier: Optional, default: "0x",
            description: "Probe bytes",
            get |layer| Some(packetcraftr_core::layer::reflect_get(&layer.bytes)),
            set |layer, value, name| packetcraftr_core::layer::reflect_set(
                &mut layer.bytes, probe_schema(), name, value
            )
        },
        "ipv4" => {
            kind: Ipv4, tier: Required,
            description: "Probe IPv4 address",
            get |layer| Some(packetcraftr_core::layer::reflect_get(&layer.ipv4)),
            set |layer, value, name| packetcraftr_core::layer::reflect_set(
                &mut layer.ipv4, probe_schema(), name, value
            )
        },
        "ipv6" => {
            kind: Ipv6, tier: Required,
            description: "Probe IPv6 address",
            get |layer| Some(packetcraftr_core::layer::reflect_get(&layer.ipv6)),
            set |layer, value, name| packetcraftr_core::layer::reflect_set(
                &mut layer.ipv6, probe_schema(), name, value
            )
        },
        "mac" => {
            kind: Mac, tier: Required,
            description: "Probe MAC address",
            get |layer| Some(packetcraftr_core::layer::reflect_get(&layer.mac)),
            set |layer, value, name| packetcraftr_core::layer::reflect_set(
                &mut layer.mac, probe_schema(), name, value
            )
        },
        "token" => {
            kind: Bytes, tier: Required,
            description: "Eight-byte token",
            get |layer| Some(packetcraftr_core::layer::reflect_get(&layer.token)),
            set |layer, value, name| packetcraftr_core::layer::reflect_set(
                &mut layer.token, probe_schema(), name, value
            )
        },
        "wire" => {
            kind: Unsigned, tier: Derived,
            description: "Derived wire value",
            wire: wire
        }
    }
    layout fn probe_layout();
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Child {
    value: u8,
}

reflective_layer! {
    fn child_schema() => { protocol: packetcraftr_core::layer::Id::new("child"), name: "Child" }
    impl Child {
        "value" => {
            kind: Unsigned, tier: Required,
            description: "Child value",
            get |layer| Some(packetcraftr_core::layer::reflect_get(&layer.value)),
            set |layer, value, name| packetcraftr_core::layer::reflect_set(
                &mut layer.value, child_schema(), name, value
            ),
            layout: (0, 1)
        }
    }
    layout fn child_layout();
}

#[derive(Clone, Copy, Debug)]
struct ProbeCodec;

impl LayerCodec for ProbeCodec {
    fn protocol_id(&self) -> packetcraftr_core::layer::Id {
        "probe".into()
    }

    fn aliases(&self) -> &'static [&'static str] {
        &["p"]
    }

    fn encode(
        &self,
        layer: &dyn Layer,
        _payload: &[u8],
        _context: &LayerEncodeContext<'_>,
    ) -> Result<EncodedLayer, packetcraftr_core::codec::Error> {
        let probe = layer.as_any().downcast_ref::<Probe>().ok_or_else(|| {
            packetcraftr_core::codec::Error::WrongLayer {
                expected: "probe".into(),
                actual: layer.protocol_id().clone(),
            }
        })?;
        let mut encoded = EncodedLayer::header(vec![probe.value], Box::new(probe.clone()));
        encoded.fields = probe_layout();
        encoded
            .diagnostics
            .push(Diagnostic::info("probe.encoded", "encoded probe"));
        Ok(encoded)
    }

    fn decode(
        &self,
        input: &[u8],
        _context: &LayerDecodeContext<'_>,
    ) -> Result<DecodedLayerValue, packetcraftr_core::codec::Error> {
        let Some(value) = input.first().copied() else {
            return Err(packetcraftr_core::codec::Error::Truncated {
                protocol: "probe".into(),
                needed: 1,
                available: 0,
            });
        };
        let payload_len = input.len() - 1;
        Ok(DecodedLayerValue {
            layer: Box::new(Probe {
                value,
                ..Probe::default()
            }),
            consumed: 1,
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
    ) -> Result<Box<dyn Layer>, packetcraftr_core::codec::Error> {
        let mut layer = Probe::default();
        for (name, value) in fields {
            layer.set_field(name, value.clone())?;
        }
        Ok(Box::new(layer))
    }
}

#[derive(Clone, Copy, Debug)]
struct ChildCodec;

impl LayerCodec for ChildCodec {
    fn protocol_id(&self) -> packetcraftr_core::layer::Id {
        "child".into()
    }

    fn encode(
        &self,
        layer: &dyn Layer,
        _payload: &[u8],
        _context: &LayerEncodeContext<'_>,
    ) -> Result<EncodedLayer, packetcraftr_core::codec::Error> {
        let child = layer.as_any().downcast_ref::<Child>().ok_or_else(|| {
            packetcraftr_core::codec::Error::WrongLayer {
                expected: "child".into(),
                actual: layer.protocol_id().clone(),
            }
        })?;
        let mut encoded = EncodedLayer::header(vec![child.value], Box::new(child.clone()));
        encoded.fields = child_layout();
        Ok(encoded)
    }

    fn decode(
        &self,
        input: &[u8],
        _context: &LayerDecodeContext<'_>,
    ) -> Result<DecodedLayerValue, packetcraftr_core::codec::Error> {
        let value =
            input
                .first()
                .copied()
                .ok_or_else(|| packetcraftr_core::codec::Error::Truncated {
                    protocol: "child".into(),
                    needed: 1,
                    available: 0,
                })?;
        let mut decoded = DecodedLayerValue::terminal(Box::new(Child { value }), 1);
        decoded.fields = child_layout();
        Ok(decoded)
    }

    fn make_layer(
        &self,
        fields: &BTreeMap<String, FieldValue>,
    ) -> Result<Box<dyn Layer>, packetcraftr_core::codec::Error> {
        let mut layer = Child::default();
        for (name, value) in fields {
            layer.set_field(name, value.clone())?;
        }
        Ok(Box::new(layer))
    }
}

fn registry() -> packetcraftr_core::registry::Registry {
    let mut builder = packetcraftr_core::registry::Builder::new();
    builder
        .register_builtin_codec(ProbeCodec, ProbeCodec.aliases())
        .expect("register probe");
    builder
        .register_builtin_codec(ChildCodec, ChildCodec.aliases())
        .expect("register child");
    builder.bind_link_type(777, "probe").expect("bind root");
    builder.bind("probe", 7, "child", 10).expect("bind child");
    builder.build().expect("valid test registry")
}

/// The link type the fixture registry binds to the `probe` root.
const PROBE_LINK_TYPE: LinkType = LinkType(777);

/// Protocol order plus every reflected field, the comparison the document
/// projection preserves exactly.
fn structure(packet: &Packet) -> document::Packet {
    document::Packet::from_packet(packet)
}

fn decode_probe(
    registry: &Arc<packetcraftr_core::registry::Registry>,
    bytes: impl Into<Bytes>,
    options: decode::Options,
) -> Result<decode::DecodedPacket, decode::Error> {
    let frame = Frame::new(SystemTime::UNIX_EPOCH, PROBE_LINK_TYPE, bytes)?;
    decode::Dissector::new(Arc::clone(registry)).decode(frame, options)
}

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
    assert!(matches!(
        packet.replace(99, Child::default()),
        Err(packetcraftr_core::Error::IndexOutOfBounds { index: 99, len: 4 })
    ));
    assert_eq!(structure(packet), structure(&before_failed_mutations));
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
    assert_eq!(
        packet
            .iter()
            .filter(|layer| layer.as_any().is::<Probe>())
            .count(),
        2
    );
    assert_eq!(
        packet
            .iter()
            .filter(|layer| layer.protocol_id() == &packetcraftr_core::layer::Id::new("probe"))
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
        .get_mut::<Probe>()
        .expect("probe layer")
        .set_field("probe_value", 42_u8.into())
        .expect("edit reflected value");
    assert_eq!(
        packet
            .iter()
            .find(|layer| layer.protocol_id() == &packetcraftr_core::layer::Id::new("probe"))
            .and_then(|layer| layer.field("probe_value")),
        Some(42_u8.into())
    );
    let before_failed_edits = packet.clone();
    assert!(matches!(
        packet
            .get_mut::<Probe>()
            .expect("probe layer")
            .set_field("unknown", 1_u8.into()),
        Err(FieldError::UnknownField { .. })
    ));
    assert!(matches!(
        packet
            .get_mut::<Probe>()
            .expect("probe layer")
            .set_field("value", FieldValue::Unsigned(256)),
        Err(FieldError::OutOfRange { .. })
    ));
    assert_eq!(structure(&packet), structure(&before_failed_edits));

    let clone = packet.clone();
    assert_eq!(structure(&packet), structure(&clone));
    packet.get_mut::<Probe>().expect("probe layer").value = 43;
    assert_ne!(structure(&packet), structure(&clone));
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
fn templates_expand_one_axis_and_report_limits_and_edit_errors() {
    let mut base = Packet::new();
    base.push(Probe::default());
    let template = template::Template::new(base)
        .axis(0, "label", vec![FieldValue::Text("replaced".to_owned())])
        .axis(0, "value", vec![10_u8.into(), 11_u8.into(), 12_u8.into()]);
    assert_eq!(
        template.expansion_len().expect("bounded axis"),
        3,
        "a second axis replaces the first rather than multiplying with it"
    );
    assert!(matches!(
        template.expand(2),
        Err(template::Error::ExpansionLimit {
            requested: 3,
            limit: 2
        })
    ));
    let expanded = template
        .expand(3)
        .expect("within limit")
        .collect::<Result<Vec<_>, _>>()
        .expect("valid edits");
    let values = expanded
        .iter()
        .map(|packet| {
            let layer = packet.get::<Probe>().expect("probe");
            (layer.value, layer.label.as_str())
        })
        .collect::<Vec<_>>();
    assert_eq!(
        values,
        [(10, "probe"), (11, "probe"), (12, "probe")],
        "only the surviving axis is applied; the replaced one leaves no trace"
    );

    let axisless = template::Template::new(Packet::new());
    assert_eq!(axisless.expansion_len().expect("one packet"), 1);
    assert_eq!(axisless.expand(1).expect("one ordinal").len(), 1);

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
    // packet/v2 coercion
    assert!(matches!(
        error,
        expression::Error::Value {
            layer: 0,
            ref field,
            ..
        } if field == "bytes"
    ));

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
                max_nesting: 65,
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
    let json = serde_json::to_string_pretty(&document).expect("JSON serialization");
    let yaml = noyalib::to_string(&document).expect("YAML serialization");
    assert!(matches!(
        document::Packet::parse(&json, document::Format::Json, json.len() - 1),
        Err(document::Error::SizeLimit { .. })
    ));
    assert!(matches!(
        document::Packet::parse_with_resource_limits(
            &json,
            document::Format::Json,
            json.len(),
            0,
            document::DEFAULT_MAX_DOCUMENT_NESTING,
        ),
        Err(document::Error::LayerLimit { limit: 0 })
    ));
    let from_json =
        document::Packet::parse(&json, document::Format::Json, json.len()).expect("JSON parse");
    let from_yaml =
        document::Packet::parse(&yaml, document::Format::Yaml, yaml.len()).expect("YAML parse");
    assert_eq!(from_json, document);
    assert_eq!(from_yaml, document);
    assert_eq!(
        structure(
            &document
                .to_packet(&registry, 1)
                .expect("document conversion")
        ),
        structure(&packet)
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
        document::Packet::parse_with_resource_limits(
            &json,
            document::Format::Json,
            json.len(),
            packetcraftr_core::build::DEFAULT_MAX_LAYERS,
            document::MAX_DOCUMENT_NESTING + 1,
        ),
        Err(document::Error::InvalidLimit { .. })
    ));
    assert!(document::Packet::parse("{} trailing", document::Format::Json, 20).is_err());
    assert!(document::Packet::parse("---\n{}\n---\n{}", document::Format::Yaml, 20).is_err());
    let duplicate = "schema: packetcraftr.packet/v1\nschema: duplicate\nlayers: []\n";
    assert!(document::Packet::parse(duplicate, document::Format::Yaml, duplicate.len()).is_err());
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
        Err(packetcraftr_core::Error::IndexOutOfBounds { index: 99, len: 2 })
    ));
    assert!(matches!(
        failed_lookups.replace(99, Probe::default()),
        Err(packetcraftr_core::Error::IndexOutOfBounds { index: 99, len: 2 })
    ));
    assert!(matches!(
        failed_lookups.remove(99),
        Err(packetcraftr_core::Error::IndexOutOfBounds { index: 99, len: 2 })
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
    let registry = Arc::new(registry());
    assert_registry_queries(&registry);
    let (builder, decoded) = build_and_decode_probe(&registry);

    assert_failed_packet_lookups(decoded);
    assert_root_decode_behavior(&registry);
    assert_build_decode_limits(&registry, &builder);
}

fn assert_registry_binding_conflicts() {
    let mut duplicate = packetcraftr_core::registry::Builder::new();
    duplicate
        .register_builtin_codec(ProbeCodec, ProbeCodec.aliases())
        .expect("first codec");
    assert!(matches!(
        duplicate.register_builtin_codec(ProbeCodec, ProbeCodec.aliases()),
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
    bindings
        .register_builtin_codec(ProbeCodec, ProbeCodec.aliases())
        .expect("probe");
    bindings
        .register_builtin_codec(ChildCodec, ChildCodec.aliases())
        .expect("child");
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
    canonical
        .register_builtin_codec(ProbeCodec, ProbeCodec.aliases())
        .expect("probe");
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
    unknown
        .register_builtin_codec(ProbeCodec, ProbeCodec.aliases())
        .expect("probe");
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
        .register_builtin_codec(ProbeCodec, ProbeCodec.aliases())
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
fn expression_v2_coercion_repins() {
    let registry = packetcraftr_core::protocol::builtin::registry().expect("built-in registry");

    // udp(destination_port=0x35) -> 53
    let packet = expression::parse(
        "udp(destination_port=0x35)",
        &registry,
        expression::Options::default(),
    )
    .expect("udp with hex destination_port");
    assert_eq!(
        packet
            .layer(0)
            .expect("udp layer")
            .field("destination_port"),
        Some(FieldValue::Unsigned(53))
    );

    // udp(dport=0x35) -> 53
    let packet_alias =
        expression::parse("udp(dport=0x35)", &registry, expression::Options::default())
            .expect("udp with aliased dport");
    assert_eq!(
        packet_alias
            .layer(0)
            .expect("udp layer")
            .field("destination_port"),
        Some(FieldValue::Unsigned(53))
    );

    // raw(text=true) -> Text "true"
    let raw_packet = expression::parse("raw(text=true)", &registry, expression::Options::default())
        .expect("raw with text=true");
    assert_eq!(
        raw_packet.layer(0).expect("raw layer").field("bytes"),
        Some(FieldValue::Bytes(Bytes::from_static(b"true")))
    );

    // ipv4(destination=192.0.2.1)
    let ip_packet = expression::parse(
        "ipv4(destination=192.0.2.1)",
        &registry,
        expression::Options::default(),
    )
    .expect("ipv4 with destination");
    assert_eq!(
        ip_packet.layer(0).expect("ipv4 layer").field("destination"),
        Some(FieldValue::Ipv4(Ipv4Addr::new(192, 0, 2, 1)))
    );

    // ipv4(ttl=300) -> error naming ttl
    let ttl_err = expression::parse("ipv4(ttl=300)", &registry, expression::Options::default())
        .expect_err("ttl 300 exceeds u8");
    assert!(
        ttl_err.to_string().contains("ttl"),
        "expected error naming ttl, got: {ttl_err}"
    );

    // ethernet(ether_type=raw:0x0800) -> Raw bytes
    let eth_packet = expression::parse(
        "ethernet(ether_type=raw:0x0800)",
        &registry,
        expression::Options::default(),
    )
    .expect("ethernet with raw ether_type");
    assert_eq!(
        eth_packet
            .layer(0)
            .expect("ethernet layer")
            .field("ether_type"),
        Some(FieldValue::Bytes(Bytes::from_static(&[0x08, 0x00])))
    );

    // ipv4(checksum=auto) still Auto
    let ip_auto = expression::parse(
        "ipv4(checksum=auto)",
        &registry,
        expression::Options::default(),
    )
    .expect("ipv4 with checksum=auto");
    assert_eq!(
        ip_auto.layer(0).expect("ipv4 layer").field("checksum"),
        Some(FieldValue::Text("auto".to_owned()))
    );

    // a list on a scalar field errors
    let list_err = expression::parse(
        "ipv4(ttl=[1, 2])",
        &registry,
        expression::Options::default(),
    )
    .expect_err("list on scalar field ttl");
    assert!(
        matches!(list_err, expression::Error::Syntax { .. }),
        "expected syntax error, got: {list_err}"
    );
    assert!(
        list_err
            .to_string()
            .contains("field ttl does not accept a list"),
        "unexpected error message: {list_err}"
    );
}

#[test]
fn registry_rejects_alias_binding_and_filter_contract_conflicts() {
    assert_registry_binding_conflicts();
    assert_filter_field_binding_conflicts();
}
