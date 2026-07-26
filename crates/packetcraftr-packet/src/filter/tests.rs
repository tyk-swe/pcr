// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::any::Any;
use std::collections::BTreeMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::OnceLock;

use bytes::Bytes;

use super::super::Packet;
use super::super::codec::{
    CodecError, DecodedLayerValue, EncodedLayer, LayerCodec, LayerDecodeContext, LayerEncodeContext,
};
use super::super::field::{FieldKind, FieldValue};
use super::super::layer::{FieldError, FieldSchema, Layer, LayerSchema, ProtocolId};
use super::super::registry::ProtocolRegistry;
use super::engine::MAX_FILTER_NESTING;
use super::{Filter, FilterError, FilterOptions};

// A self-contained registry keeps these tests inside the packet crate, which
// deliberately does not depend on the built-in protocol catalog. One layer
// exposes every filterable field kind.
#[derive(Clone, Debug)]
struct Probe {
    port: u64,
    address: Ipv4Addr,
    address6: Ipv6Addr,
    hardware: [u8; 6],
    label: String,
    payload: Bytes,
    flagged: bool,
    offset: i64,
    tags: Vec<FieldValue>,
}

impl Default for Probe {
    fn default() -> Self {
        Self {
            port: 0,
            address: Ipv4Addr::UNSPECIFIED,
            address6: Ipv6Addr::UNSPECIFIED,
            hardware: [0; 6],
            label: String::new(),
            payload: Bytes::new(),
            flagged: false,
            offset: 0,
            tags: Vec::new(),
        }
    }
}

impl Layer for Probe {
    fn schema(&self) -> &'static LayerSchema {
        static SCHEMA: OnceLock<LayerSchema> = OnceLock::new();
        static FIELDS: &[FieldSchema] = &[
            FieldSchema {
                name: "port",
                kind: FieldKind::Unsigned,
                derived: false,
                required: true,
                description: "probe port",
            },
            FieldSchema {
                name: "address",
                kind: FieldKind::Ipv4,
                derived: false,
                required: true,
                description: "probe IPv4 address",
            },
            FieldSchema {
                name: "address6",
                kind: FieldKind::Ipv6,
                derived: false,
                required: true,
                description: "probe IPv6 address",
            },
            FieldSchema {
                name: "hardware",
                kind: FieldKind::Mac,
                derived: false,
                required: true,
                description: "probe MAC address",
            },
            FieldSchema {
                name: "label",
                kind: FieldKind::Text,
                derived: false,
                required: true,
                description: "probe label",
            },
            FieldSchema {
                name: "payload",
                kind: FieldKind::Bytes,
                derived: false,
                required: true,
                description: "probe payload",
            },
            FieldSchema {
                name: "flagged",
                kind: FieldKind::Bool,
                derived: false,
                required: true,
                description: "probe flag",
            },
            FieldSchema {
                name: "offset",
                kind: FieldKind::Signed,
                derived: false,
                required: true,
                description: "probe offset",
            },
            FieldSchema {
                name: "tags",
                kind: FieldKind::List,
                derived: false,
                required: false,
                description: "probe tags",
            },
        ];
        SCHEMA.get_or_init(|| LayerSchema {
            protocol: ProtocolId::new("probe"),
            name: "Probe test layer",
            fields: FIELDS,
        })
    }

    fn clone_box(&self) -> Box<dyn Layer> {
        Box::new(self.clone())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn field(&self, name: &str) -> Option<FieldValue> {
        match name {
            "port" => Some(FieldValue::Unsigned(self.port)),
            "address" => Some(FieldValue::Ipv4(self.address)),
            "address6" => Some(FieldValue::Ipv6(self.address6)),
            "hardware" => Some(FieldValue::Mac(self.hardware)),
            "label" => Some(FieldValue::Text(self.label.clone())),
            "payload" => Some(FieldValue::Bytes(self.payload.clone())),
            "flagged" => Some(FieldValue::Bool(self.flagged)),
            "offset" => Some(FieldValue::Signed(self.offset)),
            "tags" => (!self.tags.is_empty()).then(|| FieldValue::List(self.tags.clone())),
            _ => None,
        }
    }

    fn set_field(&mut self, name: &str, _value: FieldValue) -> Result<(), FieldError> {
        Err(FieldError::UnknownField {
            protocol: ProtocolId::new("probe"),
            field: name.to_owned(),
        })
    }
}

#[derive(Debug)]
struct ProbeCodec;

impl LayerCodec for ProbeCodec {
    fn protocol_id(&self) -> ProtocolId {
        ProtocolId::new("probe")
    }

    fn aliases(&self) -> &'static [&'static str] {
        &["prb"]
    }

    fn encode(
        &self,
        _layer: &dyn Layer,
        _payload: &[u8],
        _context: &LayerEncodeContext<'_>,
    ) -> Result<EncodedLayer, CodecError> {
        unreachable!("filter tests never encode")
    }

    fn decode(
        &self,
        _input: &[u8],
        _context: &LayerDecodeContext<'_>,
    ) -> Result<DecodedLayerValue, CodecError> {
        unreachable!("filter tests never decode")
    }

    fn make_layer(
        &self,
        _fields: &BTreeMap<String, FieldValue>,
    ) -> Result<Box<dyn Layer>, CodecError> {
        Ok(Box::new(Probe::default()))
    }
}

fn registry() -> ProtocolRegistry {
    let mut builder = ProtocolRegistry::builder();
    builder.register_codec(ProbeCodec).unwrap();
    builder.build().unwrap()
}

fn compile(source: &str) -> Result<Filter, FilterError> {
    Filter::compile(source, &registry(), FilterOptions::default())
}

fn packet_of(layers: Vec<Probe>) -> Packet {
    let mut packet = Packet::with_capacity(layers.len());
    for layer in layers {
        packet.push(layer);
    }
    packet
}

fn probe(port: u64) -> Probe {
    Probe {
        port,
        address: Ipv4Addr::new(192, 0, 2, 10),
        address6: "2001:db8::10".parse().unwrap(),
        hardware: [2, 0, 0, 0, 0, 1],
        label: "alpha".to_owned(),
        payload: Bytes::from_static(&[0xde, 0xad]),
        flagged: true,
        offset: -5,
        tags: Vec::new(),
    }
}

#[test]
fn presence_matches_any_registered_name_or_alias() {
    let packet = packet_of(vec![probe(443)]);
    for source in ["probe", "prb", "PROBE"] {
        assert!(compile(source).unwrap().matches(&packet), "{source}");
    }
    assert!(!compile("probe").unwrap().matches(&Packet::new()));
}

#[test]
fn every_operator_applies_to_the_kinds_that_support_it() {
    let packet = packet_of(vec![probe(443)]);
    for (source, expected) in [
        ("probe.port == 443", true),
        ("probe.port == 0x1bb", true),
        ("probe.port != 443", false),
        ("probe.port < 444", true),
        ("probe.port <= 443", true),
        ("probe.port > 443", false),
        ("probe.port >= 443", true),
        ("probe.offset == -5", true),
        ("probe.offset < 0", true),
        ("probe.flagged == true", true),
        ("probe.flagged == false", false),
        ("probe.label == alpha", true),
        ("probe.label == \"alpha\"", true),
        ("probe.label != beta", true),
        ("probe.payload == dead", true),
        ("probe.payload == 0xdead", true),
        ("probe.payload == beef", false),
        ("probe.hardware == 02:00:00:00:00:01", true),
        ("probe.hardware == 02-00-00-00-00-01", true),
        ("probe.hardware != 02:00:00:00:00:02", true),
        ("probe.address == 192.0.2.10", true),
        ("probe.address6 == 2001:db8::10", true),
    ] {
        assert_eq!(
            compile(source).unwrap().matches(&packet),
            expected,
            "{source}"
        );
    }
}

#[test]
fn address_prefixes_test_containment_in_both_families() {
    let packet = packet_of(vec![probe(443)]);
    for (source, expected) in [
        ("probe.address == 192.0.2.0/24", true),
        ("probe.address == 192.0.2.8/29", true),
        ("probe.address == 192.0.2.0/30", false),
        ("probe.address == 0.0.0.0/0", true),
        ("probe.address != 198.51.100.0/24", true),
        ("probe.address6 == 2001:db8::/32", true),
        ("probe.address6 == 2001:db8::10/128", true),
        ("probe.address6 == 2001:db9::/32", false),
        ("probe.address6 == ::/0", true),
    ] {
        assert_eq!(
            compile(source).unwrap().matches(&packet),
            expected,
            "{source}"
        );
    }
}

#[test]
fn logical_operators_bind_with_conventional_precedence() {
    let packet = packet_of(vec![probe(443)]);
    for (source, expected) in [
        ("probe.port == 443 && probe.label == alpha", true),
        ("probe.port == 80 || probe.port == 443", true),
        ("probe.port == 80 || probe.port == 8080", false),
        // && binds tighter than ||, so this is `80 || (443 && alpha)`.
        (
            "probe.port == 80 || probe.port == 443 && probe.label == alpha",
            true,
        ),
        (
            "(probe.port == 80 || probe.port == 443) && probe.label == beta",
            false,
        ),
        ("!probe.port == 80", true),
        ("!(probe.port == 443)", false),
        ("!!probe.port == 443", true),
        ("probe && !probe.flagged == false", true),
    ] {
        assert_eq!(
            compile(source).unwrap().matches(&packet),
            expected,
            "{source}"
        );
    }
}

#[test]
fn a_comparison_matches_when_any_layer_of_that_protocol_satisfies_it() {
    let packet = packet_of(vec![probe(443), probe(80)]);

    assert!(compile("probe.port == 80").unwrap().matches(&packet));
    assert!(compile("probe.port == 443").unwrap().matches(&packet));
    // Any-layer semantics make `!=` and `!(==)` genuinely different once a
    // protocol repeats, which is the documented behaviour.
    assert!(compile("probe.port != 443").unwrap().matches(&packet));
    assert!(!compile("!(probe.port == 443)").unwrap().matches(&packet));
}

#[test]
fn an_absent_layer_or_field_never_satisfies_a_comparison() {
    let empty = Packet::new();
    assert!(!compile("probe.port == 443").unwrap().matches(&empty));
    assert!(compile("!probe.port == 443").unwrap().matches(&empty));

    // `tags` is optional and unset here, so no layer supplies a value.
    let packet = packet_of(vec![probe(443)]);
    assert!(!compile("probe.port == 8080").unwrap().matches(&packet));
}

#[test]
fn unknown_names_are_reported_with_their_position_and_the_valid_choices() {
    assert!(matches!(
        compile("nope").unwrap_err(),
        FilterError::UnknownProtocol { offset: 0, name } if name == "nope"
    ));
    assert!(matches!(
        compile("probe.port == 1 && nope.x == 2").unwrap_err(),
        FilterError::UnknownProtocol { offset: 19, .. }
    ));

    let error = compile("probe.sport == 443").unwrap_err();
    let FilterError::UnknownField {
        offset,
        protocol,
        field,
        available,
    } = &error
    else {
        panic!("expected an unknown-field error, got {error}");
    };
    assert_eq!(*offset, 0);
    assert_eq!(protocol, "probe");
    assert_eq!(field, "sport");
    assert!(available.contains(&"port".to_owned()));
    assert!(error.to_string().contains("port, address"));
}

#[test]
fn impossible_comparisons_are_rejected_before_any_packet_is_read() {
    for source in [
        "probe.port == notanumber",
        "probe.port == -1",
        "probe.address == 192.0.2.300",
        "probe.address == 192.0.2.0/33",
        "probe.address6 == 2001:db8::/129",
        "probe.hardware == 02:00:00:00:00",
        "probe.flagged == yes",
        "probe.payload == abc",
    ] {
        assert!(
            matches!(
                compile(source).unwrap_err(),
                FilterError::TypeMismatch { .. }
            ),
            "{source}"
        );
    }
    for source in [
        "probe.label < alpha",
        "probe.address < 192.0.2.1",
        "probe.flagged >= true",
        "probe.payload > dead",
        // A prefix names a set, so ordering it is meaningless even though the
        // field kind itself is orderable-looking.
        "probe.address6 <= 2001:db8::/32",
    ] {
        assert!(
            matches!(
                compile(source).unwrap_err(),
                FilterError::UnorderedField { .. }
            ),
            "{source}"
        );
    }
    assert!(matches!(
        compile("probe.tags == 1").unwrap_err(),
        FilterError::UnfilterableField { .. }
    ));
}

#[test]
fn syntax_errors_carry_the_byte_offset_that_failed() {
    for (source, offset) in [
        ("probe.port =", 11_usize),
        ("probe.port == ", 11),
        ("(probe", 6),
        ("probe.port == 1)", 15),
        ("probe.port == 1 &", 16),
        ("probe.port == 1 & probe", 16),
        ("&& probe", 0),
        ("probe.", 0),
        ("probe.port.extra == 1", 0),
        ("probe == 1", 0),
        ("probe.label == \"unterminated", 15),
        ("probe.port == 1 @ 2", 16),
    ] {
        let error = compile(source).unwrap_err();
        let reported = match error {
            FilterError::Syntax { offset, .. } => offset,
            other => panic!("{source}: expected a syntax error, got {other}"),
        };
        assert_eq!(reported, offset, "{source}");
    }
}

#[test]
fn empty_oversized_and_deeply_nested_filters_are_bounded() {
    assert!(matches!(compile("").unwrap_err(), FilterError::Empty));
    assert!(matches!(compile("   ").unwrap_err(), FilterError::Empty));

    let registry = registry();
    assert!(matches!(
        Filter::compile(
            "probe",
            &registry,
            FilterOptions {
                max_bytes: 4,
                ..FilterOptions::default()
            }
        )
        .unwrap_err(),
        FilterError::SizeLimit {
            actual: 5,
            limit: 4
        }
    ));
    assert!(matches!(
        Filter::compile(
            "probe",
            &registry,
            FilterOptions {
                max_nesting: MAX_FILTER_NESTING + 1,
                ..FilterOptions::default()
            }
        )
        .unwrap_err(),
        FilterError::InvalidNestingLimit { .. }
    ));

    let nested = format!(
        "{}probe{}",
        "(".repeat(MAX_FILTER_NESTING + 1),
        ")".repeat(MAX_FILTER_NESTING + 1)
    );
    assert!(matches!(
        compile(&nested).unwrap_err(),
        FilterError::NestingLimit { .. }
    ));
    // Repeated negation recurses too, so the same budget bounds it.
    let negated = format!("{}probe", "!".repeat(MAX_FILTER_NESTING + 1));
    assert!(matches!(
        compile(&negated).unwrap_err(),
        FilterError::NestingLimit { .. }
    ));
}

#[test]
fn a_compiled_filter_retains_its_exact_source() {
    let filter = compile("probe.port == 443").unwrap();
    assert_eq!(filter.source(), "probe.port == 443");
}
