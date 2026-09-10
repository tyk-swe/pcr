// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Contracts for templates, expressions, and document round trips.

mod common;

use bytes::Bytes;
use common::probe::{Probe, probe_registry, structure};
use packetcraftr_core::field::FieldValue;
use packetcraftr_core::{document, expression, packet::Packet, template};
use std::collections::BTreeMap;
use std::net::Ipv4Addr;

#[test]
fn templates_expand_cartesian_axes_and_report_limits_and_edit_errors() {
    let mut base = Packet::new();
    base.push(Probe::default());
    let template = template::Template::new(base)
        .axis(
            0,
            "label",
            vec![
                FieldValue::Text("a".to_owned()),
                FieldValue::Text("b".to_owned()),
            ],
        )
        .axis(0, "value", vec![10_u8.into(), 11_u8.into(), 12_u8.into()]);
    assert_eq!(template.expansion_len().unwrap(), 6);
    assert!(matches!(
        template.expand(5),
        Err(template::Error::ExpansionLimit {
            requested: 6,
            limit: 5
        })
    ));
    let expanded = template
        .expand(6)
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
        [
            (10, "a"),
            (11, "a"),
            (12, "a"),
            (10, "b"),
            (11, "b"),
            (12, "b")
        ]
    );

    let axisless = template::Template::new(Packet::new());
    assert_eq!(axisless.expansion_len().unwrap(), 1);
    assert_eq!(axisless.expand(1).expect("one ordinal").len(), 1);
    let empty = template::Template::new(Packet::new()).axis(0, "value", Vec::new());
    assert_eq!(empty.expansion_len().unwrap(), 0);
    assert_eq!(empty.expand(0).expect("empty expansion").len(), 0);

    let bad_index = template::Template::new(Packet::new()).axis(1, "value", vec![1_u8.into()]);
    assert!(matches!(
        bad_index.expand(1),
        Err(template::Error::LayerIndex { index: 1, len: 0 })
    ));
    let mut packet = Packet::new();
    packet.push(Probe::default());
    let bad_field = template::Template::new(packet).axis(0, "missing", vec![1_u8.into()]);
    assert!(matches!(
        bad_field.expand(1),
        Err(template::Error::Field { layer: 0, .. })
    ));
}

#[test]
fn template_aliases_value_errors_and_overflow_are_rejected_before_iteration() {
    use packetcraftr_core::protocol::{network::Ipv4, transport::Udp};
    let mut base = Packet::new();
    base.push(Udp::default());
    let repeated = template::Template::new(base.clone())
        .axis(0, "sport", vec![1_u16.into()])
        .axis(0, "source_port", vec![2_u16.into()]);
    assert!(matches!(
        repeated.expand(1),
        Err(template::Error::DuplicateAxis { layer: 0, .. })
    ));
    let invalid = template::Template::new(base).axis(
        0,
        "sport",
        vec![1_u16.into(), FieldValue::Unsigned(65_536)],
    );
    assert!(matches!(
        invalid.expand(2),
        Err(template::Error::Field { .. })
    ));

    let mut base = Packet::new();
    for _ in 0..usize::BITS {
        base.push(Ipv4::default());
    }
    let mut product = template::Template::new(base);
    for index in 0..usize::BITS as usize {
        product = product.axis(index, "ttl", vec![1_u8.into(), 2_u8.into()]);
    }
    assert!(matches!(
        product.expansion_len(),
        Err(template::Error::ExpansionOverflow)
    ));
    assert!(matches!(
        product.expand(usize::MAX),
        Err(template::Error::ExpansionOverflow)
    ));
    let empty = product.axis(0, "tos", vec![]);
    assert_eq!(
        empty.expansion_len().unwrap(),
        0,
        "an empty factor makes the entire product empty"
    );
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
    for (input, expected) in [
        ("abc", "hex value must contain an even number of digits"),
        ("zz", "invalid hex at byte 0"),
    ] {
        match packetcraftr_core::protocol::raw::parse_hex(input) {
            Err(packetcraftr_core::codec::Error::Invalid { message, .. }) => {
                assert_eq!(message, expected, "{input}");
            }
            other => panic!("{input}: expected an invalid raw layer error, got {other:?}"),
        }
    }
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
    let registry = probe_registry();
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
        document::Packet::parse_with_limits(
            &json,
            document::Format::Json,
            &document::DocumentLimits {
                max_input_bytes: json.len(),
                max_layers: 0,
                ..document::DocumentLimits::DEFAULT
            },
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
        document::Packet::parse_with_limits(
            &json,
            document::Format::Json,
            &document::DocumentLimits {
                max_nesting: document::MAX_DOCUMENT_NESTING + 1,
                ..document::DocumentLimits::DEFAULT
            },
        ),
        Err(document::Error::InvalidLimit { .. })
    ));
    // Each of these must surface as a parse failure of the named format, never
    // as an accepted document or a limit breach.
    let duplicate = "schema: packetcraftr.packet/v1\nschema: duplicate\nlayers: []\n";
    for (input, format, expected_format, expected_fragment) in [
        (
            r#"{"schema":"packetcraftr.packet/v1","layers":[]} trailing"#,
            document::Format::Json,
            "JSON",
            "trailing",
        ),
        (
            "---\nschema: packetcraftr.packet/v1\nlayers: []\n---\n{}",
            document::Format::Yaml,
            "YAML",
            "multiple yaml documents",
        ),
        (duplicate, document::Format::Yaml, "YAML", "duplicate"),
    ] {
        match document::Packet::parse(input, format, input.len()) {
            Err(document::Error::Parse { format, message }) => {
                assert_eq!(format, expected_format, "{input:?}");
                assert!(
                    message.to_lowercase().contains(expected_fragment),
                    "{input:?}: {message}"
                );
            }
            other => panic!("{input:?}: expected a {expected_format} parse error, got {other:?}"),
        }
    }
}
