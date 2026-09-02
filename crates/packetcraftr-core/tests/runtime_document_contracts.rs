// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
// Test code indexes fixtures and counts by hand; the fail-closed lints are
// for library paths.
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

//! Contracts for templates, expressions, and document round trips.

mod common;

use bytes::Bytes;
use common::probe::{Probe, probe_registry, structure};
use packetcraftr_core::field::FieldValue;
use packetcraftr_core::{Packet, document, expression, template};
use std::collections::BTreeMap;
use std::net::Ipv4Addr;

#[test]
fn templates_expand_one_axis_and_report_limits_and_edit_errors() {
    let mut base = Packet::new();
    base.push(Probe::default());
    let template = template::Template::new(base)
        .axis(0, "label", vec![FieldValue::Text("replaced".to_owned())])
        .axis(0, "value", vec![10_u8.into(), 11_u8.into(), 12_u8.into()]);
    assert_eq!(
        template.expansion_len(),
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
    assert_eq!(axisless.expansion_len(), 1);
    assert_eq!(axisless.expand(1).expect("one ordinal").len(), 1);

    let empty = template::Template::new(Packet::new()).axis(0, "value", Vec::new());
    assert_eq!(empty.expansion_len(), 0);
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
    assert!(document::Packet::parse("{} trailing", document::Format::Json, 20).is_err());
    assert!(document::Packet::parse("---\n{}\n---\n{}", document::Format::Yaml, 20).is_err());
    let duplicate = "schema: packetcraftr.packet/v1\nschema: duplicate\nlayers: []\n";
    assert!(document::Packet::parse(duplicate, document::Format::Yaml, duplicate.len()).is_err());
}
