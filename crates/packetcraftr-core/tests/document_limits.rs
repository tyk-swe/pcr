// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
//! Semantic resource limits of the packet-document parser, enforced
//! identically for JSON and YAML.
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::collections::BTreeMap;

use packetcraftr_core::document::{
    DEFAULT_MAX_DOCUMENT_BYTES, DocumentLimits, Error, Format, Layer, Limit, MAX_DOCUMENT_NESTING,
    PACKET_DOCUMENT_SCHEMA_V1, Packet,
};
use packetcraftr_core::field::FieldValue;
use serde::Deserialize;

const SCHEMA: &str = PACKET_DOCUMENT_SCHEMA_V1;

/// Wraps layer JSON in a complete document.
fn document(layers: &str) -> String {
    document_with_schema(SCHEMA, layers)
}

fn document_with_schema(schema: &str, layers: &str) -> String {
    format!("{{\"schema\":\"{schema}\",\"layers\":[{layers}]}}")
}

/// One layer with the given field entries (`"name": value` fragments).
fn layer(protocol: &str, fields: &[String]) -> String {
    format!(
        "{{\"protocol\":\"{protocol}\",\"fields\":{{{}}}}}",
        fields.join(",")
    )
}

fn unsigned(name: &str, value: u64) -> String {
    format!("\"{name}\":{{\"type\":\"unsigned\",\"value\":{value}}}")
}

fn text(name: &str, value: &str) -> String {
    format!("\"{name}\":{{\"type\":\"text\",\"value\":\"{value}\"}}")
}

fn bytes(name: &str, length: usize) -> String {
    let items = vec!["7"; length].join(",");
    format!("\"{name}\":{{\"type\":\"bytes\",\"value\":[{items}]}}")
}

fn list_of_unsigned(name: &str, length: usize) -> String {
    let items = vec!["{\"type\":\"unsigned\",\"value\":1}"; length].join(",");
    format!("\"{name}\":{{\"type\":\"list\",\"value\":[{items}]}}")
}

/// A field holding `depth` nested lists, innermost empty.
fn nested_lists(name: &str, depth: usize) -> String {
    let mut value = "[]".to_owned();
    for _ in 1..depth {
        value = format!("[{{\"type\":\"list\",\"value\":{value}}}]");
    }
    format!("\"{name}\":{{\"type\":\"list\",\"value\":{value}}}")
}

/// The same document as YAML, produced from the JSON value tree so the two
/// inputs are structurally identical.
fn to_yaml(json: &str) -> String {
    let mut deserializer = serde_json::Deserializer::from_str(json);
    deserializer.disable_recursion_limit();
    let value = serde_json::Value::deserialize(&mut deserializer).expect("fixture JSON is valid");
    // The YAML serializer stops at 128 nested containers; beyond that the
    // JSON text itself is the flow-style YAML twin.
    noyalib::to_string(&value).unwrap_or_else(|_| json.to_owned())
}

/// Parses the JSON fixture in both formats and requires the same verdict:
/// equal documents, or the same limit (or both a format error).
fn parse_both(json: &str, limits: &DocumentLimits) -> Result<Packet, Error> {
    let yaml = to_yaml(json);
    let from_json = Packet::parse_with_limits(json, Format::Json, limits);
    let from_yaml = Packet::parse_with_limits(&yaml, Format::Yaml, limits);
    match (&from_json, &from_yaml) {
        (Ok(json_document), Ok(yaml_document)) => assert_eq!(json_document, yaml_document),
        (Err(json_error), Err(yaml_error)) => {
            assert_eq!(
                json_error.limit(),
                yaml_error.limit(),
                "JSON reported {json_error}, YAML reported {yaml_error}"
            );
            assert_eq!(
                std::mem::discriminant(json_error),
                std::mem::discriminant(yaml_error),
                "JSON reported {json_error}, YAML reported {yaml_error}"
            );
        }
        (json_result, yaml_result) => {
            panic!("format disagreement for {json}: JSON {json_result:?}, YAML {yaml_result:?}")
        }
    }
    from_json
}

fn limit_of(result: Result<Packet, Error>) -> Limit {
    match result {
        Ok(document) => panic!("document was accepted: {document:?}"),
        Err(error) => error
            .limit()
            .unwrap_or_else(|| panic!("not a limit error: {error}")),
    }
}

/// Every limit at its boundary and one unit over, with the same verdict in
/// both formats.
#[test]
fn every_limit_is_exact_at_the_boundary_and_rejects_one_unit_over() {
    struct Case {
        limit: Limit,
        at: String,
        over: String,
        limits: DocumentLimits,
    }
    let name = |length: usize| "n".repeat(length);
    let cases = [
        Case {
            limit: Limit::Layers,
            at: document(&vec![layer("raw", &[]); 3].join(",")),
            over: document(&vec![layer("raw", &[]); 4].join(",")),
            limits: DocumentLimits {
                max_layers: 3,
                ..DocumentLimits::DEFAULT
            },
        },
        Case {
            limit: Limit::Nesting,
            at: document(&layer("raw", &[nested_lists("f", 4)])),
            over: document(&layer("raw", &[nested_lists("f", 5)])),
            limits: DocumentLimits {
                max_nesting: 4,
                ..DocumentLimits::DEFAULT
            },
        },
        Case {
            limit: Limit::FieldsPerLayer,
            at: document(&layer(
                "raw",
                &(0..5)
                    .map(|i| unsigned(&format!("f{i}"), 1))
                    .collect::<Vec<_>>(),
            )),
            over: document(&layer(
                "raw",
                &(0..6)
                    .map(|i| unsigned(&format!("f{i}"), 1))
                    .collect::<Vec<_>>(),
            )),
            limits: DocumentLimits {
                max_fields_per_layer: 5,
                ..DocumentLimits::DEFAULT
            },
        },
        Case {
            limit: Limit::TotalNodes,
            // The list node plus its three items.
            at: document(&layer("raw", &[list_of_unsigned("f", 3)])),
            over: document(&layer("raw", &[list_of_unsigned("f", 4)])),
            limits: DocumentLimits {
                max_total_nodes: 4,
                ..DocumentLimits::DEFAULT
            },
        },
        Case {
            limit: Limit::ListItems,
            at: document(&layer("raw", &[list_of_unsigned("f", 3)])),
            over: document(&layer("raw", &[list_of_unsigned("f", 4)])),
            limits: DocumentLimits {
                max_list_items: 3,
                ..DocumentLimits::DEFAULT
            },
        },
        Case {
            limit: Limit::TotalListItems,
            at: document(&layer(
                "raw",
                &[list_of_unsigned("a", 2), list_of_unsigned("b", 2)],
            )),
            over: document(&layer(
                "raw",
                &[list_of_unsigned("a", 2), list_of_unsigned("b", 3)],
            )),
            limits: DocumentLimits {
                max_total_list_items: 4,
                ..DocumentLimits::DEFAULT
            },
        },
        Case {
            limit: Limit::ProtocolNameBytes,
            at: document(&layer(&name(8), &[])),
            over: document(&layer(&name(9), &[])),
            limits: DocumentLimits {
                max_protocol_name_bytes: 8,
                ..DocumentLimits::DEFAULT
            },
        },
        Case {
            limit: Limit::FieldNameBytes,
            at: document(&layer("raw", &[unsigned(&name(8), 1)])),
            over: document(&layer("raw", &[unsigned(&name(9), 1)])),
            limits: DocumentLimits {
                max_field_name_bytes: 8,
                ..DocumentLimits::DEFAULT
            },
        },
        Case {
            limit: Limit::TextBytes,
            at: document(&layer("raw", &[text("f", &"t".repeat(30))])),
            over: document(&layer("raw", &[text("f", &"t".repeat(31))])),
            limits: DocumentLimits {
                max_text_bytes: 30,
                ..DocumentLimits::DEFAULT
            },
        },
        Case {
            limit: Limit::ByteValueBytes,
            at: document(&layer("raw", &[bytes("f", 6)])),
            over: document(&layer("raw", &[bytes("f", 7)])),
            limits: DocumentLimits {
                max_byte_value_bytes: 6,
                ..DocumentLimits::DEFAULT
            },
        },
        Case {
            limit: Limit::TotalPayloadBytes,
            // Two 8-byte integers plus a 4-byte text value.
            at: document(&layer(
                "raw",
                &[unsigned("a", 1), unsigned("b", 2), text("c", "abcd")],
            )),
            over: document(&layer(
                "raw",
                &[unsigned("a", 1), unsigned("b", 2), text("c", "abcde")],
            )),
            limits: DocumentLimits {
                max_total_payload_bytes: 20,
                ..DocumentLimits::DEFAULT
            },
        },
    ];
    for case in cases {
        parse_both(&case.at, &case.limits)
            .unwrap_or_else(|error| panic!("{} at boundary rejected: {error}", case.limit));
        let limit = limit_of(parse_both(&case.over, &case.limits));
        assert_eq!(limit, case.limit, "one unit over {}", case.limit);
        assert_eq!(
            Error::ResourceLimit {
                limit,
                maximum: case.limits.maximum(limit)
            }
            .limit(),
            Some(limit)
        );
    }
}

#[test]
fn schema_respects_the_configured_text_limit() {
    let limits = DocumentLimits {
        max_text_bytes: 1,
        ..DocumentLimits::DEFAULT
    };
    assert_eq!(
        limit_of(parse_both(&document(""), &limits)),
        Limit::TextBytes
    );

    let schema = "s".repeat(300);
    let limits = DocumentLimits {
        max_text_bytes: schema.len(),
        ..DocumentLimits::DEFAULT
    };
    parse_both(&document_with_schema(&schema, ""), &limits)
        .expect("schema at the configured text limit is accepted");
}

#[test]
fn input_byte_ceiling_is_exact_per_format() {
    let json = document(&layer("raw", &[unsigned("f", 1)]));
    let yaml = to_yaml(&json);
    for (input, format) in [(&json, Format::Json), (&yaml, Format::Yaml)] {
        let at = DocumentLimits {
            max_input_bytes: input.len(),
            ..DocumentLimits::DEFAULT
        };
        Packet::parse_with_limits(input, format, &at).expect("exact input length is accepted");
        let over = DocumentLimits {
            max_input_bytes: input.len() - 1,
            ..DocumentLimits::DEFAULT
        };
        assert!(matches!(
            Packet::parse_with_limits(input, format, &over),
            Err(Error::SizeLimit { .. })
        ));
        assert_eq!(
            Packet::parse_with_limits(input, format, &over)
                .err()
                .and_then(|error| error.limit()),
            Some(Limit::InputBytes)
        );
    }
}

#[test]
fn invalid_limits_are_rejected_before_any_parsing() {
    let limits = DocumentLimits {
        max_nesting: MAX_DOCUMENT_NESTING + 1,
        ..DocumentLimits::DEFAULT
    };
    for format in [Format::Json, Format::Yaml] {
        assert!(matches!(
            Packet::parse_with_limits("not a document", format, &limits),
            Err(Error::InvalidLimit {
                field: "max_nesting",
                ..
            })
        ));
    }
}

#[test]
fn many_shallow_fields_exhaust_the_per_layer_and_node_budgets() {
    let fields = (0..300)
        .map(|i| unsigned(&format!("field_{i}"), i))
        .collect::<Vec<_>>();
    let json = document(&layer("raw", &fields));
    assert_eq!(
        limit_of(parse_both(&json, &DocumentLimits::DEFAULT)),
        Limit::FieldsPerLayer
    );
    let wide = DocumentLimits {
        max_fields_per_layer: 1_000,
        max_total_nodes: 299,
        ..DocumentLimits::DEFAULT
    };
    assert_eq!(limit_of(parse_both(&json, &wide)), Limit::TotalNodes);
    let wider = DocumentLimits {
        max_total_nodes: 300,
        ..wide
    };
    let parsed = parse_both(&json, &wider).expect("300 fields fit 300 nodes");
    assert_eq!(parsed.layers[0].fields.len(), 300);
}

#[test]
fn deeply_nested_lists_are_bounded_without_exhausting_the_stack() {
    let at_maximum = document(&layer("raw", &[nested_lists("f", MAX_DOCUMENT_NESTING)]));
    parse_both(&at_maximum, &DocumentLimits::DEFAULT).expect("maximum nesting is accepted");
    let over = document(&layer(
        "raw",
        &[nested_lists("f", MAX_DOCUMENT_NESTING + 1)],
    ));
    assert_eq!(
        limit_of(parse_both(&over, &DocumentLimits::DEFAULT)),
        Limit::Nesting
    );
    // Deep enough to exceed every configured depth, shallow enough for the
    // test helper that builds the YAML twin from a value tree.
    let absurd = document(&layer("raw", &[nested_lists("f", 300)]));
    assert_eq!(
        limit_of(parse_both(&absurd, &DocumentLimits::DEFAULT)),
        Limit::Nesting
    );
    // A nested list consumes nodes and aggregate list items as well as depth.
    let counted = DocumentLimits {
        max_total_nodes: 3,
        ..DocumentLimits::DEFAULT
    };
    assert_eq!(
        limit_of(parse_both(
            &document(&layer("raw", &[nested_lists("f", 4)])),
            &counted
        )),
        Limit::TotalNodes
    );
    let counted_items = DocumentLimits {
        max_total_list_items: 2,
        ..DocumentLimits::DEFAULT
    };
    assert_eq!(
        limit_of(parse_both(
            &document(&layer("raw", &[nested_lists("f", 4)])),
            &counted_items
        )),
        Limit::TotalListItems
    );
}

#[test]
fn many_small_lists_exhaust_the_aggregate_list_budget() {
    let fields = (0..40)
        .map(|i| list_of_unsigned(&format!("l{i}"), 3))
        .collect::<Vec<_>>();
    let json = document(&layer("raw", &fields));
    let limits = DocumentLimits {
        max_list_items: 3,
        max_total_list_items: 119,
        ..DocumentLimits::DEFAULT
    };
    assert_eq!(limit_of(parse_both(&json, &limits)), Limit::TotalListItems);
    let exact = DocumentLimits {
        max_total_list_items: 120,
        ..limits
    };
    parse_both(&json, &exact).expect("120 aggregate items fit exactly");
}

#[test]
fn huge_names_strings_and_byte_values_are_rejected_by_their_own_limit() {
    let long = "x".repeat(DocumentLimits::DEFAULT.max_field_name_bytes + 1);
    assert_eq!(
        limit_of(parse_both(
            &document(&layer("raw", &[unsigned(&long, 1)])),
            &DocumentLimits::DEFAULT
        )),
        Limit::FieldNameBytes
    );
    let long_protocol = "p".repeat(DocumentLimits::DEFAULT.max_protocol_name_bytes + 1);
    assert_eq!(
        limit_of(parse_both(
            &document(&layer(&long_protocol, &[])),
            &DocumentLimits::DEFAULT
        )),
        Limit::ProtocolNameBytes
    );
    let long_text = "t".repeat(DocumentLimits::DEFAULT.max_text_bytes + 1);
    assert_eq!(
        limit_of(parse_both(
            &document(&layer("raw", &[text("f", &long_text)])),
            &DocumentLimits::DEFAULT
        )),
        Limit::TextBytes
    );
    let limits = DocumentLimits {
        max_byte_value_bytes: 1_000,
        ..DocumentLimits::DEFAULT
    };
    assert_eq!(
        limit_of(parse_both(
            &document(&layer("raw", &[bytes("f", 1_001)])),
            &limits
        )),
        Limit::ByteValueBytes
    );
}

#[test]
fn many_small_scalars_exhaust_the_total_payload_budget() {
    let fields = (0..100)
        .map(|i| unsigned(&format!("u{i}"), i))
        .collect::<Vec<_>>();
    let json = document(&layer("raw", &fields));
    let limits = DocumentLimits {
        max_total_payload_bytes: 799,
        ..DocumentLimits::DEFAULT
    };
    assert_eq!(
        limit_of(parse_both(&json, &limits)),
        Limit::TotalPayloadBytes
    );
    let exact = DocumentLimits {
        max_total_payload_bytes: 800,
        ..limits
    };
    parse_both(&json, &exact).expect("100 integers are 800 payload bytes");
    // Byte values and text share the same budget.
    let mixed = document(&layer(
        "raw",
        &[bytes("b", 500), text("t", &"a".repeat(301))],
    ));
    assert_eq!(
        limit_of(parse_both(&mixed, &exact)),
        Limit::TotalPayloadBytes
    );
}

#[test]
fn layers_share_one_total_node_budget() {
    let layers = (0..4)
        .map(|i| layer(&format!("p{i}"), &[unsigned("a", 1), unsigned("b", 2)]))
        .collect::<Vec<_>>()
        .join(",");
    let json = document(&layers);
    let limits = DocumentLimits {
        max_total_nodes: 7,
        ..DocumentLimits::DEFAULT
    };
    assert_eq!(limit_of(parse_both(&json, &limits)), Limit::TotalNodes);
    let exact = DocumentLimits {
        max_total_nodes: 8,
        ..limits
    };
    assert_eq!(
        parse_both(&json, &exact)
            .expect("eight nodes across four layers")
            .layers
            .len(),
        4
    );
}

#[test]
fn malformed_input_near_each_threshold_is_a_format_error_not_a_limit() {
    let limits = DocumentLimits {
        max_layers: 2,
        max_fields_per_layer: 2,
        max_list_items: 2,
        max_text_bytes: 4,
        max_byte_value_bytes: 2,
        ..DocumentLimits::DEFAULT
    };
    let complete = [
        document_with_schema("v", &vec![layer("raw", &[]); 2].join(",")),
        document_with_schema("v", &layer("raw", &[unsigned("a", 1), unsigned("b", 2)])),
        document_with_schema("v", &layer("raw", &[list_of_unsigned("l", 2)])),
        document_with_schema("v", &layer("raw", &[text("t", "abcd")])),
        document_with_schema("v", &layer("raw", &[bytes("b", 2)])),
    ];
    for json in complete {
        parse_both(&json, &limits).expect("exact-threshold document parses");
        // Truncating flow-style input leaves an unclosed container in both
        // formats; block-style YAML can stay well-formed when cut.
        let truncated = &json[..json.len() - 3];
        for format in [Format::Json, Format::Yaml] {
            match Packet::parse_with_limits(truncated, format, &limits) {
                Err(Error::Parse { .. }) => {}
                other => panic!("truncated {format:?} document: {other:?}"),
            }
        }
    }
    // Wrong value types at a threshold are format errors too.
    let wrong = document_with_schema(
        "v",
        &layer(
            "raw",
            &["\"a\":{\"type\":\"bytes\",\"value\":[1,\"two\"]}".to_owned()],
        ),
    );
    assert!(matches!(
        parse_both(&wrong, &limits),
        Err(Error::Parse { .. })
    ));
}

#[test]
fn duplicate_fields_are_rejected_deliberately_in_both_formats() {
    let json = document(&layer("raw", &[unsigned("dup", 1), unsigned("dup", 2)]));
    match Packet::parse_with_limits(&json, Format::Json, &DocumentLimits::DEFAULT) {
        Err(Error::Parse { message, .. }) => {
            assert!(
                message.contains("duplicate reflective field \"dup\""),
                "{message}"
            );
        }
        other => panic!("duplicate JSON field: {other:?}"),
    }
    let yaml = format!(
        "schema: {SCHEMA}\nlayers:\n  - protocol: raw\n    fields:\n      dup: {{type: unsigned, value: 1}}\n      dup: {{type: unsigned, value: 2}}\n"
    );
    assert!(matches!(
        Packet::parse_with_limits(&yaml, Format::Yaml, &DocumentLimits::DEFAULT),
        Err(Error::Parse { .. })
    ));
    let duplicate_tag = document(&layer(
        "raw",
        &["\"a\":{\"type\":\"unsigned\",\"type\":\"signed\",\"value\":1}".to_owned()],
    ));
    assert!(matches!(
        Packet::parse_with_limits(&duplicate_tag, Format::Json, &DocumentLimits::DEFAULT),
        Err(Error::Parse { .. })
    ));
}

#[test]
fn value_before_type_is_accepted_and_budgeted_conservatively() {
    let yaml = format!(
        "schema: {SCHEMA}\nlayers:\n  - protocol: raw\n    fields:\n      bytes:\n        value: [222, 173, 190, 239]\n        type: bytes\n      name:\n        value: host\n        type: text\n      addr:\n        value: 192.0.2.1\n        type: ipv4\n      mac:\n        value: [1, 2, 3, 4, 5, 6]\n        type: mac\n      items:\n        value: [{{type: unsigned, value: 7}}]\n        type: list\n      count:\n        value: -3\n        type: signed\n"
    );
    let parsed = Packet::parse_with_limits(&yaml, Format::Yaml, &DocumentLimits::DEFAULT)
        .expect("value-first documents parse");
    let fields = &parsed.layers[0].fields;
    assert_eq!(
        fields["bytes"],
        FieldValue::from(vec![222_u8, 173, 190, 239])
    );
    assert_eq!(fields["name"], FieldValue::Text("host".to_owned()));
    assert_eq!(
        fields["addr"],
        FieldValue::Ipv4("192.0.2.1".parse().expect("documentation address"))
    );
    assert_eq!(fields["mac"], FieldValue::Mac([1, 2, 3, 4, 5, 6]));
    assert_eq!(
        fields["items"],
        FieldValue::List(vec![FieldValue::Unsigned(7)])
    );
    assert_eq!(fields["count"], FieldValue::Signed(-3));

    // A buffered byte array is charged as list items and nodes as well, so it
    // fits a narrower envelope than the type-first form, never a wider one.
    let narrow = DocumentLimits {
        max_list_items: 3,
        ..DocumentLimits::DEFAULT
    };
    let value_first = "{\"schema\":\"packetcraftr.packet/v1\",\"layers\":[{\"protocol\":\"raw\",\"fields\":{\"b\":{\"value\":[1,2,3,4],\"type\":\"bytes\"}}}]}";
    assert_eq!(
        limit_of(Packet::parse_with_limits(
            value_first,
            Format::Json,
            &narrow
        )),
        Limit::ListItems
    );
    parse_both(&document(&layer("raw", &[bytes("b", 4)])), &narrow)
        .expect("type-first bytes are not list items");
    // Type mismatches after buffering are format errors.
    let mismatch = "{\"schema\":\"packetcraftr.packet/v1\",\"layers\":[{\"protocol\":\"raw\",\"fields\":{\"b\":{\"value\":[1,300],\"type\":\"bytes\"}}}]}";
    assert!(matches!(
        Packet::parse_with_limits(mismatch, Format::Json, &DocumentLimits::DEFAULT),
        Err(Error::Parse { .. })
    ));
}

#[test]
fn value_first_ipv6_is_charged_at_its_fixed_retained_width() {
    let json_value_first = document(&layer(
        "raw",
        &["\"addr\":{\"value\":\"::\",\"type\":\"ipv6\"}".to_owned()],
    ));
    let json_type_first = document(&layer(
        "raw",
        &["\"addr\":{\"type\":\"ipv6\",\"value\":\"::\"}".to_owned()],
    ));
    let yaml_value_first = format!(
        "schema: {SCHEMA}\nlayers:\n  - protocol: raw\n    fields:\n      addr:\n        value: \"::\"\n        type: ipv6\n"
    );
    let yaml_type_first = format!(
        "schema: {SCHEMA}\nlayers:\n  - protocol: raw\n    fields:\n      addr:\n        type: ipv6\n        value: \"::\"\n"
    );
    let cases = [
        (json_value_first.as_str(), Format::Json),
        (json_type_first.as_str(), Format::Json),
        (yaml_value_first.as_str(), Format::Yaml),
        (yaml_type_first.as_str(), Format::Yaml),
    ];
    let too_small = DocumentLimits {
        max_total_payload_bytes: 15,
        ..DocumentLimits::DEFAULT
    };
    for (input, format) in cases {
        assert_eq!(
            limit_of(Packet::parse_with_limits(input, format, &too_small)),
            Limit::TotalPayloadBytes,
            "{format:?} field order bypassed the fixed IPv6 width"
        );
        let exact = DocumentLimits {
            max_total_payload_bytes: 16,
            ..too_small
        };
        Packet::parse_with_limits(input, format, &exact)
            .unwrap_or_else(|error| panic!("{format:?} exact IPv6 width rejected: {error}"));
    }
}

#[test]
fn value_first_bytes_respect_the_per_value_byte_limit() {
    let limits = DocumentLimits {
        max_list_items: 10,
        max_byte_value_bytes: 2,
        ..DocumentLimits::DEFAULT
    };
    let json = "{\"schema\":\"packetcraftr.packet/v1\",\"layers\":[{\"protocol\":\"raw\",\"fields\":{\"b\":{\"value\":[1,2,3],\"type\":\"bytes\"}}}]}";
    assert_eq!(
        limit_of(Packet::parse_with_limits(json, Format::Json, &limits)),
        Limit::ByteValueBytes
    );
    let yaml = format!(
        "schema: {SCHEMA}\nlayers:\n  - protocol: raw\n    fields:\n      b:\n        value: [1, 2, 3]\n        type: bytes\n"
    );
    assert_eq!(
        limit_of(Packet::parse_with_limits(&yaml, Format::Yaml, &limits)),
        Limit::ByteValueBytes
    );
}

#[test]
fn accepted_documents_are_stable_across_serialize_and_reparse() {
    let mut fields = BTreeMap::new();
    fields.insert("flag".to_owned(), FieldValue::Bool(true));
    // The YAML serializer only represents unsigned values up to `i64::MAX`.
    fields.insert("count".to_owned(), FieldValue::Unsigned(1 << 62));
    fields.insert("delta".to_owned(), FieldValue::Signed(i64::MIN));
    fields.insert(
        "name".to_owned(),
        FieldValue::Text("héllo \"quoted\"".to_owned()),
    );
    fields.insert("payload".to_owned(), FieldValue::from(vec![0_u8, 255, 16]));
    fields.insert(
        "v4".to_owned(),
        FieldValue::Ipv4("192.0.2.7".parse().expect("documentation address")),
    );
    fields.insert(
        "v6".to_owned(),
        FieldValue::Ipv6("2001:db8::1".parse().expect("documentation address")),
    );
    fields.insert("mac".to_owned(), FieldValue::Mac([0, 1, 2, 3, 4, 5]));
    fields.insert(
        "items".to_owned(),
        FieldValue::List(vec![
            FieldValue::List(vec![FieldValue::Unsigned(1)]),
            FieldValue::Text("x".to_owned()),
        ]),
    );
    let original = Packet {
        schema: SCHEMA.to_owned(),
        layers: vec![
            Layer {
                protocol: "ipv4".to_owned(),
                fields,
            },
            Layer {
                protocol: "raw".to_owned(),
                fields: BTreeMap::new(),
            },
        ],
    };
    let json = serde_json::to_string(&original).expect("serialize JSON");
    let yaml = noyalib::to_string(&original).expect("serialize YAML");
    let from_json = Packet::parse_with_limits(&json, Format::Json, &DocumentLimits::DEFAULT)
        .expect("reparse JSON");
    let from_yaml = Packet::parse_with_limits(&yaml, Format::Yaml, &DocumentLimits::DEFAULT)
        .expect("reparse YAML");
    assert_eq!(from_json, original);
    assert_eq!(from_yaml, original);
    let again = serde_json::to_string(&from_yaml).expect("serialize again");
    assert_eq!(again, json);
    assert_eq!(
        Packet::parse(&again, Format::Json, DEFAULT_MAX_DOCUMENT_BYTES).expect("simple entry"),
        original
    );
}

#[test]
fn shipped_examples_remain_valid_under_default_limits() {
    let directory =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/documents");
    let mut checked = 0;
    for entry in std::fs::read_dir(&directory).expect("examples directory") {
        let path = entry.expect("directory entry").path();
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("");
        if !name.starts_with("packet-") {
            continue;
        }
        let format = match path.extension().and_then(|extension| extension.to_str()) {
            Some("json") => Format::Json,
            Some("yaml" | "yml") => Format::Yaml,
            _ => continue,
        };
        let input = std::fs::read_to_string(&path).expect("example is UTF-8");
        let parsed = Packet::parse_with_limits(&input, format, &DocumentLimits::DEFAULT)
            .unwrap_or_else(|error| panic!("{name} rejected: {error}"));
        parsed.validate_schema().expect("current schema");
        checked += 1;
    }
    assert!(
        checked >= 4,
        "expected the shipped packet examples, found {checked}"
    );
}

#[test]
fn limit_names_are_stable_and_cover_every_field() {
    let names = Limit::ALL
        .iter()
        .map(|limit| limit.field())
        .collect::<Vec<_>>();
    assert_eq!(
        names,
        [
            "max_input_bytes",
            "max_layers",
            "max_nesting",
            "max_fields_per_layer",
            "max_total_nodes",
            "max_list_items",
            "max_total_list_items",
            "max_protocol_name_bytes",
            "max_field_name_bytes",
            "max_text_bytes",
            "max_byte_value_bytes",
            "max_total_payload_bytes",
        ]
    );
    for limit in Limit::ALL {
        assert_eq!(limit.to_string(), limit.field());
        assert!(DocumentLimits::DEFAULT.maximum(limit) > 0);
    }
    assert_eq!(DocumentLimits::default(), DocumentLimits::DEFAULT);
    const {
        assert!(
            DocumentLimits::DEFAULT.max_total_payload_bytes * 2 <= DEFAULT_MAX_DOCUMENT_BYTES,
            "payload defaults stay well inside the raw byte ceiling"
        );
    }
    let error = Error::ResourceLimit {
        limit: Limit::ListItems,
        maximum: 9,
    };
    assert_eq!(
        error.to_string(),
        "packet document exceeds configured limit max_list_items=9"
    );
}

/// Regressions found by the packet-document fuzz targets while the semantic
/// limits were introduced.
#[test]
fn fuzz_regressions_stay_fixed() {
    let cases: [(&str, Format); 6] = [
        // Layer probe past the layer limit must not recurse without bound.
        (
            "{\"schema\":\"packetcraftr.packet/v1\",\"layers\":[{},{\"protocol\":\"raw\",\"fields\":{\"f\":{\"type\":\"list\",\"value\":[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[",
            Format::Json,
        ),
        // Unknown tags and keys stay format errors.
        (
            "{\"schema\":\"packetcraftr.packet/v1\",\"layers\":[{\"protocol\":\"raw\",\"fields\":{\"f\":{\"type\":\"float\",\"value\":1.5}}}]}",
            Format::Json,
        ),
        (
            "{\"schema\":\"packetcraftr.packet/v1\",\"layers\":[{\"protocol\":\"raw\",\"fields\":{\"f\":{\"type\":\"unsigned\",\"value\":1,\"extra\":0}}}]}",
            Format::Json,
        ),
        // Value-first with an unusable shape.
        (
            "{\"schema\":\"packetcraftr.packet/v1\",\"layers\":[{\"protocol\":\"raw\",\"fields\":{\"f\":{\"value\":[[1]],\"type\":\"list\"}}}]}",
            Format::Json,
        ),
        (
            "{\"schema\":\"packetcraftr.packet/v1\",\"layers\":[{\"protocol\":\"raw\",\"fields\":{\"f\":{\"value\":{\"type\":\"bool\",\"value\":true},\"type\":\"bool\"}}}]}",
            Format::Json,
        ),
        // YAML anchors and multiple documents remain refused.
        (
            "schema: &a packetcraftr.packet/v1\nlayers: *a\n",
            Format::Yaml,
        ),
    ];
    for (input, format) in cases {
        let limits = DocumentLimits {
            max_layers: 1,
            ..DocumentLimits::DEFAULT
        };
        let result = Packet::parse_with_limits(input, format, &limits);
        assert!(result.is_err(), "{input:?} unexpectedly parsed: {result:?}");
    }
}
