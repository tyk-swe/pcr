// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr_core::document::{
    DocumentLimits, Error, Format, Limit, MAX_DOCUMENT_NESTING, PACKET_DOCUMENT_SCHEMA_V2, Packet,
};
use packetcraftr_core::error::Classified;
use serde::Deserialize;

const SCHEMA: &str = PACKET_DOCUMENT_SCHEMA_V2;

fn document(layers: &str) -> String {
    document_with_schema(SCHEMA, layers)
}

fn document_with_schema(schema: &str, layers: &str) -> String {
    format!("{{\"schema\":\"{schema}\",\"layers\":[{layers}]}}")
}

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

fn nested_lists(name: &str, depth: usize) -> String {
    let mut value = "[]".to_owned();
    for _ in 1..depth {
        value = format!("[{{\"type\":\"list\",\"value\":{value}}}]");
    }
    format!("\"{name}\":{{\"type\":\"list\",\"value\":{value}}}")
}

fn to_yaml(json: &str) -> String {
    let mut deserializer = serde_json::Deserializer::from_str(json);
    deserializer.disable_recursion_limit();
    let value = serde_json::Value::deserialize(&mut deserializer).expect("fixture JSON is valid");
    // The YAML serializer stops at 128 nested containers; beyond that the
    // JSON text itself is the flow-style YAML twin.
    noyalib::to_string(&value).unwrap_or_else(|_| json.to_owned())
}

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

#[test]
fn every_limit_exact_boundary_reject_one_unit() {
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
fn invalid_limits_reject_before_parsing() {
    let limits = DocumentLimits {
        max_nesting: MAX_DOCUMENT_NESTING + 1,
        ..DocumentLimits::DEFAULT
    };
    for format in [Format::Json, Format::Yaml] {
        let error = Packet::parse_with_limits("not a document", format, &limits)
            .expect_err("an unsupported limit is refused");
        assert!(matches!(
            error,
            Error::InvalidLimit {
                field: "max_nesting",
                ..
            }
        ));
        let classification = error.classification();
        assert_eq!(classification.code, "cli.document_limit");
        assert!(
            classification
                .remediation
                .is_some_and(|remediation| remediation.contains("configured document limit")),
            "{:?}",
            classification.remediation
        );
    }
}

#[test]
fn deeply_nested_no_exhausting_stack() {
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
    let absurd = document(&layer("raw", &[nested_lists("f", 300)]));
    assert_eq!(
        limit_of(parse_both(&absurd, &DocumentLimits::DEFAULT)),
        Limit::Nesting
    );
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
