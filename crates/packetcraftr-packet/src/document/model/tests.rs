// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;

use bytes::Bytes;

use super::error::DocumentError;
use super::types::{
    DocumentFormat, LayerDocument, MAX_DOCUMENT_NESTING, PACKET_DOCUMENT_SCHEMA_V1, PacketDocument,
};
use crate::field::FieldValue;

#[test]
fn yaml_byte_arrays_round_trip_like_json_byte_arrays() {
    let yaml = r#"
schema: packetcraftr.packet/v1
layers:
  - protocol: raw
    fields:
      bytes:
        type: bytes
        value: [104, 101, 108, 108, 111]
"#;
    let document = PacketDocument::parse(yaml, DocumentFormat::Yaml, 4096).unwrap();
    assert_eq!(
        document.layers[0].fields.get("bytes"),
        Some(&FieldValue::Bytes(Bytes::from_static(b"hello")))
    );
    assert!(document.to_yaml().unwrap().contains("- 104"));
}

#[test]
fn document_field_nesting_is_configurable_and_bounded() {
    let json = r#"{
            "schema":"packetcraftr.packet/v1",
            "layers":[{"protocol":"raw","fields":{"bytes":{
                "type":"list","value":[{"type":"list","value":[{
                    "type":"list","value":[]
                }]}]
            }}}]
        }"#;

    assert!(matches!(
        PacketDocument::parse_with_limits(json, DocumentFormat::Json, 4096, 2),
        Err(DocumentError::NestingLimit { limit: 2 })
    ));

    let yaml = r#"
schema: packetcraftr.packet/v1
layers:
  - protocol: raw
    fields:
      bytes:
        type: list
        value:
          - type: list
            value:
              - type: list
                value: []
"#;
    assert!(matches!(
        PacketDocument::parse_with_limits(yaml, DocumentFormat::Yaml, 4096, 2),
        Err(DocumentError::NestingLimit { limit: 2 })
    ));
}

#[test]
fn layer_limits_fire_during_json_and_yaml_deserialization() {
    let json = r#"{
            "schema":"packetcraftr.packet/v1",
            "layers":[{"protocol":"raw"},{"protocol":"raw"}]
        }"#;
    let yaml = r#"
schema: packetcraftr.packet/v1
layers:
  - protocol: raw
  - protocol: raw
"#;
    for (format, input) in [(DocumentFormat::Json, json), (DocumentFormat::Yaml, yaml)] {
        assert!(matches!(
            PacketDocument::parse_with_resource_limits(input, format, 4096, 1, 8),
            Err(DocumentError::LayerLimit { limit: 1 })
        ));
    }
}

#[test]
fn stable_document_parser_rejects_ambiguous_or_amplifying_yaml() {
    let multiple = r#"
schema: packetcraftr.packet/v1
layers: []
---
schema: packetcraftr.packet/v1
layers: []
"#;
    assert!(matches!(
        PacketDocument::parse(multiple, DocumentFormat::Yaml, 4096),
        Err(DocumentError::Parse { .. })
    ));

    let alias = r#"
schema: packetcraftr.packet/v1
layers:
  - &raw
    protocol: raw
  - *raw
"#;
    assert!(matches!(
        PacketDocument::parse(alias, DocumentFormat::Yaml, 4096),
        Err(DocumentError::Parse { .. })
    ));

    let custom_tag = r#"
schema: packetcraftr.packet/v1
layers:
  - protocol: !application raw
"#;
    assert!(matches!(
        PacketDocument::parse(custom_tag, DocumentFormat::Yaml, 4096),
        Err(DocumentError::Parse { .. })
    ));

    let duplicate = r#"
schema: packetcraftr.packet/v1
schema: packetcraftr.packet/v1
layers: []
"#;
    assert!(matches!(
        PacketDocument::parse(duplicate, DocumentFormat::Yaml, 4096),
        Err(DocumentError::Parse { .. })
    ));
}

#[test]
fn duplicate_reflective_fields_and_excess_limit_requests_are_rejected() {
    let duplicate = r#"{
            "schema":"packetcraftr.packet/v1",
            "layers":[{"protocol":"raw","fields":{
                "bytes":{"type":"bytes","value":[0]},
                "bytes":{"type":"bytes","value":[1]}
            }}]
        }"#;
    assert!(matches!(
        PacketDocument::parse(duplicate, DocumentFormat::Json, 4096),
        Err(DocumentError::Parse { .. })
    ));
    for unknown in [
        r#"{"schema":"packetcraftr.packet/v1","layers":[],"timeout":1}"#,
        r#"{"schema":"packetcraftr.packet/v1","layers":[{"protocol":"raw","route":"lab0"}]}"#,
        r#"{"schema":"packetcraftr.packet/v1","layers":[{"protocol":"raw","fields":{"bytes":{"type":"bytes","value":[],"encoding":"hex"}}}]}"#,
    ] {
        let result = PacketDocument::parse(unknown, DocumentFormat::Json, 4096);
        assert!(
            matches!(&result, Err(DocumentError::Parse { .. })),
            "{unknown}: {result:?}"
        );
    }
    let unknown_yaml = r#"
schema: packetcraftr.packet/v1
layers:
  - protocol: raw
    fields:
      bytes:
        type: bytes
        value: []
        encoding: hex
"#;
    assert!(matches!(
        PacketDocument::parse(unknown_yaml, DocumentFormat::Yaml, 4096),
        Err(DocumentError::Parse { .. })
    ));
    assert!(matches!(
        PacketDocument::parse_with_resource_limits(
            r#"{"schema":"packetcraftr.packet/v1","layers":[]}"#,
            DocumentFormat::Json,
            4096,
            64,
            MAX_DOCUMENT_NESTING + 1,
        ),
        Err(DocumentError::InvalidLimit {
            field: "max_nesting",
            ..
        })
    ));
}

#[test]
fn the_absolute_nesting_boundary_is_accepted_and_the_next_level_is_rejected() {
    let mut value = FieldValue::Bytes(Bytes::new());
    for _ in 0..MAX_DOCUMENT_NESTING {
        value = FieldValue::List(vec![value]);
    }
    let document = PacketDocument {
        schema: PACKET_DOCUMENT_SCHEMA_V1.to_owned(),
        layers: vec![LayerDocument {
            protocol: "raw".to_owned(),
            fields: BTreeMap::from([("bytes".to_owned(), value.clone())]),
        }],
    };
    let json = document.to_json_pretty().unwrap();
    let yaml = document.to_yaml().unwrap();
    for (format, input) in [
        (DocumentFormat::Json, json.as_str()),
        (DocumentFormat::Yaml, yaml.as_str()),
    ] {
        PacketDocument::parse_with_limits(input, format, 64 * 1024, MAX_DOCUMENT_NESTING).unwrap();
    }

    let too_deep = PacketDocument {
        schema: PACKET_DOCUMENT_SCHEMA_V1.to_owned(),
        layers: vec![LayerDocument {
            protocol: "raw".to_owned(),
            fields: BTreeMap::from([("bytes".to_owned(), FieldValue::List(vec![value]))]),
        }],
    };
    let json = too_deep.to_json_pretty().unwrap();
    let yaml = too_deep.to_yaml().unwrap();
    for (format, input) in [
        (DocumentFormat::Json, json.as_str()),
        (DocumentFormat::Yaml, yaml.as_str()),
    ] {
        assert!(matches!(
            PacketDocument::parse_with_limits(input, format, 64 * 1024, MAX_DOCUMENT_NESTING,),
            Err(DocumentError::NestingLimit {
                limit: MAX_DOCUMENT_NESTING
            })
        ));
    }
}
