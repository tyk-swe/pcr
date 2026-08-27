// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::sync::Arc;
use std::time::SystemTime;

use packetcraftr_core::build::{Builder, Context, DEFAULT_MAX_LAYERS, Options};
use packetcraftr_core::decode::{Dissector, Options as DecodeOptions};
use packetcraftr_core::document::v2::{Document, Minimized};
use packetcraftr_core::document::{DEFAULT_MAX_DOCUMENT_BYTES, Format, Packet as V1Packet};
use packetcraftr_core::error::Classified;
use packetcraftr_core::field::FieldValue;
use packetcraftr_core::frame::{Frame, LinkType};
use packetcraftr_core::protocol::builtin;

fn test_registry() -> Arc<packetcraftr_core::registry::Registry> {
    Arc::new(builtin::registry().expect("builtin registry should initialize"))
}

#[test]
fn test_1_parse_yaml_and_json_matching_v1_example_bytes() {
    let registry = test_registry();
    let builder = Builder::new(Arc::clone(&registry));

    let yaml_doc = r#"schema: packetcraftr.packet/v2
layers:
  - ethernet: {destination: "02:00:00:00:00:02", source: "02:00:00:00:00:01"}
  - ipv4: {source: 192.0.2.1, destination: 192.0.2.2, identification: 4660, dont_fragment: true}
  - udp: {source_port: 49152, destination_port: 9}
  - raw: {bytes: 0x68656c6c6f}
"#;

    let json_doc = r#"{
  "schema": "packetcraftr.packet/v2",
  "layers": [
    {"ethernet": {"destination": "02:00:00:00:00:02", "source": "02:00:00:00:00:01"}},
    {"ipv4": {"source": "192.0.2.1", "destination": "192.0.2.2", "identification": 4660, "dont_fragment": true}},
    {"udp": {"source_port": 49152, "destination_port": 9}},
    {"raw": {"bytes": "0x68656c6c6f"}}
  ]
}"#;

    let v2_yaml = Document::parse(yaml_doc, Format::Yaml, DEFAULT_MAX_DOCUMENT_BYTES)
        .expect("yaml parse should succeed");
    let v2_json = Document::parse(json_doc, Format::Json, DEFAULT_MAX_DOCUMENT_BYTES)
        .expect("json parse should succeed");

    let pkt_yaml = v2_yaml
        .to_packet(&registry, DEFAULT_MAX_LAYERS)
        .expect("yaml to_packet should succeed");
    let pkt_json = v2_json
        .to_packet(&registry, DEFAULT_MAX_LAYERS)
        .expect("json to_packet should succeed");

    let built_yaml = builder
        .build(pkt_yaml, Context::default(), Options::default())
        .expect("build yaml packet should succeed");
    let built_json = builder
        .build(pkt_json, Context::default(), Options::default())
        .expect("build json packet should succeed");

    let v1_content = r#"{
  "schema": "packetcraftr.packet/v1",
  "layers": [
    {
      "protocol": "ethernet",
      "fields": {
        "destination": { "type": "mac", "value": [2, 0, 0, 0, 0, 2] },
        "source": { "type": "mac", "value": [2, 0, 0, 0, 0, 1] }
      }
    },
    {
      "protocol": "ipv4",
      "fields": {
        "identification": { "type": "unsigned", "value": 4660 },
        "dont_fragment": { "type": "bool", "value": true },
        "ttl": { "type": "unsigned", "value": 64 },
        "source": { "type": "ipv4", "value": "192.0.2.1" },
        "destination": { "type": "ipv4", "value": "192.0.2.2" }
      }
    },
    {
      "protocol": "udp",
      "fields": {
        "source_port": { "type": "unsigned", "value": 49152 },
        "destination_port": { "type": "unsigned", "value": 9 }
      }
    },
    {
      "protocol": "raw",
      "fields": {
        "bytes": { "type": "bytes", "value": [104, 101, 108, 108, 111] }
      }
    }
  ]
}"#;
    let v1_doc = V1Packet::parse(v1_content, Format::Json, DEFAULT_MAX_DOCUMENT_BYTES)
        .expect("v1 json parse should succeed");
    let v1_pkt = v1_doc
        .to_packet(&registry, DEFAULT_MAX_LAYERS)
        .expect("v1 to_packet should succeed");
    let built_v1 = builder
        .build(v1_pkt, Context::default(), Options::default())
        .expect("build v1 packet should succeed");

    assert_eq!(built_yaml.bytes, built_v1.bytes);
    assert_eq!(built_json.bytes, built_v1.bytes);
}

#[test]
fn test_2_emit_parse_round_trip_and_stability() {
    let registry = test_registry();

    let doc_str = "schema: packetcraftr.packet/v2\nlayers:\n  - ethernet:\n      destination: \"02:00:00:00:00:02\"\n      source: \"02:00:00:00:00:01\"\n  - ipv4:\n      identification: 4660\n      dont_fragment: true\n      source: \"192.0.2.1\"\n      destination: \"192.0.2.2\"\n  - udp:\n      source_port: 49152\n      destination_port: 9\n  - raw:\n      bytes: \"0x68656c6c6f\"\n";

    let parsed = Document::parse(doc_str, Format::Yaml, DEFAULT_MAX_DOCUMENT_BYTES)
        .expect("parse should succeed");
    let packet = parsed
        .to_packet(&registry, DEFAULT_MAX_LAYERS)
        .expect("to_packet should succeed");
    let builder = Builder::new(Arc::clone(&registry));
    let built = builder
        .build(packet, Context::default(), Options::default())
        .expect("build should succeed");
    let frame = Frame::new(SystemTime::UNIX_EPOCH, LinkType::ETHERNET, built.bytes).unwrap();
    let decoded = Dissector::new(Arc::clone(&registry))
        .decode(frame, DecodeOptions::default())
        .unwrap();
    let (emitted_doc, status) = Document::from_decoded(&decoded, &registry, false);
    assert_eq!(status, Minimized::Derived);
    let emitted = emitted_doc
        .to_yaml_string()
        .expect("to_yaml_string should succeed");
    assert_eq!(emitted.trim(), doc_str.trim());

    let doc1 = Document::from_packet(&decoded.packet);
    let yaml1 = doc1
        .to_yaml_string()
        .expect("doc1 to_yaml_string should succeed");

    let parsed2 = Document::parse(&yaml1, Format::Yaml, DEFAULT_MAX_DOCUMENT_BYTES)
        .expect("parse yaml1 should succeed");
    let packet2 = parsed2
        .to_packet(&registry, DEFAULT_MAX_LAYERS)
        .expect("packet2 should succeed");
    let doc2 = Document::from_packet(&packet2);
    let yaml2 = doc2
        .to_yaml_string()
        .expect("doc2 to_yaml_string should succeed");

    assert_eq!(yaml1, yaml2);
}

#[test]
fn test_3_error_table_contracts() {
    let registry = test_registry();

    struct TestCase {
        name: &'static str,
        input: &'static str,
        expected_code: &'static str,
        required_substrings: &'static [&'static str],
    }

    let parse_test_cases = [
        TestCase {
            name: "no schema",
            input: "layers: []\n",
            expected_code: "document.unknown_schema",
            required_substrings: &["schema", "expected"],
        },
        TestCase {
            name: "packet/v3",
            input: "schema: packetcraftr.packet/v3\nlayers: []\n",
            expected_code: "document.unknown_schema",
            required_substrings: &["schema", "packetcraftr.packet/v3", "expected"],
        },
        TestCase {
            name: "two-key layer map",
            input: "schema: packetcraftr.packet/v2\nlayers:\n  - ethernet: {}\n    ipv4: {}\n",
            expected_code: "document.layer_shape",
            required_substrings: &["layer#0", "expected"],
        },
        TestCase {
            name: "scalar instead of map in layer",
            input: "schema: packetcraftr.packet/v2\nlayers:\n  - udp\n",
            expected_code: "document.layer_shape",
            required_substrings: &["layer#0", "udp", "expected"],
        },
    ];

    for tc in parse_test_cases {
        let err = Document::parse(tc.input, Format::Yaml, DEFAULT_MAX_DOCUMENT_BYTES)
            .expect_err(&format!("{} should error on parse", tc.name));
        assert_eq!(
            err.classification().code,
            tc.expected_code,
            "case: {}",
            tc.name
        );
        let msg = err.to_string();
        for sub in tc.required_substrings {
            assert!(
                msg.contains(sub),
                "case '{}': message '{}' missing '{}'",
                tc.name,
                msg,
                sub
            );
        }
    }

    let model_test_cases = [
        TestCase {
            name: "unknown protocol",
            input: "schema: packetcraftr.packet/v2\nlayers:\n  - unknownproto: {}\n",
            expected_code: "document.unknown_protocol",
            required_substrings: &["layer#0", "unknownproto", "expected"],
        },
        TestCase {
            name: "unknown field",
            input: "schema: packetcraftr.packet/v2\nlayers:\n  - ipv4: {source: 192.0.2.1, destination: 192.0.2.2, badfield: 1}\n",
            expected_code: "document.unknown_field",
            required_substrings: &["ipv4.badfield", "badfield", "expected"],
        },
        TestCase {
            name: "alias and canonical duplicate",
            input: "schema: packetcraftr.packet/v2\nlayers:\n  - udp: {dport: 1, destination_port: 1, source_port: 1}\n",
            expected_code: "document.duplicate_field",
            required_substrings: &[
                "udp.destination_port",
                "dport",
                "destination_port",
                "expected",
            ],
        },
        TestCase {
            name: "ttl 300 out of range",
            input: "schema: packetcraftr.packet/v2\nlayers:\n  - ipv4: {source: 192.0.2.1, destination: 192.0.2.2, ttl: 300}\n",
            expected_code: "document.value_form",
            required_substrings: &["ipv4.ttl", "300", "expected"],
        },
        TestCase {
            name: "ttl -1 negative",
            input: "schema: packetcraftr.packet/v2\nlayers:\n  - ipv4: {source: 192.0.2.1, destination: 192.0.2.2, ttl: -1}\n",
            expected_code: "document.value_form",
            required_substrings: &["ipv4.ttl", "-1", "expected"],
        },
        TestCase {
            name: "auto on ipv4.ttl",
            input: "schema: packetcraftr.packet/v2\nlayers:\n  - ipv4: {source: 192.0.2.1, destination: 192.0.2.2, ttl: auto}\n",
            expected_code: "document.auto_not_derived",
            required_substrings: &["ipv4.ttl", "auto", "expected"],
        },
        TestCase {
            name: "missing required ipv4.source",
            input: "schema: packetcraftr.packet/v2\nlayers:\n  - ipv4: {destination: 192.0.2.2}\n",
            expected_code: "document.missing_required",
            required_substrings: &["ipv4.source", "expected"],
        },
        TestCase {
            name: "tls decode_only layer",
            input: "schema: packetcraftr.packet/v2\nlayers:\n  - tls: {}\n",
            expected_code: "document.decode_only",
            required_substrings: &["tls", "tls", "expected"],
        },
        TestCase {
            name: "list on scalar",
            input: "schema: packetcraftr.packet/v2\nlayers:\n  - ipv4: {source: 192.0.2.1, destination: 192.0.2.2, ttl: [1, 2]}\n",
            expected_code: "document.value_form",
            required_substrings: &["ipv4.ttl", "expected"],
        },
        TestCase {
            name: "odd bytes length",
            input: "schema: packetcraftr.packet/v2\nlayers:\n  - raw: {bytes: 0xabc}\n",
            expected_code: "document.value_form",
            required_substrings: &["raw.bytes", "0xabc", "expected"],
        },
    ];

    for tc in model_test_cases {
        let doc = Document::parse(tc.input, Format::Yaml, DEFAULT_MAX_DOCUMENT_BYTES)
            .expect_err_or_doc(&format!("{} should parse", tc.name));
        let err = doc
            .to_packet(&registry, DEFAULT_MAX_LAYERS)
            .expect_err(&format!("{} should error on to_packet", tc.name));
        assert_eq!(
            err.classification().code,
            tc.expected_code,
            "case: {}",
            tc.name
        );
        let msg = err.to_string();
        for sub in tc.required_substrings {
            assert!(
                msg.contains(sub),
                "case '{}': message '{}' missing '{}'",
                tc.name,
                msg,
                sub
            );
        }
    }
}

trait ResultExt {
    fn expect_err_or_doc(self, msg: &str) -> Document;
}

impl ResultExt for Result<Document, packetcraftr_core::document::Error> {
    fn expect_err_or_doc(self, msg: &str) -> Document {
        match self {
            Ok(doc) => doc,
            Err(e) => panic!("{msg}: unexpected parse error {e}"),
        }
    }
}

#[test]
fn test_4_limits_mirror_v1() {
    let large = "schema: packetcraftr.packet/v2\nlayers: []\n# ".to_owned() + &"x".repeat(100);
    let err = Document::parse_with_resource_limits(&large, Format::Yaml, 50, 64, 64)
        .expect_err("oversized should error");
    assert_eq!(err.classification().code, "document.limit");

    let three_layers = r#"schema: packetcraftr.packet/v2
layers:
  - ethernet: {destination: "02:00:00:00:00:02", source: "02:00:00:00:00:01"}
  - ipv4: {source: 192.0.2.1, destination: 192.0.2.2}
  - udp: {source_port: 1, destination_port: 2}
"#;
    let err = Document::parse_with_resource_limits(three_layers, Format::Yaml, 10000, 2, 64)
        .expect_err("max_layers 2 should error on 3 layers");
    assert_eq!(err.classification().code, "document.limit");

    let dup_key = "schema: packetcraftr.packet/v2\nschema: packetcraftr.packet/v2\nlayers: []\n";
    let err =
        Document::parse(dup_key, Format::Yaml, 10000).expect_err("duplicate YAML key should error");
    assert_eq!(err.classification().code, "document.parse");

    let multi_doc = "schema: packetcraftr.packet/v2\nlayers: []\n---\nschema: packetcraftr.packet/v2\nlayers: []\n";
    let err = Document::parse(multi_doc, Format::Yaml, 10000)
        .expect_err("multiple YAML docs should error");
    assert_eq!(err.classification().code, "document.parse");
}

#[test]
fn test_5_yaml_quirks() {
    let registry = test_registry();

    let doc_010 = r#"schema: packetcraftr.packet/v2
layers:
  - ipv4: {source: 192.0.2.1, destination: 192.0.2.2, ttl: 010}
"#;
    let doc = Document::parse(doc_010, Format::Yaml, 10000).expect("parse 010 should succeed");
    let pkt = doc
        .to_packet(&registry, DEFAULT_MAX_LAYERS)
        .expect("to_packet 010");
    assert_eq!(
        pkt.layer(0).unwrap().field("ttl"),
        Some(FieldValue::Unsigned(10))
    );

    let doc_hex = r#"schema: packetcraftr.packet/v2
layers:
  - ipv4: {source: 192.0.2.1, destination: 192.0.2.2, identification: 0x10}
"#;
    let doc = Document::parse(doc_hex, Format::Yaml, 10000).expect("parse 0x10 should succeed");
    let pkt = doc
        .to_packet(&registry, DEFAULT_MAX_LAYERS)
        .expect("to_packet 0x10");
    assert_eq!(
        pkt.layer(0).unwrap().field("identification"),
        Some(FieldValue::Unsigned(16))
    );

    let doc_1e3 = r#"schema: packetcraftr.packet/v2
layers:
  - udp: {source_port: 1e3, destination_port: 9}
"#;
    let doc = Document::parse(doc_1e3, Format::Yaml, 10000).expect("parse 1e3");
    let err = doc
        .to_packet(&registry, DEFAULT_MAX_LAYERS)
        .expect_err("1e3 on u16 should fail");
    assert_eq!(err.classification().code, "document.value_form");

    let doc_yes = r#"schema: packetcraftr.packet/v2
layers:
  - ipv4: {source: 192.0.2.1, destination: 192.0.2.2, dont_fragment: yes}
"#;
    let doc = Document::parse(doc_yes, Format::Yaml, 10000).expect("parse yes");
    let err = doc
        .to_packet(&registry, DEFAULT_MAX_LAYERS)
        .expect_err("yes on bool should fail");
    assert_eq!(err.classification().code, "document.value_form");
}

#[test]
fn test_6_minimizer_derived_vs_full_literals() {
    let registry = test_registry();
    let builder = Builder::new(Arc::clone(&registry));

    let yaml_doc = r#"schema: packetcraftr.packet/v2
layers:
  - ethernet: {destination: "02:00:00:00:00:02", source: "02:00:00:00:00:01"}
  - ipv4: {source: 192.0.2.1, destination: 192.0.2.2, identification: 4660, dont_fragment: true}
  - udp: {source_port: 49152, destination_port: 9}
  - raw: {bytes: 0x68656c6c6f}
"#;

    let doc = Document::parse(yaml_doc, Format::Yaml, DEFAULT_MAX_DOCUMENT_BYTES).unwrap();
    let pkt = doc.to_packet(&registry, DEFAULT_MAX_LAYERS).unwrap();
    let built = builder
        .build(pkt, Context::default(), Options::default())
        .unwrap();

    let frame = Frame::new(
        SystemTime::UNIX_EPOCH,
        LinkType::ETHERNET,
        built.bytes.clone(),
    )
    .unwrap();
    let dissector = Dissector::new(Arc::clone(&registry));
    let decoded = dissector.decode(frame, DecodeOptions::default()).unwrap();

    // 1. Minimized emit with full = false
    let (minimized_doc, status) = Document::from_decoded(&decoded, &registry, false);
    assert_eq!(status, Minimized::Derived);
    let minimized_yaml = minimized_doc.to_yaml_string().unwrap();
    assert!(
        !minimized_yaml.contains("checksum:"),
        "should omit checksum: {minimized_yaml}"
    );
    assert!(
        !minimized_yaml.contains("total_length:"),
        "should omit total_length: {minimized_yaml}"
    );
    assert!(
        !minimized_yaml.contains("length:"),
        "should omit length: {minimized_yaml}"
    );
    assert!(
        !minimized_yaml.contains("ether_type:"),
        "should omit ether_type: {minimized_yaml}"
    );
    assert!(
        !minimized_yaml.contains("protocol:"),
        "should omit protocol: {minimized_yaml}"
    );

    // 2. Corrupt IPv4 checksum byte
    let mut corrupted_bytes = built.bytes.to_vec();
    // IPv4 header checksum is at offset 14 + 10 = 24
    if let Some(chk_byte) = corrupted_bytes.get_mut(24) {
        *chk_byte = chk_byte.wrapping_add(1);
    }
    let corrupted_frame =
        Frame::new(SystemTime::UNIX_EPOCH, LinkType::ETHERNET, corrupted_bytes).unwrap();
    let corrupted_decoded = dissector
        .decode(corrupted_frame, DecodeOptions::default())
        .unwrap();
    let (corrupted_doc, corrupted_status) =
        Document::from_decoded(&corrupted_decoded, &registry, false);
    assert_eq!(corrupted_status, Minimized::FullLiterals);
    let corrupted_yaml = corrupted_doc.to_yaml_string().unwrap();
    assert!(
        corrupted_yaml.contains("checksum:"),
        "should contain literal checksum: {corrupted_yaml}"
    );

    // 3. Full = true
    let (full_doc, full_status) = Document::from_decoded(&decoded, &registry, true);
    assert_eq!(full_status, Minimized::Skipped);
    let full_yaml = full_doc.to_yaml_string().unwrap();
    assert!(
        full_yaml.contains("checksum:"),
        "full should contain checksum: {full_yaml}"
    );
    assert!(
        full_yaml.contains("total_length:"),
        "full should contain total_length: {full_yaml}"
    );
    assert!(
        full_yaml.contains("length:"),
        "full should contain length: {full_yaml}"
    );
    assert!(
        full_yaml.contains("ether_type:"),
        "full should contain ether_type: {full_yaml}"
    );
}

#[test]
fn test_7_upgrade_all_v1_documents() {
    let registry = test_registry();
    let builder = Builder::new(Arc::clone(&registry));

    let v1_documents = [
        (
            "packet-ipv4-udp.json",
            Format::Json,
            r#"{
  "schema": "packetcraftr.packet/v1",
  "layers": [
    {
      "protocol": "ethernet",
      "fields": {
        "destination": { "type": "mac", "value": [2, 0, 0, 0, 0, 2] },
        "source": { "type": "mac", "value": [2, 0, 0, 0, 0, 1] }
      }
    },
    {
      "protocol": "ipv4",
      "fields": {
        "identification": { "type": "unsigned", "value": 4660 },
        "dont_fragment": { "type": "bool", "value": true },
        "ttl": { "type": "unsigned", "value": 64 },
        "source": { "type": "ipv4", "value": "192.0.2.1" },
        "destination": { "type": "ipv4", "value": "192.0.2.2" }
      }
    },
    {
      "protocol": "udp",
      "fields": {
        "source_port": { "type": "unsigned", "value": 49152 },
        "destination_port": { "type": "unsigned", "value": 9 }
      }
    },
    {
      "protocol": "raw",
      "fields": {
        "bytes": { "type": "bytes", "value": [104, 101, 108, 108, 111] }
      }
    }
  ]
}"#,
        ),
        (
            "packet-gre-sctp.json",
            Format::Json,
            r#"{
  "schema": "packetcraftr.packet/v1",
  "layers": [
    {
      "protocol": "ipv4",
      "fields": {
        "source": { "type": "ipv4", "value": "192.0.2.1" },
        "destination": { "type": "ipv4", "value": "192.0.2.2" }
      }
    },
    {
      "protocol": "gre",
      "fields": {
        "key": { "type": "unsigned", "value": 287454020 },
        "sequence": { "type": "unsigned", "value": 7 }
      }
    },
    {
      "protocol": "ipv6",
      "fields": {
        "source": { "type": "ipv6", "value": "2001:db8::1" },
        "destination": { "type": "ipv6", "value": "2001:db8::2" }
      }
    },
    {
      "protocol": "sctp",
      "fields": {
        "source_port": { "type": "unsigned", "value": 40000 },
        "destination_port": { "type": "unsigned", "value": 5000 },
        "verification_tag": { "type": "unsigned", "value": 0 }
      }
    },
    {
      "protocol": "raw",
      "fields": {
        "bytes": {
          "type": "bytes",
          "value": [
            1, 0, 0, 20, 17, 34, 51, 68, 0, 1, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0
          ]
        }
      }
    }
  ]
}"#,
        ),
        (
            "packet-igmp.json",
            Format::Json,
            r#"{
  "schema": "packetcraftr.packet/v1",
  "layers": [
    {
      "protocol": "ipv4",
      "fields": {
        "source": { "type": "ipv4", "value": "192.0.2.1" },
        "destination": { "type": "ipv4", "value": "224.0.0.1" },
        "ttl": { "type": "unsigned", "value": 1 }
      }
    },
    {
      "protocol": "igmp",
      "fields": {
        "type": { "type": "unsigned", "value": 17 },
        "code": { "type": "unsigned", "value": 0 },
        "body": { "type": "bytes", "value": [224, 0, 0, 1] }
      }
    }
  ]
}"#,
        ),
        (
            "packet-raw.yaml",
            Format::Yaml,
            r#"schema: packetcraftr.packet/v1
layers:
  - protocol: raw
    fields:
      bytes:
        value: [222, 173, 190, 239]
        type: bytes
"#,
        ),
    ];

    for (name, format, content) in v1_documents {
        let v1_doc = V1Packet::parse(content, format, DEFAULT_MAX_DOCUMENT_BYTES)
            .unwrap_or_else(|e| panic!("failed parsing v1 doc {name}: {e}"));
        let v1_pkt = v1_doc
            .to_packet(&registry, DEFAULT_MAX_LAYERS)
            .unwrap_or_else(|e| panic!("failed converting v1 pkt {name}: {e}"));
        let v1_built = builder
            .build(v1_pkt, Context::default(), Options::default())
            .unwrap_or_else(|e| panic!("failed building v1 pkt {name}: {e}"));

        let v2_doc = Document::from_v1(&v1_doc, &registry)
            .unwrap_or_else(|e| panic!("failed upgrading v1 to v2 {name}: {e}"));
        let v2_pkt = v2_doc
            .to_packet(&registry, DEFAULT_MAX_LAYERS)
            .unwrap_or_else(|e| panic!("failed converting v2 pkt {name}: {e}"));
        let v2_built = builder
            .build(v2_pkt, Context::default(), Options::default())
            .unwrap_or_else(|e| panic!("failed building v2 pkt {name}: {e}"));

        assert_eq!(
            v2_built.bytes, v1_built.bytes,
            "mismatch in bytes for {name}"
        );
    }
}

#[test]
fn test_8_detect_schema_skips_an_unrelated_earlier_schema_substring() {
    let json = r#"{
  "options_schema": "not-the-real-one",
  "schema": "packetcraftr.packet/v2",
  "layers": []
}"#;
    assert_eq!(
        Document::detect_schema(json),
        Some("packetcraftr.packet/v2"),
        "an earlier `schema` substring inside an unrelated key must not shadow the real one"
    );

    let yaml = "options_schema: not-the-real-one\nschema: packetcraftr.packet/v2\nlayers: []\n";
    assert_eq!(
        Document::detect_schema(yaml),
        Some("packetcraftr.packet/v2"),
        "same check for YAML"
    );

    assert_eq!(
        Document::detect_schema("just a schema-like string with no colon"),
        None
    );
}
