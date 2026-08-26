// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
// Test code indexes fixtures and counts by hand; the fail-closed lints are
// for library paths.
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

//! Keeps `schemas/packetcraftr.packet.v2.schema.json` and the published
//! `examples/documents/packet-*` files in step with the document loader.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use packetcraftr::core::{
    build::{Builder, Context, DEFAULT_MAX_LAYERS, Options},
    document::{
        DEFAULT_MAX_DOCUMENT_BYTES, Format, Packet as PacketV1, deprecated_schema_diagnostic,
        v2::Document as DocumentV2,
    },
    protocol::builtin::registry,
};
use serde_json::Value;

mod support;

/// The published packet examples, and how many of those are JSON. Both are
/// exact: a new example has to be added here on purpose.
const PUBLISHED_PACKET_EXAMPLES: usize = 4;
const PUBLISHED_JSON_PACKET_EXAMPLES: usize = 3;

const INLINE_V1_IPV4_UDP: &str = r#"{
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

fn examples_directory() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/documents")
}

fn packet_examples() -> Vec<PathBuf> {
    let mut examples = fs::read_dir(examples_directory())
        .expect("published examples directory must exist")
        .map(|entry| {
            entry
                .expect("published example entry must be readable")
                .path()
        })
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("packet-"))
        })
        .collect::<Vec<_>>();
    examples.sort();
    assert_eq!(
        examples.len(),
        PUBLISHED_PACKET_EXAMPLES,
        "expected exactly {PUBLISHED_PACKET_EXAMPLES} published packet examples, found {examples:?}"
    );
    examples
}

fn format_for(path: &Path) -> Format {
    match path.extension().and_then(|extension| extension.to_str()) {
        Some("json") => Format::Json,
        Some("yaml" | "yml") => Format::Yaml,
        other => panic!("{}: unexpected extension {other:?}", path.display()),
    }
}

#[test]
fn every_published_json_packet_example_validates_against_the_schema() {
    let validator = support::packet_schema_validator();

    let mut validated = 0_usize;
    for path in packet_examples() {
        if format_for(&path) != Format::Json {
            continue;
        }
        let document: Value = serde_json::from_str(
            &fs::read_to_string(&path).expect("published example must be readable"),
        )
        .unwrap_or_else(|error| panic!("{} must be valid JSON: {error}", path.display()));
        validator.validate(&document).unwrap_or_else(|error| {
            panic!(
                "{} must validate against the packet schema: {error}",
                path.display()
            )
        });
        validated += 1;
    }
    assert_eq!(
        validated, PUBLISHED_JSON_PACKET_EXAMPLES,
        "expected exactly {PUBLISHED_JSON_PACKET_EXAMPLES} JSON packet examples, validated {validated}"
    );
}

#[test]
fn every_published_packet_example_loads_and_builds() {
    let registry = std::sync::Arc::new(registry().expect("built-in registry"));
    let builder = Builder::new(Arc::clone(&registry));
    for path in packet_examples() {
        let input = fs::read_to_string(&path).expect("published example must be readable");
        let document = DocumentV2::parse(&input, format_for(&path), DEFAULT_MAX_DOCUMENT_BYTES)
            .unwrap_or_else(|error| panic!("{} must parse as v2: {error}", path.display()));
        let packet = document
            .to_packet(&registry, DEFAULT_MAX_LAYERS)
            .unwrap_or_else(|error| panic!("{} must convert to packet: {error}", path.display()));
        assert!(!packet.is_empty(), "{} must declare layers", path.display());

        let built = builder
            .build(packet, Context::default(), Options::default())
            .unwrap_or_else(|error| panic!("{} must build: {error}", path.display()));
        assert!(
            !built.bytes.is_empty(),
            "{} must build bytes",
            path.display()
        );
    }
}

#[test]
fn v1_document_fixture_builds_identical_bytes_and_yields_deprecation_diagnostic() {
    let registry = std::sync::Arc::new(registry().expect("built-in registry"));
    let builder = Builder::new(Arc::clone(&registry));

    // Build v2 published document
    let v2_path = examples_directory().join("packet-ipv4-udp.json");
    let v2_input = fs::read_to_string(&v2_path).expect("v2 example must be readable");
    let v2_doc = DocumentV2::parse(&v2_input, Format::Json, DEFAULT_MAX_DOCUMENT_BYTES)
        .expect("v2 document must parse");
    let v2_packet = v2_doc
        .to_packet(&registry, DEFAULT_MAX_LAYERS)
        .expect("v2 doc to packet");
    let v2_built = builder
        .build(v2_packet, Context::default(), Options::default())
        .expect("v2 build");

    // Build inline v1 document
    let v1_doc = PacketV1::parse(INLINE_V1_IPV4_UDP, Format::Json, DEFAULT_MAX_DOCUMENT_BYTES)
        .expect("v1 document must parse");
    let v1_packet = v1_doc
        .to_packet(&registry, DEFAULT_MAX_LAYERS)
        .expect("v1 doc to packet");
    let v1_built = builder
        .build(v1_packet, Context::default(), Options::default())
        .expect("v1 build");

    assert_eq!(
        v1_built.bytes, v2_built.bytes,
        "v1 and v2 packet documents must produce identical wire bytes"
    );

    // Convert v1 to v2 via upgrade and verify bytes
    let upgraded_doc = DocumentV2::from_v1(&v1_doc, &registry).expect("upgrade v1 to v2");
    let upgraded_packet = upgraded_doc
        .to_packet(&registry, DEFAULT_MAX_LAYERS)
        .expect("upgraded doc to packet");
    let upgraded_built = builder
        .build(upgraded_packet, Context::default(), Options::default())
        .expect("upgraded build");
    assert_eq!(
        upgraded_built.bytes, v2_built.bytes,
        "upgraded v2 document must produce identical wire bytes"
    );

    // Verify deprecation diagnostic
    let diag = deprecated_schema_diagnostic("test-packet.json");
    assert_eq!(diag.code, "document.deprecated_schema");
    assert_eq!(
        diag.severity,
        packetcraftr::core::diagnostic::Severity::Warning
    );
    assert_eq!(
        diag.message,
        "packetcraftr.packet/v1 is deprecated; run `packetcraftr convert test-packet.json` to rewrite it as packetcraftr.packet/v2"
    );

    let stdin_diag = deprecated_schema_diagnostic("-");
    assert_eq!(
        stdin_diag.message,
        "packetcraftr.packet/v1 is deprecated; run `packetcraftr convert -` to rewrite it as packetcraftr.packet/v2"
    );
}
