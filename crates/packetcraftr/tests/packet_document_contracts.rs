// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
// Test code indexes fixtures and counts by hand; the fail-closed lints are
// for library paths.
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

//! Keeps `schemas/packetcraftr.packet.v1.schema.json` and the published
//! `examples/documents/packet-*` files in step with the document loader.

use std::fs;
use std::path::{Path, PathBuf};

use packetcraftr::core::document::{DEFAULT_MAX_DOCUMENT_BYTES, Format, Packet};
use serde_json::Value;

mod support;

/// The published packet examples, and how many of those are JSON. Both are
/// exact: a new example has to be added here on purpose.
const PUBLISHED_PACKET_EXAMPLES: usize = 4;
const PUBLISHED_JSON_PACKET_EXAMPLES: usize = 3;

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
    let registry = packetcraftr::core::protocol::builtin::registry().expect("built-in registry");
    for path in packet_examples() {
        let input = fs::read_to_string(&path).expect("published example must be readable");
        let document = Packet::parse(&input, format_for(&path), DEFAULT_MAX_DOCUMENT_BYTES)
            .unwrap_or_else(|error| panic!("{} must parse: {error}", path.display()));
        let packet = document
            .to_packet(&registry, packetcraftr::core::build::DEFAULT_MAX_LAYERS)
            .unwrap_or_else(|error| panic!("{} must convert: {error}", path.display()));
        assert!(!packet.is_empty(), "{} must declare layers", path.display());

        // A document produced from the packet must describe the same layers.
        let reconverted = Packet::from_packet(&packet);
        assert_eq!(
            reconverted.layers.len(),
            document.layers.len(),
            "{} must round-trip its layer count",
            path.display()
        );
    }
}
