// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use serde_json::{Value, json};

mod common;

use common::schema_validator;

fn validator(schema: &str) -> jsonschema::Validator {
    let schema: Value = serde_json::from_str(schema).expect("published schema must be JSON");
    jsonschema::validator_for(&schema).expect("published schema must compile")
}

fn rewrite_v2_validator() -> jsonschema::Validator {
    validator(include_str!(
        "../../../schemas/packetcraftr.rewrite.v2.schema.json"
    ))
}

#[test]
fn schema_accepts_one_based_source_frames_and_rejects_zero() {
    let validator = schema_validator();
    let mut document: Value = serde_json::from_str(include_str!(
        "../../../examples/documents/output-read-dissect-event.json"
    ))
    .expect("published read example must be JSON");
    document["result"]["source_frame"] = json!(1);
    validator
        .validate(&document)
        .unwrap_or_else(|error| panic!("source frame 1 is valid: {error}"));
    document["result"]["source_frame"] = json!(0);
    assert!(
        validator.validate(&document).is_err(),
        "source frame 0 is invalid"
    );
}

#[test]
fn rewrite_v2_schema_rejects_unknown_assignment_properties() {
    let document = json!({
        "schema": "packetcraftr.rewrite/v2",
        "rules": [{"assign": [{"field": "ipv4.ttl", "value": 63, "occurrence": 2}]}],
    });
    assert!(!rewrite_v2_validator().is_valid(&document));
}

/// Every published example document validates against the schema it names,
/// so an example cannot drift from a contract without failing here. The YAML
/// packet example is parsed by the document parser and validated through its
/// serialized form, since the schema describes the JSON representation.
#[test]
fn every_published_example_document_matches_its_declared_schema() {
    use packetcraftr_core::document::{DEFAULT_MAX_DOCUMENT_BYTES, Format, Packet};

    let packet_validator = validator(include_str!(
        "../../../schemas/packetcraftr.packet.v2.schema.json"
    ));
    let udp_profiles_validator = validator(include_str!(
        "../../../schemas/packetcraftr.udp-profiles.v1.schema.json"
    ));
    let rewrite_v2 = rewrite_v2_validator();
    let output_validator = schema_validator();

    let directory = concat!(env!("CARGO_MANIFEST_DIR"), "/../../examples/documents");
    let mut paths: Vec<_> = std::fs::read_dir(directory)
        .expect("published examples directory")
        .map(|entry| entry.expect("example entry").path())
        .collect();
    paths.sort();

    let mut validated = 0_usize;
    let mut failures = Vec::new();
    for path in &paths {
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        let text = std::fs::read_to_string(path).expect("example must be UTF-8");
        let document: Value = match path.extension().and_then(|e| e.to_str()) {
            Some("json") => serde_json::from_str(&text)
                .unwrap_or_else(|error| panic!("{name} must be JSON: {error}")),
            Some("yaml") => {
                let packet = Packet::parse(&text, Format::Yaml, DEFAULT_MAX_DOCUMENT_BYTES)
                    .unwrap_or_else(|error| panic!("{name} must be a packet document: {error}"));
                serde_json::to_value(packet).expect("packet documents serialize")
            }
            other => panic!("{name}: unexpected example extension {other:?}"),
        };
        let schema = document["schema"]
            .as_str()
            .unwrap_or_else(|| panic!("{name} must declare a schema"));
        let validator = match schema {
            "packetcraftr.output/v6" => output_validator,
            "packetcraftr.packet/v2" => &packet_validator,
            "packetcraftr.rewrite/v2" => &rewrite_v2,
            "packetcraftr.udp-profiles/v1" => &udp_profiles_validator,
            other => panic!("{name} declares an unknown schema {other}"),
        };
        if let Err(error) = validator.validate(&document) {
            failures.push(format!("{name}: {error}"));
        }
        validated += 1;
    }
    assert!(
        failures.is_empty(),
        "invalid examples:\n{}",
        failures.join("\n")
    );
    assert!(
        validated > 100,
        "expected every published example to be validated, saw {validated}"
    );
}
