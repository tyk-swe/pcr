// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use serde_json::{Value, json};

mod common;

use common::schema_validator;

fn validator(schema: &str) -> jsonschema::Validator {
    let schema: Value = serde_json::from_str(schema).expect("published schema must be JSON");
    jsonschema::validator_for(&schema).expect("published schema must compile")
}

fn rewrite_v1_validator() -> jsonschema::Validator {
    validator(include_str!(
        "../../../schemas/packetcraftr.rewrite.v1.schema.json"
    ))
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
fn rewrite_v1_schema_accepts_the_published_rules_and_rejects_an_empty_patch() {
    let validator = rewrite_v1_validator();
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../examples/documents/rewrite-lab-host.json"
    ))
    .unwrap();
    assert!(validator.is_valid(&fixture));
    let mut invalid = fixture.clone();
    invalid["rules"][0]["patch"] = json!({});
    assert!(!validator.is_valid(&invalid));
}

#[test]
fn rewrite_v2_schema_rejects_unknown_assignment_properties() {
    let document = json!({
        "schema": "packetcraftr.rewrite/v2",
        "rules": [{"assign": [{"field": "ipv4.ttl", "value": 63, "occurrence": 2}]}],
    });
    assert!(!rewrite_v2_validator().is_valid(&document));
}
