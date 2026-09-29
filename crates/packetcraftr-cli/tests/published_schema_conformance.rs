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
fn v4_dns_query_codes_are_bounded_in_aggregate_and_every_stream_shape() {
    let validator = schema_validator();
    for example in [
        include_str!("../../../examples/documents/output-dns-success.json"),
        include_str!("../../../examples/documents/output-dns-event.json"),
        include_str!("../../../examples/documents/output-dns-record-event.json"),
        include_str!("../../../examples/documents/output-dns-rejected-event.json"),
        include_str!("../../../examples/documents/output-dns-complete.json"),
    ] {
        let mut document: Value = serde_json::from_str(example).unwrap();
        for code in [0, 1, 65000, 65535] {
            document["result"]["query_type"] = json!(code);
            validator.validate(&document).unwrap();
        }
        for invalid in [
            json!(-1),
            json!(65536),
            json!(1.5),
            json!("a"),
            json!("65000"),
            json!("TYPE65000"),
        ] {
            document["result"]["query_type"] = invalid;
            assert!(validator.validate(&document).is_err());
        }
        document["result"]["query_type"] = json!(1);
        document["schema"] = json!("packetcraftr.output/v2");
        assert!(validator.validate(&document).is_err());
    }
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
fn rewrite_v2_schema_accepts_the_published_rules_and_rejects_empty_assigns() {
    let validator = rewrite_v2_validator();
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../examples/documents/rewrite-field-edits.json"
    ))
    .unwrap();
    assert!(validator.is_valid(&fixture));
    let mut invalid = fixture.clone();
    invalid["rules"][0]["assign"] = json!([]);
    assert!(!validator.is_valid(&invalid));
    invalid = fixture.clone();
    invalid["schema"] = json!("packetcraftr.rewrite/v1");
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

#[test]
fn rewrite_schemas_accept_filters_up_to_the_filter_length_limit_as_the_loader_does() {
    let filter = format!("udp && ({})", vec!["udp.port == 53"; 700].join(" || "));
    assert!(
        8192 < filter.len() && filter.len() <= packetcraftr_core::filter::DEFAULT_MAX_FILTER_BYTES
    );
    let v1 = json!({
        "schema": "packetcraftr.rewrite/v1",
        "rules": [{"filter": filter, "patch": {"source_port": 1}}],
    });
    let v2 = json!({
        "schema": "packetcraftr.rewrite/v2",
        "rules": [{"filter": filter, "assign": ["ipv4.ttl=63"]}],
    });
    rewrite_v1_validator()
        .validate(&v1)
        .unwrap_or_else(|error| panic!("v1 filter within the limit is valid: {error}"));
    rewrite_v2_validator()
        .validate(&v2)
        .unwrap_or_else(|error| panic!("v2 filter within the limit is valid: {error}"));
}

#[test]
fn rewrite_v2_schema_accepts_zero_padded_assignment_text_as_the_loader_does() {
    let document = json!({
        "schema": "packetcraftr.rewrite/v2",
        "rules": [{"assign": [format!("ipv4.ttl={}63", "0".repeat(9000))]}],
    });
    rewrite_v2_validator()
        .validate(&document)
        .unwrap_or_else(|error| panic!("zero-padded assignment text is valid: {error}"));
}

#[test]
fn udp_profile_schema_accepts_the_published_profiles_and_bounds_names_as_the_loader_does() {
    let validator = validator(include_str!(
        "../../../schemas/packetcraftr.udp-profiles.v1.schema.json"
    ));
    let sample: Value = serde_json::from_str(include_str!(
        "../../../examples/documents/udp-profiles.json"
    ))
    .unwrap();
    assert!(validator.is_valid(&sample));
    for (name, valid) in [
        ("\u{e9}".repeat(128), true),
        ("\u{e9}".repeat(129), false),
        (String::new(), false),
        ("tab\tname".to_owned(), false),
    ] {
        let mut named = sample.clone();
        named["profiles"][0]["profile"]["name"] = json!(name);
        assert_eq!(validator.is_valid(&named), valid, "{name:?}");
    }
}

#[test]
fn tcp_profile_schema_matches_bytes_only_loader_and_response_ceiling() {
    let schema = validator(include_str!(
        "../../../schemas/packetcraftr.tcp-profiles.v1.schema.json"
    ));
    let sample: Value = serde_json::from_str(include_str!(
        "../../../examples/documents/tcp-profiles.json"
    ))
    .unwrap();
    schema.validate(&sample).unwrap();
    packetcraftr_core::document::tcp_profiles::parse(&serde_json::to_vec(&sample).unwrap())
        .unwrap();
    let mut invalid = sample.clone();
    invalid["profiles"][0]["profile"]["response"] = json!({"type":"dns"});
    assert!(!schema.is_valid(&invalid));
    assert!(
        packetcraftr_core::document::tcp_profiles::parse(&serde_json::to_vec(&invalid).unwrap())
            .is_err()
    );
    invalid = sample.clone();
    invalid["profiles"][0]["profile"]["response"]["max_length"] = json!(65537);
    assert!(!schema.is_valid(&invalid));
    invalid = sample;
    invalid["profiles"][0]["profile"]["request"]["type"] = json!("dns");
    assert!(!schema.is_valid(&invalid));
}
