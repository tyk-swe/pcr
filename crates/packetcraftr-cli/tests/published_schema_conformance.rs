// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Boundary checks of the published JSON schemas against their published
//! examples: each schema accepts its example and rejects values outside the
//! contract.

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
fn udp_profile_schema_accepts_the_published_profiles_and_bounds_names_as_the_loader_does() {
    let validator = validator(include_str!(
        "../../../schemas/packetcraftr.udp-profiles.v1.schema.json"
    ));
    let sample: Value = serde_json::from_str(include_str!(
        "../../../examples/documents/udp-profiles.json"
    ))
    .unwrap();
    assert!(validator.is_valid(&sample));
    // The schema bounds names as the loader does: characters, not bytes, and
    // no control characters.
    for (name, valid) in [
        ("\u{e9}".repeat(128), true),
        ("tab\tname".to_owned(), false),
    ] {
        let mut named = sample.clone();
        named["profiles"][0]["profile"]["name"] = json!(name);
        assert_eq!(validator.is_valid(&named), valid, "{name:?}");
    }
}

#[test]
fn v7_signed_intervals_and_transaction_outcomes_are_strict() {
    let validator = schema_validator();
    let mut document: Value = serde_json::from_str(include_str!(
        "../../../examples/documents/output-http-transaction-event.json"
    ))
    .expect("published transaction example must be JSON");
    validator
        .validate(&document)
        .expect("the signed-interval example validates");

    // Negative timing stays visible, but a zero interval is never negative.
    for interval in [
        json!({"nanoseconds": 0, "negative": true}),
        json!({"nanoseconds": -1, "negative": false}),
        json!({"nanoseconds": "1", "negative": false}),
    ] {
        document["result"]["response_header_wait"] = interval.clone();
        assert!(validator.validate(&document).is_err(), "{interval}");
    }
    // Nanoseconds are bounded to u128::MAX. Lossless JSON comparison cannot
    // tell 2^128-1 from 2^128, so the rejection case is unambiguously larger.
    document["result"]["response_header_wait"] = serde_json::from_str::<Value>(
        r#"{"nanoseconds": 34028236692093846346337460743176821145600, "negative": false}"#,
    )
    .unwrap();
    assert!(validator.validate(&document).is_err(), "beyond u128::MAX");
    document["result"]["response_header_wait"] = serde_json::from_str::<Value>(
        r#"{"nanoseconds": 340282366920938463463374607431768211455, "negative": true}"#,
    )
    .unwrap();
    validator.validate(&document).expect("u128::MAX validates");

    for (field, invalid) in [
        ("outcome", json!("matched")),
        ("outcome", json!(1)),
        ("response_status", json!(99)),
        ("response_status", json!(600)),
        ("index", json!(0)),
    ] {
        let mut mutated = document.clone();
        mutated["result"][field] = invalid.clone();
        assert!(validator.validate(&mutated).is_err(), "{field} = {invalid}");
    }
}

#[test]
fn v7_body_export_records_are_strict() {
    let validator = schema_validator();
    let mut document: Value = serde_json::from_str(include_str!(
        "../../../examples/documents/output-http-body-export-success.json"
    ))
    .expect("published body-export example must be JSON");
    validator
        .validate(&document)
        .expect("the body-export example validates");

    for (field, invalid) in [
        (
            "sha256",
            json!("2CF24DBA5FB0A30E26E83B2AC5B9E29E1B161E5C1FA7425E73043362938B9824"),
        ),
        ("sha256", json!("abcd")),
        ("representation", json!("http_body_raw")),
        ("bytes", json!(-1)),
        ("message", json!(0)),
    ] {
        document["result"]["body_export"][field] = invalid.clone();
        assert!(
            validator.validate(&document).is_err(),
            "body_export.{field} = {invalid}"
        );
    }
    document["result"]["body_export"] = serde_json::Value::Null;
    validator
        .validate(&document)
        .expect("body_export stays nullable");
}

#[test]
fn v7_split_parts_and_report_bounds_are_strict() {
    let validator = schema_validator();
    let mut document: Value = serde_json::from_str(include_str!(
        "../../../examples/documents/output-split-success.json"
    ))
    .expect("published split example must be JSON");
    validator
        .validate(&document)
        .expect("the split example validates");

    for file in [
        "chunk-000001.pcapng",
        "part-1.pcapng",
        "part-000001.pcap.gzx",
        "../part-000001.pcapng",
    ] {
        document["result"]["files"][0]["file"] = json!(file);
        assert!(
            validator.validate(&document).is_err(),
            "split filename {file}"
        );
    }
    document["result"]["files"][0]["file"] = json!("part-000001.pcap.zst");
    validator
        .validate(&document)
        .expect("compressed pcap part names validate");

    document["result"]["frames_per_file"] = json!(0);
    assert!(validator.validate(&document).is_err());
    document["result"]["frames_per_file"] = json!(3);
    document["result"]["files"] = json!([]);
    assert!(validator.validate(&document).is_err(), "no empty part list");
}

#[test]
fn v7_expert_gate_vocabulary_and_minimums_are_strict() {
    let validator = schema_validator();
    let mut document: Value = serde_json::from_str(include_str!(
        "../../../examples/documents/output-expert-gate-success.json"
    ))
    .expect("published gate example must be JSON");
    validator
        .validate(&document)
        .expect("the gate example validates");

    for (field, invalid) in [
        ("verdict", json!("ok")),
        ("reason", json!("none")),
        ("min_severity", json!("notice")),
        ("minimum_frames", json!(0)),
        ("triggering_findings", json!(-1)),
    ] {
        document["result"]["gate"][field] = invalid.clone();
        assert!(
            validator.validate(&document).is_err(),
            "gate.{field} = {invalid}"
        );
    }
    document["result"]["gate"] = serde_json::Value::Null;
    validator.validate(&document).expect("gate stays nullable");
}
