// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! The `packetcraftr.udp-profiles/v1` document.

use std::sync::Arc;

use packetcraftr::scan::profile::{DocumentError, MAX_PROFILE_BYTES, parse_document};
use packetcraftr_core::error::{Classified, Kind};
use serde_json::{Value, json};

const SAMPLE: &str = include_str!("../../../examples/documents/udp-profiles.json");

fn sample() -> Value {
    serde_json::from_str(SAMPLE).unwrap()
}

fn parse(document: &Value) -> Result<(), DocumentError> {
    parse_document(&serde_json::to_vec(document).unwrap()).map(drop)
}

#[test]
fn the_published_example_maps_each_port_to_a_shared_profile() {
    let profiles = parse_document(SAMPLE.as_bytes()).unwrap();
    assert_eq!(
        profiles.keys().copied().collect::<Vec<_>>(),
        [53, 9000, 9001]
    );
    assert_eq!(profiles[&53].name(), "dns-example");
    assert!(Arc::ptr_eq(&profiles[&9000], &profiles[&9001]));

    // The same profile under several assignments is compiled once.
    let mut repeated = sample();
    let first = repeated["profiles"][0].clone();
    let mut again = first.clone();
    again["ports"] = json!([5353, 53]);
    repeated["profiles"] = json!([first, again]);
    let profiles = parse_document(&serde_json::to_vec(&repeated).unwrap()).unwrap();
    assert!(Arc::ptr_eq(&profiles[&53], &profiles[&5353]));
}

#[test]
fn document_refusals_keep_their_published_codes_and_messages() {
    const SHAPE: &str =
        "UDP profiles require schema packetcraftr.udp-profiles/v1 and 1..=256 assignments";
    let mut cases = Vec::new();
    let mut document = sample();
    document["schema"] = json!("packetcraftr.udp-profiles/v2");
    cases.push((document, SHAPE.to_owned()));
    let mut document = sample();
    document["profiles"] = json!([]);
    cases.push((document, SHAPE.to_owned()));
    let mut document = sample();
    document["profiles"] = json!(vec![sample()["profiles"][0].clone(); 257]);
    cases.push((document, SHAPE.to_owned()));
    let mut document = sample();
    document["profiles"][0]["ports"] = json!([]);
    cases.push((
        document,
        "each UDP profile needs 1..=4096 port entries".to_owned(),
    ));
    let mut document = sample();
    document["profiles"][1]["ports"] = json!([53]);
    cases.push((document, "conflicting UDP profiles for port 53".to_owned()));
    let mut document = sample();
    let profile = document["profiles"][0]["profile"].clone();
    document["profiles"] = json!([
        {"ports": (0..3000).collect::<Vec<u16>>(), "profile": profile},
        {"ports": (3000..6000).collect::<Vec<u16>>(), "profile": profile},
    ]);
    cases.push((document, "UDP profiles exceed 4096 mapped ports".to_owned()));
    for (document, message) in cases {
        let error = parse(&document).expect_err("refused");
        let classification = error.classification();
        assert_eq!(
            (classification.code, classification.kind, error.to_string()),
            ("cli.error", Kind::Usage, message)
        );
        assert!(error.causes().is_empty());
    }
}

#[test]
fn distinct_profiles_share_one_storage_budget() {
    let profile = sample()["profiles"][0]["profile"].clone();
    let assignments: Vec<Value> = (0..200)
        .map(|index| {
            let mut profile = profile.clone();
            profile["name"] = json!(format!("profile-{index}"));
            let label = format!("x{index:03}{}", "a".repeat(55));
            profile["request"]["name"] = json!(format!("{label}.{label}.{label}.{label}."));
            json!({"ports": [index + 1], "profile": profile})
        })
        .collect();
    let document = json!({"schema": "packetcraftr.udp-profiles/v1", "profiles": assignments});
    let bytes = serde_json::to_vec(&document).unwrap();
    assert!(bytes.len() < MAX_PROFILE_BYTES);
    let error = parse_document(&bytes).expect_err("over budget");
    assert!(matches!(error, DocumentError::Storage), "{error:?}");
    assert_eq!(error.to_string(), "compiled UDP profiles exceed 1 MiB");
}

#[test]
fn an_invalid_profile_keeps_its_own_classification() {
    let mut document = sample();
    document["profiles"][1]["profile"]["response"]["checks"][0]["mask"] = json!("00");
    let error = parse(&document).expect_err("mask length differs from data");
    assert!(matches!(error, DocumentError::Profile(_)), "{error:?}");
    assert_eq!(error.classification().code, "cli.udp_profile");
}

#[test]
fn syntax_refusals_name_the_parser_reason_once() {
    let mut document = sample();
    document["profiles"][0]["unknown"] = json!(true);
    for bytes in [b"{".to_vec(), serde_json::to_vec(&document).unwrap()] {
        let error = parse_document(&bytes).expect_err("refused");
        assert!(matches!(error, DocumentError::Syntax(_)), "{error:?}");
        assert!(error.to_string().starts_with("invalid UDP profiles: "));
        assert_eq!(error.classification().code, "cli.error");
        assert!(error.causes().is_empty());
    }
    let oversized = vec![b' '; MAX_PROFILE_BYTES + 1];
    assert!(matches!(
        parse_document(&oversized),
        Err(DocumentError::DocumentSize { .. })
    ));
}
