// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

fn corpus_schema() -> jsonschema::Validator {
    let schema: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../schemas/packetcraftr.scanner-corpus.v1.schema.json"
    ))
    .expect("corpus schema parses");
    jsonschema::validator_for(&schema).expect("corpus schema compiles")
}

#[test]
fn the_corpus_document_validates_against_its_local_schema() {
    let corpus: serde_json::Value =
        serde_json::from_str(include_str!("../../../../docs/scanner-corpus.v1.json"))
            .expect("corpus parses");
    corpus_schema()
        .validate(&corpus)
        .expect("the corpus satisfies its schema");
}

#[test]
fn the_corpus_inventory_is_unique_and_complete() {
    let corpus: serde_json::Value =
        serde_json::from_str(include_str!("../../../../docs/scanner-corpus.v1.json"))
            .expect("corpus parses");
    let scenarios = corpus["scenarios"].as_array().expect("scenarios");
    let ids: std::collections::BTreeSet<_> = scenarios
        .iter()
        .map(|scenario| scenario["id"].as_str().expect("id"))
        .collect();
    assert_eq!(ids.len(), scenarios.len(), "scenario ids are unique");
    let windows = corpus["request"]["windows"].as_array().expect("windows");
    let families = corpus["families"].as_array().expect("families");
    let transports = corpus["transports"].as_array().expect("transports");
    let cells = scenarios.len() * families.len() * transports.len() * windows.len();
    assert_eq!(cells, 72, "raw scan cells: 6 conditions x 2 x 3 x 2");
    let trace = corpus["traceroute_scenarios"].as_array().expect("trace");
    assert_eq!(trace.len() * families.len() * transports.len(), 12);
    let connect = corpus["native_connect_scenarios"]
        .as_array()
        .expect("connect");
    assert_eq!(connect.len() * families.len(), 4);
}

#[test]
fn trace_path_inventory_is_ordered_and_strict() {
    let corpus: serde_json::Value =
        serde_json::from_str(include_str!("../../../../docs/scanner-corpus.v1.json"))
            .expect("corpus parses");
    let cases = corpus["trace_path_scenarios"]
        .as_array()
        .expect("trace paths");
    let ids: Vec<_> = cases
        .iter()
        .map(|case| case["id"].as_str().expect("id"))
        .collect();
    assert_eq!(ids, ["shared-path", "divergent-paths", "silent-hop"]);
    for case in cases {
        let targets: std::collections::BTreeSet<_> = case["targets"]
            .as_array()
            .expect("targets")
            .iter()
            .map(|target| target.as_str().expect("target"))
            .collect();
        let paths: std::collections::BTreeSet<_> = case["paths"]
            .as_array()
            .expect("paths")
            .iter()
            .map(|path| path["target"].as_str().expect("path target"))
            .collect();
        assert_eq!(targets, paths, "every declared target has one path");
        let without = case["expected_probes_without_reuse"]
            .as_u64()
            .expect("count");
        let with = case["expected_probes_with_reuse"].as_u64().expect("count");
        assert!(with <= without, "reuse cannot send more probes");
    }
    let mut unknown = corpus.clone();
    unknown["trace_path_scenarios"][0]["paths"][0]["unknown"] = true.into();
    assert!(
        corpus_schema().validate(&unknown).is_err(),
        "trace-path paths stay strict"
    );
    let mut short = corpus;
    short["trace_path_scenarios"].as_array_mut().unwrap().pop();
    assert!(
        corpus_schema().validate(&short).is_err(),
        "the trace-path inventory stays complete"
    );
}

#[test]
fn discovery_corpus_conditions_are_unique_ordered_and_dual_stack() {
    let corpus: serde_json::Value =
        serde_json::from_str(include_str!("../../../../docs/scanner-corpus.v1.json")).unwrap();
    let cases = corpus["discovery_scenarios"].as_array().unwrap();
    let ids: Vec<_> = cases
        .iter()
        .map(|case| case["id"].as_str().unwrap())
        .collect();
    assert_eq!(
        ids,
        [
            "discovery-responsive",
            "discovery-closed-but-responsive",
            "discovery-silent",
            "discovery-blocked",
            "discovery-routed",
            "discovery-shared-link-address"
        ]
    );
    for case in cases {
        assert_eq!(case["families"], serde_json::json!(["ipv4", "ipv6"]));
    }
    let mut duplicate = corpus.clone();
    duplicate["discovery_scenarios"][0]["unknown"] = true.into();
    assert!(
        corpus_schema().validate(&duplicate).is_err(),
        "discovery fixture boundaries stay strict"
    );
}

#[test]
fn identification_inventory_preserves_uncertainty_and_claim_confidence() {
    let corpus: serde_json::Value =
        serde_json::from_str(include_str!("../../../../docs/scanner-corpus.v1.json")).unwrap();
    let cases = corpus["identification_scenarios"].as_array().unwrap();
    let ids: std::collections::BTreeSet<_> = cases
        .iter()
        .map(|case| case["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids.len(), 10);
    for case in cases {
        assert_eq!(case["families"], serde_json::json!(["ipv4", "ipv6"]));
        if matches!(
            case["expected"]["outcome"].as_str(),
            Some("unknown" | "ambiguous" | "malformed" | "truncated" | "excluded")
        ) {
            assert!(case["expected"]["version"].is_null());
        }
        if case["id"] == "identification-misleading-banner" {
            assert_eq!(case["expected"]["confidence"], "claim");
        }
    }
    let mut invalid = corpus.clone();
    invalid["identification_scenarios"][0]["authenticated"] = true.into();
    assert!(corpus_schema().validate(&invalid).is_err());
    let mut absent = corpus.clone();
    absent
        .as_object_mut()
        .unwrap()
        .remove("identification_scenarios");
    assert!(corpus_schema().validate(&absent).is_err());
    let mut short = corpus;
    short["identification_scenarios"]
        .as_array_mut()
        .unwrap()
        .pop();
    assert!(corpus_schema().validate(&short).is_err());
}
