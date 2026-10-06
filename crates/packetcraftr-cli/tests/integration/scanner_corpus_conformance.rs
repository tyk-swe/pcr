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
