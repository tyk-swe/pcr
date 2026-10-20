// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use serde_json::Value;

use crate::common::*;

fn list_arguments<'a>(extra: &'a [&'a str]) -> Vec<&'a str> {
    let mut arguments = vec!["network", "scan", "--list", "--output", "json"];
    arguments.extend(extra);
    arguments
}

fn result_targets(json: &Value) -> &[Value] {
    json["result"]["targets"].as_array().expect("targets")
}

fn addresses(json: &Value) -> Vec<&str> {
    result_targets(json)
        .iter()
        .map(|target| target["address"].as_str().expect("address"))
        .collect()
}

#[test]
fn list_json_reports_targets_origins_and_no_resolution() {
    let output = run_success(&list_arguments(&["192.0.2.1", "10.0.0.0/30", "192.0.2.1"]));
    let json = parse_json(&output);
    assert_eq!(json["result"]["method"], "target_list");
    assert_eq!(json["result"]["resolution_performed"], false);
    assert_eq!(
        addresses(&json),
        ["192.0.2.1", "10.0.0.0", "10.0.0.1", "10.0.0.2", "10.0.0.3"]
    );
    let origins = &result_targets(&json)[0]["origins"];
    assert_eq!(origins.as_array().expect("origins").len(), 2);
    assert_eq!(origins[0]["index"], 0);
    assert_eq!(origins[0]["source"], "argument 1");
    assert_eq!(origins[1]["index"], 2);
    assert_eq!(origins[1]["source"], "argument 3");
    assert_eq!(
        json["result"]["duplicates"],
        serde_json::json!([{"index": 2, "source": "argument 3"}])
    );
    assert_eq!(
        json["diagnostics"],
        serde_json::json!([{
            "code": "scan.duplicate_declaration",
            "severity": "warning",
            "message": "target declaration 3 (argument 3) duplicates an earlier declaration and was coalesced",
        }])
    );
}
