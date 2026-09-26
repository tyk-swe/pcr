// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
mod common;
use common::{parse_json, run};
#[test]
fn profile_files_validate_before_target_resolution() {
    let sample: serde_json::Value = serde_json::from_str(include_str!(
        "../../../examples/documents/udp-profiles.json"
    ))
    .unwrap();
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("profiles.json");
    std::fs::write(&path, serde_json::to_vec(&sample).unwrap()).unwrap();
    let output = run(&[
        "--output",
        "json",
        "scan",
        "no-resolution.example.test",
        "--transport",
        "udp",
        "--ports",
        "53,9000",
        "--udp-profiles",
        path.to_str().unwrap(),
    ]);
    assert!(!output.status.success());
    let result = parse_json(&output);
    assert!(
        result["error"]["message"]
            .as_str()
            .unwrap()
            .contains("hostname")
    );
    let mut bad = sample.clone();
    bad["profiles"][1]["ports"] = serde_json::json!([53]);
    std::fs::write(&path, serde_json::to_vec(&bad).unwrap()).unwrap();
    let output = run(&[
        "--output",
        "json",
        "scan",
        "no-resolution.example.test",
        "--transport",
        "udp",
        "--ports",
        "53",
        "--udp-profiles",
        path.to_str().unwrap(),
    ]);
    assert!(
        parse_json(&output)["error"]["message"]
            .as_str()
            .unwrap()
            .contains("conflicting UDP profiles")
    );
    bad = sample.clone();
    bad["profiles"][1]["profile"]["response"]["checks"][0]["mask"] = serde_json::json!("00");
    std::fs::write(&path, serde_json::to_vec(&bad).unwrap()).unwrap();
    let output = run(&[
        "--output",
        "json",
        "scan",
        "no-resolution.example.test",
        "--transport",
        "udp",
        "--ports",
        "9000",
        "--udp-profiles",
        path.to_str().unwrap(),
    ]);
    assert_eq!(parse_json(&output)["error"]["code"], "cli.udp_profile");
    let output = run(&[
        "--output",
        "json",
        "scan",
        "192.0.2.1",
        "--ports",
        "80",
        "--udp-profiles",
        path.to_str().unwrap(),
    ]);
    assert!(
        parse_json(&output)["error"]["message"]
            .as_str()
            .unwrap()
            .contains("requires --transport udp")
    );
}
