// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
mod support;
use support::{parse_json, run, run_success, schema_validator};

#[test]
fn offline_dns_output_preserves_records_and_scoped_transaction_evidence() {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/captures/dns-response.pcap");
    let path = path.to_str().unwrap();
    let document = parse_json(&run_success(&["--output", "json", "dns-read", path]));
    let result = &document["result"];
    assert_eq!(result["summary"]["complete_messages"], 1);
    assert_eq!(result["transactions"][0]["status"], "orphan_response");
    assert_eq!(result["messages"][0]["sources"][0]["number"], 1);
    assert!(
        result["messages"][0]["fields"]["answers"]["value"]
            .as_array()
            .unwrap()
            .len()
            == 1
    );
    let validator = schema_validator();
    assert!(validator.is_valid(&document));
    let output = run_success(&["--output", "ndjson", "dns-read", path]);
    let records: Vec<serde_json::Value> = std::str::from_utf8(&output.stdout)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(
        records
            .iter()
            .map(|v| v["event"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["dns_message", "dns_transaction", "complete"]
    );
    for record in &records {
        assert!(validator.is_valid(record), "{record}");
    }
    let output = run(&[
        "--output",
        "ndjson",
        "dns-read",
        path,
        "--max-application-output-bytes",
        "1",
    ]);
    assert!(!output.status.success());
    let error: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(error["event"], "error");
    assert_eq!(error["sequence"], 0);
    let output = run(&["--output", "json", "dns-read", path, "--stream", "tcp:999"]);
    assert!(!output.status.success());
    let output = run(&["--output", "json", "dns-read", path, "--bad-option"]);
    let error = parse_json(&output);
    assert_eq!(error["command"], "dns-read");
}
