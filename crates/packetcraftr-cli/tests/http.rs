// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
mod support;
use support::{parse_json, run, run_success, schema_validator};
#[test]
fn http_command_reports_sourced_messages_without_retaining_entity_bodies() {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/captures/http-stream.pcap");
    let path = path.to_str().unwrap();
    let document = parse_json(&run_success(&["--output", "json", "http", path]));
    let validator = schema_validator();
    assert!(validator.is_valid(&document));
    let messages = document["result"]["messages"].as_array().unwrap();
    assert_eq!(messages.len(), 2);
    assert_eq!(messages[0]["start"]["method"], "GET");
    assert_eq!(messages[0]["start"]["target"], "/example");
    assert_eq!(messages[0]["sources"][0]["number"], 4);
    assert_eq!(messages[0]["sources"][1]["number"], 5);
    assert_eq!(messages[1]["request"], 1);
    assert_eq!(messages[1]["body_bytes"], 5);
    assert_eq!(messages[1]["trailers"][0]["value"], "yes");
    assert!(messages[1].get("body").is_none());
    let output = run_success(&["--output", "ndjson", "http", path]);
    let records: Vec<serde_json::Value> = std::str::from_utf8(&output.stdout)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(
        records
            .iter()
            .map(|row| row["event"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["http_message", "http_message", "complete"]
    );
    for row in &records {
        assert!(validator.is_valid(row), "{row}");
    }
    let limited = parse_json(&run_success(&[
        "--output",
        "json",
        "http",
        path,
        "--max-http-body-bytes",
        "4",
    ]));
    assert_eq!(limited["result"]["messages"][1]["status"], "limit");
    assert!(
        !run(&["--output", "json", "http", path, "--stream", "udp:0"])
            .status
            .success()
    );
    let output = run(&[
        "--output",
        "json",
        "http",
        path,
        "--max-application-output-bytes",
        "1",
    ]);
    assert!(!output.status.success());
    assert_eq!(parse_json(&output)["error"]["kind"], "policy");
}
