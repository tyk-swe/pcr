// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod support;
use serde_json::Value;
use support::{parse_json, parse_ndjson, run, run_success};

fn capture() -> String {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/captures/clock-regression.pcap")
        .to_str()
        .unwrap()
        .to_owned()
}
fn setting<'a>(record: &'a Value, name: &str) -> &'a Value {
    record["resources"]["settings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["name"] == name)
        .unwrap()
}
#[test]
fn opt_in_aggregate_metadata_preserves_default_contract_and_reports_provenance() {
    let path = capture();
    let ordinary = parse_json(&run_success(&[
        "--output",
        "json",
        "stats",
        &path,
        "--max-frames",
        "7",
    ]));
    assert!(ordinary.get("resources").is_none());
    let mut observed = parse_json(&run_success(&[
        "--resource-diagnostics",
        "--output",
        "json",
        "stats",
        &path,
        "--max-frames",
        "7",
    ]));
    assert_eq!(setting(&observed, "--max-frames")["value"], 7);
    assert_eq!(setting(&observed, "--max-frames")["source"], "override");
    assert_eq!(
        setting(&observed, "--max-flows")["stage"],
        "indexed_metadata"
    );
    assert_eq!(setting(&observed, "--max-flows")["source"], "default");
    assert_eq!(observed["resources"]["hard_rss_limit"], false);
    assert_eq!(
        setting(&observed, "--max-tcp-reassembly-bytes")["enabled"],
        false
    );
    observed.as_object_mut().unwrap().remove("resources");
    assert_eq!(ordinary, observed);
}
#[test]
fn first_and_terminal_stream_records_expose_output_policy_without_new_events() {
    let path = capture();
    let records = parse_ndjson(&run_success(&[
        "--output",
        "ndjson",
        "--resource-diagnostics",
        "--output-timeout-ms",
        "1500",
        "read",
        &path,
    ]));
    assert_eq!(records.len(), 4);
    assert_eq!(setting(&records[0], "--output-timeout-ms")["value"], 1500);
    assert_eq!(
        setting(&records[0], "terminal_error_timeout_ms")["value"],
        1000
    );
    assert!(records[1].get("resources").is_none());
    assert!(records[2].get("resources").is_none());
    assert_eq!(records[3]["event"], "complete");
    assert!(records[3].get("resources").is_some());
    let worker = records[0]["resources"]["workers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|worker| worker["name"] == "output_writer")
        .unwrap();
    assert_eq!(worker["capacity"], 1);
    assert_eq!(worker["active"], 1);
}
#[test]
fn failure_reports_effective_settings_and_invalid_options_fail_before_work() {
    let records = parse_ndjson(&run(&[
        "--output",
        "ndjson",
        "--resource-diagnostics",
        "read",
        "missing-capture.pcap",
    ]));
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["event"], "error");
    assert!(records[0].get("resources").is_some());
    for value in ["0", "3600001", "-1", "invalid"] {
        let output = run(&[
            "--output",
            "ndjson",
            "--output-timeout-ms",
            value,
            "read",
            "missing-capture.pcap",
        ]);
        assert_eq!(output.status.code(), Some(2));
        assert_eq!(parse_ndjson(&output)[0]["error"]["kind"], "cli");
    }
    assert_eq!(
        run(&["--resource-diagnostics", "protocols"]).status.code(),
        Some(2)
    );
    let error = parse_json(&run(&[
        "--output",
        "json",
        "--output-timeout-ms",
        "1",
        "protocols",
    ]));
    assert_eq!(error["error"]["kind"], "cli");
}
