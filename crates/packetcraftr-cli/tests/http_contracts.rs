// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
mod common;
use common::{assert_contiguous, parse_json, parse_ndjson, run, run_success};
#[test]
fn http_command_reports_sourced_messages_without_retaining_entity_bodies() {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/captures/http-stream.pcap");
    let path = path.to_str().unwrap();
    let document = parse_json(&run_success(&["--output", "json", "http", path]));
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
    let records = parse_ndjson(&run_success(&["--output", "ndjson", "http", path]));
    assert_eq!(
        records
            .iter()
            .map(|row| row["event"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["http_message", "http_message", "complete"]
    );
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

#[test]
fn http_rejects_zero_ports_and_out_of_range_body_limits_as_usage_errors() {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/captures/http-stream.pcap");
    let path = path.to_str().unwrap();
    for (flag, value) in [
        ("--http-port", "0"),
        ("--max-http-body-bytes", "0"),
        ("--max-http-body-bytes", "268435457"),
    ] {
        let output = run(&["--output", "json", "http", path, flag, value]);
        assert_eq!(output.status.code(), Some(2), "{flag} {value}: {output:?}");
        let error = parse_json(&output)["error"].clone();
        assert_eq!(error["kind"], "cli", "{flag} {value}");
        assert!(
            error["message"].as_str().unwrap().contains(flag),
            "{flag} {value}: {error}"
        );
    }
    let accepted = parse_json(&run_success(&[
        "--output",
        "json",
        "http",
        path,
        "--max-http-body-bytes",
        "268435456",
        "--http-port",
        "65535",
    ]));
    assert_eq!(accepted["result"]["messages"].as_array().unwrap().len(), 2);
}

#[test]
fn application_output_budget_counts_only_compact_event_payloads() {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/captures/http-stream.pcap");
    let expected_text = concat!(
        "HTTP tcp:0 message=1 status=complete GET /example body_bytes=0 request=none frames=4,5\n",
        "  Host: example.test\n",
        "  X-Test: one\n",
        "  X-Test: two\n",
        "HTTP tcp:0 message=2 status=complete 200 OK body_bytes=5 request=1 frames=6,7\n",
        "  Transfer-Encoding: chunked\n",
        "2 HTTP/1 messages, 2 complete, 0 incomplete, 0 malformed; 0 requests without a captured final response\n",
    );
    common::application_output::assert_exact_budget(
        "http",
        &path,
        &[
            ("http_message", "messages"),
            ("http_stream_issue", "issues"),
        ],
        expected_text,
        "analysis consumer failed at frame 7",
        &["application output exceeds --max-application-output-bytes"],
    );
}

#[test]
fn ndjson_budget_preserves_the_emitted_prefix_on_exhaustion() {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/captures/http-stream.pcap");
    let path = path.to_str().unwrap();
    let document = parse_json(&run_success(&["--output", "json", "http", path]));
    let first = serde_json::to_vec(&document["result"]["messages"][0])
        .unwrap()
        .len()
        .to_string();
    let output = run(&[
        "--output",
        "ndjson",
        "http",
        path,
        "--max-application-output-bytes",
        &first,
    ]);
    assert_eq!(output.status.code(), Some(6));
    let records = parse_ndjson(&output);
    assert_eq!(
        records
            .iter()
            .map(|record| record["event"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["http_message", "error"]
    );
    assert_contiguous(&records);
    assert_eq!(records[0]["result"], document["result"]["messages"][0]);
    assert_eq!(records[1]["error"]["code"], "policy.denied");
    assert_eq!(
        records[1]["error"]["message"],
        "analysis consumer failed at frame 7"
    );
    assert_eq!(
        records[1]["error"]["causes"][0],
        "application output exceeds --max-application-output-bytes"
    );
}

#[test]
fn zero_application_message_limit_is_a_usage_error() {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/captures/http-stream.pcap");
    let path = path.to_str().unwrap();
    let output = run(&[
        "--output",
        "json",
        "http",
        path,
        "--max-application-messages",
        "0",
    ]);
    assert_eq!(output.status.code(), Some(2));
    let error = &parse_json(&output)["error"];
    assert_eq!(error["code"], "cli.analysis_limit");
    assert_eq!(error["kind"], "cli");
    assert!(
        error["message"].as_str().unwrap().contains("max_messages"),
        "{error}"
    );
}
