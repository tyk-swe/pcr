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
fn application_output_budget_counts_only_compact_event_payloads() {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/captures/http-stream.pcap");
    let path = path.to_str().unwrap();
    let document = parse_json(&run_success(&["--output", "json", "http", path]));
    let total: usize = ["messages", "issues"]
        .iter()
        .flat_map(|key| document["result"][key].as_array().unwrap().iter())
        .map(|value| serde_json::to_vec(value).unwrap().len())
        .sum();
    let command = "http";
    let event_collections = [
        ("http_message", "messages"),
        ("http_stream_issue", "issues"),
    ];
    let expected_text = "HTTP tcp:0 message=1 Complete GET /example body_bytes=0 request=None frames=[4, 5]\n  Host: example.test\n  X-Test: one\n  X-Test: two\nHTTP tcp:0 message=2 Complete 200 OK body_bytes=5 request=Some(1) frames=[6, 7]\n  Transfer-Encoding: chunked\n2 HTTP/1 messages, 2 complete, 0 incomplete, 0 malformed; 0 requests without a captured final response\n";
    let error_message = "analysis consumer failed at frame 7: application output exceeds --max-application-output-bytes";
    let exact = total.to_string();
    let under = (total - 1).to_string();
    for format in ["json", "ndjson", "text"] {
        let success = run_success(&[
            "--output",
            format,
            command,
            path,
            "--max-application-output-bytes",
            &exact,
        ]);
        match format {
            "json" => assert_eq!(parse_json(&success)["result"], document["result"]),
            "ndjson" => {
                let records = parse_ndjson(&success);
                assert_contiguous(&records);
                assert_eq!(records.last().unwrap()["event"], "complete");
                for &(event, key) in &event_collections {
                    let values = records
                        .iter()
                        .filter(|record| record["event"] == event)
                        .map(|record| record["result"].clone())
                        .collect();
                    assert_eq!(serde_json::Value::Array(values), document["result"][key]);
                }
            }
            "text" => assert_eq!(String::from_utf8(success.stdout).unwrap(), expected_text),
            _ => unreachable!(),
        }
        let failure = run(&[
            "--output",
            format,
            command,
            path,
            "--max-application-output-bytes",
            &under,
        ]);
        assert_eq!(failure.status.code(), Some(6), "format {format}");
        let error = match format {
            "json" => parse_json(&failure)["error"].clone(),
            "ndjson" => {
                let records = parse_ndjson(&failure);
                assert_contiguous(&records);
                assert_eq!(records.last().unwrap()["event"], "error");
                assert_eq!(
                    records
                        .iter()
                        .filter(|record| record["event"] == "error")
                        .count(),
                    1
                );
                assert!(records.iter().all(|record| record["event"] != "complete"));
                records.last().unwrap()["error"].clone()
            }
            "text" => continue,
            _ => unreachable!(),
        };
        assert_eq!(error["code"], "policy.denied");
        assert_eq!(error["message"], error_message);
    }
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
        "analysis consumer failed at frame 7: application output exceeds --max-application-output-bytes"
    );
}
