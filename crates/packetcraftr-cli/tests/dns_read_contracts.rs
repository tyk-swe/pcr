// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
mod common;
use common::{assert_contiguous, parse_json, parse_ndjson, run, run_success};

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
    let records = parse_ndjson(&run_success(&["--output", "ndjson", "dns-read", path]));
    assert_eq!(
        records
            .iter()
            .map(|v| v["event"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["dns_message", "dns_transaction", "complete"]
    );
    let output = run(&[
        "--output",
        "ndjson",
        "dns-read",
        path,
        "--max-application-output-bytes",
        "1",
    ]);
    assert!(!output.status.success());
    let records = parse_ndjson(&output);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["event"], "error");
    assert_eq!(records[0]["sequence"], 0);
    let output = run(&["--output", "json", "dns-read", path, "--stream", "tcp:999"]);
    assert!(!output.status.success());
    let output = run(&["--output", "json", "dns-read", path, "--bad-option"]);
    let error = parse_json(&output);
    assert_eq!(error["command"], "dns-read");
}

/// `--dns-port` adds nonstandard services; port 53 is always analyzed.
#[test]
fn additional_dns_ports_keep_the_standard_port() {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/captures/dns-response.pcap");
    let document = parse_json(&run_success(&[
        "--output",
        "json",
        "dns-read",
        path.to_str().unwrap(),
        "--dns-port",
        "5353",
    ]));
    assert_eq!(document["result"]["summary"]["complete_messages"], 1);
}

#[test]
fn application_output_budget_counts_only_compact_event_payloads() {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/captures/dns-response.pcap");
    let path = path.to_str().unwrap();
    let document = parse_json(&run_success(&["--output", "json", "dns-read", path]));
    let total: usize = ["messages", "transactions", "issues"]
        .iter()
        .flat_map(|key| document["result"][key].as_array().unwrap().iter())
        .map(|value| serde_json::to_vec(value).unwrap().len())
        .sum();
    let command = "dns-read";
    let event_collections = [
        ("dns_message", "messages"),
        ("dns_transaction", "transactions"),
        ("dns_stream_issue", "issues"),
    ];
    let expected_text = "DNS Udp:0 message=1 Complete 192.0.2.53:53 -> 198.51.100.8:49152 frames=[1] {class=1,name=example.test.,type=1}\n  transaction id=4660 OrphanResponse queries=[] response=Some(1) latest_latency=None\n1 DNS messages; 0 matched and 0 unanswered transactions in 1 captured frames\n";
    let error_message = "application output exceeds --max-application-output-bytes";
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
fn ndjson_budget_shares_the_charge_across_event_kinds() {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/captures/dns-response.pcap");
    let path = path.to_str().unwrap();
    let document = parse_json(&run_success(&["--output", "json", "dns-read", path]));
    let first = serde_json::to_vec(&document["result"]["messages"][0])
        .unwrap()
        .len()
        .to_string();
    let output = run(&[
        "--output",
        "ndjson",
        "dns-read",
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
        ["dns_message", "error"]
    );
    assert_contiguous(&records);
    assert_eq!(records[0]["result"], document["result"]["messages"][0]);
    assert_eq!(records[1]["error"]["code"], "policy.denied");
    assert_eq!(
        records[1]["error"]["message"],
        "application output exceeds --max-application-output-bytes"
    );
}
