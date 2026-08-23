// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod support;

use serde_json::Value;

use support::{assert_contiguous, parse_json, parse_ndjson, run, run_success};

#[test]
fn offline_fuzz_is_bounded_reproducible_and_reports_rejections() {
    let packet = "ipv4(src=192.0.2.1,dst=198.51.100.2)/\
                  udp(sport=12345,dport=9)/raw(text=hello)";
    let arguments = [
        "--output",
        "json",
        "fuzz",
        "--packet",
        packet,
        "--seed",
        "7",
        "--cases",
        "32",
        "--max-field-bytes",
        "32",
        "--max-shrink-steps",
        "3",
    ];
    let first = run(&arguments);
    let second = run(&arguments);
    assert!(first.status.success(), "{:?}", first.stderr);
    assert!(second.status.success(), "{:?}", second.stderr);
    assert_eq!(first.stdout, second.stdout);
    let value = parse_json(&first);
    assert_eq!(value["result"]["cases_generated"], 32);
    let built = value["result"]["cases_built"].as_u64().expect("count");
    let rejected = value["result"]["cases_rejected"].as_u64().expect("count");
    assert_eq!(built + rejected, 32);
    assert!(built > 0);
    assert!(rejected > 0);

    let permissive = run(&[
        "--output",
        "ndjson",
        "fuzz",
        "--packet",
        packet,
        "--seed",
        "11",
        "--first-case",
        "100",
        "--cases",
        "8",
        "--mode",
        "permissive",
        "--strategy",
        "malformed,random",
        "--field",
        "0.ttl",
        "--field",
        "2.bytes",
        "--max-field-bytes",
        "16",
        "--max-shrink-steps",
        "2",
    ]);
    assert!(permissive.status.success(), "{:?}", permissive.stderr);
    let lines: Vec<&str> = std::str::from_utf8(&permissive.stdout)
        .expect("NDJSON must be UTF-8")
        .lines()
        .collect();
    assert_eq!(lines.len(), 9);
    let terminal: Value = serde_json::from_str(lines.last().expect("terminal record"))
        .expect("terminal record must parse");
    assert_eq!(terminal["result"]["event"], "complete");
}

#[test]
fn offline_fuzz_rejects_live_only_options_and_has_an_independent_packet_limit() {
    let base = ["fuzz", "--packet", "raw(text=hi)", "--cases", "1"];
    for live_only in [
        &["--allow-permissive-live"][..],
        &["--destination", "127.0.0.1"],
        &["--timeout-ms", "1"],
        &["--rate", "1"],
        &["--interface", "1"],
        &["--source", "127.0.0.1"],
        &["--link-mode", "layer3"],
        &["--max-queue-frames", "1"],
        &["--max-captured-bytes", "64"],
        &["--snap-length", "64"],
        &["--overflow-policy", "drop-newest"],
        &["--allow-public-destinations"],
        &["--allow-permissive-packets"],
        &["--max-packets", "1"],
        &["--max-bytes", "64"],
    ] {
        let arguments = base
            .iter()
            .copied()
            .chain(live_only.iter().copied())
            .collect::<Vec<_>>();
        let output = run(&arguments);
        assert_eq!(output.status.code(), Some(2), "{arguments:?}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("--live"),
            "{arguments:?}: {:?}",
            output.stderr
        );
    }

    let offline = run(&[
        "--output",
        "json",
        "fuzz",
        "--packet",
        "raw(text=hi)",
        "--cases",
        "1",
        "--max-packet-bytes",
        "64",
    ]);
    assert!(offline.status.success(), "{:?}", offline.stderr);
}

#[test]
fn fuzz_stream_preserves_cases_before_a_late_campaign_failure() {
    let output = run(&[
        "--output",
        "ndjson",
        "fuzz",
        "--packet",
        "raw(text=abcd)",
        "--field",
        "0.bytes",
        "--strategy",
        "bit-flip",
        "--cases",
        "3",
        "--max-cases",
        "3",
        "--max-packet-bytes",
        "32",
        "--max-total-bytes",
        "60",
        "--max-field-bytes",
        "16",
    ]);
    assert_eq!(output.status.code(), Some(6));
    let records = parse_ndjson(&output);
    assert_contiguous(&records);
    assert_eq!(records.len(), 3);
    assert_eq!(records[0]["result"]["case"]["index"], 0);
    assert_eq!(records[1]["result"]["case"]["index"], 1);
    assert_eq!(records[2]["status"], "error");
    assert_eq!(records[2]["sequence"], 2);
    assert!(
        records
            .iter()
            .all(|record| record["result"]["event"] != "complete")
    );
}

#[test]
fn fuzz_aggregate_is_collected_from_the_streamed_case_path() {
    let common = [
        "fuzz",
        "--packet",
        "raw(text=abcd)",
        "--field",
        "0.bytes",
        "--strategy",
        "bit-flip",
        "--cases",
        "3",
        "--max-cases",
        "3",
        "--max-packet-bytes",
        "32",
        "--max-total-bytes",
        "100",
        "--max-field-bytes",
        "16",
    ];
    let aggregate_arguments = ["--output", "json"]
        .into_iter()
        .chain(common)
        .collect::<Vec<_>>();
    let stream_arguments = ["--output", "ndjson"]
        .into_iter()
        .chain(common)
        .collect::<Vec<_>>();
    let aggregate = parse_json(&run_success(&aggregate_arguments));
    let streamed = parse_ndjson(&run_success(&stream_arguments));
    let streamed_cases = streamed[..streamed.len() - 1]
        .iter()
        .map(|record| record["result"]["case"].clone())
        .collect::<Vec<_>>();
    let complete = streamed.last().expect("fuzz completion record");

    assert_eq!(
        aggregate["result"]["cases"]
            .as_array()
            .expect("aggregate fuzz cases"),
        &streamed_cases
    );
    for field in ["cases_generated", "cases_built", "cases_rejected"] {
        assert_eq!(aggregate["result"][field], complete["result"][field]);
    }
    assert_eq!(aggregate["stats"], complete["stats"]);
}
