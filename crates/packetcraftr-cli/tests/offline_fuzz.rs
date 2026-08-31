// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
// Test code indexes fixtures and counts by hand; the fail-closed lints are
// for library paths.
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

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
    // Everything the campaign derives from its seed repeats exactly. The one
    // measured column is `stats.elapsed`, which reports how long generation
    // actually took, so it is required to be present rather than equal.
    let mut documents = [parse_json(&first), parse_json(&second)];
    for document in &mut documents {
        assert!(document["stats"]["elapsed"].is_object(), "{document}");
        document["stats"]["elapsed"] = Value::Null;
    }
    let [value, repeated] = documents;
    assert_eq!(value, repeated);
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
        &["--allow-malformed-live"][..],
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
    // The aggregate document is exactly the collected stream, statistics
    // included. `elapsed` measures the run that produced each document, so
    // only that column may differ between the two runs.
    let mut statistics = [aggregate["stats"].clone(), complete["stats"].clone()];
    for stats in &mut statistics {
        assert!(stats["elapsed"].is_object(), "{stats}");
        stats["elapsed"] = Value::Null;
    }
    let [aggregate_stats, complete_stats] = statistics;
    assert_eq!(aggregate_stats, complete_stats);
}

#[test]
fn offline_fuzz_text_preserves_reproduction_and_outcome_details() {
    let output = run_success(&[
        "--output",
        "text",
        "fuzz",
        "--packet",
        "ipv4(src=192.0.2.1,dst=198.51.100.2)/udp(sport=12345,dport=9)/raw(text=hello)",
        "--seed",
        "7",
        "--cases",
        "32",
        "--max-field-bytes",
        "32",
        "--max-shrink-steps",
        "3",
    ]);
    let text = String::from_utf8(output.stdout).expect("text output must be UTF-8");

    assert!(text.starts_with("mode=offline seed=7 first_case=0 generated=32"));
    assert!(text.contains(" outcome=built "));
    assert!(text.contains(" outcome=rejected "));
    assert!(text.contains(" reproduce=--seed 7 --first-case "));
    assert!(text.contains("\n  original="));
    assert!(text.contains("\n  frame "));
    assert!(text.contains("\n  error kind="));
    assert!(text.contains("\nfuzz completed 32 case(s), "));
    assert!(text.contains(" packet operation(s), "));
    assert!(text.ends_with(" byte(s)\n"));
}
