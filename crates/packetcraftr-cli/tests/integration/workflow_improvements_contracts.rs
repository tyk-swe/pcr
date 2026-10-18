// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::{
    common::{assert_contiguous, parse_json, parse_ndjson, path_text, run, run_success},
    process_support::run_with_stdin,
};
use std::path::PathBuf;

fn example(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples")
        .join(path)
}

#[test]
fn statistics_selection_preserves_totals_and_csv_contract() {
    let capture = example("captures/http-stream.pcap");
    let path = path_text(&capture);
    let baseline = parse_json(&run_success(&[
        "--output", "json", "analyze", "stats", path, "--table", "overview",
    ]));
    let filtered = parse_json(&run_success(&[
        "--output",
        "json",
        "analyze",
        "stats",
        path,
        "--table",
        "overview",
        "--min-frames",
        "18446744073709551615",
    ]));
    for key in [
        "protocol_count",
        "endpoint_count",
        "conversation_count",
        "frames_matched",
        "bytes_matched",
    ] {
        assert_eq!(filtered["result"][key], baseline["result"][key]);
    }
    for key in ["protocols", "endpoints", "conversations"] {
        assert_eq!(filtered["result"][key].as_array().unwrap().len(), 0);
    }
    let ranked = parse_json(&run_success(&[
        "--output",
        "json",
        "analyze",
        "stats",
        path,
        "--sort",
        "duration",
        "--min-frames",
        "1",
        "--top",
        "1",
    ]));
    assert_eq!(
        ranked["result"]["conversations"].as_array().unwrap().len(),
        1
    );
    let csv = run_success(&[
        "--output",
        "csv",
        "analyze",
        "stats",
        path,
        "--table",
        "endpoints",
        "--min-frames",
        "18446744073709551615",
    ]);
    assert_eq!(
        csv.stdout,
        b"address,tx_frames,tx_bytes,rx_frames,rx_bytes\r\n"
    );
}

#[test]
fn invalid_statistics_options_fail_before_opening_input() {
    for flags in [
        vec!["--table", "fragments", "--top", "0"],
        vec!["--table", "fragments", "--min-frames", "0"],
        vec!["--table", "endpoints", "--sort", "duration"],
    ] {
        let mut args = vec!["--output", "json", "analyze", "stats", "missing.pcap"];
        args.extend(flags);
        let output = run(&args);
        assert_eq!(output.status.code(), Some(2));
        assert_eq!(parse_json(&output)["error"]["kind"], "usage");
    }
}

#[test]
fn security_json_stdin_matches_files_and_preserves_sources() {
    let capture = example("captures/tls-handshake.pcapng");
    let indicators = example("documents/indicators.json");
    let disk = parse_json(&run_success(&[
        "--output",
        "json",
        "analyze",
        "hunt",
        path_text(&capture),
        "--indicators",
        path_text(&indicators),
    ]));
    let piped = run_with_stdin(
        &[
            "--output",
            "json",
            "analyze",
            "hunt",
            path_text(&capture),
            "--indicators",
            "-",
        ],
        &std::fs::read(&indicators).unwrap(),
    );
    assert!(piped.status.success());
    let piped = parse_json(&piped);
    assert_eq!(disk["result"]["findings"], piped["result"]["findings"]);
    assert_eq!(
        disk["result"]["sources"][0]["sha256"],
        piped["result"]["sources"][0]["sha256"]
    );
    assert_eq!(piped["result"]["sources"][0]["path"], "-");

    let scan = example("documents/output-scan-success.json");
    let bytes = std::fs::read(&scan).unwrap();
    let disk_diff = parse_json(&run_success(&[
        "--output",
        "json",
        "analyze",
        "scan-diff",
        path_text(&scan),
        path_text(&scan),
    ]));
    for inputs in [["-", path_text(&scan)], [path_text(&scan), "-"]] {
        let diff = run_with_stdin(
            &[
                "--output",
                "json",
                "analyze",
                "scan-diff",
                inputs[0],
                inputs[1],
            ],
            &bytes,
        );
        assert!(diff.status.success());
        let diff = parse_json(&diff);
        assert_eq!(diff["result"]["findings"], disk_diff["result"]["findings"]);
        assert_eq!(
            diff["result"]["completeness"],
            disk_diff["result"]["completeness"]
        );
    }

    let dir = tempfile::tempdir().unwrap();
    let html = dir.path().join("assessment.html");
    let assessment = run_with_stdin(
        &[
            "--output",
            "json",
            "analyze",
            "report",
            "-",
            "--html",
            path_text(&html),
        ],
        &serde_json::to_vec(&piped).unwrap(),
    );
    assert!(assessment.status.success());
    let sources = parse_json(&assessment)["result"]["sources"]
        .as_array()
        .unwrap()
        .clone();
    assert_eq!(sources.len(), 2);
    assert_eq!(sources[1], piped["result"]["sources"][0]);
    assert!(html.exists());
}

#[test]
fn conflicting_stdin_inputs_fail_before_io_or_publication() {
    let dir = tempfile::tempdir().unwrap();
    let html = dir.path().join("never-created.html");
    for args in [
        vec!["analyze", "hunt", "-", "--indicators", "-"],
        vec!["analyze", "scan-diff", "-", "-"],
        vec!["analyze", "report", "-", "-", "--html", path_text(&html)],
    ] {
        let mut command = vec!["--output", "json"];
        command.extend(args);
        let output = run(&command);
        assert_eq!(output.status.code(), Some(2));
        assert!(
            parse_json(&output)["error"]["message"]
                .as_str()
                .unwrap()
                .contains("only one input")
        );
    }
    assert!(!html.exists());
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
}

#[test]
fn incomplete_gate_publishes_successful_json_ndjson_and_html() {
    let capture = example("captures/beacon-periodic.pcap");
    for format in ["json", "ndjson"] {
        let output = run(&[
            "--output",
            format,
            "analyze",
            "beacons",
            path_text(&capture),
            "--filter",
            "tcp",
            "--fail-incomplete",
        ]);
        assert_eq!(output.status.code(), Some(1));
        let complete = if format == "json" {
            parse_json(&output)
        } else {
            let records = parse_ndjson(&output);
            assert_contiguous(&records);
            assert_eq!(records.last().unwrap()["event"], "complete");
            records.last().unwrap().clone()
        };
        assert_eq!(complete["status"], "success");
        assert_eq!(complete["result"]["completeness"]["complete"], false);
    }
    for finding_only in [false, true] {
        let mut input: serde_json::Value = serde_json::from_slice(include_bytes!(
            "../../../../examples/documents/output-hunt-success.json"
        ))
        .unwrap();
        if finding_only {
            input["result"]["findings"][0]["complete"] = false.into();
        } else {
            input["result"]["completeness"]["complete"] = false.into();
        }
        let dir = tempfile::tempdir().unwrap();
        let html = dir.path().join("assessment.html");
        let output = run_with_stdin(
            &[
                "--output",
                "json",
                "analyze",
                "report",
                "-",
                "--html",
                path_text(&html),
                "--fail-incomplete",
            ],
            &serde_json::to_vec(&input).unwrap(),
        );
        assert_eq!(output.status.code(), Some(1));
        assert_eq!(parse_json(&output)["status"], "success");
        assert!(html.exists());
    }
}

#[test]
fn oversized_inline_file_and_stdin_hex_share_the_budget_error() {
    let dir = tempfile::tempdir().unwrap();
    let hex = dir.path().join("frame.hex");
    std::fs::write(&hex, b"00112233").unwrap();
    for source in [
        ["--hex", "00112233"],
        ["--hex-file", path_text(&hex)],
        ["--hex", "-"],
    ] {
        let output = run_with_stdin(
            &[
                "--output",
                "json",
                "packet",
                "dissect",
                source[0],
                source[1],
                "--max-packet-size",
                "2",
            ],
            b"00112233",
        );
        let error = parse_json(&output);
        assert_eq!(error["error"]["code"], "policy.decode_resource_limit");
        assert!(!output.status.success());
    }
}
