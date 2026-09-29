// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use serde_json::Value;
use std::fs;
use std::path::PathBuf;

mod common;
use common::{parse_json, path_text, run_success};

#[test]
fn published_stats_examples_reproduce_from_their_example_captures() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let cases: [(&str, &[&str], &str); 2] = [
        (
            "examples/captures/clock-regression.pcap",
            &["--table", "io", "--interval-ms", "1000"],
            "examples/documents/output-stats-clock.json",
        ),
        (
            "examples/captures/scoped-vxlan.pcap",
            &["--table", "conversations"],
            "examples/documents/output-stats-scopes.json",
        ),
    ];
    for (capture, arguments, example) in cases {
        let capture_path = root.join(capture);
        let mut invocation = vec!["--output", "json", "stats", path_text(&capture_path)];
        invocation.extend_from_slice(arguments);
        let output = run_success(&invocation);
        let published: Value = serde_json::from_str(
            &fs::read_to_string(root.join(example)).expect("published example must be readable"),
        )
        .expect("published example must be JSON");
        assert_eq!(
            parse_json(&output),
            published,
            "{example} must equal the current `stats` output for {capture}"
        );
    }
}
