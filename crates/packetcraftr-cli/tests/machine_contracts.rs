// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr_cli::output::{
    contract::{Command, SCHEMA_V6},
    envelope::Envelope,
    stream::StreamEncoder,
};
use serde_json::{Value, json};
use std::fs;
use std::path::PathBuf;

mod common;
use common::TestRecord;

use common::{SharedBuffer, parse_json, path_text, run_success};

#[test]
fn aggregate_and_stream_envelopes_keep_version_and_discriminators() {
    let aggregate = serde_json::to_value(Envelope::success(
        Command::Protocols,
        json!({"count": 1}),
        Vec::new(),
    ))
    .expect("aggregate must serialize");
    assert_eq!(aggregate["schema"], SCHEMA_V6);
    assert_eq!(aggregate["command"], "protocols");
    assert_eq!(aggregate["mode"], "aggregate");
    assert_eq!(aggregate["status"], "success");
    assert!(aggregate.get("sequence").is_none());

    let output = SharedBuffer::default();
    let encoder = StreamEncoder::new(Command::Read, output.clone());
    for frame in 0..8 {
        encoder
            .emit_data(TestRecord(json!({"frame": frame})), Vec::new())
            .expect("stream must serialize");
    }
    let stream = output.records().pop().expect("eighth record");
    assert_eq!(stream["schema"], SCHEMA_V6);
    assert_eq!(stream["mode"], "stream");
    assert_eq!(stream["sequence"], 7);
}

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
