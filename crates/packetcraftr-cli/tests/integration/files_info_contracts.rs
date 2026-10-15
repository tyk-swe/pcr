// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! `files info` contracts: metadata output, compression, and bounds.

use std::path::PathBuf;

use crate::common;

use common::{parse_json, parse_ndjson, path_text, run, run_success};

fn bundled(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn bundled_text(relative: &str) -> String {
    path_text(&bundled(relative)).to_owned()
}

#[test]
fn bundled_pcapng_reports_its_container_and_interfaces() {
    let capture = bundled_text("../../examples/captures/tls-handshake.pcapng");
    let report = parse_json(&run_success(&[
        "--output", "json", "files", "info", &capture,
    ]));
    assert_eq!(report["command"], "info");
    assert_eq!(report["result"]["format"], "pcapng");
    assert_eq!(report["result"]["compression"], "none");
    assert_eq!(report["result"]["endianness"], "little");
    assert_eq!(report["result"]["pcapng_version"]["major"], 1);
    assert_eq!(report["result"]["sections"], 1);
    assert_eq!(report["result"]["frames"], 8);
    assert_eq!(report["result"]["truncated_frames"], 0);
    assert_eq!(report["result"]["packet_blocks"]["enhanced"], 8);
    assert_eq!(report["result"]["packet_blocks"]["classic"], 0);
    assert_eq!(report["result"]["declares_fcs"], false);
    let interfaces = report["result"]["interfaces"].as_array().unwrap();
    assert_eq!(interfaces.len(), 1);
    assert_eq!(interfaces[0]["global_id"], 0);
    assert_eq!(interfaces[0]["section"], 0);
    assert_eq!(interfaces[0]["local_id"], 0);
    assert_eq!(interfaces[0]["timestamp_resolution"]["decimal"], 9);

    let rendered = run_success(&["files", "info", &capture]);
    let text = String::from_utf8_lossy(&rendered.stdout);
    assert!(
        text.starts_with(
            "format=pcapng compression=none endianness=little pcapng_version=1.0 \
             sections=1 frames=8"
        ),
        "summary line: {text}"
    );
    assert!(
        text.contains("interface=0 link_type=228"),
        "interface line: {text}"
    );
    assert!(
        text.contains("packet_blocks classic=0 enhanced=8 simple=0 obsolete=0"),
        "block line: {text}"
    );
}

#[test]
fn bundled_classic_pcap_reports_its_header_without_sections() {
    let capture = bundled_text("../../examples/captures/http-stream.pcap");
    let report = parse_json(&run_success(&[
        "--output", "json", "files", "info", &capture,
    ]));
    assert_eq!(report["result"]["format"], "pcap");
    assert!(report["result"]["pcapng_version"].is_null());
    assert_eq!(report["result"]["sections"], 1);
    assert_eq!(report["result"]["packet_blocks"]["classic"], 7);
    let interfaces = report["result"]["interfaces"].as_array().unwrap();
    assert_eq!(interfaces.len(), 1);
    assert!(interfaces[0]["section"].is_null());
    assert!(interfaces[0]["local_id"].is_null());
    assert_eq!(interfaces[0]["timestamp_resolution"]["decimal"], 6);
}

#[test]
fn gzip_sources_report_compression_and_stdin_matches_the_file() {
    // Produce a compressed capture with the tool's own writer so the fixture
    // needs no test-only compression dependency.
    let directory = tempfile::tempdir().unwrap();
    let source = bundled_text("../../examples/captures/dns-response.pcap");
    let compressed = directory.path().join("merged.pcapng.gz");
    run_success(&[
        "files",
        "merge",
        "--write",
        path_text(&compressed),
        "--compression",
        "gzip",
        "--max-reorder-frames",
        "1",
        &source,
    ]);
    let encoded = std::fs::read(&compressed).unwrap();
    let output = crate::capture_support::assert_file_stdin_parity(&encoded, "info", &[], "json", 0);
    let report = parse_json(&output);
    assert_eq!(report["result"]["compression"], "gzip");
    assert_eq!(report["result"]["format"], "pcapng");
    assert_eq!(report["result"]["frames"], 1);
}

#[test]
fn ndjson_info_is_one_complete_record() {
    let capture = bundled_text("../../examples/captures/tls-handshake.pcapng");
    let records = parse_ndjson(&run_success(&[
        "--output", "ndjson", "files", "info", &capture,
    ]));
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["event"], "complete");
    assert_eq!(records[0]["command"], "info");
    assert_eq!(records[0]["result"]["format"], "pcapng");
}

#[test]
fn frame_ceilings_fail_the_pass_with_a_policy_error() {
    let capture = bundled_text("../../examples/captures/tls-handshake.pcapng");
    let output = run(&["files", "info", &capture, "--max-frames", "1"]);
    assert_eq!(output.status.code(), Some(6), "{output:?}");
    assert!(
        String::from_utf8_lossy(&output.stdout).is_empty(),
        "no partial metadata is published: {output:?}"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("exceeds the configured limit"),
        "{:?}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn missing_captures_fail_as_io_errors_before_any_output() {
    let missing = bundled_text("does-not-exist.pcapng");
    let output = run(&["files", "info", &missing]);
    assert_eq!(output.status.code(), Some(5), "{output:?}");
    assert!(String::from_utf8_lossy(&output.stdout).is_empty());
}
