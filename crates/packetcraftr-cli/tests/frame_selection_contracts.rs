// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

// `read --frames` and `--every` select source positions in every read path.

#[path = "common/capture.rs"]
mod capture_support;
mod common;
#[path = "common/process.rs"]
mod process_support;

use capture_support::{TCP_CLIENT, UDP_CLIENT, write_pcap};
use common::{path_text, run, run_success};
use process_support::decode_hex;

const FRAMES: u8 = 12;

/// Twelve frames that differ in their last byte, stamped at n seconds and 250 ms.
fn capture(template: &str) -> tempfile::NamedTempFile {
    let frames = (1..=FRAMES)
        .map(|number| {
            let mut bytes = decode_hex(template);
            *bytes.last_mut().unwrap() = number;
            bytes
        })
        .collect::<Vec<_>>();
    write_pcap(&frames)
}

#[test]
fn malformed_selections_are_usage_errors_before_input_is_read() {
    let many = (1..=257)
        .map(|index| (index * 2).to_string())
        .collect::<Vec<_>>()
        .join(",");
    let long = "1,".repeat(2049);
    for selectors in [
        vec!["--frames", "5-2"],
        vec!["--frames", "0"],
        vec!["--frames", "1,,2"],
        vec!["--frames", ""],
        vec!["--frames", "a-b"],
        vec!["--every", "0"],
        vec!["--frames", many.as_str()],
        vec!["--frames", long.as_str()],
    ] {
        let mut arguments = vec!["read", "missing.pcap"];
        arguments.extend_from_slice(&selectors);
        let output = run(&arguments);
        assert_eq!(output.status.code(), Some(2), "{selectors:?}");
        assert!(output.stdout.is_empty(), "{selectors:?}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !stderr.contains("missing.pcap"),
            "{selectors:?} opened the input: {stderr}"
        );
    }
    let at_limit = (1..=256)
        .map(|index| (index * 2).to_string())
        .collect::<Vec<_>>()
        .join(",");
    let file = capture(UDP_CLIENT);
    run_success(&["read", path_text(file.path()), "--frames", &at_limit]);
}

#[test]
fn skipped_frames_still_consume_the_input_budgets() {
    let file = capture(UDP_CLIENT);
    let path = path_text(file.path());
    let limited = run(&["read", path, "--frames", "1", "--max-frames", "5"]);
    assert_eq!(limited.status.code(), Some(6));
    assert!(String::from_utf8_lossy(&limited.stderr).contains("policy.capture_stream_limit"));
    run_success(&["read", path, "--frames", "1", "--max-frames", "12"]);
    let bytes = run(&[
        "read",
        path,
        "--frames",
        "1",
        "--max-bytes",
        "100",
        "--max-frame-bytes",
        "100",
    ]);
    assert_eq!(bytes.status.code(), Some(6));
    let projected = run(&[
        "--output",
        "csv",
        "read",
        path,
        "--field",
        "frame.number",
        "--frames",
        "1",
        "--max-frames",
        "5",
    ]);
    assert_eq!(projected.status.code(), Some(6));
    // The stream-indexing analysis path charges skipped frames too.
    let tcp = capture(TCP_CLIENT);
    let indexed = run(&[
        "--output",
        "csv",
        "read",
        path_text(tcp.path()),
        "--field",
        "tcp.stream",
        "--frames",
        "1",
        "--max-frames",
        "5",
    ]);
    assert_eq!(indexed.status.code(), Some(6));
    assert!(String::from_utf8_lossy(&indexed.stderr).contains("policy.capture_stream_limit"));
}
