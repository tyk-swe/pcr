// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod support;
use packetcraftr_core::analysis::pcap::compression::Input;
use std::{
    io::{Cursor, Read},
    path::PathBuf,
};
use support::{parse_ndjson, run, run_success};

#[test]
fn capture_paths_and_outputs_detect_both_formats_without_filename_hints() {
    let source =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/captures/dns-response.pcap");
    let original = std::fs::read(&source).unwrap();
    for compression in ["gzip", "zstd"] {
        let output = run_success(&[
            "--output",
            "pcap",
            "read",
            source.to_str().unwrap(),
            "--compression",
            compression,
        ]);
        let mut input = Input::new(Cursor::new(&output.stdout), Default::default()).unwrap();
        let mut bytes = Vec::new();
        input.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, original);
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), &output.stdout).unwrap();
        let copied = run_success(&["--output", "pcap", "read", file.path().to_str().unwrap()]);
        assert_eq!(copied.stdout, original);
        let limited = run(&[
            "--output",
            "ndjson",
            "read",
            file.path().to_str().unwrap(),
            "--max-decoded-bytes",
            "24",
        ]);
        assert!(!limited.status.success());
        assert_eq!(parse_ndjson(&limited).last().unwrap()["event"], "error");
        let corrupt = &output.stdout[..output.stdout.len() - 1];
        std::fs::write(file.path(), corrupt).unwrap();
        let result = run(&["--output", "ndjson", "read", file.path().to_str().unwrap()]);
        assert!(!result.status.success());
        assert_eq!(parse_ndjson(&result).last().unwrap()["event"], "error");
    }
}

#[test]
fn invalid_compression_output_is_rejected_before_live_or_input_work() {
    for command in [
        vec!["capture", "--interface", "missing-interface"],
        vec!["read", "/missing/capture"],
        vec!["send", "--packet", "invalid"],
        vec!["fragment", "--mtu", "128", "--packet", "invalid"],
    ] {
        let mut arguments = vec!["--output", "text"];
        arguments.extend(command);
        arguments.extend(["--compression", "gzip"]);
        let output = run(&arguments);
        assert!(!output.status.success());
        assert!(
            String::from_utf8(output.stderr)
                .unwrap()
                .contains("--compression requires")
        );
    }
}
