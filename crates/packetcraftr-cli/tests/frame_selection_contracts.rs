// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

// `read --frames` and `--every` select source positions in every read path.

use std::io::Cursor;

use packetcraftr_core::capture_file::Reader;
use packetcraftr_core::frame::Frame;

#[path = "common/capture.rs"]
mod capture_support;
mod common;
#[path = "common/process.rs"]
mod process_support;

use capture_support::{TCP_CLIENT, UDP_CLIENT, write_pcap};
use common::{parse_ndjson, path_text, run, run_success};
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

fn source_frames(output: &std::process::Output) -> Vec<u64> {
    parse_ndjson(output)
        .iter()
        .filter_map(|record| record["result"]["source_frame"].as_u64())
        .collect()
}

fn read_frames(bytes: &[u8]) -> Vec<Frame> {
    let mut reader = Reader::new(Cursor::new(bytes)).unwrap();
    std::iter::from_fn(|| reader.next_frame().unwrap()).collect()
}

fn last_bytes(frames: &[Frame]) -> Vec<u8> {
    frames
        .iter()
        .map(|frame| *frame.bytes().last().unwrap())
        .collect()
}

#[test]
fn ranges_and_every_select_original_source_positions() {
    let file = capture(UDP_CLIENT);
    let path = path_text(file.path());
    for (selectors, expected) in [
        (&["--frames", "2-3,10"][..], vec![2, 3, 10]),
        (&["--frames", "10-"], vec![10, 11, 12]),
        (&["--frames", "1-3,2-5,5"], vec![1, 2, 3, 4, 5]),
        (&["--frames", "13-"], vec![]),
        (&["--every", "5"], vec![1, 6, 11]),
        (&["--every", "1"], (1..=12).collect()),
        (&["--frames", "3-", "--every", "5"], vec![6, 11]),
        (&["--frames", "1,6", "--every", "5"], vec![1, 6]),
        (
            &[
                "--frames",
                "2-8",
                "--filter",
                "frame.number > 4",
                "--start-epoch",
                "6",
            ],
            vec![6, 7, 8],
        ),
    ] {
        let mut arguments = vec!["--output", "ndjson", "read", path];
        arguments.extend_from_slice(selectors);
        let output = run_success(&arguments);
        assert_eq!(source_frames(&output), expected, "{selectors:?}");
    }
    let text = run_success(&["read", path, "--frames", "2-3,10"]);
    let numbers = String::from_utf8(text.stdout)
        .unwrap()
        .lines()
        .map(|line| line.split(':').next().unwrap().to_owned())
        .collect::<Vec<_>>();
    assert_eq!(numbers, ["2", "3", "10"]);
    let hex = run_success(&["--output", "hex", "read", path, "--every", "5"]);
    assert_eq!(String::from_utf8(hex.stdout).unwrap().lines().count(), 3);
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

#[test]
fn capture_output_copies_selected_records_verbatim() {
    let file = capture(UDP_CLIENT);
    let source = std::fs::read(file.path()).unwrap();
    let all = read_frames(&source);
    let path = path_text(file.path());
    for (selectors, positions) in [
        (&["--frames", "2-3,10"][..], vec![2_usize, 3, 10]),
        (&["--every", "5"], vec![1, 6, 11]),
        (
            &["--frames", "3-", "--every", "5", "--filter", "udp"],
            vec![6, 11],
        ),
    ] {
        let mut arguments = vec!["--output", "pcap", "read", path];
        arguments.extend_from_slice(selectors);
        let output = run_success(&arguments);
        let copied = read_frames(&output.stdout);
        assert_eq!(
            copied,
            positions
                .iter()
                .map(|position| all[position - 1].clone())
                .collect::<Vec<_>>(),
            "{selectors:?}"
        );
        // Header plus each selected record, byte for byte.
        let record = 16 + all[0].bytes().len();
        let mut expected = source[..24].to_vec();
        for position in positions {
            let start = 24 + (position - 1) * record;
            expected.extend_from_slice(&source[start..start + record]);
        }
        assert_eq!(output.stdout, expected, "{selectors:?}");
    }
}

#[test]
fn pcapng_capture_output_and_normalization_apply_the_selection() {
    let file = capture(UDP_CLIENT);
    let source = std::fs::read(file.path()).unwrap();
    let pcapng = run_success(&[
        "--output",
        "pcapng",
        "read",
        path_text(file.path()),
        "--normalize",
    ]);
    let ng = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(ng.path(), &pcapng.stdout).unwrap();
    let ng_path = path_text(ng.path());
    assert_eq!(read_frames(&source).len(), 12);

    let copied = run_success(&[
        "--output", "pcapng", "read", ng_path, "--frames", "2-3,10", "--filter", "udp",
    ]);
    assert_eq!(last_bytes(&read_frames(&copied.stdout)), [2, 3, 10]);
    let verbatim = run_success(&["--output", "pcapng", "read", ng_path, "--every", "4"]);
    assert_eq!(last_bytes(&read_frames(&verbatim.stdout)), [1, 5, 9]);

    for format in ["pcapng", "pcap"] {
        let normalized = run_success(&[
            "--output",
            format,
            "read",
            ng_path,
            "--normalize",
            "--frames",
            "3-",
            "--every",
            "5",
        ]);
        let frames = read_frames(&normalized.stdout);
        assert_eq!(last_bytes(&frames), [6, 11], "{format}");
    }
    // Skipped frames still consume the budget in normalization.
    let limited = run(&[
        "--output",
        "pcapng",
        "read",
        ng_path,
        "--normalize",
        "--frames",
        "1",
        "--max-frames",
        "3",
    ]);
    assert_eq!(limited.status.code(), Some(6));
}

#[test]
fn field_projection_applies_the_selection_in_both_analysis_paths() {
    let udp = capture(UDP_CLIENT);
    let tcp = capture(TCP_CLIENT);
    for (file, fields) in [
        (&udp, vec!["--field", "frame.number"]),
        // A stream index forces the indexing analysis path.
        (
            &tcp,
            vec!["--field", "frame.number", "--field", "tcp.stream"],
        ),
    ] {
        let mut arguments = vec!["--output", "csv", "read", path_text(file.path())];
        arguments.extend(fields);
        arguments.extend(["--frames", "2-3,10", "--every", "1"]);
        let output = run_success(&arguments);
        let rows = String::from_utf8(output.stdout).unwrap();
        let numbers = rows
            .lines()
            .skip(1)
            .map(|line| line.split(',').next().unwrap().trim_matches('"').to_owned())
            .collect::<Vec<_>>();
        assert_eq!(numbers, ["2", "3", "10"], "{rows}");
    }
    // Stream numbering stays global even though the first frames are not shown.
    let output = run_success(&[
        "--output",
        "csv",
        "read",
        path_text(tcp.path()),
        "--field",
        "tcp.stream",
        "--frames",
        "12",
    ]);
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        "\"tcp.stream\"\n\"0\"\n"
    );
}
