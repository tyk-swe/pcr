// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod common;
use common::{parse_json, run, run_success};
use packetcraftr_core::{
    capture_file::{Reader, Writer},
    frame::{Frame, LinkType},
};
use std::time::{Duration, UNIX_EPOCH};

fn fixture(path: &std::path::Path) {
    let mut writer = Writer::pcap(Vec::new(), LinkType::IPV4).unwrap();
    for (index, bytes) in [vec![1; 20], vec![1; 20], vec![2; 70]]
        .into_iter()
        .enumerate()
    {
        writer
            .write_frame(
                &Frame::new(
                    UNIX_EPOCH + Duration::from_secs(index as u64 + 2),
                    LinkType::IPV4,
                    bytes,
                )
                .unwrap(),
            )
            .unwrap();
    }
    std::fs::write(path, writer.into_inner()).unwrap();
}

#[test]
fn dedup_and_split_publish_exact_independently_readable_frames_without_overwrites() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source.pcap");
    fixture(&source);
    let output = dir.path().join("unique.pcap");
    let args = [
        "--output",
        "json",
        "dedup",
        source.to_str().unwrap(),
        "--write",
        output.to_str().unwrap(),
    ];
    let report = parse_json(&run_success(&args));
    assert_eq!(report["result"]["duplicates"], 1);
    let bytes = std::fs::read(&output).unwrap();
    let frames: Vec<_> = Reader::new(std::io::Cursor::new(&bytes))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(frames.len(), 2);
    assert_eq!(frames[0].bytes().as_ref(), [1; 20]);
    assert_eq!(frames[1].bytes().as_ref(), [2; 70]);
    assert!(!run(&args).status.success());
    assert_eq!(std::fs::read(&output).unwrap(), bytes);
    let split = dir.path().join("split");
    let report = parse_json(&run_success(&[
        "--output",
        "json",
        "split",
        source.to_str().unwrap(),
        "--write",
        split.to_str().unwrap(),
        "--packets",
        "1",
    ]));
    assert_eq!(
        report["result"]["frames_per_file"],
        serde_json::json!([1, 1, 1])
    );
    for entry in std::fs::read_dir(&split).unwrap() {
        let mut reader = Reader::new(std::fs::File::open(entry.unwrap().path()).unwrap()).unwrap();
        assert!(reader.next_frame().unwrap().is_some());
        assert!(reader.next_frame().unwrap().is_none());
    }
}

#[test]
fn exact_shift_rejects_rounding_and_split_failure_cleans_the_directory() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source.pcap");
    fixture(&source);
    let output = dir.path().join("shift.pcap");
    run_success(&[
        "shift-time",
        source.to_str().unwrap(),
        "--seconds",
        "-1.000001",
        "--write",
        output.to_str().unwrap(),
    ]);
    let first = Reader::new(std::fs::File::open(&output).unwrap())
        .unwrap()
        .next_frame()
        .unwrap()
        .unwrap();
    assert_eq!(
        first.timestamp,
        Some(UNIX_EPOCH + Duration::new(0, 999_999_000))
    );
    let failed = dir.path().join("rounded.pcap");
    assert!(
        !run(&[
            "shift-time",
            source.to_str().unwrap(),
            "--seconds",
            "0.0000000001",
            "--write",
            failed.to_str().unwrap()
        ])
        .status
        .success()
    );
    assert!(!failed.exists());
    let split = dir.path().join("failed-split");
    assert!(
        !run(&[
            "split",
            source.to_str().unwrap(),
            "--packets",
            "1",
            "--max-files",
            "2",
            "--write",
            split.to_str().unwrap()
        ])
        .status
        .success()
    );
    assert!(!split.exists());
    for selectors in [vec![], vec!["--packets", "1", "--bytes", "10"]] {
        let mut args = vec![
            "split",
            source.to_str().unwrap(),
            "--write",
            split.to_str().unwrap(),
        ];
        args.extend(selectors);
        assert_eq!(run(&args).status.code(), Some(2));
    }
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 2);
}

#[test]
fn size_histogram_uses_captured_length_and_timing_is_accessible() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source.pcap");
    fixture(&source);
    let result = parse_json(&run_success(&[
        "--output",
        "json",
        "stats",
        source.to_str().unwrap(),
        "--table",
        "sizes",
    ]));
    let bins = result["result"]["sizes"].as_array().unwrap();
    assert_eq!(bins.len(), 8);
    assert_eq!(bins[0]["frames"], 2);
    assert_eq!(bins[1]["frames"], 1);
    let result = parse_json(&run_success(&[
        "--output",
        "json",
        "stats",
        source.to_str().unwrap(),
        "--table",
        "tcp-timing",
    ]));
    assert_eq!(result["result"]["tcp_timing"], serde_json::json!([]));
}
