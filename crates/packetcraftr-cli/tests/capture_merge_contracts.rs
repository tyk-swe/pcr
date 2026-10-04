// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
#![allow(dead_code)]

#[path = "common/capture.rs"]
mod capture_support;
mod common;
#[path = "common/process.rs"]
mod process_support;

use capture_support::{Record, write_records};
use common::{parse_json, run, run_success};
use packetcraftr_core::capture_file::{Reader, compression::Input};

#[test]
fn merged_file_never_overwrites_path() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/captures");
    let source = root.join("dns-response.pcap");
    let directory = tempfile::tempdir().unwrap();
    let target = directory.path().join("merged.pcapng.zst");
    let arguments = [
        "--output",
        "json",
        "merge",
        source.to_str().unwrap(),
        source.to_str().unwrap(),
        "--write",
        target.to_str().unwrap(),
        "--compression",
        "zstd",
    ];
    let report = parse_json(&run_success(&arguments));
    assert_eq!(report["result"]["frames"], 2);
    assert_eq!(report["result"]["interfaces"].as_array().unwrap().len(), 2);
    let bytes = std::fs::read(&target).unwrap();
    let input = Input::new(std::io::Cursor::new(&bytes), Default::default()).unwrap();
    let mut reader = Reader::new(input).unwrap();
    let first = reader.next_frame().unwrap().unwrap();
    let second = reader.next_frame().unwrap().unwrap();
    assert_eq!(first.bytes(), second.bytes());
    assert_ne!(first.interface, second.interface);
    assert!(!run(&arguments).status.success());
    assert_eq!(std::fs::read(&target).unwrap(), bytes);
    let broken = root.join("clock-regression.pcap");
    let absent = directory.path().join("failed.pcapng");
    let output = run(&[
        "merge",
        broken.to_str().unwrap(),
        source.to_str().unwrap(),
        "--write",
        absent.to_str().unwrap(),
    ]);
    assert!(!output.status.success());
    assert!(!absent.exists());
}

#[test]
fn source_count_stdin_repeats_usage_errors() {
    let directory = tempfile::tempdir().unwrap();
    let target = directory.path().join("merged.pcapng");
    let absent = directory.path().join("absent.pcap");
    for sources in [vec![absent.to_str().unwrap(); 65], vec!["-", "-"]] {
        let mut arguments = vec!["--output", "json", "merge"];
        arguments.extend(sources);
        arguments.extend(["--write", target.to_str().unwrap()]);
        let output = run(&arguments);
        assert_eq!(output.status.code(), Some(2), "{output:?}");
        let error = parse_json(&output)["error"].clone();
        assert_eq!(error["kind"], "usage");
        assert_eq!(
            error["message"],
            "merge accepts at most 64 captures and one stdin source"
        );
        assert!(!target.exists());
    }
}

/// A classic capture whose frame bytes are the tag, stamped at the given seconds.
fn tagged_capture(frames: &[(u32, u8)]) -> tempfile::NamedTempFile {
    write_records(
        &frames
            .iter()
            .map(|(seconds, tag)| Record::new((*seconds, 0), vec![*tag]))
            .collect::<Vec<_>>(),
    )
}

fn merge_arguments<'a>(
    target: &'a std::path::Path,
    inputs: &'a [&tempfile::NamedTempFile],
    extra: &[&'a str],
) -> Vec<&'a str> {
    let mut arguments = vec!["merge", "--write", target.to_str().unwrap()];
    arguments.extend_from_slice(extra);
    arguments.extend(inputs.iter().map(|input| input.path().to_str().unwrap()));
    arguments
}

/// Runs merge over `inputs` with `extra` arguments and returns each output frame's tag and second.
fn merged_tags(inputs: &[&tempfile::NamedTempFile], extra: &[&str]) -> Vec<(u8, u64)> {
    let directory = tempfile::tempdir().unwrap();
    let target = directory.path().join("merged.pcapng");
    run_success(&merge_arguments(&target, inputs, extra));
    let mut reader = Reader::new(std::fs::File::open(&target).unwrap()).unwrap();
    let mut frames = Vec::new();
    while let Some(frame) = reader.next_frame().unwrap() {
        let seconds = frame
            .timestamp
            .unwrap()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        frames.push((frame.bytes()[0], seconds));
    }
    frames
}

/// Exit code of a merge that must fail without publishing its destination.
fn merge_failure(inputs: &[&tempfile::NamedTempFile], extra: &[&str]) -> Option<i32> {
    let directory = tempfile::tempdir().unwrap();
    let target = directory.path().join("merged.pcapng");
    let output = run(&merge_arguments(&target, inputs, extra));
    assert!(!output.status.success(), "{output:?}");
    assert!(!target.exists());
    output.status.code()
}

/// Every frame's capture time and bytes, in file order.
fn capture_frames(path: &std::path::Path) -> Vec<(std::time::SystemTime, Vec<u8>)> {
    let mut reader = Reader::new(std::fs::File::open(path).unwrap()).unwrap();
    let mut frames = Vec::new();
    while let Some(frame) = reader.next_frame().unwrap() {
        frames.push((frame.timestamp.unwrap(), frame.bytes().to_vec()));
    }
    frames
}
