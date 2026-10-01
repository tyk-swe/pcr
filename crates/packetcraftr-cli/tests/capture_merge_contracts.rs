// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#[path = "common/capture.rs"]
mod capture_support;
mod common;
#[path = "common/process.rs"]
mod process_support;

use capture_support::{Record, write_records};
use common::{parse_json, run, run_success};
use packetcraftr_core::capture_file::{Reader, compression::Input};

#[test]
fn merged_file_is_compressed_scoped_and_never_overwrites_an_existing_path() {
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
fn per_section_interface_limit_does_not_bound_the_merged_output() {
    let source = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/captures/dns-response.pcap");
    let directory = tempfile::tempdir().unwrap();
    let target = directory.path().join("merged.pcapng");
    let report = parse_json(&run_success(&[
        "--output",
        "json",
        "merge",
        source.to_str().unwrap(),
        source.to_str().unwrap(),
        "--max-interfaces",
        "1",
        "--write",
        target.to_str().unwrap(),
    ]));
    assert_eq!(report["result"]["interfaces"].as_array().unwrap().len(), 2);
    let mut reader = Reader::new(std::fs::File::open(&target).unwrap()).unwrap();
    while reader.next_frame().unwrap().is_some() {}
    assert_eq!(reader.interfaces().len(), 2);
}

#[test]
fn source_count_and_repeated_stdin_are_usage_errors_before_any_output_is_staged() {
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
        assert_eq!(error["kind"], "cli");
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

#[test]
fn append_order_concatenates_captures_without_interleaving() {
    let first = tagged_capture(&[(10, 1), (20, 2)]);
    let second = tagged_capture(&[(1, 3), (5, 4)]);
    assert_eq!(
        merged_tags(&[&first, &second], &["--order", "append"]),
        [(1, 10), (2, 20), (3, 1), (4, 5)]
    );
    assert_eq!(
        merged_tags(&[&first, &second], &["--order", "chronological"]),
        [(3, 1), (4, 5), (1, 10), (2, 20)]
    );
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

#[test]
fn append_order_keeps_regressing_timestamps_verbatim_where_chronological_refuses() {
    let regression = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/captures/clock-regression.pcap");
    let input = capture_frames(&regression);
    assert!(
        input.windows(2).any(|pair| pair[1].0 < pair[0].0),
        "the fixture must regress"
    );
    let directory = tempfile::tempdir().unwrap();
    let appended = directory.path().join("appended.pcapng");
    let report = parse_json(&run_success(&[
        "--output",
        "json",
        "merge",
        "--order",
        "append",
        "--write",
        appended.to_str().unwrap(),
        regression.to_str().unwrap(),
        regression.to_str().unwrap(),
    ]));
    assert_eq!(report["result"]["frames"], 2 * input.len());
    let repeated: Vec<_> = input.iter().chain(&input).cloned().collect();
    assert_eq!(capture_frames(&appended), repeated);
    let chronological = directory.path().join("chronological.pcapng");
    let refused = run(&[
        "--output",
        "json",
        "merge",
        "--write",
        chronological.to_str().unwrap(),
        regression.to_str().unwrap(),
        regression.to_str().unwrap(),
    ]);
    assert_eq!(refused.status.code(), Some(3), "{refused:?}");
    assert_eq!(
        parse_json(&refused)["error"]["code"],
        "packet.capture_merge_order"
    );
    assert!(!chronological.exists());
}

#[test]
fn reorder_window_sorts_a_single_capture_and_refuses_displacement_beyond_it() {
    let inverted = tagged_capture(&[(1, 1), (3, 3), (2, 2), (4, 4)]);
    assert_eq!(
        merged_tags(&[&inverted], &["--max-reorder-frames", "2"]),
        [(1, 1), (2, 2), (3, 3), (4, 4)]
    );
    let far = tagged_capture(&[(3, 1), (4, 2), (1, 3), (2, 4)]);
    assert_eq!(
        merge_failure(&[&far], &["--max-reorder-frames", "2"]),
        Some(3)
    );
    assert_eq!(
        merge_failure(&[&inverted], &["--max-reorder-frames", "1"]),
        Some(3)
    );
}

#[test]
fn reorder_window_merges_multi_queue_captures_with_source_ordered_ties() {
    let left = tagged_capture(&[(2, 1), (1, 2), (4, 3)]);
    let right = tagged_capture(&[(3, 4), (2, 5), (4, 6)]);
    assert_eq!(
        merged_tags(&[&left, &right], &["--max-reorder-frames", "2"]),
        [(2, 1), (1, 2), (5, 2), (4, 3), (3, 4), (6, 4)]
    );
}

#[test]
fn reorder_window_reads_stay_within_the_stream_byte_budget() {
    // Frames are charged as they are read into the window, so the cumulative budget bounds it.
    let inverted = tagged_capture(&[(1, 1), (3, 3), (2, 2), (4, 4)]);
    assert_eq!(
        merge_failure(
            &[&inverted],
            &[
                "--max-reorder-frames",
                "4",
                "--max-bytes",
                "2",
                "--max-frame-bytes",
                "2"
            ]
        ),
        Some(6)
    );
}

#[test]
fn single_capture_and_conflicting_order_options_are_usage_errors() {
    let capture = tagged_capture(&[(1, 1), (2, 2)]);
    for extra in [
        &[][..],
        &["--order", "append"],
        &["--order", "append", "--max-reorder-frames", "2"],
        &["--max-reorder-frames", "65537"],
    ] {
        assert_eq!(merge_failure(&[&capture], extra), Some(2), "{extra:?}");
    }
    assert_eq!(
        merge_failure(
            &[&capture, &capture],
            &["--order", "append", "--max-reorder-frames", "2"]
        ),
        Some(2)
    );
}
