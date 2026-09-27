// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! `split` process contracts: fixed part names, faithful independent parts,
//! compressed input/output, bounded staging, and publication guarantees.

mod common;
#[path = "common/process.rs"]
mod process_support;

use common::{parse_json, parse_ndjson, path_text, run, run_success};
use process_support::run_with_stdin;

use packetcraftr_core::capture_file::{Reader, Writer, compression};
use packetcraftr_core::frame::{Frame, LinkType};
use serde_json::Value;
use std::io::{Cursor, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, UNIX_EPOCH};

const HANDSHAKE: &[u8] = include_bytes!("../../../examples/captures/tls-handshake.pcapng");

/// A PCAPNG written in-process with `frames` distinct timestamped packets.
fn pcapng_source(frames: u64) -> Vec<u8> {
    let mut writer = Writer::pcapng(Vec::new()).unwrap();
    writer.add_interface(LinkType::ETHERNET).unwrap();
    for index in 0..frames {
        let frame = Frame::new(
            UNIX_EPOCH + Duration::from_secs(index),
            LinkType::ETHERNET,
            vec![index as u8; 64],
        )
        .unwrap();
        writer.write_frame(&frame).unwrap();
    }
    writer.into_inner()
}

/// A classic PCAP written in-process; split must keep its container.
fn pcap_source(frames: u64) -> Vec<u8> {
    let mut writer = Writer::pcap(Vec::new(), LinkType::ETHERNET).unwrap();
    for index in 0..frames {
        let frame = Frame::new(
            UNIX_EPOCH + Duration::from_secs(index),
            LinkType::ETHERNET,
            vec![index as u8; 64],
        )
        .unwrap();
        writer.write_frame(&frame).unwrap();
    }
    writer.into_inner()
}

fn compressed(format: compression::Format, bytes: &[u8]) -> Vec<u8> {
    let mut output = compression::Output::new(Vec::new(), format).unwrap();
    output.write_all(bytes).unwrap();
    output.finish().unwrap()
}

/// Decompresses `bytes`, whose container codec is detected by magic.
fn decoded(bytes: &[u8]) -> Vec<u8> {
    let mut input = compression::Input::new(Cursor::new(bytes), Default::default()).unwrap();
    let mut decoded = Vec::new();
    input.read_to_end(&mut decoded).unwrap();
    decoded
}

/// Every physical frame in `bytes`, in order, as opaque payloads.
fn frame_bytes(bytes: &[u8]) -> Vec<Vec<u8>> {
    let mut reader = Reader::new(Cursor::new(bytes)).unwrap();
    let mut frames = Vec::new();
    while let Some(frame) = reader.next_frame().unwrap() {
        frames.push(frame.bytes().to_vec());
    }
    frames
}

fn frame_count(bytes: &[u8]) -> u64 {
    u64::try_from(frame_bytes(bytes).len()).unwrap()
}

fn parts_directory(root: &Path) -> PathBuf {
    let directory = root.join("parts");
    std::fs::create_dir(&directory).unwrap();
    directory
}

fn write_capture(root: &Path, name: &str, bytes: &[u8]) -> PathBuf {
    let path = root.join(name);
    std::fs::write(&path, bytes).unwrap();
    path
}

fn entries(directory: &Path) -> Vec<String> {
    let mut names = std::fs::read_dir(directory)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    names.sort();
    names
}

fn split_args<'a>(
    capture: &'a Path,
    directory: &'a Path,
    frames_per_file: &str,
    extra: &[&'a str],
) -> Vec<String> {
    [
        "split".to_owned(),
        path_text(capture).to_owned(),
        "--frames-per-file".to_owned(),
        frames_per_file.to_owned(),
        "--write-dir".to_owned(),
        path_text(directory).to_owned(),
    ]
    .into_iter()
    .chain(extra.iter().map(|flag| (*flag).to_owned()))
    .collect()
}

fn run_split(
    format: &str,
    capture: &Path,
    directory: &Path,
    frames_per_file: &str,
    extra: &[&str],
) -> std::process::Output {
    let mut arguments = vec!["--output".to_owned(), format.to_owned()];
    arguments.extend(split_args(capture, directory, frames_per_file, extra));
    let references = arguments.iter().map(String::as_str).collect::<Vec<_>>();
    run(&references)
}

#[test]
fn split_writes_exactly_named_parts_that_independently_reread() {
    let root = tempfile::tempdir().unwrap();
    let directory = parts_directory(root.path());
    // The destination extension follows the detected container, never the
    // source filename.
    let capture = write_capture(root.path(), "capture.not-a-capture", &pcap_source(5));
    let output = run_split("json", &capture, &directory, "2", &[]);
    assert!(output.status.success(), "{output:?}");
    let report = parse_json(&output);
    let result = &report["result"];
    assert_eq!(result["format"], "pcap");
    assert_eq!(result["compression"], "none");
    assert_eq!(result["directory"], path_text(&directory));
    assert_eq!(result["frames_per_file"], 2);
    assert_eq!(result["frames_read"], 5);
    assert_eq!(result["captured_bytes_read"], 5 * 64);
    assert!(result["metadata_records"].as_u64().unwrap() >= 1);
    assert_eq!(
        entries(&directory),
        ["part-000001.pcap", "part-000002.pcap", "part-000003.pcap"]
    );
    let files = result["files"].as_array().unwrap();
    assert_eq!(files.len(), 3);
    let source_frames = frame_bytes(&pcap_source(5));
    let mut written = Vec::new();
    let mut expected_ranges = vec![(1_u64, 2_u64), (3, 4), (5, 5)];
    for (position, file) in files.iter().enumerate() {
        let index = u64::try_from(position + 1).unwrap();
        let (first, last) = expected_ranges.remove(0);
        assert_eq!(file["index"], index);
        assert_eq!(
            file["file"],
            format!("part-{index:06}.pcap"),
            "fixed part names in index order"
        );
        assert_eq!(file["first_frame"], first);
        assert_eq!(file["last_frame"], last);
        assert_eq!(file["frames"], last - first + 1);
        let path = directory.join(file["file"].as_str().unwrap());
        let bytes = std::fs::read(&path).unwrap();
        assert_eq!(
            bytes.len() as u64,
            file["encoded_bytes"].as_u64().unwrap(),
            "the report holds the exact closed file length"
        );
        assert_eq!(file["encoded_bytes"], file["decoded_bytes"]);
        let part_frames = frame_bytes(&bytes);
        assert_eq!(part_frames.len() as u64, file["frames"].as_u64().unwrap());
        written.extend(part_frames);
    }
    assert_eq!(
        written, source_frames,
        "contiguous parts hold every source payload exactly once"
    );
}

#[test]
fn split_accepts_redirected_stdin_and_compressed_input() {
    let root = tempfile::tempdir().unwrap();
    let source = pcapng_source(6);
    for (format, name) in [
        (compression::Format::Gzip, "capture.bin"),
        (compression::Format::Zstd, "capture.gz"),
    ] {
        let compressed_bytes = compressed(format, &source);
        let case_directory = root.path().join(format!("file-{name}"));
        let directory = case_directory.join("parts");
        std::fs::create_dir_all(&directory).unwrap();
        // Compressed input is detected by magic; filenames stay irrelevant.
        let capture = write_capture(&case_directory, name, &compressed_bytes);
        let output = run_split("json", &capture, &directory, "3", &[]);
        assert!(output.status.success(), "{format:?} file: {output:?}");
        let report = parse_json(&output);
        assert_eq!(report["result"]["format"], "pcapng");
        assert_eq!(report["result"]["files"].as_array().unwrap().len(), 2);

        // The same bytes over redirected stdin produce the same parts.
        let stdin_directory = case_directory.join("stdin");
        std::fs::create_dir(&stdin_directory).unwrap();
        let stdin = run_with_stdin(
            &[
                "--output",
                "json",
                "split",
                "-",
                "--frames-per-file",
                "3",
                "--write-dir",
                path_text(&stdin_directory),
            ],
            &compressed_bytes,
        );
        assert!(stdin.status.success(), "{format:?} stdin: {stdin:?}");
        let stdin_report = parse_json(&stdin);
        assert_eq!(stdin_report["result"]["files"].as_array().unwrap().len(), 2);
        let streamed = entries(&stdin_directory);
        for (published, streamed) in entries(&directory).into_iter().zip(streamed) {
            assert_eq!(published, streamed);
            assert_eq!(
                frame_bytes(&std::fs::read(directory.join(&published)).unwrap()),
                frame_bytes(&std::fs::read(stdin_directory.join(&streamed)).unwrap())
            );
        }
    }
}

#[test]
fn split_compresses_every_part_independently_of_input_and_stdout_format() {
    let root = tempfile::tempdir().unwrap();
    let capture = write_capture(root.path(), "input", &pcapng_source(5));
    for (flag, suffix) in [("gzip", "pcapng.gz"), ("zstd", "pcapng.zst")] {
        let directory = root.path().join(format!("parts-{flag}"));
        std::fs::create_dir(&directory).unwrap();
        // Text stdout proves --compression applies to the saved files only.
        let output = run_split("text", &capture, &directory, "2", &["--compression", flag]);
        assert!(output.status.success(), "{flag}: {output:?}");
        assert_eq!(entries(&directory).len(), 3);
        for file in entries(&directory) {
            assert!(file.ends_with(&format!(".{suffix}")), "{file}");
            let encoded = std::fs::read(directory.join(&file)).unwrap();
            let decoded_bytes = decoded(&encoded);
            let mut reader = Reader::new(Cursor::new(&decoded_bytes)).unwrap();
            let mut frames = 0_u64;
            while reader.next_frame().unwrap().is_some() {
                frames += 1;
            }
            assert!(frames >= 1, "{file} rereads as an independent capture");
        }
    }
}

#[test]
fn split_report_counts_exact_encoded_bytes_below_the_compressor() {
    let root = tempfile::tempdir().unwrap();
    let directory = parts_directory(root.path());
    let capture = write_capture(root.path(), "input", &pcapng_source(4));
    let output = run_split(
        "ndjson",
        &capture,
        &directory,
        "2",
        &["--compression", "gzip"],
    );
    assert!(output.status.success(), "{output:?}");
    let records = parse_ndjson(&output);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["event"], "complete");
    let result = &records[0]["result"];
    assert_eq!(result["compression"], "gzip");
    let mut encoded_total = 0_u64;
    for file in result["files"].as_array().unwrap() {
        assert!(file["file"].as_str().unwrap().ends_with(".pcapng.gz"));
        let size = std::fs::metadata(directory.join(file["file"].as_str().unwrap()))
            .unwrap()
            .len();
        assert_eq!(
            file["encoded_bytes"].as_u64().unwrap(),
            size,
            "encoded bytes are the closed file's exact length"
        );
        assert!(file["encoded_bytes"].as_u64().unwrap() < file["decoded_bytes"].as_u64().unwrap());
        encoded_total += size;
    }
    assert_eq!(
        result["encoded_bytes_written"].as_u64().unwrap(),
        encoded_total
    );
}

#[test]
fn split_writes_one_metadata_part_for_an_empty_capture() {
    let root = tempfile::tempdir().unwrap();
    let directory = parts_directory(root.path());
    let capture = write_capture(root.path(), "empty.pcapng", &pcapng_source(0));
    let output = run_split("json", &capture, &directory, "2", &[]);
    assert!(output.status.success(), "{output:?}");
    let report = parse_json(&output);
    let files = report["result"]["files"].as_array().unwrap();
    assert_eq!(files.len(), 1);
    assert_eq!(files[0]["file"], "part-000001.pcapng");
    assert_eq!(files[0]["frames"], 0);
    assert_eq!(files[0]["first_frame"], Value::Null);
    assert_eq!(files[0]["last_frame"], Value::Null);
    let part = std::fs::read(directory.join("part-000001.pcapng")).unwrap();
    assert_eq!(frame_count(&part), 0);
    assert!(
        !part.is_empty(),
        "the metadata-only part is a valid capture"
    );
}

#[test]
fn split_never_overwrites_an_existing_name_and_writes_nothing_before_it() {
    let root = tempfile::tempdir().unwrap();
    let directory = parts_directory(root.path());
    let capture = write_capture(root.path(), "input", &pcapng_source(5));
    // A collision at the second predicted name still blocks the whole split.
    let occupied = directory.join("part-000002.pcapng");
    std::fs::write(&occupied, b"mine").unwrap();
    let output = run_split("text", &capture, &directory, "2", &[]);
    assert_eq!(output.status.code(), Some(5), "{output:?}");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("io.output_file"), "{stderr}");
    assert!(stderr.contains("part-000002.pcapng"), "{stderr}");
    assert_eq!(std::fs::read(&occupied).unwrap(), b"mine");
    assert_eq!(entries(&directory), ["part-000002.pcapng"]);
}

#[cfg(unix)]
#[test]
fn split_never_follows_a_dangling_symlink_at_a_predicted_name() {
    let root = tempfile::tempdir().unwrap();
    let directory = parts_directory(root.path());
    let capture = write_capture(root.path(), "input", &pcapng_source(3));
    let dangling = directory.join("part-000001.pcapng");
    std::os::unix::fs::symlink("missing-target", &dangling).unwrap();
    let output = run_split("text", &capture, &directory, "1", &[]);
    assert_eq!(output.status.code(), Some(5), "{output:?}");
    assert_eq!(
        std::fs::read_link(&dangling).unwrap(),
        PathBuf::from("missing-target")
    );
    assert_eq!(entries(&directory).len(), 1);
}

#[test]
fn split_requires_an_existing_output_directory() {
    let root = tempfile::tempdir().unwrap();
    let capture = write_capture(root.path(), "input", &pcapng_source(2));
    for directory in [
        root.path().join("missing"),
        capture.clone(), // a file is not a directory
    ] {
        let output = run_split("text", &capture, &directory, "1", &[]);
        assert_eq!(output.status.code(), Some(5), "{directory:?}: {output:?}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("io.output_file"),
            "{output:?}"
        );
    }
}

#[test]
fn split_rejects_malformed_input_before_any_destination() {
    let root = tempfile::tempdir().unwrap();
    let cases: Vec<(&str, Vec<u8>, i32)> = vec![
        ("empty input", Vec::new(), 3),
        ("unrecognized magic", b"nope".to_vec(), 3),
        (
            "truncated tail",
            HANDSHAKE[..HANDSHAKE.len() - 4].to_vec(),
            3,
        ),
    ];
    for (label, bytes, code) in cases {
        let case_directory = root.path().join(label);
        let directory = case_directory.join("parts");
        std::fs::create_dir_all(&directory).unwrap();
        let capture = write_capture(&case_directory, "input", &bytes);
        let output = run_split("ndjson", &capture, &directory, "2", &[]);
        assert_eq!(output.status.code(), Some(code), "{label}: {output:?}");
        let records = parse_ndjson(&output);
        assert_eq!(records.last().unwrap()["status"], "error");
        assert_eq!(
            entries(&directory),
            Vec::<String>::new(),
            "{label} leaves no destination"
        );
    }
}

#[test]
fn split_enforces_declared_finite_limits() {
    let root = tempfile::tempdir().unwrap();
    let capture = write_capture(root.path(), "input", &pcapng_source(8));
    let cases: Vec<(&str, &[&str])> = vec![
        // Fewer parts than the plan needs.
        ("--max-files", &["--max-files", "2"][..]),
        // Metadata ceilings below the retained cache.
        (
            "--max-split-metadata-records",
            &["--max-split-metadata-records", "1"][..],
        ),
        (
            "--max-split-metadata-bytes",
            &["--max-split-metadata-bytes", "8"][..],
        ),
        // Decoded output below the generated part bytes.
        (
            "--max-split-output-bytes",
            &["--max-split-output-bytes", "64"][..],
        ),
        // Physical input reader bounds.
        ("--max-frames", &["--max-frames", "3"][..]),
    ];
    for (label, flags) in cases {
        let directory = root.path().join(label.trim_start_matches("--"));
        std::fs::create_dir(&directory).unwrap();
        let output = run_split("text", &capture, &directory, "2", flags);
        assert_eq!(output.status.code(), Some(6), "{label}: {output:?}");
        assert_eq!(
            entries(&directory),
            Vec::<String>::new(),
            "{label} leaves no destination"
        );
    }
}

#[test]
fn split_encoded_ceiling_trips_below_compressor_finish_bytes() {
    let root = tempfile::tempdir().unwrap();
    // A tiny source compresses poorly, so the encoded total exceeds the
    // decoded total; a ceiling between them can only trip in the CLI counter.
    let source = pcapng_source(0);
    let capture = write_capture(root.path(), "empty", &source);
    let measured_directory = root.path().join("measured");
    std::fs::create_dir(&measured_directory).unwrap();
    let measured = run_split(
        "json",
        &capture,
        &measured_directory,
        "1",
        &["--compression", "gzip"],
    );
    assert!(measured.status.success(), "{measured:?}");
    let measured_report = parse_json(&measured);
    let result = &measured_report["result"];
    let decoded = result["decoded_bytes_written"].as_u64().unwrap();
    let encoded = result["encoded_bytes_written"].as_u64().unwrap();
    assert!(encoded > decoded, "{encoded} must exceed {decoded}");

    let directory = parts_directory(root.path());
    let limit = decoded.to_string();
    let output = run_split(
        "text",
        &capture,
        &directory,
        "1",
        &["--compression", "gzip", "--max-split-output-bytes", &limit],
    );
    assert_eq!(output.status.code(), Some(6), "{output:?}");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("policy.capture_split_limit"), "{stderr}");
    assert_eq!(entries(&directory), Vec::<String>::new());
}

#[test]
fn split_usage_errors_precede_source_io() {
    let root = tempfile::tempdir().unwrap();
    let directory = parts_directory(root.path());
    // The source never exists: option refusals must still be usage errors.
    let missing = root.path().join("missing-input.pcapng");
    for flags in [
        vec!["--frames-per-file", "0"],
        vec!["--frames-per-file", "1", "--max-files", "0"],
        vec!["--frames-per-file", "1", "--max-split-output-bytes", "0"],
    ] {
        let mut arguments = vec![
            "split".to_owned(),
            path_text(&missing).to_owned(),
            "--write-dir".to_owned(),
            path_text(&directory).to_owned(),
        ];
        arguments.extend(flags.iter().map(|flag| (*flag).to_owned()));
        let references = arguments.iter().map(String::as_str).collect::<Vec<_>>();
        let output = run(&references);
        assert_eq!(output.status.code(), Some(2), "{arguments:?}: {output:?}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("cli.capture_split"),
            "{output:?}"
        );
    }
}

#[test]
fn split_help_lists_every_bounded_option() {
    let output = run_success(&["split", "--help"]);
    let help = String::from_utf8(output.stdout).unwrap();
    for flag in [
        "--frames-per-file",
        "--write-dir",
        "--compression",
        "--max-files",
        "--max-split-metadata-records",
        "--max-split-metadata-bytes",
        "--max-split-output-bytes",
        "--max-frames",
        "--max-bytes",
        "--max-encoded-bytes",
        "--max-decoded-bytes",
        "--max-frame-bytes",
        "--max-interfaces",
        "--max-duration-ms",
    ] {
        assert!(help.contains(flag), "help must list {flag}: {help}");
    }
}

/// The complete report is prepared before the first commit, so a stdout
/// failure after publication must keep the published parts.
#[cfg(packetcraftr_test_dev_full)]
#[test]
fn split_keeps_published_parts_when_the_report_write_fails() {
    common::require_dev_full();
    let root = tempfile::tempdir().unwrap();
    let directory = parts_directory(root.path());
    let capture = write_capture(root.path(), "input", &pcapng_source(4));
    let full = std::fs::OpenOptions::new()
        .write(true)
        .open("/dev/full")
        .expect("/dev/full must be writable");
    let output = Command::new(env!("CARGO_BIN_EXE_packetcraftr"))
        .args(split_args(&capture, &directory, "2", &[]))
        .stdout(Stdio::from(full))
        .output()
        .expect("CLI process must start");
    assert_eq!(output.status.code(), Some(5), "{output:?}");
    assert_eq!(
        entries(&directory),
        ["part-000001.pcapng", "part-000002.pcapng"],
        "stdout failure after commit keeps the published parts"
    );
    for entry in entries(&directory) {
        assert!(!std::fs::read(directory.join(entry)).unwrap().is_empty());
    }
}

/// `-` names redirected stdin; a terminal stdin is refused before any read.
#[cfg(packetcraftr_test_util_linux)]
#[test]
fn split_rejects_terminal_stdin() {
    common::require_util_linux_script();
    let root = tempfile::tempdir().unwrap();
    let directory = parts_directory(root.path());
    let mut command = Command::new("script");
    command.env(
        "CAPTURE_STDIN_TEST_BINARY",
        env!("CARGO_BIN_EXE_packetcraftr"),
    );
    command.args([
        "--quiet",
        "--return",
        "--command",
        &format!(
            "exec \"$CAPTURE_STDIN_TEST_BINARY\" split - --frames-per-file 1 --write-dir {}",
            path_text(&directory)
        ),
        "/dev/null",
    ]);
    let output = command.output().expect("script must run");
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    let terminal = String::from_utf8_lossy(&output.stdout);
    assert!(terminal.contains("cli.input_source"), "{terminal}");
    assert_eq!(entries(&directory), Vec::<String>::new());
}
