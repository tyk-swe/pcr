// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
// Test code indexes fixtures and counts by hand; the fail-closed lints are
// for library paths.
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::io::BufWriter;
use std::process::Command;
use std::time::{Instant, SystemTime};

use packetcraftr::analysis::pcap::{Limits, Writer};
use packetcraftr::core::frame::{Frame, LinkType};

#[test]
fn document_output_timing_is_within_bound_of_ndjson() {
    let hex_str =
        "02000000000202000000000108004500001c123400004011e496c0000201c0000202c000003500080000";
    let frame_bytes: Vec<u8> = (0..hex_str.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex_str[i..i + 2], 16).unwrap())
        .collect();

    let temp_dir = tempfile::tempdir().expect("tempdir must create");
    let capture_path = temp_dir.path().join("timing-20k.pcap");
    let file = std::fs::File::create(&capture_path).expect("pcap file must create");
    let buf_writer = BufWriter::new(file);

    let frame_count = 20_000;
    let mut writer = Writer::pcap(buf_writer, LinkType::ETHERNET).expect("pcap header must write");
    writer
        .set_stream_limits(Limits {
            max_frames: 50_000,
            max_bytes: 500_000_000,
        })
        .expect("set_stream_limits must succeed");
    let frame = Frame::new(SystemTime::UNIX_EPOCH, LinkType::ETHERNET, frame_bytes)
        .expect("frame must create");
    for _ in 0..frame_count {
        writer.write_frame(&frame).expect("frame must write");
    }
    drop(writer);

    let exe = env!("CARGO_BIN_EXE_packetcraftr");

    // 1. Measure ndjson --dissect wall time
    let start_ndjson = Instant::now();
    let ndjson_output = Command::new(exe)
        .args([
            "--output",
            "ndjson",
            "read",
            capture_path.to_str().unwrap(),
            "--dissect",
            "--max-frames",
            "50000",
        ])
        .output()
        .expect("ndjson read must execute");
    let ndjson_duration = start_ndjson.elapsed();
    assert!(
        ndjson_output.status.success(),
        "ndjson read failed: {:?}",
        String::from_utf8_lossy(&ndjson_output.stderr)
    );

    // 2. Measure document wall time
    let start_document = Instant::now();
    let doc_output = Command::new(exe)
        .args([
            "--output",
            "document",
            "read",
            capture_path.to_str().unwrap(),
            "--max-frames",
            "50000",
        ])
        .output()
        .expect("document read must execute");
    let doc_duration = start_document.elapsed();
    assert!(
        doc_output.status.success(),
        "document read failed: {:?}",
        String::from_utf8_lossy(&doc_output.stderr)
    );

    // Assert that the document output contains exactly 20_000 `---` lines
    let doc_stdout = String::from_utf8_lossy(&doc_output.stdout);
    let separator_count = doc_stdout.lines().filter(|line| *line == "---").count();
    assert_eq!(
        separator_count, frame_count,
        "document output must contain exactly {frame_count} `---` separators, found {separator_count}"
    );

    // Assert document output is actually faster than ndjson --dissect, not just
    // within some multiple of it: a bound above 1x would still pass if document
    // output regressed to be slower, the opposite of what this test guards.
    let max_allowed_ms = ndjson_duration.as_millis().max(100);
    eprintln!(
        "20k frames: ndjson={:?}, document={:?}, max_allowed_ms={max_allowed_ms}ms",
        ndjson_duration, doc_duration
    );
    assert!(
        doc_duration.as_millis() <= max_allowed_ms,
        "document wall time ({:?}) was not faster than ndjson wall time ({:?})",
        doc_duration,
        ndjson_duration
    );
}
