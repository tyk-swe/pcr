// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
mod support;
use support::{parse_json, run, run_success};
#[test]
fn export_uses_a_stable_compressed_snapshot_and_publishes_only_valid_captures() {
    use packetcraftr_core::analysis::pcap::{Reader, compression::Input};
    let source = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/captures/http-stream.pcap");
    let source = source.to_str().unwrap();
    let directory = tempfile::tempdir().unwrap();
    let target = directory.path().join("selected.pcap.gz");
    let target = target.to_str().unwrap();
    let args = [
        "--output",
        "json",
        "export",
        source,
        "--stream",
        "tcp:0",
        "--write",
        target,
        "--compression",
        "gzip",
    ];
    let result = parse_json(&run_success(&args));
    assert_eq!(result["result"]["frames_selected"], 7);
    assert_eq!(
        result["result"]["source_frames"],
        serde_json::json!([1, 2, 3, 4, 5, 6, 7])
    );
    let saved = std::fs::read(target).unwrap();
    let mut reader =
        Reader::new(Input::new(std::io::Cursor::new(&saved), Default::default()).unwrap()).unwrap();
    let mut count = 0;
    while reader.next_frame().unwrap().is_some() {
        count += 1;
    }
    assert_eq!(count, 7);
    assert!(!run(&args).status.success());
    assert_eq!(std::fs::read(target).unwrap(), saved);
    let limited = directory.path().join("limited.pcap");
    let output = run(&[
        "--output",
        "json",
        "export",
        source,
        "--stream",
        "tcp:0",
        "--write",
        limited.to_str().unwrap(),
        "--max-selected-frames",
        "1",
    ]);
    assert!(!output.status.success());
    assert!(!limited.exists());
    let empty = directory.path().join("empty.pcap");
    let result = parse_json(&run_success(&[
        "--output",
        "json",
        "export",
        source,
        "--stream",
        "udp:999",
        "--write",
        empty.to_str().unwrap(),
    ]));
    assert_eq!(result["result"]["frames_selected"], 0);
    assert_eq!(result["result"]["unmatched_streams"][0]["index"], 999);
    assert!(
        Reader::new(std::fs::File::open(empty).unwrap())
            .unwrap()
            .next_frame()
            .unwrap()
            .is_none()
    );
}
