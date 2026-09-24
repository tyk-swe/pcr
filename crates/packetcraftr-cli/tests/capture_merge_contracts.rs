// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod common;
use common::{parse_json, run, run_success};
use packetcraftr_core::analysis::pcap::{Reader, compression::Input};

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

/// `--max-interfaces` bounds each input section, so the single merged output
/// section may hold one interface per source without tripping it.
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
