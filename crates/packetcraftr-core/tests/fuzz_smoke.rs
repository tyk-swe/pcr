// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::fs;
use std::path::Path;

use packetcraftr_core::document::{DocumentLimits, Format, Packet as DocPacket};

#[path = "../../../fuzz/fuzz_targets/ip_reassembly_support.rs"]
mod ip_reassembly_support;

/// The checked-in seed corpus for one fuzz target; a missing corpus is a
/// harness defect, not an empty smoke test.
fn corpus(target: &str) -> std::path::PathBuf {
    seed_dir(Path::new("fuzz/corpora").join(target))
}

/// The published examples that seed a fuzz target instead of a corpus copy,
/// so the seeds cannot drift from the documents the schemas pin.
fn published_examples(kind: &str) -> std::path::PathBuf {
    seed_dir(Path::new("examples").join(kind))
}

fn seed_dir(relative: std::path::PathBuf) -> std::path::PathBuf {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(relative);
    assert!(
        path.is_dir(),
        "missing fuzz seed directory {}",
        path.display()
    );
    path
}

#[test]
fn smoke_test_json_packet_documents() {
    let corpus_dir = published_examples("documents");
    let mut checked = 0_usize;
    {
        for entry in fs::read_dir(corpus_dir)
            .expect("corpus directory")
            .flatten()
        {
            checked += 1;
            let path = entry.path();
            if path.is_file() {
                let data = fs::read(&path).expect("read corpus file");
                let Ok(text) = std::str::from_utf8(&data) else {
                    continue;
                };
                if let Ok(parsed) = DocPacket::parse_with_limits(
                    text,
                    Format::Json,
                    &DocumentLimits {
                        max_input_bytes: 64 * 1024,
                        max_layers: 32,
                        ..DocumentLimits::DEFAULT
                    },
                ) {
                    let re_json = serde_json::to_string(&parsed).expect("serialize");
                    let re_parsed = DocPacket::parse_with_limits(
                        &re_json,
                        Format::Json,
                        &DocumentLimits {
                            max_input_bytes: 64 * 1024,
                            max_layers: 32,
                            ..DocumentLimits::DEFAULT
                        },
                    );
                    assert!(re_parsed.is_ok());
                }
            }
        }
    }
    assert!(checked > 0, "corpus must contain seed inputs");
}

#[test]
fn smoke_test_ip_reassembly_seeds_reach_completion_and_overlap() {
    let corpus_dir = corpus("ip_reassembly");
    let mut coverage = ip_reassembly_support::Coverage::default();
    let mut checked = 0_usize;
    for entry in fs::read_dir(corpus_dir)
        .expect("IP reassembly corpus directory")
        .flatten()
    {
        let path = entry.path();
        if path.is_file() {
            checked = checked.saturating_add(1);
            let seed_coverage =
                ip_reassembly_support::run(&fs::read(&path).expect("read IP reassembly seed"));
            coverage.completed |= seed_coverage.completed;
            coverage.overlap |= seed_coverage.overlap;
        }
    }

    assert!(checked > 0, "IP reassembly corpus must contain seeds");
    assert!(coverage.completed, "seed corpus must reach completion");
    assert!(coverage.overlap, "seed corpus must reach overlap handling");
}
