// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::fs;
use std::path::Path;

use packetcraftr_core::document::{DocumentLimits, Format, Packet as DocPacket};

#[path = "../../../fuzz/fuzz_targets/ip_reassembly_support.rs"]
mod ip_reassembly_support;

fn corpus(target: &str) -> std::path::PathBuf {
    seed_dir(Path::new("fuzz/corpora").join(target))
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
fn yaml_packet_document_seeds_parse_under_the_fuzz_limits() {
    let mut checked = 0_usize;
    for entry in fs::read_dir(corpus("packet_document_yaml"))
        .expect("corpus directory")
        .flatten()
    {
        let path = entry.path();
        let text = fs::read_to_string(&path).expect("read YAML seed");
        DocPacket::parse_with_limits(
            &text,
            Format::Yaml,
            &DocumentLimits {
                max_input_bytes: 64 * 1024,
                max_layers: 32,
                ..DocumentLimits::DEFAULT
            },
        )
        .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
        checked += 1;
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
