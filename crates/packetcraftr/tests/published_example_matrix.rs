// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
// Test code indexes fixtures and counts by hand; the fail-closed lints are
// for library paths.
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

//! Pins every file in `examples/documents` by name: the
//! `output-<command>-<kind>.json` document each command publishes for the four
//! canonical kinds, the sub-kind documents that show one branch of a command's
//! output, and the packet documents used as command input. A missing or stray
//! file fails here instead of going unnoticed.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use packetcraftr::output::contract::Command;

const KINDS: [&str; 4] = ["success", "event", "complete", "error"];

/// Documents published beyond the canonical kinds, each showing one branch a
/// command's output can take.
const SUB_KIND_EXAMPLES: [&str; 11] = [
    "output-dissect-filter-no-match.json",
    "output-dns-attempt-response-event.json",
    "output-dns-record-event.json",
    "output-dns-rejected-event.json",
    "output-exchange-diagnostic-event.json",
    "output-exchange-response-event.json",
    "output-exchange-sent-event.json",
    "output-exchange-unanswered-event.json",
    "output-exchange-undecoded-event.json",
    "output-exchange-unsolicited-event.json",
    "output-protocols-detail-success.json",
];

/// Packet documents, which are command input rather than command output.
const PACKET_EXAMPLES: [&str; 4] = [
    "packet-gre-sctp.json",
    "packet-igmp.json",
    "packet-ipv4-udp.json",
    "packet-raw.yaml",
];

/// Every file name in `examples/documents`.
fn published_example_names() -> BTreeSet<String> {
    let directory = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/documents");
    fs::read_dir(&directory)
        .expect("published examples directory must exist")
        .map(|entry| {
            entry
                .expect("published example entry must be readable")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect()
}

/// Expected example kinds per command. Aggregate-only commands publish
/// `success`; streaming-only commands publish `event` and `complete` (or
/// `success` where the stream ends in an aggregate). Every command publishes
/// `error`.
fn expected_kinds(command: Command) -> &'static [&'static str] {
    match command {
        Command::Build
        | Command::Convert
        | Command::Dissect
        | Command::Protocols
        | Command::Plan
        | Command::Send
        | Command::Interfaces
        | Command::Routes
        | Command::Stats => &["success", "error"],
        Command::Exchange => &["success", "complete", "error"],
        Command::Capture | Command::Read => &["event", "complete", "error"],
        Command::Replay | Command::Expert => &["success", "event", "error"],
        Command::Scan
        | Command::Follow
        | Command::Tls
        | Command::Traceroute
        | Command::Dns
        | Command::Fuzz => &["success", "event", "complete", "error"],
    }
}

/// Every file the matrix expects, canonical kinds and pinned names together.
fn expected_example_names() -> BTreeSet<String> {
    let mut expected = BTreeSet::new();
    for command in Command::ALL.iter().copied() {
        for kind in expected_kinds(command) {
            expected.insert(format!("output-{command}-{kind}.json"));
        }
    }
    expected.extend(
        SUB_KIND_EXAMPLES
            .iter()
            .chain(PACKET_EXAMPLES.iter())
            .map(|name| (*name).to_owned()),
    );
    expected
}

#[test]
fn every_command_publishes_exactly_its_example_kinds() {
    let names = published_example_names();

    for command in Command::ALL.iter().copied() {
        let expected = expected_kinds(command)
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        let actual = KINDS
            .iter()
            .copied()
            .filter(|kind| names.contains(&format!("output-{command}-{kind}.json")))
            .collect::<BTreeSet<_>>();
        assert_eq!(
            actual, expected,
            "{command}: published example kinds differ from the expected matrix"
        );
    }
}

#[test]
fn published_examples_are_pinned_by_name() {
    let published = published_example_names();
    let expected = expected_example_names();
    let stray = published.difference(&expected).collect::<Vec<_>>();
    let missing = expected.difference(&published).collect::<Vec<_>>();
    assert!(
        stray.is_empty() && missing.is_empty(),
        "examples/documents differs from the pinned matrix: stray {stray:?}, missing \
         {missing:?}; add or remove the name here together with the file"
    );
}
