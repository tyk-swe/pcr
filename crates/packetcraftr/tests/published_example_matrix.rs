// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
// Test code indexes fixtures and counts by hand; the fail-closed lints are
// for library paths.
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

//! Pins which `examples/documents/output-<command>-<kind>.json` files each
//! command publishes, so a missing or stray example fails here instead of
//! going unnoticed.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use packetcraftr::output::contract::Command;

const KINDS: [&str; 4] = ["success", "event", "complete", "error"];

/// Expected example kinds per command. Aggregate-only commands publish
/// `success`; streaming-only commands publish `event` and `complete` (or
/// `success` where the stream ends in an aggregate). Every command publishes
/// `error`.
fn expected_kinds(command: Command) -> &'static [&'static str] {
    match command {
        Command::Build
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

#[test]
fn every_command_publishes_exactly_its_example_kinds() {
    let directory = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/documents");
    let names = fs::read_dir(&directory)
        .expect("published examples directory must exist")
        .map(|entry| {
            entry
                .expect("published example entry must be readable")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .filter(|name| name.starts_with("output-") && name.ends_with(".json"))
        .collect::<BTreeSet<_>>();

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
