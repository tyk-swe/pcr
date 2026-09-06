// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
// Test code indexes fixtures and counts by hand; the fail-closed lints are
// for library paths.
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

//! Required command examples and published error-code consistency.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;

use packetcraftr::output::contract::Command;
use serde_json::Value;

mod support;

use support::output_schema;

/// The published examples directory.
fn documents_directory() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/documents")
}

/// Every file name in `examples/documents`.
fn published_example_names() -> BTreeSet<String> {
    let directory = documents_directory();
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
fn every_command_publishes_its_required_example_kinds() {
    let names = published_example_names();
    for command in Command::ALL.iter().copied() {
        for kind in expected_kinds(command) {
            let name = format!("output-{command}-{kind}.json");
            assert!(names.contains(&name), "missing required example {name}");
        }
    }
}

/// Every published `output-*` document whose name ends in `suffix`, parsed.
fn published_output_documents(suffix: &str) -> Vec<(String, Value)> {
    published_example_names()
        .into_iter()
        .filter(|name| name.starts_with("output-") && name.ends_with(suffix))
        .map(|name| {
            let document = serde_json::from_str(
                &fs::read_to_string(documents_directory().join(&name))
                    .expect("published example must be readable"),
            )
            .expect("published example must be JSON");
            (name, document)
        })
        .collect()
}

/// Every stable error code the published documents name, with the `kind` each
/// was published under.
fn published_error_codes() -> BTreeMap<String, BTreeSet<(String, String)>> {
    let mut codes: BTreeMap<String, BTreeSet<(String, String)>> = BTreeMap::new();
    for (name, document) in published_output_documents("-error.json") {
        let error = &document["error"];
        let code = error["code"].as_str().expect("an error names its code");
        let kind = error["kind"].as_str().expect("an error names its kind");
        codes
            .entry(code.to_owned())
            .or_default()
            .insert((kind.to_owned(), name));
    }
    codes
}

/// The stable code vocabulary carries its class in its own prefix, so
/// `policy.public_destination` cannot be published as anything but
/// `"kind": "policy"`. Nothing else enforces the pairing, and the pairing is
/// what makes a code readable without the schema in hand.
#[test]
fn every_published_error_code_agrees_with_its_kind() {
    // The schema is the authority on the class vocabulary, so this check moves
    // with the contract rather than with any one crate's enum.
    let vocabulary = output_schema()["$defs"]["error"]["properties"]["kind"]["enum"]
        .as_array()
        .expect("the schema enumerates the failure classes")
        .iter()
        .map(|kind| {
            kind.as_str()
                .expect("each failure class is a string")
                .to_owned()
        })
        .collect::<BTreeSet<_>>();
    let codes = published_error_codes();
    assert!(
        !codes.is_empty(),
        "the published examples must include error documents"
    );

    for (code, publications) in codes {
        let prefix = code
            .split('.')
            .next()
            .expect("split always yields one element");
        assert!(
            vocabulary.contains(prefix),
            "{code}: prefix {prefix} is not one of the stable failure classes {vocabulary:?}"
        );
        let kinds = publications
            .iter()
            .map(|(kind, _)| kind.clone())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            kinds,
            BTreeSet::from([prefix.to_owned()]),
            "{code}: published under {kinds:?} by {publications:?}, but its prefix says {prefix}"
        );
    }
}
