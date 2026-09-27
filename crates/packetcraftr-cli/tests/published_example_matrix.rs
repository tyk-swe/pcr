// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;

use packetcraftr_cli::output::contract::Command;
use serde_json::Value;

mod common;

use common::{output_schema, schema_validator};

fn documents_directory() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/documents")
}

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

fn expected_kinds(command: Command) -> &'static [&'static str] {
    match command {
        Command::Rewrite
        | Command::Export
        | Command::Merge
        | Command::Exchange
        | Command::VerifyForwarding => &["success", "complete", "error"],
        Command::Protocols
        | Command::Plan
        | Command::Send
        | Command::Interfaces
        | Command::Routes
        | Command::Stats => &["success", "error"],
        Command::Fragment
        | Command::Dissect
        | Command::Read
        | Command::Capture
        | Command::Build
        | Command::Scan
        | Command::Replay
        | Command::Expert
        | Command::Follow
        | Command::Tls
        | Command::Traceroute
        | Command::Http
        | Command::DnsRead
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

#[test]
fn every_published_output_example_validates_against_the_schema() {
    let validator = schema_validator();
    let mut examples = fs::read_dir(documents_directory())
        .expect("published examples directory must exist")
        .map(|entry| {
            entry
                .expect("published example entry must be readable")
                .path()
        })
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("output-") && name.ends_with(".json"))
        })
        .collect::<Vec<_>>();
    examples.sort();
    assert!(!examples.is_empty(), "published output examples must exist");

    for path in examples {
        let document: Value = serde_json::from_str(
            &fs::read_to_string(&path).expect("published example must be readable"),
        )
        .unwrap_or_else(|error| panic!("{} must be valid JSON: {error}", path.display()));
        validator.validate(&document).unwrap_or_else(|error| {
            panic!(
                "{} must validate against the output schema: {error}",
                path.display()
            )
        });
    }
}

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

#[test]
fn every_published_error_code_agrees_with_its_kind() {
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
