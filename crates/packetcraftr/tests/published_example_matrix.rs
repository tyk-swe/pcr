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

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;

use packetcraftr::output::contract::Command;
use serde_json::Value;

mod support;

use support::output_schema;

const KINDS: [&str; 4] = ["success", "event", "complete", "error"];

/// Documents published beyond the canonical kinds, each showing one branch a
/// command's output can take.
const SUB_KIND_EXAMPLES: [&str; 30] = [
    "output-dissect-diagnostic-success.json",
    "output-dissect-filter-no-match.json",
    "output-dns-any-success.json",
    "output-dns-attempt-response-event.json",
    "output-dns-cname-record-event.json",
    "output-dns-ptr-record-event.json",
    "output-dns-record-event.json",
    "output-dns-rejected-event.json",
    "output-dns-srv-record-event.json",
    "output-exchange-diagnostic-event.json",
    "output-exchange-response-event.json",
    "output-exchange-sent-event.json",
    "output-exchange-unanswered-event.json",
    "output-exchange-undecoded-event.json",
    "output-exchange-unsolicited-event.json",
    "output-expert-ip-incomplete-event.json",
    "output-follow-ip-completed-event.json",
    "output-protocols-detail-success.json",
    "output-read-dissect-event.json",
    "output-scan-response-event.json",
    "output-scan-undecoded-event.json",
    "output-stats-endpoints-success.json",
    "output-stats-fragments-success.json",
    "output-stats-io-success.json",
    "output-stats-ports-success.json",
    "output-stats-protocols-success.json",
    "output-tls-alert-event.json",
    "output-tls-ip-overlap-event.json",
    "output-tls-truncated-event.json",
    "output-traceroute-undecoded-event.json",
];

/// Schema property paths no published example exercises, each with the reason
/// an offline run cannot publish it. An entry covers itself and every path
/// beneath it, and fails as stale once an example does exercise it.
const UNPUBLISHED_PROPERTIES: [(&str, &str); 9] = [
    (
        "captureStatistics.receiver_dropped_frames",
        "serialized only when a live capture backend drops frames",
    ),
    (
        "dnsRecord.edns",
        "OPT pseudo-records are lifted into the response's edns metadata before any record is \
         published",
    ),
    (
        "fuzzCase.decoded",
        "fuzz dissects the frame it sent, which only a live run has",
    ),
    (
        "fuzzCase.error",
        "a case fails only while a live run transmits it",
    ),
    (
        "fuzzCase.sent",
        "the transmitted frame exists only after a live run sends the case",
    ),
    (
        "materializedRoute.neighbor",
        "neighbor resolution runs ARP/NDP on a live interface with a capture backend",
    ),
    (
        "replayTiming.fixed_rate",
        "replay sends on a live interface; the published aggregate shows immediate timing",
    ),
    (
        "replayTiming.scaled",
        "replay sends on a live interface; the published aggregate shows immediate timing",
    ),
    (
        "tlsSession.alerts_dropped",
        "serialized only past the 32-alert per-session cap",
    ),
];

/// Packet documents, which are command input rather than command output.
const PACKET_EXAMPLES: [&str; 4] = [
    "packet-gre-sctp.json",
    "packet-igmp.json",
    "packet-ipv4-udp.json",
    "packet-raw.yaml",
];

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

/// The definition a local `$ref` names, with its name.
fn referenced_definition<'a>(schema: &'a Value, reference: &'a str) -> (&'a str, &'a Value) {
    let name = reference
        .strip_prefix("#/$defs/")
        .expect("the output schema only references its own $defs");
    let definition = &schema["$defs"][name];
    assert!(definition.is_object(), "{reference}: unknown definition");
    (name, definition)
}

/// Every property path the schema declares, scoped by the definition that
/// declares it: `statsIo.buckets`, `materializedRoute.neighbor.mac_address`.
fn schema_property_paths(schema: &Value) -> BTreeSet<String> {
    fn walk<'a>(
        schema: &'a Value,
        node: &'a Value,
        prefix: &str,
        visited: &mut BTreeSet<&'a str>,
        paths: &mut BTreeSet<String>,
    ) {
        if let Some(reference) = node["$ref"].as_str() {
            let (name, definition) = referenced_definition(schema, reference);
            if visited.insert(name) {
                walk(schema, definition, name, visited, paths);
            }
        }
        for combinator in ["oneOf", "anyOf", "allOf"] {
            for branch in node[combinator].as_array().into_iter().flatten() {
                walk(schema, branch, prefix, visited, paths);
            }
        }
        for (name, property) in node["properties"].as_object().into_iter().flatten() {
            let path = format!("{prefix}.{name}");
            walk(schema, property, &path, visited, paths);
            paths.insert(path);
        }
        for keyword in ["items", "additionalProperties"] {
            if node[keyword].is_object() {
                walk(schema, &node[keyword], prefix, visited, paths);
            }
        }
    }

    let mut paths = BTreeSet::new();
    walk(schema, schema, "root", &mut BTreeSet::new(), &mut paths);
    paths
}

/// Whether a combinator branch can describe `instance`: every `const`
/// discriminator it declares agrees with the instance, and every key it
/// requires is present. Branches with other keywords are taken as applicable.
fn branch_applies(schema: &Value, branch: &Value, instance: &Value) -> bool {
    let branch = match branch["$ref"].as_str() {
        Some(reference) => referenced_definition(schema, reference).1,
        None => branch,
    };
    let Some(fields) = instance.as_object() else {
        return true;
    };
    let required_present = branch["required"]
        .as_array()
        .into_iter()
        .flatten()
        .all(|key| key.as_str().is_none_or(|key| fields.contains_key(key)));
    let constants_agree =
        branch["properties"]
            .as_object()
            .into_iter()
            .flatten()
            .all(
                |(name, property)| match (property.get("const"), fields.get(name)) {
                    (Some(expected), Some(actual)) => expected == actual,
                    _ => true,
                },
            );
    required_present && constants_agree
}

/// Records every property path `instance` exercises under `node`, walking
/// the schema and the document together so a property counts only where the
/// schema declares it.
fn mark_covered<'a>(
    schema: &'a Value,
    node: &'a Value,
    instance: &Value,
    prefix: &str,
    covered: &mut BTreeSet<String>,
) {
    let (node, prefix): (&Value, &str) = match node["$ref"].as_str() {
        Some(reference) => {
            let (name, definition) = referenced_definition(schema, reference);
            (definition, name)
        }
        None => (node, prefix),
    };
    for combinator in ["oneOf", "anyOf", "allOf"] {
        for branch in node[combinator].as_array().into_iter().flatten() {
            if branch_applies(schema, branch, instance) {
                mark_covered(schema, branch, instance, prefix, covered);
            }
        }
    }
    match instance {
        Value::Object(fields) => {
            for (key, value) in fields {
                if let Some(property) = node["properties"].get(key) {
                    let path = format!("{prefix}.{key}");
                    mark_covered(schema, property, value, &path, covered);
                    covered.insert(path);
                } else if node["additionalProperties"].is_object() {
                    mark_covered(
                        schema,
                        &node["additionalProperties"],
                        value,
                        prefix,
                        covered,
                    );
                }
            }
        }
        Value::Array(items) if node["items"].is_object() => {
            for item in items {
                mark_covered(schema, &node["items"], item, prefix, covered);
            }
        }
        _ => {}
    }
}

/// Whether the allow-list explains why `path` (or an ancestor) is unpublished.
fn is_explained_unpublished(path: &str) -> bool {
    UNPUBLISHED_PROPERTIES.iter().any(|(entry, _)| {
        path == *entry
            || path
                .strip_prefix(entry)
                .is_some_and(|rest| rest.starts_with('.'))
    })
}

/// Nearly every object in the schema closes with `additionalProperties:
/// false`, so a consumer generating strict types from the published examples
/// never learns about a property no example serializes. Every declared
/// property must therefore appear in some `output-*.json`, or carry a reason
/// it cannot.
#[test]
fn every_schema_property_appears_in_a_published_example() {
    let schema = output_schema();
    let paths = schema_property_paths(schema);
    assert!(
        paths.len() > 300,
        "the walker must resolve $refs: only {} property paths found",
        paths.len()
    );

    let mut covered = BTreeSet::new();
    for (_, document) in published_output_documents(".json") {
        mark_covered(schema, schema, &document, "root", &mut covered);
    }

    let unpublished = paths
        .iter()
        .filter(|path| !covered.contains(*path))
        .collect::<Vec<_>>();
    let unexplained = unpublished
        .iter()
        .filter(|path| !is_explained_unpublished(path))
        .collect::<Vec<_>>();
    assert!(
        unexplained.is_empty(),
        "{} of {} schema property paths appear in no examples/documents/output-*.json: \
         {unexplained:#?}; publish an example that serializes each, or add the path to \
         UNPUBLISHED_PROPERTIES with the reason no offline run can",
        unexplained.len(),
        paths.len()
    );

    let stale = UNPUBLISHED_PROPERTIES
        .iter()
        .filter(|(entry, _)| !paths.contains(*entry) || covered.contains(*entry))
        .map(|(entry, _)| *entry)
        .collect::<Vec<_>>();
    assert!(
        stale.is_empty(),
        "UNPUBLISHED_PROPERTIES entries that the schema no longer declares or an example now \
         exercises: {stale:?}; remove them"
    );
}
