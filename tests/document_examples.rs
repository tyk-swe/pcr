// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn binary() -> Command {
    Command::new(env!("CARGO_BIN_EXE_packetcraftr"))
}

fn example(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("examples/documents")
        .join(name)
}

fn json_file(name: &str) -> serde_json::Value {
    serde_json::from_slice(&fs::read(example(name)).unwrap()).unwrap()
}

#[test]
fn packet_document_example_builds_through_the_public_cli() {
    let output = binary()
        .args([
            "--output",
            "json",
            "build",
            "--packet-file",
            example("packet-ipv4-udp.json").to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["schema"], "packetcraftr.output/v1");
    assert_eq!(value["status"], "success");
    assert_eq!(value["result"]["length"], 47);
}

#[test]
fn published_build_success_output_matches_the_cli() {
    let output = binary()
        .args(["--output", "json", "build", "--packet", "raw(hex=deadbeef)"])
        .output()
        .unwrap();

    assert!(output.status.success());
    let actual: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(actual, json_file("output-build-success.json"));
}

#[test]
fn published_build_error_output_matches_the_cli() {
    let output = binary()
        .args(["--output", "json", "build", "--packet", "ethernet()/udp()"])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(3));
    let actual: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(actual, json_file("output-build-error.json"));
}

#[test]
fn published_exchange_stream_event_matches_the_typed_contract() {
    let event = packetcraftr::StreamRecord::success(
        packetcraftr::CommandName::Exchange,
        3,
        packetcraftr::ExchangeStreamCommandResult::Complete {
            unanswered: vec![1, 2],
        },
        Vec::new(),
    );

    assert_eq!(
        serde_json::to_value(event).unwrap(),
        json_file("output-exchange-event.json")
    );
}
