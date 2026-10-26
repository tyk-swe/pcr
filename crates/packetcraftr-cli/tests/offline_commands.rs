// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::{Command, Output};

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_packetcraftr"))
        .args(args)
        .output()
        .unwrap_or_else(|error| panic!("failed to run packetcraftr {args:?}: {error}"))
}

fn capture_path(name: &str) -> PathBuf {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/captures")
        .join(name);
    assert!(
        path.is_file(),
        "example capture missing: {}",
        path.display()
    );
    path
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn assert_success(output: &Output, args: &[&str]) -> String {
    let text = stdout(output);
    assert!(
        output.status.success(),
        "packetcraftr {args:?} should exit 0, got {:?}\nstdout:\n{text}\nstderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !text.trim().is_empty(),
        "packetcraftr {args:?} should write non-empty stdout"
    );
    text
}

#[test]
fn help_exits_zero_and_names_the_tool() {
    let args = ["--help"];
    let output = run(&args);
    let text = assert_success(&output, &args);
    assert!(
        text.contains("packetcraftr"),
        "--help should name the tool, got:\n{text}"
    );
}

#[test]
fn packet_build_raw_exits_zero_with_built_bytes() {
    let args = ["packet", "build", "--packet", "raw(text=hello)"];
    let output = run(&args);
    let text = assert_success(&output, &args);
    let compact: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    assert!(
        compact.contains("68656c6c6f"),
        "built bytes should encode \"hello\" (68 65 6c 6c 6f), got:\n{text}"
    );
}

#[test]
fn files_read_dns_capture_with_dissect_exits_zero() {
    let capture = capture_path("dns-response.pcap");
    let capture = capture.to_string_lossy().into_owned();
    let args = ["files", "read", capture.as_str(), "--dissect"];
    let output = run(&args);
    let text = assert_success(&output, &args);
    assert!(
        text.to_lowercase().contains("dns"),
        "dissected output should identify the DNS layer, got:\n{text}"
    );
}

#[test]
fn analyze_dns_on_dns_capture_exits_zero() {
    let capture = capture_path("dns-response.pcap");
    let capture = capture.to_string_lossy().into_owned();
    let args = ["analyze", "dns", capture.as_str()];
    let output = run(&args);
    let text = assert_success(&output, &args);
    assert!(
        text.contains("DNS"),
        "DNS analysis should report DNS messages, got:\n{text}"
    );
}

#[test]
fn files_read_mqtt_capture_as_json_exits_zero_with_json_envelope() {
    let capture = capture_path("protocol-mqtt.pcap");
    let capture = capture.to_string_lossy().into_owned();
    let args = [
        "--output",
        "json",
        "files",
        "read",
        capture.as_str(),
        "--field",
        "frame.number",
    ];
    let output = run(&args);
    let text = assert_success(&output, &args);
    let trimmed = text.trim();
    assert!(
        trimmed.starts_with('{') && trimmed.ends_with('}'),
        "JSON stdout should be a single object, got:\n{text}"
    );
    assert!(
        trimmed.contains("\"packetcraftr.output/v1\""),
        "JSON stdout should carry the owned output schema value, got:\n{text}"
    );
    assert!(
        trimmed.contains("\"status\"") && trimmed.contains("\"success\""),
        "JSON stdout should report a success envelope, got:\n{text}"
    );
}

#[test]
fn files_read_missing_capture_exits_nonzero() {
    let missing = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/captures/missing-offline-corpus.pcap");
    assert!(
        !missing.exists(),
        "failure-case path must not exist: {}",
        missing.display()
    );
    let missing = missing.to_string_lossy().into_owned();
    let args = ["files", "read", missing.as_str(), "--dissect"];
    let output = run(&args);
    assert!(
        !output.status.success(),
        "packetcraftr {args:?} should exit non-zero for a missing input file, got {:?}\nstdout:\n{}",
        output.status.code(),
        stdout(&output)
    );
    assert!(
        !output.stderr.is_empty(),
        "packetcraftr {args:?} should explain the failure on stderr"
    );
}

fn analyze_http2_json(capture_name: &str) -> serde_json::Value {
    let capture = capture_path(capture_name);
    let capture = capture.to_string_lossy().into_owned();
    let args = ["--output", "json", "analyze", "http2", capture.as_str()];
    let output = run(&args);
    let text = assert_success(&output, &args);
    serde_json::from_str(&text)
        .unwrap_or_else(|error| panic!("analyze http2 should emit valid JSON: {error}\n{text}"))
}

#[test]
fn analyze_http2_multiplexed_capture_reports_streams_and_push() {
    let json = analyze_http2_json("http2-multiplexed.pcapng");
    let result = &json["result"];
    let connections = result["connections"].as_array().unwrap();
    assert_eq!(connections.len(), 1);
    assert_eq!(connections[0]["startup"], "prior_knowledge");
    assert_eq!(connections[0]["status"], "complete");
    let messages = result["messages"].as_array().unwrap();
    assert_eq!(messages.len(), 7);
    let kinds: Vec<_> = messages
        .iter()
        .map(|message| message["kind"].as_str().unwrap())
        .collect();
    assert_eq!(
        kinds,
        [
            "request",
            "request",
            "push_promise",
            "response",
            "response",
            "response",
            "request"
        ]
    );
    assert!(
        messages
            .iter()
            .all(|message| message["status"] == "complete")
    );
    assert!(result["issues"].as_array().unwrap().is_empty());
    let summary = &result["summary"];
    assert_eq!(summary["connections"], 1);
    assert_eq!(summary["prior_knowledge_connections"], 1);
    assert_eq!(summary["upgraded_connections"], 0);
    assert_eq!(summary["unsupported_connections"], 0);
    assert_eq!(summary["frames"], 22);
    assert_eq!(summary["streams"], 4);
    assert_eq!(summary["messages"], 7);
    assert_eq!(summary["complete_messages"], 7);
    assert_eq!(summary["issues"], 0);
}

#[test]
fn analyze_http2_upgrade_capture_reports_h2c_startup() {
    let json = analyze_http2_json("http2-upgrade.pcapng");
    let result = &json["result"];
    let connections = result["connections"].as_array().unwrap();
    assert_eq!(connections.len(), 1);
    assert_eq!(connections[0]["startup"], "h2c");
    assert_eq!(connections[0]["status"], "complete");
    let messages = result["messages"].as_array().unwrap();
    assert_eq!(messages.len(), 2);
    assert_eq!(messages[0]["kind"], "request");
    assert_eq!(messages[0]["status"], "complete");
    assert_eq!(messages[0]["http2_stream_id"], 1);
    assert_eq!(messages[1]["kind"], "response");
    assert_eq!(messages[1]["status"], "complete");
    assert_eq!(messages[1]["http2_stream_id"], 1);
    assert_eq!(messages[1]["request"], 1);
    assert!(result["issues"].as_array().unwrap().is_empty());
    let summary = &result["summary"];
    assert_eq!(summary["connections"], 1);
    assert_eq!(summary["prior_knowledge_connections"], 0);
    assert_eq!(summary["upgraded_connections"], 1);
    assert_eq!(summary["unsupported_connections"], 0);
    assert_eq!(summary["frames"], 6);
    assert_eq!(summary["streams"], 1);
    assert_eq!(summary["messages"], 2);
    assert_eq!(summary["complete_messages"], 2);
    assert_eq!(summary["issues"], 0);
}
