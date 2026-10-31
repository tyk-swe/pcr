// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
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

fn assert_error(output: &Output, expected_code: &str) {
    assert!(
        !output.status.success(),
        "expected {expected_code}, got success:\n{}",
        stdout(output)
    );
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
            panic!(
                "expected JSON error: {error}\nstdout:\n{}\nstderr:\n{}",
                stdout(output),
                String::from_utf8_lossy(&output.stderr)
            )
        });
    assert_eq!(report["error"]["code"], expected_code, "{report}");
}

fn capture_frames(path: &Path) -> Vec<Vec<u8>> {
    let source = std::fs::File::open(path).expect("open capture");
    packetcraftr_core::capture_file::Reader::with_limits(source, Default::default())
        .expect("read capture header")
        .map(|frame| frame.expect("read capture frame").bytes().to_vec())
        .collect()
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
fn pcapng_output_can_be_read_back() {
    let args = [
        "--output",
        "pcapng",
        "packet",
        "build",
        "--packet",
        "ipv4()/icmpv4(identifier=1)",
        "--link-type",
        "ipv4",
    ];
    let output = run(&args);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let reader = packetcraftr_core::capture_file::Reader::with_limits(
        output.stdout.as_slice(),
        Default::default(),
    )
    .expect("read generated capture header");
    assert_eq!(
        reader.format(),
        packetcraftr_core::capture_file::Format::PcapNg
    );
    let capture = tempfile::NamedTempFile::new().expect("create capture file");
    std::fs::write(capture.path(), &output.stdout).expect("write capture");
    let capture_path = capture.path().to_string_lossy();
    let args = ["--output", "ndjson", "files", "read", capture_path.as_ref()];
    let output = run(&args);
    let text = assert_success(&output, &args);
    let events = text
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).expect("valid NDJSON"))
        .collect::<Vec<_>>();
    assert_eq!(
        events
            .iter()
            .filter(|event| event["event"] == "frame")
            .count(),
        1
    );
}

#[test]
fn invalid_output_format_is_rejected() {
    let args = [
        "--output",
        "pcap-ng",
        "packet",
        "build",
        "--packet",
        "raw(text=hello)",
    ];
    let output = run(&args);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(
        error.contains("pcap-ng") && error.contains("pcapng"),
        "{error}"
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

#[test]
fn files_merge_honors_capture_limits() {
    let source = capture_path("dns-response.pcap");
    let source_frames = capture_frames(&source);
    assert!(!source_frames.is_empty());
    let source_size = std::fs::metadata(&source).unwrap().len().to_string();
    let source = source.to_str().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let merged = dir.path().join("merged.pcapng");
    let command = [
        "--output", "json", "files", "merge", source, source, "--order", "append",
    ];
    let args = [
        &command[..],
        &[
            "--write",
            merged.to_str().unwrap(),
            "--max-frame-bytes",
            "65536",
            "--max-bytes",
            "65536",
            "--max-encoded-bytes",
            &source_size,
            "--max-decoded-bytes",
            &source_size,
            "--max-interfaces",
            "1",
        ],
    ]
    .concat();
    assert_success(&run(&args), &args);
    let expected: Vec<_> = source_frames
        .iter()
        .chain(&source_frames)
        .cloned()
        .collect();
    assert_eq!(capture_frames(&merged), expected);

    let failures: [(&[&str], &str); 2] = [
        (
            &["--max-encoded-bytes", "0"],
            "packet.capture_compression_limit",
        ),
        (
            &["--max-frame-bytes", "2", "--max-bytes", "1"],
            "cli.capture_limit",
        ),
    ];
    for (index, (limits, code)) in failures.iter().enumerate() {
        let destination = dir.path().join(format!("rejected-merge-{index}.pcapng"));
        let args = [
            &command[..],
            &["--write", destination.to_str().unwrap()],
            limits,
        ]
        .concat();
        assert_error(&run(&args), code);
        assert!(!destination.exists());
    }
}

#[test]
fn files_export_honors_capture_limits() {
    let source = capture_path("dns-response.pcap");
    let source_frames = capture_frames(&source);
    assert!(!source_frames.is_empty());
    let source_size = std::fs::metadata(&source).unwrap().len().to_string();
    let source = source.to_str().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let exported = dir.path().join("exported.pcap");
    let command = [
        "--output", "json", "files", "export", source, "--filter", "dns",
    ];
    let args = [
        &command[..],
        &[
            "--write",
            exported.to_str().unwrap(),
            "--max-frame-bytes",
            "65536",
            "--max-bytes",
            "65536",
            "--max-encoded-bytes",
            &source_size,
            "--max-decoded-bytes",
            &source_size,
            "--max-interfaces",
            "1",
        ],
    ]
    .concat();
    assert_success(&run(&args), &args);
    assert_eq!(capture_frames(&exported), source_frames);

    let failures: [(&[&str], &str); 2] = [
        (
            &["--max-decoded-bytes", "0"],
            "packet.capture_compression_limit",
        ),
        (&["--max-interfaces", "0"], "cli.capture_limit"),
    ];
    for (index, (limits, code)) in failures.iter().enumerate() {
        let destination = dir.path().join(format!("rejected-export-{index}.pcap"));
        let args = [
            &command[..],
            &["--write", destination.to_str().unwrap()],
            limits,
        ]
        .concat();
        assert_error(&run(&args), code);
        assert!(!destination.exists());
    }
}

#[test]
fn verify_forwarding_applies_capture_limits_to_both_inputs() {
    let ingress = capture_path("dns-response.pcap");
    let egress = capture_path("http-stream.pcap");
    let ingress_size = std::fs::metadata(&ingress).unwrap().len();
    assert!(std::fs::metadata(&egress).unwrap().len() > ingress_size);
    let limit = ingress_size.to_string();
    let ingress = ingress.to_str().unwrap();
    let egress = egress.to_str().unwrap();
    let args = [
        "--output",
        "json",
        "analyze",
        "verify-forwarding",
        ingress,
        ingress,
        "--identity",
        "ipv4.identification",
        "--max-encoded-bytes",
        &limit,
    ];
    assert_success(&run(&args), &args);
    let args = [
        "--output",
        "json",
        "analyze",
        "verify-forwarding",
        ingress,
        egress,
        "--identity",
        "ipv4.identification",
        "--max-encoded-bytes",
        &limit,
    ];
    assert_error(&run(&args), "packet.capture_compression_limit");
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

#[test]
fn analyze_scan_diff_reports_changes_and_input_provenance() {
    use serde_json::json;
    use sha2::{Digest, Sha256};

    let dir = tempfile::tempdir().unwrap();
    let before_path = dir.path().join("before.json");
    let after_path = dir.path().join("after.json");
    let before = json!({
        "schema":"packetcraftr.output/v1", "command":"scan", "mode":"aggregate", "status":"success",
        "result":{"method":"tcp_connect", "endpoints":[
            {"address":"192.0.2.1", "port":443, "inference":{"state":"closed", "supporting":[1]}},
            {"address":"192.0.2.2", "port":443, "inference":{"state":"open", "supporting":[2]}}
        ]}
    });
    let after = json!({
        "schema":"packetcraftr.output/v1", "command":"scan", "mode":"aggregate", "status":"success",
        "result":{"method":"tcp_connect", "endpoints":[
            {"address":"192.0.2.1", "port":443, "inference":{"state":"open", "supporting":[3]}}
        ]}
    });
    let before_bytes = serde_json::to_vec(&before).unwrap();
    let after_bytes = serde_json::to_vec(&after).unwrap();
    std::fs::write(&before_path, &before_bytes).unwrap();
    std::fs::write(&after_path, &after_bytes).unwrap();
    let before_path = before_path.to_str().unwrap();
    let after_path = after_path.to_str().unwrap();
    let args = [
        "--output",
        "json",
        "analyze",
        "scan-diff",
        before_path,
        after_path,
    ];
    let output = run(&args);
    let report: serde_json::Value = serde_json::from_str(&assert_success(&output, &args)).unwrap();
    let result = &report["result"];
    assert_eq!(report["command"], "scan-diff");
    assert_eq!(result["kind"], "scan-diff");
    let findings = result["findings"].as_array().unwrap();
    assert_eq!(findings.len(), 2);
    let changed = findings
        .iter()
        .find(|f| f["rule_id"] == "scan.state_changed")
        .unwrap();
    assert_eq!(changed["severity"], "medium");
    assert_eq!(
        changed["evidence"]["before"],
        before["result"]["endpoints"][0]
    );
    assert_eq!(
        changed["evidence"]["after"],
        after["result"]["endpoints"][0]
    );
    let coverage = findings
        .iter()
        .find(|f| f["rule_id"] == "scan.coverage_changed")
        .unwrap();
    assert_eq!(
        coverage["evidence"]["before"],
        before["result"]["endpoints"][1]
    );
    assert!(coverage["evidence"]["after"].is_null());
    assert_eq!(result["measurements"]["before_endpoints"], 2);
    assert_eq!(result["measurements"]["after_endpoints"], 1);
    let hash = |bytes: &[u8]| {
        Sha256::digest(bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    };
    assert_eq!(
        result["sources"],
        json!([
            {"path": before_path, "sha256": hash(&before_bytes)},
            {"path": after_path, "sha256": hash(&after_bytes)}
        ])
    );
}

#[test]
fn analyze_scan_diff_rejects_invalid_scan_input() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("invalid.json");
    std::fs::write(&path, br#"{"schema":"packetcraftr.output/v1","command":"scan","mode":"aggregate","status":"failure"}"#).unwrap();
    let path = path.to_str().unwrap();
    let args = ["--output", "json", "analyze", "scan-diff", path, path];
    let output = run(&args);
    assert_eq!(output.status.code(), Some(2));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["status"], "error");
    assert_eq!(report["error"]["code"], "cli.security_input");
}
