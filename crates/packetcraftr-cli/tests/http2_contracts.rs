// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
mod common;
#[path = "common/process.rs"]
mod process_support;
#[allow(dead_code)]
#[path = "common/tls_capture.rs"]
mod tls_capture;
use std::io::Write as _;
use std::path::PathBuf;

use common::{assert_contiguous, parse_json, parse_ndjson, run, run_success};

fn multiplexed() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/captures/http2-multiplexed.pcapng")
}
fn upgrade() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/captures/http2-upgrade.pcapng")
}

#[test]
#[ignore = "regenerates the checked-in captures; run explicitly when fixtures change"]
fn write_example_captures() {
    let directory = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/captures");
    std::fs::write(
        directory.join("http2-multiplexed.pcapng"),
        common::http2_capture::capture_bytes(&[common::http2_capture::multiplexed(80)]),
    )
    .expect("multiplexed example must write");
    std::fs::write(
        directory.join("http2-upgrade.pcapng"),
        common::http2_capture::capture_bytes(&[common::http2_capture::upgrade(80)]),
    )
    .expect("upgrade example must write");
}

#[test]
fn checked_in_captures_match_the_generator() {
    assert_eq!(
        std::fs::read(multiplexed()).expect("checked-in capture must exist"),
        common::http2_capture::capture_bytes(&[common::http2_capture::multiplexed(80)]),
        "regenerate examples/captures/http2-multiplexed.pcapng after fixture changes"
    );
    assert_eq!(
        std::fs::read(upgrade()).expect("checked-in capture must exist"),
        common::http2_capture::capture_bytes(&[common::http2_capture::upgrade(80)]),
        "regenerate examples/captures/http2-upgrade.pcapng after fixture changes"
    );
}

#[test]
fn multiplexed_capture_reports_all_frame_types_and_messages() {
    let path = multiplexed();
    let path = path.to_str().unwrap();
    let document = parse_json(&run_success(&["--output", "json", "http2", path]));
    let result = &document["result"];
    let summary = &result["summary"];
    assert_eq!(summary["connections"], 1);
    assert_eq!(summary["prior_knowledge_connections"], 1);
    assert_eq!(summary["issues"], 0, "{document}");
    let messages = result["messages"].as_array().unwrap();
    assert_eq!(messages.len(), 7, "{document}");
    let kinds: Vec<_> = messages
        .iter()
        .map(|m| m["kind"].as_str().unwrap())
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
        ],
        "{document}"
    );
    let stream3 = messages
        .iter()
        .find(|m| m["http2_stream_id"] == 3 && m["kind"] == "response")
        .expect("stream 3 response");
    assert_eq!(stream3["body_bytes"], 5);
    let stream1 = messages
        .iter()
        .find(|m| m["http2_stream_id"] == 1 && m["kind"] == "response")
        .expect("stream 1 response");
    assert_eq!(stream1["body_bytes"], 3);
    assert_eq!(stream1["trailers"][0]["name"], "age");
    assert_eq!(stream1["trailers"][0]["value"], "3");
    let pushed = messages
        .iter()
        .find(|m| m["http2_stream_id"] == 2 && m["kind"] == "response")
        .expect("pushed response");
    assert_eq!(pushed["status"], "complete");
    let types: Vec<u64> = result["frames"]
        .as_array()
        .unwrap()
        .iter()
        .map(|frame| frame["frame_type"].as_u64().unwrap())
        .collect();
    assert_eq!(
        types,
        [
            4, 4, 4, 4, 1, 1, 9, 5, 1, 0, 1, 0, 1, 1, 1, 3, 6, 6, 2, 8, 7, 7
        ],
        "{document}"
    );
    let connection = &result["connections"][0];
    assert_eq!(connection["startup"], "prior_knowledge");
    assert_eq!(connection["status"], "complete");
    assert_eq!(connection["streams"], 4);
    assert_eq!(connection["pending_pings"], 0);
}

#[test]
fn ndjson_reports_contiguous_stream_with_all_event_kinds() {
    let path = multiplexed();
    let records = parse_ndjson(&run_success(&[
        "--output",
        "ndjson",
        "http2",
        path.to_str().unwrap(),
    ]));
    assert_contiguous(&records);
    let names: Vec<_> = records
        .iter()
        .map(|record| record["event"].as_str().unwrap())
        .collect();
    assert_eq!(
        names.iter().filter(|name| **name == "http2_frame").count(),
        22
    );
    assert_eq!(
        names
            .iter()
            .filter(|name| **name == "http2_message")
            .count(),
        7
    );
    assert_eq!(
        names
            .iter()
            .filter(|name| **name == "http2_connection")
            .count(),
        1
    );
    assert_eq!(names.iter().filter(|name| **name == "complete").count(), 1);
    assert_eq!(names.last(), Some(&"complete"));
}

#[test]
fn upgrade_capture_reports_h2c_connection() {
    let path = upgrade();
    let document = parse_json(&run_success(&[
        "--output",
        "json",
        "http2",
        path.to_str().unwrap(),
    ]));
    let result = &document["result"];
    assert_eq!(result["summary"]["upgraded_connections"], 1, "{document}");
    let connection = &result["connections"][0];
    assert_eq!(connection["startup"], "h2c");
    assert_eq!(connection["status"], "complete");
    assert_eq!(connection["streams"], 1);
    let response = connection["upgrade_response"].as_object().unwrap();
    assert_eq!(response["start"]["status"], 101);
    let request = result["messages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["kind"] == "request")
        .expect("upgrade request");
    assert_eq!(request["http2_stream_id"], 1);
    assert_eq!(request["body_bytes"], 4);
    assert_eq!(request["upgrade_head"]["start"]["method"], "POST");
    let response = result["messages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["kind"] == "response")
        .expect("upgrade response");
    assert_eq!(response["body_bytes"], 5);
}

#[test]
fn text_and_stream_outputs_escape_and_stay_bounded() {
    let path = multiplexed();
    let path = path.to_str().unwrap();
    let text = run_success(&["http2", path]);
    let stdout = String::from_utf8_lossy(&text.stdout);
    assert!(stdout.contains("HTTP2 tcp:0"));
    assert!(stdout.contains("startup=prior_knowledge"));
    assert!(!stdout.chars().any(|c| c.is_control() && c != '\n'));
}

#[test]
fn custom_and_default_ports_are_respected() {
    let nonstandard =
        common::http2_capture::write_capture(&[common::http2_capture::multiplexed(8000)]);
    let path = common::path_text(nonstandard.path());
    let silent = parse_json(&run_success(&["--output", "json", "http2", path]));
    assert_eq!(silent["result"]["summary"]["connections"], 0);
    let selected = parse_json(&run_success(&[
        "--output",
        "json",
        "http2",
        path,
        "--http2-port",
        "8000",
    ]));
    assert_eq!(selected["result"]["summary"]["connections"], 1);
}

#[test]
fn selector_and_transport_rules_apply() {
    let path = multiplexed();
    let path = path.to_str().unwrap();
    let selected = parse_json(&run_success(&[
        "--output", "json", "http2", path, "--stream", "tcp:0",
    ]));
    assert_eq!(selected["result"]["summary"]["connections"], 1);
    let output = run(&["--output", "json", "http2", path, "--stream", "tcp:9"]);
    assert!(!output.status.success());
    let output = run(&["--output", "json", "http2", path, "--stream", "udp:0"]);
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(parse_json(&output)["error"]["kind"], "cli");
    assert!(
        parse_json(&output)["error"]["message"]
            .as_str()
            .unwrap()
            .contains("HTTP/2 inspection requires --stream tcp:INDEX")
    );
}

#[test]
fn limits_are_usage_errors_before_input() {
    use packetcraftr_core::analysis::http2 as h2;

    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("missing.pcapng");
    let path = common::path_text(&path);
    for (flag, maximum) in [
        ("--max-http2-frames", h2::MAX_FRAMES),
        ("--max-http2-streams", h2::MAX_STREAMS as u64),
        ("--max-http2-active-streams", h2::MAX_ACTIVE_STREAMS as u64),
        ("--max-http2-frame-bytes", h2::MAX_FRAME_BYTES as u64),
        (
            "--max-http2-header-block-bytes",
            h2::MAX_HEADER_BLOCK_BYTES as u64,
        ),
        ("--max-http2-header-bytes", h2::MAX_HEADER_BYTES as u64),
        ("--max-http2-headers", h2::MAX_HEADERS as u64),
        ("--max-http2-table-bytes", h2::MAX_TABLE_BYTES as u64),
        ("--max-http2-continuations", h2::MAX_CONTINUATIONS as u64),
        (
            "--max-http2-pending-settings",
            h2::MAX_PENDING_SETTINGS as u64,
        ),
        ("--max-http2-body-bytes", h2::MAX_BODY_BYTES),
    ] {
        for value in [0, maximum + 1] {
            let value = value.to_string();
            let output = run(&["--output", "json", "http2", path, flag, &value]);
            assert_eq!(output.status.code(), Some(2), "{flag}={value}: {output:?}");
            assert_eq!(
                parse_json(&output)["error"]["kind"],
                "cli",
                "{flag}={value}"
            );
        }
    }
    let output = run(&["--output", "json", "http2", path, "--http2-port", "0"]);
    assert_eq!(output.status.code(), Some(2));
}

#[test]
fn file_stdin_and_compressed_parity() {
    use common::http2_capture::{capture_bytes, multiplexed};
    let bytes = capture_bytes(&[multiplexed(80)]);
    let plain = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(plain.path(), &bytes).unwrap();
    let reference = run_success(&[
        "--output",
        "ndjson",
        "http2",
        common::path_text(plain.path()),
    ]);
    let via_stdin = process_support::run_with_stdin(&["--output", "ndjson", "http2", "-"], &bytes);
    assert!(via_stdin.status.success());
    assert_eq!(via_stdin.stdout, reference.stdout, "uncompressed stdin");
    for compression in ["gzip", "zstd"] {
        let mut compressed = Vec::new();
        {
            let mut output = packetcraftr_core::capture_file::compression::Output::new(
                &mut compressed,
                if compression == "gzip" {
                    packetcraftr_core::capture_file::compression::Format::Gzip
                } else {
                    packetcraftr_core::capture_file::compression::Format::Zstd
                },
            )
            .expect("compressor initializes");
            output.write_all(&bytes).expect("capture compresses");
            output.finish().expect("compressor finishes");
        }
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), &compressed).unwrap();
        let via_file = run_success(&[
            "--output",
            "ndjson",
            "http2",
            common::path_text(file.path()),
        ]);
        assert_eq!(via_file.stdout, reference.stdout, "{compression}");
        let via_stdin =
            process_support::run_with_stdin(&["--output", "ndjson", "http2", "-"], &compressed);
        assert!(via_stdin.status.success());
        assert_eq!(via_stdin.stdout, reference.stdout, "{compression} stdin");
    }
}

#[test]
fn application_output_budget_is_exact_for_all_formats() {
    let path = upgrade();
    let expected_text = concat!(
        "HTTP2 tcp:0 stream=1 message=1 kind=request status=complete body_bytes=4 request=none frames=4\n",
        "  Host: www.example.com\n",
        "  Connection: upgrade, HTTP2-Settings\n",
        "  Upgrade: h2c\n",
        "  HTTP2-Settings: AAEAAAAA\n",
        "  Content-Length: 4\n",
        "H2 tcp:0 frame=1 type=0x04 stream=0 length=0 flags=0x00\n",
        "H2 tcp:0 frame=2 type=0x04 stream=0 length=0 flags=0x00\n",
        "H2 tcp:0 frame=3 type=0x04 stream=0 length=0 flags=0x01\n",
        "H2 tcp:0 frame=4 type=0x04 stream=0 length=0 flags=0x01\n",
        "H2 tcp:0 frame=5 type=0x01 stream=1 length=2 flags=0x04\n",
        "H2 tcp:0 frame=6 type=0x00 stream=1 length=5 flags=0x01\n",
        "HTTP2 tcp:0 stream=1 message=2 kind=response status=complete body_bytes=5 request=1 frames=7\n",
        "  :status: 200\n",
        "HTTP2 tcp:0 connection startup=h2c status=complete streams=1 frames=6 issues=0\n",
        "1 HTTP/2 connections (0 prior knowledge, 1 h2c, 0 unsupported); 2 messages (2 complete, 0 incomplete, 0 malformed, 0 limited); 0 issues\n",
    );
    common::application_output::assert_exact_budget(
        "http2",
        &path,
        &[
            ("http2_frame", "frames"),
            ("http2_message", "messages"),
            ("http2_issue", "issues"),
            ("http2_connection", "connections"),
        ],
        expected_text,
        "application output exceeds --max-application-output-bytes",
        &[],
    );
}

#[test]
fn fatal_budget_keeps_ndjson_prefix_and_emits_one_error() {
    let path = multiplexed();
    let document = parse_json(&run_success(&[
        "--output",
        "json",
        "http2",
        path.to_str().unwrap(),
    ]));
    let first_frame = serde_json::to_vec(&document["result"]["frames"][0])
        .unwrap()
        .len()
        .to_string();
    let output = run(&[
        "--output",
        "ndjson",
        "http2",
        path.to_str().unwrap(),
        "--max-application-output-bytes",
        &first_frame,
    ]);
    assert_eq!(output.status.code(), Some(6));
    let records = parse_ndjson(&output);
    assert_contiguous(&records);
    let names: Vec<_> = records
        .iter()
        .map(|r| r["event"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["http2_frame", "error"]);
    assert_eq!(records[0]["result"], document["result"]["frames"][0]);
    assert_eq!(records[1]["error"]["code"], "policy.denied");
}

#[test]
fn resource_diagnostics_declare_all_http2_limits() {
    let path = multiplexed();
    let document = parse_json(&run_success(&[
        "--resource-diagnostics",
        "--output",
        "json",
        "http2",
        path.to_str().unwrap(),
    ]));
    let overridden = parse_json(&run_success(&[
        "--resource-diagnostics",
        "--resource-preset",
        "workstation-v1",
        "--output",
        "json",
        "http2",
        path.to_str().unwrap(),
        "--max-http2-headers",
        "77",
    ]));
    for name in [
        "--max-http2-frames",
        "--max-http2-streams",
        "--max-http2-active-streams",
        "--max-http2-frame-bytes",
        "--max-http2-header-block-bytes",
        "--max-http2-header-bytes",
        "--max-http2-headers",
        "--max-http2-table-bytes",
        "--max-http2-continuations",
        "--max-http2-pending-settings",
        "--max-http2-body-bytes",
    ] {
        let setting = document["resources"]["settings"]
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["name"] == name)
            .unwrap_or_else(|| panic!("{name} must be declared"));
        assert_eq!(setting["source"], "default", "{name}");
    }
    let overridden = overridden["resources"]["settings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["name"] == "--max-http2-headers")
        .unwrap();
    assert_eq!(overridden["value"], 77);
    assert_eq!(overridden["source"], "override");
    let preset = parse_json(&run_success(&[
        "--resource-preset",
        "workstation-v1",
        "--resource-diagnostics",
        "--output",
        "json",
        "http2",
        common::path_text(&path),
    ]));
    for (name, source) in [
        ("--max-frames", "preset:workstation-v1"),
        ("--max-application-messages", "preset:workstation-v1"),
        ("--max-http2-headers", "default"),
    ] {
        let setting = preset["resources"]["settings"]
            .as_array()
            .unwrap()
            .iter()
            .find(|setting| setting["name"] == name)
            .expect("declared setting");
        assert_eq!(setting["source"], source, "{name}");
    }
}

#[test]
fn invalid_header_bytes_are_escaped_and_hex_faithful() {
    let mut exchange = common::http2_capture::Exchange::new(80);
    let mut preface = packetcraftr_core::protocol::application::http2::CLIENT_PREFACE.to_vec();
    preface.extend_from_slice(&common::http2_capture::frame(0x4, 0, 0, &[]));
    exchange.client(&preface);
    exchange.server(&common::http2_capture::frame(0x4, 0, 0, &[]));
    exchange.server(&common::http2_capture::frame(0x4, 0x1, 0, &[]));
    exchange.client(&common::http2_capture::frame(0x4, 0x1, 0, &[]));
    let mut block = common::http2_capture::REQUEST.to_vec();
    block.extend_from_slice(&[0x00, 0x02, b'a', 0x1b]);
    block.extend_from_slice(&[0x03, b'x', 0x1b, b'y']);
    exchange.client(&common::http2_capture::frame(0x1, 0x4 | 0x1, 1, &block));
    let capture = common::http2_capture::write_capture(&[exchange]);
    let path = common::path_text(capture.path());
    let text = run_success(&["http2", path]);
    let stdout = String::from_utf8_lossy(&text.stdout);
    assert!(
        !stdout.chars().any(|c| c.is_control() && c != '\n'),
        "{stdout}"
    );
    assert!(stdout.contains("\\u{1b}"), "{stdout}");
    let document = parse_json(&run_success(&["--output", "json", "http2", path]));
    let header = &document["result"]["messages"][0]["headers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|h| h["name_hex"].as_str().unwrap().ends_with("1b"))
        .expect("the control-byte header field");
    assert_eq!(header["value_hex"], "781b79");
}

#[test]
fn tls_server_port_is_unsupported_not_fabricated() {
    let tls = tls_capture::write_capture(&[tls_capture::Handshake::complete(
        40_000,
        443,
        "api.example.test",
    )]);
    let document = parse_json(&run_success(&[
        "--output",
        "json",
        "http2",
        common::path_text(tls.path()),
        "--http2-port",
        "443",
    ]));
    let result = &document["result"];
    assert_eq!(
        result["summary"]["unsupported_connections"], 1,
        "{document}"
    );
    assert_eq!(result["messages"].as_array().unwrap().len(), 0);
    let connection = &result["connections"][0];
    assert_eq!(connection["startup"], "unknown");
    assert_eq!(connection["status"], "unsupported");
}

#[test]
fn ndjson_malformed_headers_emit_issue_and_single_connection() {
    use common::http2_capture::{Exchange, frame, settings};
    let mut exchange = Exchange::new(80);
    let mut preface = packetcraftr_core::protocol::application::http2::CLIENT_PREFACE.to_vec();
    preface.extend_from_slice(&settings(&[]));
    preface.extend_from_slice(&frame(
        0x1,
        0x4 | 0x1,
        1,
        &[0x00, 0x03, b'B', b'A', b'D', 0x01, b'v'],
    ));
    exchange.client(&preface);
    let path = common::http2_capture::write_capture(&[exchange]);
    let records = parse_ndjson(&run_success(&[
        "--output",
        "ndjson",
        "http2",
        common::path_text(path.path()),
    ]));
    assert_contiguous(&records);
    let names: Vec<_> = records
        .iter()
        .map(|record| record["event"].as_str().unwrap())
        .collect();
    assert!(names.contains(&"http2_issue"), "{names:?}");
    assert_eq!(
        names
            .iter()
            .filter(|name| **name == "http2_connection")
            .count(),
        1
    );
    assert_eq!(names.iter().filter(|name| **name == "complete").count(), 1);
    assert_eq!(names.last(), Some(&"complete"));
}

#[test]
fn published_http2_examples_match_the_real_cli() {
    let documents = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/documents");
    let read_document = |name: &str| {
        serde_json::from_str::<serde_json::Value>(
            &std::fs::read_to_string(documents.join(name)).expect("published example"),
        )
        .expect("published example parses")
    };
    let path = multiplexed();
    let aggregate = parse_json(&run_success(&[
        "--output",
        "json",
        "http2",
        common::path_text(&path),
    ]));
    assert_eq!(aggregate, read_document("output-http2-success.json"));
    let records = parse_ndjson(&run_success(&[
        "--output",
        "ndjson",
        "http2",
        common::path_text(&path),
    ]));
    for document in [
        "output-http2-event.json",
        "output-http2-connection-event.json",
    ] {
        let event = read_document(document);
        assert!(
            records.contains(&event),
            "published {document} must appear verbatim in the stream"
        );
    }
    assert_eq!(
        records.last(),
        Some(&read_document("output-http2-complete.json"))
    );
    let cutoff = parse_ndjson(&run_success(&[
        "--output",
        "ndjson",
        "http2",
        common::path_text(&path),
        "--stop-epoch",
        "0.008",
    ]));
    let issue = read_document("output-http2-issue-event.json");
    assert_eq!(issue["result"]["code"], "capture_end");
    assert!(
        cutoff.contains(&issue),
        "published issue event must appear verbatim under the cutoff"
    );
    let failed = run(&[
        "--output",
        "json",
        "http2",
        common::path_text(&path),
        "--max-http2-frames",
        "3",
    ]);
    assert_eq!(failed.status.code(), Some(6));
    assert_eq!(
        parse_json(&failed),
        read_document("output-http2-error.json")
    );
}

#[test]
fn schema_rejects_invalid_http2_evidence_values() {
    let path = multiplexed();
    let aggregate = parse_json(&run_success(&[
        "--output",
        "json",
        "http2",
        common::path_text(&path),
    ]));
    let validator = common::schema_validator();
    let mut case = aggregate.clone();
    case["result"]["messages"][0]["status"] = serde_json::json!("nonsense");
    assert!(validator.validate(&case).is_err());
    let mut case = aggregate.clone();
    case["result"]["frames"][0]["http2_stream_id"] = serde_json::json!(0x80000000_u32);
    assert!(validator.validate(&case).is_err());
    let mut case = aggregate.clone();
    case["result"]["messages"][0]["http2_stream_id"] = serde_json::json!(0x80000000_u32);
    assert!(validator.validate(&case).is_err());
    let mut case = aggregate.clone();
    case["result"]["messages"][0]["body_bytes"] = serde_json::json!(-1);
    assert!(validator.validate(&case).is_err());
    let mut case = aggregate.clone();
    case["result"]["messages"][0]["headers"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .for_each(|header| {
            header.as_object_mut().unwrap().remove("name_hex");
        });
    assert!(validator.validate(&case).is_err());
    let mut case = aggregate.clone();
    case["result"]["frames"][0]["header_wire_hex"] = serde_json::json!("000003fe0000000x");
    assert!(validator.validate(&case).is_err());
    let mut case = aggregate.clone();
    case["result"]["frames"][0]["header_wire_hex"] = serde_json::json!("000003fe");
    assert!(validator.validate(&case).is_err());
    for weight in [0_u64, 257] {
        let mut case = aggregate.clone();
        let frame = case["result"]["frames"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|frame| frame["control"]["type"] == "priority")
            .expect("the fixture carries a PRIORITY frame");
        frame["control"]["weight"] = serde_json::json!(weight);
        assert!(validator.validate(&case).is_err(), "weight {weight}");
    }
    for weight in [1_u64, 256] {
        let mut case = aggregate.clone();
        let frame = case["result"]["frames"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|frame| frame["control"]["type"] == "priority")
            .expect("the fixture carries a PRIORITY frame");
        frame["control"]["weight"] = serde_json::json!(weight);
        validator
            .validate(&case)
            .unwrap_or_else(|error| panic!("boundary weight {weight}: {error}"));
    }
    let mut case = aggregate.clone();
    case["result"]["connections"][0]["client_window"] = serde_json::json!(-2_147_483_649_i64);
    validator
        .validate(&case)
        .expect("negative flow-control violations fit i64");

    let mut exchange = common::http2_capture::Exchange::new(80);
    let mut preface = packetcraftr_core::protocol::application::http2::CLIENT_PREFACE.to_vec();
    preface.extend_from_slice(&common::http2_capture::settings(&[]));
    preface.extend_from_slice(&common::http2_capture::frame(
        0x1,
        0x5,
        1,
        &[0x00, 0x03, b'B', b'A', b'D', 0x01, b'v'],
    ));
    exchange.client(&preface);
    let malformed = common::http2_capture::write_capture(&[exchange]);
    let document = parse_json(&run_success(&[
        "--output",
        "json",
        "http2",
        common::path_text(malformed.path()),
    ]));
    let issues = document["result"]["issues"].as_array().unwrap();
    assert!(!issues.is_empty(), "the malformed fixture emits an issue");
    let mut case = document.clone();
    case["result"]["issues"][0]["certainty"] = serde_json::json!("nonsense");
    assert!(validator.validate(&case).is_err());
}

#[test]
fn unresolved_h2c_offer_reports_incomplete_upgrade_evidence() {
    let head: &[u8] = b"GET / HTTP/1.1\r\nHost: www.example.com\r\nConnection: upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\nHTTP2-Settings: AAEAAAAA\r\n\r\n";
    let expected_hex: String = head.iter().map(|b| format!("{b:02x}")).collect();
    let mut exchange = common::http2_capture::Exchange::new(80);
    exchange.client(head);
    let path = common::http2_capture::write_capture(&[exchange]);

    let document = parse_json(&run_success(&[
        "--output",
        "json",
        "http2",
        common::path_text(path.path()),
    ]));
    let issues = document["result"]["issues"].as_array().unwrap();
    let evidence: Vec<_> = issues
        .iter()
        .filter(|issue| issue["code"] == "incomplete_upgrade")
        .collect();
    assert_eq!(evidence.len(), 1, "{issues:?}");
    assert_eq!(evidence[0]["wire_hex"].as_str().unwrap(), expected_hex);
    assert_eq!(evidence[0]["status"], "incomplete");
    assert!(!evidence[0]["sources"].as_array().unwrap().is_empty());
    let connections = document["result"]["connections"].as_array().unwrap();
    assert_eq!(connections.len(), 1);
    assert_eq!(connections[0]["status"], "incomplete");
    assert_eq!(connections[0]["startup"], "unknown");
    let messages = document["result"]["messages"].as_array().unwrap();
    assert!(
        messages.is_empty(),
        "an unresolved offer must not invent a message: {messages:?}"
    );

    let records = parse_ndjson(&run_success(&[
        "--output",
        "ndjson",
        "http2",
        common::path_text(path.path()),
    ]));
    assert_contiguous(&records);
    let names: Vec<_> = records
        .iter()
        .map(|record| record["event"].as_str().unwrap())
        .collect();
    assert!(names.contains(&"http2_issue"), "{names:?}");
    assert_eq!(names.iter().filter(|n| **n == "complete").count(), 1);
    assert_eq!(names.last(), Some(&"complete"));
    assert!(!names.contains(&"http2_message"));

    let text = run_success(&["--output", "text", "http2", common::path_text(path.path())]);
    let stdout = String::from_utf8_lossy(&text.stdout);
    assert!(stdout.contains("incomplete_upgrade"), "{stdout}");
}

fn normalize_scope(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            map.remove("scope");
            map.remove("scopes");
            for inner in map.values_mut() {
                normalize_scope(inner);
            }
        }
        serde_json::Value::Array(items) => {
            for inner in items.iter_mut() {
                normalize_scope(inner);
            }
        }
        _ => {}
    }
}

#[test]
fn classic_pcap_reports_identical_http2_evidence() {
    let pcapng_bytes = std::fs::read(multiplexed()).expect("checked-in capture must exist");
    let mut reader =
        packetcraftr_core::capture_file::Reader::new(std::io::Cursor::new(&pcapng_bytes))
            .expect("pcapng reader");
    let mut pcap = Vec::new();
    {
        let mut writer = packetcraftr_core::capture_file::Writer::new(
            &mut pcap,
            packetcraftr_core::capture_file::Format::Pcap,
            packetcraftr_core::frame::LinkType::IPV4,
        )
        .expect("pcap writer");
        while let Some(frame) = reader.next_frame().expect("pcapng frames must read") {
            let frame = packetcraftr_core::frame::Frame::new(
                frame.timestamp.expect("fixture frames are timestamped"),
                packetcraftr_core::frame::LinkType::IPV4,
                frame.bytes().clone(),
            )
            .expect("frame rebuild");
            writer.write_frame(&frame).expect("pcap frame must write");
        }
        writer.flush().expect("pcap capture must flush");
    }
    let mut file = tempfile::NamedTempFile::new().expect("temporary pcap");
    std::io::Write::write_all(&mut file, &pcap).expect("pcap must write");
    std::io::Write::flush(&mut file).expect("pcap must flush");

    let mut pcapng = parse_json(&run_success(&[
        "--output",
        "json",
        "http2",
        &multiplexed().to_string_lossy(),
    ]));
    let mut classic = parse_json(&run_success(&[
        "--output",
        "json",
        "http2",
        &file.path().to_string_lossy(),
    ]));
    normalize_scope(&mut pcapng);
    normalize_scope(&mut classic);
    assert_eq!(
        classic, pcapng,
        "classic PCAP must carry the same HTTP/2 evidence"
    );
    let result = &pcapng["result"];
    assert_eq!(
        result["messages"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|m| m["status"] == "complete")
            .count(),
        7
    );
    assert_eq!(result["frames"].as_array().unwrap().len(), 22);
    assert!(result["issues"].as_array().unwrap().is_empty());
    for event in std::iter::once(&pcapng).flat_map(|d| d["result"]["messages"].as_array().unwrap())
    {
        for source in event["sources"].as_array().unwrap() {
            assert!(source["number"].is_u64());
            assert!(source["timestamp"].is_object());
        }
    }
}

#[test]
fn http2_epoch_bounds_filter_by_frame_time() {
    let path = multiplexed();
    let path_text = common::path_text(&path);
    let baseline = parse_json(&run_success(&["--output", "json", "http2", path_text]));
    let full = parse_json(&run_success(&[
        "--output",
        "json",
        "http2",
        path_text,
        "--start-epoch",
        "0",
        "--stop-epoch",
        "1",
    ]));
    assert_eq!(full, baseline, "a covering interval is the unfiltered run");

    let excluded = parse_json(&run_success(&[
        "--output",
        "json",
        "http2",
        path_text,
        "--start-epoch",
        "20",
    ]));
    let result = &excluded["result"];
    assert_eq!(result["connections"].as_array().unwrap().len(), 0);
    assert_eq!(result["messages"].as_array().unwrap().len(), 0);
    assert_eq!(result["frames"].as_array().unwrap().len(), 0);
    assert_eq!(result["frames_read"], baseline["result"]["frames_read"]);

    let cutoff = parse_json(&run_success(&[
        "--output",
        "json",
        "http2",
        path_text,
        "--stop-epoch",
        "0.008",
    ]));
    let result = &cutoff["result"];
    let connections = result["connections"].as_array().unwrap();
    assert_eq!(connections.len(), 1);
    assert_eq!(connections[0]["status"], "incomplete");
    let issues = result["issues"].as_array().unwrap();
    assert!(
        issues.iter().any(|issue| issue["code"] == "capture_end"),
        "the cutoff reports capture_end: {issues:?}"
    );

    let missing = tempfile::tempdir()
        .expect("temp dir")
        .path()
        .join("missing.pcapng");
    let reversed = run(&[
        "--output",
        "json",
        "http2",
        common::path_text(&missing),
        "--start-epoch",
        "2",
        "--stop-epoch",
        "1",
    ]);
    assert!(!reversed.status.success());
    assert_eq!(
        parse_json(&reversed)["error"]["code"],
        "cli.reversed_time_bounds"
    );
}
