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
fn help_succeeds_with_tool_name() {
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
fn raw_build_outputs_packet_bytes() {
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
fn dns_capture_dissects_successfully() {
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
fn dns_capture_analysis_succeeds() {
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
fn mqtt_capture_outputs_json_envelope() {
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
        trimmed.contains("\"packetcraftr.output/v19\""),
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

fn write_merge_source(
    path: &Path,
    source: usize,
    times: &[u64],
    format: packetcraftr_core::capture_file::Format,
) {
    use packetcraftr_core::capture_file::Writer;
    use packetcraftr_core::frame::{Frame, LinkType};
    use std::time::{Duration, UNIX_EPOCH};

    let mut writer = Writer::new(
        std::fs::File::create(path).unwrap(),
        format,
        LinkType::ETHERNET,
    )
    .unwrap();
    for (number, &time) in times.iter().enumerate() {
        let frame = Frame::new(
            Some(UNIX_EPOCH + Duration::from_micros(time)),
            LinkType::ETHERNET,
            vec![u8::try_from(source).unwrap(), u8::try_from(number).unwrap()],
        )
        .unwrap();
        writer.write_frame(&frame).unwrap();
    }
    writer.flush().unwrap();
}

#[test]
fn files_merge_preserves_order_and_provenance() {
    use packetcraftr_core::capture_file::{Format, MAX_MERGE_SOURCES, Reader};
    use std::time::{Duration, UNIX_EPOCH};

    let cases = [
        (
            "chronological",
            0,
            vec![
                vec![],
                vec![1, 2, 2, 7],
                vec![],
                vec![1, 2, 3],
                vec![2],
                vec![],
            ],
        ),
        ("chronological", 0, vec![vec![1, 1]; MAX_MERGE_SOURCES]),
        ("chronological", 0, vec![vec![], vec![]]),
        ("chronological", 2, vec![vec![2, 1, 2, 4, 3], vec![1, 3, 3]]),
        ("append", 0, vec![vec![], vec![3, 1, 1], vec![2, 1], vec![]]),
    ];
    for (order, window, sources) in cases {
        let dir = tempfile::tempdir().unwrap();
        let paths: Vec<_> = sources
            .iter()
            .enumerate()
            .map(|(source, times)| {
                let path = dir.path().join(format!("source-{source}"));
                let format = if source % 2 == 0 {
                    Format::Pcap
                } else {
                    Format::PcapNg
                };
                write_merge_source(&path, source, times, format);
                path
            })
            .collect();
        let destination = dir.path().join("merged.pcapng");
        let window = window.to_string();
        let args: Vec<_> = ["--output", "json", "files", "merge"]
            .into_iter()
            .chain(paths.iter().map(|path| path.to_str().unwrap()))
            .chain([
                "--write",
                destination.to_str().unwrap(),
                "--order",
                order,
                "--max-reorder-frames",
                &window,
            ])
            .collect();
        let report: serde_json::Value =
            serde_json::from_str(&assert_success(&run(&args), &args)).unwrap();
        let result = &report["result"];
        let mut expected: Vec<_> = sources
            .iter()
            .enumerate()
            .flat_map(|(source, times)| {
                times
                    .iter()
                    .enumerate()
                    .map(move |(number, &time)| (time, source, number))
            })
            .collect();
        if order == "chronological" {
            expected.sort_unstable();
        }
        let frames: Vec<_> = Reader::with_limits(
            std::fs::File::open(&destination).unwrap(),
            Default::default(),
        )
        .unwrap()
        .map(Result::unwrap)
        .collect();
        assert_eq!(frames.len(), expected.len());
        assert_eq!(result["frames"], frames.len());
        assert_eq!(
            result["captured_bytes"],
            frames
                .iter()
                .map(|frame| u64::from(frame.captured_length()))
                .sum::<u64>()
        );
        assert_eq!(
            result["source_frames"],
            serde_json::json!(sources.iter().map(Vec::len).collect::<Vec<_>>())
        );
        let interfaces = result["interfaces"].as_array().unwrap();
        assert_eq!(
            interfaces.len(),
            sources.iter().filter(|times| !times.is_empty()).count()
        );
        for (frame, (time, source, number)) in frames.iter().zip(expected) {
            assert_eq!(
                frame.timestamp,
                Some(UNIX_EPOCH + Duration::from_micros(time))
            );
            assert_eq!(
                frame.bytes().as_ref(),
                &[u8::try_from(source).unwrap(), u8::try_from(number).unwrap()]
            );
            let interface = interfaces
                .iter()
                .find(|interface| interface["output_interface"] == frame.interface.unwrap())
                .unwrap();
            assert_eq!(interface["source"], source);
            assert_eq!(interface["source_name"], paths[source].to_str().unwrap());
            assert_eq!(interface["global_interface"], 0);
        }
    }
}

#[test]
fn merge_rejects_clock_regression_before_publication() {
    use packetcraftr_core::capture_file::Format;

    for (times, window) in [(vec![2, 1], "0"), (vec![2, 3, 1], "2")] {
        let dir = tempfile::tempdir().unwrap();
        let first = dir.path().join("first.pcap");
        let second = dir.path().join("second.pcapng");
        let destination = dir.path().join("rejected.pcapng");
        write_merge_source(&first, 0, &times, Format::Pcap);
        write_merge_source(&second, 1, &[1, 4], Format::PcapNg);
        let args = [
            "--output",
            "json",
            "files",
            "merge",
            first.to_str().unwrap(),
            second.to_str().unwrap(),
            "--write",
            destination.to_str().unwrap(),
            "--max-reorder-frames",
            window,
        ];
        assert_error(&run(&args), "packet.capture_merge_order");
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
fn forwarding_limits_apply_to_both_inputs() {
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
fn http2_analysis_reports_streams_and_push() {
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
fn http2_analysis_reports_h2c_startup() {
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
fn scan_diff_reports_changes_and_provenance() {
    use serde_json::json;
    use sha2::{Digest, Sha256};

    let dir = tempfile::tempdir().unwrap();
    let before_path = dir.path().join("before.json");
    let after_path = dir.path().join("after.json");
    let before = json!({
        "schema":"packetcraftr.output/v19", "command":"scan", "mode":"aggregate", "status":"success",
        "result":{"method":"tcp_connect", "endpoints":[
            {"address":"192.0.2.1", "port":443, "inference":{"state":"closed", "supporting":[1]}},
            {"address":"192.0.2.2", "port":443, "inference":{"state":"open", "supporting":[2]}}
        ]}
    });
    let after = json!({
        "schema":"packetcraftr.output/v19", "command":"scan", "mode":"aggregate", "status":"success",
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
fn scan_diff_rejects_invalid_input() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("invalid.json");
    std::fs::write(&path, br#"{"schema":"packetcraftr.output/v19","command":"scan","mode":"aggregate","status":"failure"}"#).unwrap();
    let path = path.to_str().unwrap();
    let args = ["--output", "json", "analyze", "scan-diff", path, path];
    let output = run(&args);
    assert_eq!(output.status.code(), Some(2));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["status"], "error");
    assert_eq!(report["error"]["code"], "cli.security_input");
}

mod differential {
    use packetcraftr::differential as lib;
    use packetcraftr_cli::output::{DifferentialReport as Report, contract::Command, envelope};
    use serde_json::{Value, json};
    use std::process::Output;

    pub(super) fn campaign() -> Vec<u8> {
        let attempts = [u32::MAX, 7]
            .into_iter()
            .map(|attempt_seq| lib::AttemptEvidence {
                variant_index: 0,
                attempt_seq,
                answered: false,
                packets_sent: 1,
                payload_sha256: [0x11; 32],
                reply: None,
            })
            .collect::<Vec<_>>();
        let published = envelope::Published::<Report>::try_from(lib::Aggregate {
            valid: false,
            provisional: true,
            plan_digest: "fixture".into(),
            source_port: 40000,
            spoof_source: Some("192.0.2.1".parse().unwrap()),
            rows: lib::rows_for(&attempts),
            attempts,
            diagnostics: Vec::new(),
            stats: Default::default(),
        })
        .unwrap();
        serde_json::to_vec(&envelope::Envelope::published(
            Command::Differential,
            published,
        ))
        .unwrap()
    }

    fn reception(attempt_seq: u32) -> Vec<u8> {
        serde_json::to_vec(&lib::ReceptionRecord {
            variant_index: 0,
            attempt_seq,
            source: "192.0.2.1:40000".parse().unwrap(),
            payload_sha256: lib::hex(&[0x11; 32]),
        })
        .unwrap()
    }

    fn join(campaign: &[u8], log: &[u8]) -> Output {
        let dir = tempfile::tempdir().unwrap();
        let campaign_path = dir.path().join("campaign.json");
        let log_path = dir.path().join("receptions.jsonl");
        std::fs::write(&campaign_path, campaign).unwrap();
        std::fs::write(&log_path, log).unwrap();
        super::run(&[
            "--output",
            "json",
            "network",
            "differential-join",
            campaign_path.to_str().unwrap(),
            "--responder-log",
            log_path.to_str().unwrap(),
        ])
    }

    fn result(output: &Output) -> Value {
        serde_json::from_str(&super::assert_success(
            output,
            &["network", "differential-join"],
        ))
        .unwrap()
    }

    #[test]
    fn differential_join_preserves_existing_answers() {
        let first = join(&campaign(), &reception(u32::MAX));
        let report = result(&first);
        assert_eq!(report["result"]["rows"][0]["verdict"], "flaky");
        assert_eq!(report["result"]["attempts"][0]["attempt_seq"], u32::MAX);
        assert_eq!(report["result"]["attempts"][0]["answered"], true);
        assert_eq!(report["result"]["attempts"][1]["answered"], false);
        let second = join(
            &first.stdout,
            &[b"\n\n", reception(7).as_slice(), b"\n"].concat(),
        );
        let report = result(&second);
        assert_eq!(report["result"]["valid"], true);
        assert_eq!(report["result"]["provisional"], false);
        assert_eq!(report["result"]["rows"][0]["verdict"], "accepted");
        assert_eq!(report["result"]["rows"][0]["answered"], 2);
        assert_eq!(
            result(&join(&second.stdout, b""))["result"],
            report["result"]
        );
    }

    #[test]
    fn differential_join_rejects_reception_aliasing() {
        let mut value: Value = serde_json::from_slice(&campaign()).unwrap();
        value["result"]["attempts"][0]["attempt_seq"] = json!(u64::from(u32::MAX) + 1);
        let output = join(&serde_json::to_vec(&value).unwrap(), &reception(u32::MAX));
        super::assert_error(&output, "cli.error");
    }

    #[test]
    fn differential_join_validates_campaign_and_source() {
        let original: Value = serde_json::from_slice(&campaign()).unwrap();
        for (field, replacement) in [
            (
                "schema",
                json!(packetcraftr_core::security::AMBIGUOUS_OUTPUT_SCHEMA),
            ),
            ("schema", json!("unsupported-schema")),
            ("command", json!("scan")),
            ("mode", json!("stream")),
            ("status", json!("error")),
        ] {
            let mut value = original.clone();
            value[field] = replacement;
            let output = join(&serde_json::to_vec(&value).unwrap(), b"");
            super::assert_error(&output, "cli.error");
            if value[field] == packetcraftr_core::security::AMBIGUOUS_OUTPUT_SCHEMA {
                assert!(super::stdout(&output).contains("regenerate"));
            }
        }
        for field in ["schema", "command", "mode", "status"] {
            let mut value = original.clone();
            value.as_object_mut().unwrap().remove(field);
            super::assert_error(
                &join(&serde_json::to_vec(&value).unwrap(), b""),
                "cli.error",
            );
        }
        for field in ["source_port", "spoof_source", "attempts"] {
            let mut value = original.clone();
            value["result"].as_object_mut().unwrap().remove(field);
            super::assert_error(
                &join(&serde_json::to_vec(&value).unwrap(), b""),
                "cli.error",
            );
        }
        let mut unspoofed = original;
        unspoofed["result"]["spoof_source"] = Value::Null;
        assert_eq!(
            result(&join(&serde_json::to_vec(&unspoofed).unwrap(), b""))["result"]["spoof_source"],
            Value::Null
        );
    }

    #[test]
    fn differential_join_bounds_inputs_before_parsing() {
        let mut oversized = campaign();
        oversized.resize(16 * 1024 * 1024 + 1, b' ');
        for output in [join(&oversized, b""), join(&campaign(), &oversized)] {
            super::assert_error(&output, "cli.error");
            assert!(super::stdout(&output).contains("byte limit"));
        }
    }
}

#[cfg(unix)]
mod stalled_inputs {
    use std::io::{BufRead, BufReader, Write};
    use std::process::{Child, ChildStdin, Command, Output, Stdio};
    use std::time::{Duration, Instant};

    const DEADLINE_MS: &str = "1500";
    const EXIT_WITHIN: Duration = Duration::from_secs(10);

    fn spawn(args: &[&str], stdin: Stdio) -> Child {
        Command::new(env!("CARGO_BIN_EXE_packetcraftr"))
            .args(args)
            .stdin(stdin)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap_or_else(|error| panic!("failed to spawn packetcraftr {args:?}: {error}"))
    }

    fn spawn_with_open_stdin(args: &[&str]) -> (Child, ChildStdin) {
        let mut child = spawn(args, Stdio::piped());
        let stdin = child.stdin.take().expect("piped stdin");
        (child, stdin)
    }

    fn kill_after_timeout(mut child: Child, args: &[&str], waiting_for: &str) -> ! {
        let _ = child.kill();
        let output = child.wait_with_output().expect("reap killed child");
        panic!(
            "packetcraftr {args:?} was still running after {EXIT_WITHIN:?} waiting for {waiting_for}; killed it\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn wait_bounded(mut child: Child, args: &[&str]) -> Output {
        let started = Instant::now();
        while child.try_wait().expect("poll child status").is_none() {
            if started.elapsed() > EXIT_WITHIN {
                kill_after_timeout(child, args, "exit");
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        child.wait_with_output().expect("collect child output")
    }

    fn assert_interrupted(output: &Output, exit_code: i32, error_code: &str, message: &str) {
        assert_eq!(
            output.status.code(),
            Some(exit_code),
            "stdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        super::assert_error(output, error_code);
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert!(
            report["error"]["message"]
                .as_str()
                .is_some_and(|text| text.contains(message)),
            "{report}"
        );
    }

    fn assert_deadline(output: &Output) {
        assert_interrupted(output, 6, "policy.duration_limit", "budget");
    }

    #[test]
    fn empty_capture_stdin_reaches_deadline() {
        let args = [
            "--output",
            "json",
            "analyze",
            "stats",
            "-",
            "--max-duration-ms",
            DEADLINE_MS,
        ];
        let (child, stdin) = spawn_with_open_stdin(&args);
        let output = wait_bounded(child, &args);
        drop(stdin);
        assert_deadline(&output);
    }

    #[test]
    fn empty_document_stdin_reaches_deadline() {
        let capture = super::capture_path("dns-response.pcap");
        let capture = capture.to_str().unwrap();
        let args = [
            "--output",
            "json",
            "analyze",
            "hunt",
            capture,
            "--indicators",
            "-",
            "--max-duration-ms",
            DEADLINE_MS,
        ];
        let (child, stdin) = spawn_with_open_stdin(&args);
        let output = wait_bounded(child, &args);
        drop(stdin);
        assert_deadline(&output);
    }

    #[test]
    fn partial_capture_header_reaches_deadline() {
        let args = [
            "--output",
            "json",
            "analyze",
            "stats",
            "-",
            "--max-duration-ms",
            DEADLINE_MS,
        ];
        let (child, mut stdin) = spawn_with_open_stdin(&args);
        stdin
            .write_all(&[0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x04, 0x00, 0, 0])
            .expect("write partial PCAP header");
        stdin.flush().expect("flush partial header");
        let output = wait_bounded(child, &args);
        drop(stdin);
        assert_deadline(&output);
    }

    #[test]
    fn stalled_capture_record_reaches_deadline() {
        let args = [
            "--output",
            "json",
            "analyze",
            "stats",
            "-",
            "--max-duration-ms",
            DEADLINE_MS,
        ];
        let (child, mut stdin) = spawn_with_open_stdin(&args);
        let header = [
            [0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x04, 0x00],
            [0; 8],
            [0xff, 0xff, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00],
        ]
        .concat();
        stdin
            .write_all(&[header.as_slice(), &[0; 4]].concat())
            .expect("write PCAP header and a partial record");
        stdin.flush().expect("flush capture prefix");
        let output = wait_bounded(child, &args);
        drop(stdin);
        assert_eq!(output.status.code(), Some(6));
        super::assert_error(&output, "policy.duration_limit");
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(
            report["error"]["causes"][0]
                .as_str()
                .and_then(|cause| cause.split(':').next()),
            Some("capture operation exceeded its duration budget"),
            "{report}"
        );
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn fifo_without_writer_honors_the_deadline() {
        let directory = tempfile::tempdir().unwrap();
        let fifo = directory.path().join("capture.fifo");
        let status = Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .expect("run mkfifo");
        assert!(status.success(), "mkfifo failed: {status:?}");
        let fifo = fifo.to_str().unwrap();
        let args = [
            "--output",
            "json",
            "analyze",
            "stats",
            fifo,
            "--max-duration-ms",
            DEADLINE_MS,
        ];
        let output = wait_bounded(spawn(&args, Stdio::null()), &args);
        assert_deadline(&output);
    }

    fn sigint_handler_installed(pid: u32) -> bool {
        const SIGINT: u32 = 2;
        std::fs::read_to_string(format!("/proc/{pid}/status"))
            .ok()
            .and_then(|status| {
                status
                    .lines()
                    .find_map(|line| line.strip_prefix("SigCgt:"))
                    .and_then(|mask| u64::from_str_radix(mask.trim(), 16).ok())
            })
            .is_some_and(|mask| mask & (1 << (SIGINT - 1)) != 0)
    }

    fn open_fds() -> usize {
        std::fs::read_dir("/proc/self/fd")
            .expect("list /proc/self/fd")
            .count()
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn differential_join_cancels_stalled_inputs() {
        let directory = tempfile::tempdir().unwrap();
        let campaign = directory.path().join("campaign.json");
        let log = directory.path().join("receptions.jsonl");
        std::fs::write(&campaign, super::differential::campaign()).unwrap();
        std::fs::write(&log, b"").unwrap();
        let fifo = directory.path().join("input.fifo");
        assert!(
            Command::new("mkfifo")
                .arg(&fifo)
                .status()
                .unwrap()
                .success()
        );
        let _writer = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&fifo)
            .unwrap();
        for (campaign, log) in [(&fifo, &log), (&campaign, &fifo)] {
            let args = [
                "--output",
                "json",
                "network",
                "differential-join",
                campaign.to_str().unwrap(),
                "--responder-log",
                log.to_str().unwrap(),
            ];
            let mut child = spawn(&args, Stdio::null());
            let started = Instant::now();
            loop {
                assert!(
                    child.try_wait().unwrap().is_none(),
                    "command exited before reading input"
                );
                let reading = std::fs::read_dir(format!("/proc/{}/fd", child.id()))
                    .unwrap()
                    .filter_map(Result::ok)
                    .filter_map(|entry| std::fs::read_link(entry.path()).ok())
                    .any(|path| path == fifo);
                if reading && sigint_handler_installed(child.id()) {
                    break;
                }
                if started.elapsed() > EXIT_WITHIN {
                    kill_after_timeout(child, &args, "the stalled input");
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            assert!(
                Command::new("kill")
                    .args(["-INT", &child.id().to_string()])
                    .status()
                    .unwrap()
                    .success()
            );
            assert_interrupted(
                &wait_bounded(child, &args),
                130,
                "io.cancelled",
                "cancelled",
            );
        }
    }

    #[test]
    fn piped_capture_publishes_each_frame_before_its_input_ends() {
        let capture =
            std::fs::read(super::capture_path("dns-response.pcap")).expect("read capture");
        for format in ["ndjson", "text"] {
            let args = ["--output", format, "files", "read", "-"];
            let (mut child, mut stdin) = spawn_with_open_stdin(&args);
            let stdout = child.stdout.take().expect("piped stdout");
            let (lines, first) = std::sync::mpsc::channel();
            let reader = std::thread::spawn(move || {
                let mut stdout = BufReader::new(stdout);
                let mut line = String::new();
                stdout.read_line(&mut line).expect("read first record");
                lines.send(line).expect("receive first record");
                std::io::copy(&mut stdout, &mut std::io::sink()).expect("drain stdout");
            });
            stdin.write_all(&capture).expect("write capture");
            stdin.flush().expect("flush capture");
            let line = first
                .recv_timeout(EXIT_WITHIN)
                .expect("a frame record while stdin stays open");
            assert!(!line.is_empty(), "{format}");
            drop(stdin);
            let output = wait_bounded(child, &args);
            reader.join().expect("join stdout reader");
            assert!(output.status.success(), "{output:?}");
        }
    }

    /// Enough frames to overflow an output batch, and optionally a record cut short.
    fn synthetic_pcap(truncated: bool) -> Vec<u8> {
        let frame = [0x45_u8; 20];
        let header = [
            0xa1b2_c3d4_u32.to_le_bytes().as_slice(),
            &2_u16.to_le_bytes(),
            &4_u16.to_le_bytes(),
            &[0; 8],
            &65_535_u32.to_le_bytes(),
            &228_u32.to_le_bytes(),
        ]
        .concat();
        let record = [
            [0_u8; 8].as_slice(),
            &20_u32.to_le_bytes(),
            &20_u32.to_le_bytes(),
            &frame,
        ]
        .concat();
        let frames = record.repeat(2000);
        let tail: &[u8] = if truncated { &record[..30] } else { &[] };
        [header.as_slice(), &frames, tail].concat()
    }

    fn read_piped(args: &[&str], capture: Vec<u8>) -> Output {
        let (child, mut stdin) = spawn_with_open_stdin(args);
        let writer = std::thread::spawn(move || {
            stdin.write_all(&capture).expect("write capture");
        });
        let output = child.wait_with_output().expect("wait for child");
        writer.join().expect("join stdin writer");
        output
    }

    /// A datagram socket keeps write boundaries, so each received message is one write.
    #[cfg(target_os = "linux")]
    fn count_stdout_writes(args: &[&str]) -> usize {
        use std::os::unix::net::UnixDatagram;
        let (received, sent) = UnixDatagram::pair().expect("create socket pair");
        received.set_nonblocking(true).expect("set nonblocking");
        let mut child = Command::new(env!("CARGO_BIN_EXE_packetcraftr"))
            .args(args)
            .stdin(Stdio::null())
            .stdout(std::os::fd::OwnedFd::from(sent))
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn packetcraftr");
        let started = Instant::now();
        let mut message = vec![0_u8; 1 << 20];
        let mut writes = 0;
        loop {
            match received.recv(&mut message) {
                Ok(_) => writes += 1,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    if let Some(status) = child.try_wait().expect("poll child status") {
                        assert!(status.success(), "{args:?}: {status:?}");
                        return writes;
                    }
                    assert!(started.elapsed() < EXIT_WITHIN, "{args:?} did not exit");
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(error) => panic!("receive stdout: {error}"),
            }
        }
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn regular_file_input_coalesces_stdout_writes() {
        let file = tempfile::NamedTempFile::new().expect("create capture");
        std::fs::write(file.path(), synthetic_pcap(false)).expect("write capture");
        let path = file.path().to_string_lossy();
        for format in ["text", "ndjson"] {
            let writes = count_stdout_writes(&["--output", format, "files", "read", path.as_ref()]);
            assert!((1..200).contains(&writes), "{format} took {writes} writes");
        }
    }

    #[test]
    fn regular_file_output_matches_piped_output_through_success_and_failure() {
        for truncated in [false, true] {
            let capture = synthetic_pcap(truncated);
            let file = tempfile::NamedTempFile::new().expect("create capture");
            std::fs::write(file.path(), &capture).expect("write capture");
            let path = file.path().to_string_lossy();
            for format in ["text", "ndjson"] {
                let piped =
                    read_piped(&["--output", format, "files", "read", "-"], capture.clone());
                let regular = super::run(&["--output", format, "files", "read", path.as_ref()]);
                assert_eq!(
                    String::from_utf8_lossy(&regular.stdout),
                    String::from_utf8_lossy(&piped.stdout),
                    "{format} truncated={truncated}"
                );
                assert_eq!(
                    regular.status, piped.status,
                    "{format} truncated={truncated}"
                );
                assert_eq!(regular.status.success(), !truncated, "{format}");
                assert!(piped.stdout.len() > 16 * 1024, "{format}");
            }
        }
    }

    #[test]
    #[cfg_attr(
        not(target_os = "linux"),
        ignore = "needs /proc/<pid>/status SigCgt to know when the child's SIGINT handler is installed"
    )]
    fn first_sigint_cancels_a_stalled_stdin_capture_gracefully() {
        let args = ["--output", "ndjson", "files", "read", "-"];
        let fds_before = open_fds();
        for _ in 0..5 {
            let (mut child, stdin) = spawn_with_open_stdin(&args);
            let started = Instant::now();
            while !sigint_handler_installed(child.id()) {
                assert!(
                    child.try_wait().expect("poll child status").is_none(),
                    "packetcraftr {args:?} exited before installing its SIGINT handler"
                );
                if started.elapsed() > EXIT_WITHIN {
                    kill_after_timeout(child, &args, "its SIGINT handler");
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            let status = Command::new("kill")
                .args(["-INT", &child.id().to_string()])
                .status()
                .expect("run kill");
            assert!(status.success(), "kill -INT failed: {status:?}");
            let output = wait_bounded(child, &args);
            drop(stdin);
            assert_interrupted(&output, 130, "io.cancelled", "cancelled");
        }
        let settled = Instant::now();
        while open_fds() > fds_before {
            assert!(
                settled.elapsed() < EXIT_WITHIN,
                "test process holds {} descriptors, {fds_before} before the children ran",
                open_fds()
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}
