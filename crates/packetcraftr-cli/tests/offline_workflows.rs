// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::UNIX_EPOCH;

use packetcraftr::{
    analysis::pcap::{Format as CaptureFormat, Writer},
    core::frame::{Frame, LinkType},
};
use serde_json::Value;

#[path = "support/capture.rs"]
mod capture_support;
mod support;

use capture_support::append_truncated_record;
use support::{assert_contiguous, parse_json, parse_ndjson, run, run_success, schema_validator};

const UDP_CLIENT: &str = "450000210000000040118e95c0000201c633640230390009000d9f8868656c6c6f";
const UDP_SERVER: &str = "450000210000000040118e95c6336402c000020100093039000d957e776f726c64";
const TCP_CLIENT: &str =
    "4500002b0000000040068e96c0000201c63364023039005000000001000000005002ffffb7b80000676574";
const TCP_SERVER: &str =
    "450000280000000040068e99c6336402c0000201005030390000000a000000045012100083040000";
const TCP_DATA: &str =
    "4500002b0000000040068e96c0000201c633640230390050000000040000000b50181000be970000616263";

fn run_with_stdin(arguments: &[&str], input: &[u8]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_packetcraftr"))
        .args(arguments)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("CLI process must start");
    child
        .stdin
        .take()
        .expect("stdin must be piped")
        .write_all(input)
        .expect("stdin must accept the frame");
    child.wait_with_output().expect("CLI process must finish")
}

fn decode_hex(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let pair = std::str::from_utf8(pair).expect("fixture hex must be UTF-8");
            u8::from_str_radix(pair, 16).expect("fixture hex must be valid")
        })
        .collect()
}

fn parse_single_json(output: &Output) -> Value {
    assert!(!output.stdout.is_empty(), "JSON output must not be empty");
    assert!(
        output.stdout.ends_with(b"\n"),
        "JSON output must end with a newline"
    );
    let mut documents = serde_json::Deserializer::from_slice(&output.stdout).into_iter::<Value>();
    let value = documents
        .next()
        .expect("JSON output must contain one document")
        .expect("JSON output must parse");
    assert!(
        documents.next().is_none(),
        "JSON output must contain one document"
    );
    value
}

fn assert_matches_published_schema(value: &Value) {
    schema_validator()
        .validate(value)
        .expect("output document must validate against the published schema");
}

fn write_capture() -> tempfile::NamedTempFile {
    write_capture_frames(&[UDP_CLIENT, UDP_SERVER, TCP_CLIENT, TCP_SERVER, TCP_DATA])
}

fn write_capture_frames(frames: &[&str]) -> tempfile::NamedTempFile {
    let mut file = tempfile::NamedTempFile::new().expect("temporary capture must open");
    file.write_all(&[
        0xd4, 0xc3, 0xb2, 0xa1, // little-endian microsecond PCAP
        2, 0, 4, 0, // version 2.4
        0, 0, 0, 0, 0, 0, 0, 0, // timezone and timestamp accuracy
        0xff, 0xff, 0, 0, // snap length
        228, 0, 0, 0, // DLT_IPV4
    ])
    .expect("global header must write");

    for (index, bytes) in frames.iter().copied().map(decode_hex).enumerate() {
        let seconds = u32::try_from(index + 1).expect("fixture index fits u32");
        let length = u32::try_from(bytes.len()).expect("fixture frame fits u32");
        file.write_all(&seconds.to_le_bytes())
            .expect("timestamp seconds must write");
        file.write_all(&250_000_u32.to_le_bytes())
            .expect("timestamp fraction must write");
        file.write_all(&length.to_le_bytes())
            .expect("captured length must write");
        file.write_all(&length.to_le_bytes())
            .expect("original length must write");
        file.write_all(&bytes).expect("frame bytes must write");
    }
    file.flush().expect("capture must flush");
    file
}

fn write_capture_with_later_missing_timestamp() -> tempfile::NamedTempFile {
    let mut file = tempfile::NamedTempFile::new().expect("temporary capture must open");
    {
        let mut writer = Writer::new(&mut file, CaptureFormat::PcapNg, LinkType::IPV4)
            .expect("PCAPNG writer must initialize");
        let frame = Frame::new(UNIX_EPOCH, LinkType::IPV4, decode_hex(UDP_CLIENT))
            .expect("timestamped fixture frame must be valid");
        writer
            .write_frame(&frame)
            .expect("timestamped fixture frame must write");
        writer.flush().expect("PCAPNG prefix must flush");
    }
    let bytes = decode_hex(UDP_SERVER);
    let padded_length = bytes.len().next_multiple_of(4);
    let block_length = u32::try_from(16 + padded_length).expect("fixture block length fits");
    let original_length = u32::try_from(bytes.len()).expect("fixture frame length fits");
    file.write_all(&3_u32.to_le_bytes())
        .expect("simple packet type must write");
    file.write_all(&block_length.to_le_bytes())
        .expect("simple packet length must write");
    file.write_all(&original_length.to_le_bytes())
        .expect("simple packet original length must write");
    file.write_all(&bytes)
        .expect("simple packet payload must write");
    file.write_all(&vec![0; padded_length - bytes.len()])
        .expect("simple packet padding must write");
    file.write_all(&block_length.to_le_bytes())
        .expect("simple packet trailer must write");
    file.flush().expect("capture must flush");
    file
}

fn write_truncated_capture() -> tempfile::NamedTempFile {
    let mut file = write_capture();
    append_truncated_record(&mut file);
    file
}

fn path_text(path: &Path) -> &str {
    path.to_str().expect("temporary path must be UTF-8")
}

#[test]
fn stats_exercises_every_table_and_filtering_mode() {
    let capture = write_capture();
    let path = path_text(capture.path());

    for table in ["conversations", "endpoints", "protocols", "ports", "io"] {
        let output = run_success(&[
            "--output",
            "json",
            "stats",
            path,
            "--table",
            table,
            "--interval-ms",
            "500",
        ]);
        let value = parse_json(&output);
        assert_eq!(value["command"], "stats");
        assert_eq!(value["result"]["table"], table);
        assert_eq!(value["result"]["frames_read"], 5);
        assert_eq!(value["result"]["frames_matched"], 5);
    }

    let filtered = run_success(&[
        "--output",
        "json",
        "stats",
        path,
        "--table",
        "ports",
        "--filter",
        "udp && ip.src == 192.0.2.1",
    ]);
    let value = parse_json(&filtered);
    assert_eq!(value["result"]["frames_read"], 5);
    assert_eq!(value["result"]["frames_matched"], 1);

    for table in ["conversations", "endpoints", "protocols", "ports", "io"] {
        let output = run_success(&["stats", path, "--table", table, "--interval-ms", "500"]);
        assert!(String::from_utf8_lossy(&output.stdout).contains("matched 5 of 5"));
    }
}

#[test]
fn follow_handles_udp_directions_and_all_output_encodings() {
    let capture = write_capture();
    let path = path_text(capture.path());

    let aggregate = run(&["--output", "json", "follow", path, "--stream", "udp:0"]);
    assert!(aggregate.status.success(), "{:?}", aggregate.stderr);
    let value = parse_json(&aggregate);
    assert_eq!(value["result"]["client_bytes"], 5);
    assert_eq!(value["result"]["server_bytes"], 5);
    assert_eq!(value["result"]["chunks"].as_array().map(Vec::len), Some(2));

    let streamed = run(&["--output", "ndjson", "follow", path, "--stream", "udp:0"]);
    assert!(streamed.status.success(), "{:?}", streamed.stderr);
    let records = parse_ndjson(&streamed);
    assert_contiguous(&records);
    assert_eq!(records.len(), 3);
    assert_eq!(records[2]["status"], "success");

    let raw_client = run(&[
        "--output",
        "raw",
        "follow",
        path,
        "--stream",
        "udp:0",
        "--direction",
        "client",
    ]);
    assert!(raw_client.status.success(), "{:?}", raw_client.stderr);
    assert_eq!(raw_client.stdout, b"hello");

    let raw_server = run(&[
        "--output",
        "raw",
        "follow",
        path,
        "--stream",
        "udp:0",
        "--direction",
        "server",
    ]);
    assert!(raw_server.status.success(), "{:?}", raw_server.stderr);
    assert_eq!(raw_server.stdout, b"world");

    for format in ["text", "hex"] {
        let output = run(&["--output", format, "follow", path, "--stream", "udp:0"]);
        assert!(output.status.success(), "{format}: {:?}", output.stderr);
        assert!(!output.stdout.is_empty());
    }

    let rejected = run(&["--output", "raw", "follow", path, "--stream", "udp:0"]);
    assert_eq!(rejected.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("choose --direction"));

    for stream in ["sctp:0", "udp:nope", "udp"] {
        let rejected = run(&["follow", path, "--stream", stream]);
        assert_eq!(rejected.status.code(), Some(2));
    }
}

#[test]
fn expert_reports_tcp_state_in_aggregate_stream_and_text_modes() {
    let capture = write_capture();
    let path = path_text(capture.path());

    for format in ["json", "ndjson", "text"] {
        let output = run(&["--output", format, "expert", path, "--filter", "tcp"]);
        assert!(output.status.success(), "{format}: {:?}", output.stderr);
        assert!(!output.stdout.is_empty());
        if format == "ndjson" {
            let records = parse_ndjson(&output);
            assert_contiguous(&records);
            assert_eq!(
                records.last().and_then(|record| record["status"].as_str()),
                Some("success")
            );
        }
    }

    let selected = run(&[
        "--output",
        "json",
        "expert",
        path,
        "--min-severity",
        "error",
        "--code",
        "tcp.reset",
    ]);
    assert!(selected.status.success(), "{:?}", selected.stderr);
    let value = parse_json(&selected);
    assert_eq!(value["result"]["frames_read"], 5);
    assert_eq!(
        value["result"]["findings"].as_array().map(Vec::len),
        Some(0)
    );
}

#[test]
fn follow_and_expert_stream_failures_terminate_at_the_next_position() {
    let capture = write_truncated_capture();
    let path = path_text(capture.path());
    let commands = [
        vec!["follow", path, "--stream", "udp:0"],
        vec!["expert", path],
    ];

    for command in commands {
        let arguments = ["--output", "ndjson"]
            .into_iter()
            .chain(command.iter().copied())
            .collect::<Vec<_>>();
        let output = run(&arguments);
        assert!(!output.status.success(), "{command:?}");
        let records = parse_ndjson(&output);
        assert!(
            records.len() > 1,
            "{command:?} must preserve at least one progressive record"
        );
        assert_contiguous(&records);
        assert!(
            records[..records.len() - 1]
                .iter()
                .all(|record| record["status"] == "success")
        );
        assert_eq!(
            records.last().and_then(|record| record["status"].as_str()),
            Some("error")
        );
        assert_eq!(
            records
                .iter()
                .filter(|record| record["status"] == "error")
                .count(),
            1,
            "{command:?}"
        );
    }
}

#[test]
fn read_rewrites_same_format_and_rejects_lossy_capture_output() {
    let capture = write_capture();
    let path = path_text(capture.path());

    let dissected = run(&[
        "--output",
        "ndjson",
        "read",
        path,
        "--dissect",
        "--filter",
        "udp",
    ]);
    assert!(dissected.status.success(), "{:?}", dissected.stderr);
    let records: Vec<Value> = String::from_utf8(dissected.stdout)
        .expect("NDJSON must be UTF-8")
        .lines()
        .map(|line| serde_json::from_str(line).expect("record must parse"))
        .collect();
    assert_eq!(records.len(), 3);
    assert!(
        records[..2]
            .iter()
            .all(|record| record["result"]["decoded"].is_object())
    );
    assert_eq!(records[2]["result"]["event"], "complete");

    for format in ["text", "hex"] {
        let output = run(&["--output", format, "read", path, "--max-frames", "5"]);
        assert!(output.status.success(), "{format}: {:?}", output.stderr);
        assert!(!output.stdout.is_empty());
    }

    let pcap = run(&["--output", "pcap", "read", path]);
    assert!(pcap.status.success(), "{:?}", pcap.stderr);
    assert_eq!(
        pcap.stdout,
        std::fs::read(capture.path()).expect("capture reads")
    );

    let pcapng = run(&["--output", "pcapng", "read", path]);
    assert!(!pcapng.status.success());
    assert!(
        String::from_utf8_lossy(&pcapng.stderr).contains("without normalization"),
        "{:?}",
        pcapng.stderr
    );

    let filtered = run(&["--output", "pcap", "read", path, "--filter", "udp"]);
    assert!(!filtered.status.success());
    assert!(
        String::from_utf8_lossy(&filtered.stderr).contains("cannot filter records"),
        "{:?}",
        filtered.stderr
    );
}

#[test]
fn read_ndjson_preserves_source_identity_and_always_completes() {
    let capture = write_capture_frames(&[UDP_CLIENT, UDP_SERVER, TCP_CLIENT]);
    let path = path_text(capture.path());
    let output = run_success(&["--output", "ndjson", "read", path]);
    let records = parse_ndjson(&output);
    assert_contiguous(&records);
    assert_eq!(records.len(), 4);
    for (index, record) in records[..3].iter().enumerate() {
        assert_eq!(record["result"]["event"], "frame");
        assert_eq!(
            record["result"]["source_frame"],
            u64::try_from(index + 1).expect("fixture index fits")
        );
        assert_matches_published_schema(record);
    }
    let complete = &records[3];
    assert_eq!(complete["result"]["event"], "complete");
    assert_eq!(complete["result"]["frames_read"], 3);
    assert_eq!(complete["result"]["frames_matched"], 3);
    assert_eq!(complete["result"]["captured_bytes_read"], 109);
    assert_matches_published_schema(complete);

    let filtered = run_success(&[
        "--output",
        "ndjson",
        "read",
        path,
        "--filter",
        "frame.number == 3",
    ]);
    let records = parse_ndjson(&filtered);
    assert_contiguous(&records);
    assert_eq!(records.len(), 2);
    assert_eq!(records[0]["sequence"], 0);
    assert_eq!(records[0]["result"]["source_frame"], 3);
    assert_eq!(records[1]["sequence"], 1);
    assert_eq!(records[1]["result"]["frames_read"], 3);
    assert_eq!(records[1]["result"]["frames_matched"], 1);
    for record in &records {
        assert_matches_published_schema(record);
    }

    let text = run_success(&["read", path, "--filter", "frame.number == 3"]);
    assert!(String::from_utf8_lossy(&text.stdout).starts_with("3: "));
}

#[test]
fn read_ndjson_completes_empty_and_fully_filtered_inputs_at_zero() {
    let cases = [
        (write_capture_frames(&[]), None, 0, 0),
        (
            write_capture_frames(&[UDP_CLIENT, UDP_SERVER, TCP_CLIENT]),
            Some("frame.number == 4"),
            3,
            109,
        ),
    ];
    for (capture, filter, frames_read, captured_bytes_read) in cases {
        let path = path_text(capture.path());
        let mut arguments = vec!["--output", "ndjson", "read", path];
        if let Some(filter) = filter {
            arguments.extend(["--filter", filter]);
        }
        let output = run_success(&arguments);
        let records = parse_ndjson(&output);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["sequence"], 0);
        assert_eq!(records[0]["result"]["event"], "complete");
        assert_eq!(records[0]["result"]["frames_read"], frames_read);
        assert_eq!(records[0]["result"]["frames_matched"], 0);
        assert_eq!(
            records[0]["result"]["captured_bytes_read"],
            captured_bytes_read
        );
        assert_matches_published_schema(&records[0]);
    }
}

#[test]
fn read_limits_account_for_filtered_source_input() {
    let capture = write_capture_frames(&[UDP_CLIENT, UDP_SERVER, TCP_CLIENT]);
    let path = path_text(capture.path());
    let cases = [
        vec![
            "--output",
            "ndjson",
            "read",
            path,
            "--filter",
            "frame.number == 3",
            "--max-frames",
            "2",
        ],
        vec![
            "--output",
            "ndjson",
            "read",
            path,
            "--filter",
            "frame.number == 3",
            "--max-bytes",
            "33",
        ],
    ];
    for arguments in cases {
        let output = run(&arguments);
        assert!(!output.status.success());
        let records = parse_ndjson(&output);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["sequence"], 0);
        assert_eq!(records[0]["status"], "error");
        assert!(
            records
                .iter()
                .all(|record| record["result"]["event"] != "complete")
        );
        assert_matches_published_schema(&records[0]);
    }
}

#[test]
fn read_missing_filter_timestamp_uses_source_identity_and_next_envelope_position() {
    let capture = write_capture_with_later_missing_timestamp();
    let output = run(&[
        "--output",
        "ndjson",
        "read",
        path_text(capture.path()),
        "--filter",
        "frame.time_epoch >= 0",
    ]);
    assert!(!output.status.success());
    let records = parse_ndjson(&output);
    assert_contiguous(&records);
    assert_eq!(records.len(), 2);
    assert_eq!(records[0]["result"]["source_frame"], 1);
    assert_eq!(records[1]["sequence"], 1);
    assert_eq!(records[1]["status"], "error");
    assert!(
        records[1]["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("frame 2"))
    );
    assert!(
        records
            .iter()
            .all(|record| record["result"]["event"] != "complete")
    );
    for record in &records {
        assert_matches_published_schema(record);
    }
}

#[test]
fn packet_documents_stdin_and_file_inputs_cover_offline_input_paths() {
    let documents = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/documents");
    for document in ["packet-ipv4-udp.json", "packet-raw.yaml"] {
        let path = documents.join(document);
        let output = run(&[
            "--output",
            "hex",
            "build",
            "--packet-file",
            path_text(&path),
        ]);
        assert!(output.status.success(), "{document}: {:?}", output.stderr);
        assert!(!output.stdout.is_empty());
    }

    let frame = decode_hex(UDP_CLIENT);
    let decoded = run_with_stdin(
        &["--output", "json", "dissect", "--link-type", "228"],
        &frame,
    );
    assert!(decoded.status.success(), "{:?}", decoded.stderr);
    let decoded_value = parse_single_json(&decoded);
    assert_matches_published_schema(&decoded_value);
    assert_eq!(decoded_value["result"]["matched"], true);
    assert_eq!(
        decoded_value["result"]["dissection"]["bytes_hex"],
        UDP_CLIENT
    );

    let filtered = run_with_stdin(
        &[
            "--output",
            "json",
            "dissect",
            "--link-type",
            "228",
            "--filter",
            "tcp",
        ],
        &frame,
    );
    assert!(filtered.status.success(), "{:?}", filtered.stderr);
    let value = parse_single_json(&filtered);
    assert_matches_published_schema(&value);
    assert_eq!(value["result"]["matched"], false);
    assert!(value["result"]["dissection"].is_null());

    let matched = run_with_stdin(
        &[
            "--output",
            "json",
            "dissect",
            "--link-type",
            "228",
            "--filter",
            "udp",
        ],
        &frame,
    );
    assert!(matched.status.success(), "{:?}", matched.stderr);
    let matched_value = parse_single_json(&matched);
    assert_matches_published_schema(&matched_value);
    assert_eq!(matched_value["result"]["matched"], true);
    assert!(matched_value["result"]["dissection"].is_object());

    let malformed = run(&["--output", "json", "dissect", "--hex", "not-hex"]);
    assert_eq!(malformed.status.code(), Some(2));
    let malformed_value = parse_single_json(&malformed);
    assert_matches_published_schema(&malformed_value);
    assert_eq!(malformed_value["status"], "error");
    assert!(malformed_value["error"].is_object());
    assert!(malformed_value.get("result").is_none());

    let mut frame_file = tempfile::NamedTempFile::new().expect("frame file must open");
    frame_file.write_all(&frame).expect("frame file must write");
    let decoded = run(&[
        "--output",
        "json",
        "dissect",
        "--file",
        path_text(frame_file.path()),
        "--link-type",
        "228",
    ]);
    assert!(decoded.status.success(), "{:?}", decoded.stderr);
}

#[test]
fn format_and_limit_failures_are_reported_before_offline_work() {
    let missing = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("does-not-exist.pcap");
    let unsupported = run(&["--output", "raw", "stats", path_text(&missing)]);
    assert_eq!(unsupported.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&unsupported.stderr).contains("does not support raw"));

    let capture = write_capture();
    let path = path_text(capture.path());
    for arguments in [
        vec!["stats", path, "--interval-ms", "0"],
        vec!["stats", path, "--max-frames", "0"],
        vec!["expert", path, "--max-flows", "0"],
        vec!["read", path, "--max-frame-bytes", "0"],
    ] {
        let output = run(&arguments);
        assert!(!output.status.success(), "{arguments:?}");
    }
}

#[test]
fn every_live_command_keeps_public_destinations_behind_policy() {
    let commands: &[&[&str]] = &[
        &[
            "--output",
            "json",
            "plan",
            "--packet",
            "ipv4(dst=8.8.8.8)/udp(dport=9)",
        ],
        &[
            "--output",
            "json",
            "send",
            "--packet",
            "ipv4(dst=8.8.8.8)/udp(dport=9)",
        ],
        &[
            "--output",
            "json",
            "exchange",
            "--packet",
            "ipv4(dst=8.8.8.8)/udp(dport=9)",
        ],
        &[
            "--output",
            "ndjson",
            "capture",
            "--packet",
            "ipv4(dst=8.8.8.8)/udp(dport=9)",
            "--timeout-ms",
            "1",
        ],
        &["--output", "json", "scan", "8.8.8.8", "--ports", "80"],
        &[
            "--output",
            "json",
            "traceroute",
            "8.8.8.8",
            "--strategy",
            "icmp",
            "--max-hops",
            "1",
            "--attempts",
            "1",
        ],
        &[
            "--output",
            "json",
            "fuzz",
            "--packet",
            "ipv4(dst=8.8.8.8)/udp(dport=9)",
            "--cases",
            "1",
            "--live",
        ],
        &[
            "--output",
            "json",
            "dns",
            "8.8.8.8",
            "example.com",
            "--transaction-id",
            "7",
            "--source-port",
            "49152",
        ],
    ];

    for arguments in commands {
        let output = run(arguments);
        assert_eq!(
            output.status.code(),
            Some(6),
            "{arguments:?}: {:?}",
            output.stderr
        );
        let value: Value =
            serde_json::from_slice(&output.stdout).expect("policy error must be JSON");
        assert_eq!(value["status"], "error");
        assert_eq!(value["error"]["code"], "policy.public_destination");
    }
}

#[test]
fn protocol_discovery_lists_describes_and_rejects_names() {
    for arguments in [
        vec!["protocols"],
        vec!["protocols", "tcp"],
        vec!["--output", "json", "protocols"],
        vec!["--output", "json", "protocols", "ETH"],
    ] {
        let output = run(&arguments);
        assert!(
            output.status.success(),
            "{arguments:?}: {:?}",
            output.stderr
        );
        assert!(!output.stdout.is_empty());
    }

    let unknown = run(&["--output", "json", "protocols", "definitely-not-a-protocol"]);
    assert_eq!(unknown.status.code(), Some(2));
    let value = parse_json(&unknown);
    assert_eq!(value["error"]["code"], "cli.protocol");
    assert!(
        value["error"]["remediation"]
            .as_str()
            .expect("remediation is present")
            .contains("protocols")
    );
}
