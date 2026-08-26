// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
// Test code indexes fixtures and counts by hand; the fail-closed lints are
// for library paths.
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::io::Write;
use std::path::PathBuf;
use std::time::UNIX_EPOCH;

use packetcraftr::{
    analysis::pcap::{Format as CaptureFormat, Writer},
    core::frame::{Frame, LinkType},
};
#[path = "support/process.rs"]
mod process_support;
mod support;

use process_support::{append_truncated_record, decode_hex, run_with_stdin};
use support::{assert_contiguous, parse_json, parse_ndjson, path_text, run, run_success};

const UDP_CLIENT: &str = "450000210000000040118e95c0000201c633640230390009000d9f8868656c6c6f";
const UDP_SERVER: &str = "450000210000000040118e95c6336402c000020100093039000d957e776f726c64";
const TCP_CLIENT: &str =
    "4500002b0000000040068e96c0000201c63364023039005000000001000000005002ffffb7b80000676574";
const TCP_SERVER: &str =
    "450000280000000040068e99c6336402c0000201005030390000000a000000045012100083040000";
const TCP_DATA: &str =
    "4500002b0000000040068e96c0000201c633640230390050000000040000000b50181000be970000616263";

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

#[test]
fn stats_exercises_every_table_and_filtering_mode() {
    let capture = write_capture();
    let path = path_text(capture.path());

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
    let records = parse_ndjson(&dissected);
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
    }
    let complete = &records[3];
    assert_eq!(complete["result"]["event"], "complete");
    assert_eq!(complete["result"]["frames_read"], 3);
    assert_eq!(complete["result"]["frames_matched"], 3);
    assert_eq!(complete["result"]["captured_bytes_read"], 109);

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
}

#[test]
fn packet_documents_stdin_and_file_inputs_cover_offline_input_paths() {
    let documents = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/documents");
    for document in [
        "packet-gre-sctp.json",
        "packet-igmp.json",
        "packet-ipv4-udp.json",
        "packet-raw.yaml",
    ] {
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
    let decoded_value = parse_json(&decoded);
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
    let value = parse_json(&filtered);
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
    let matched_value = parse_json(&matched);
    assert_eq!(matched_value["result"]["matched"], true);
    assert!(matched_value["result"]["dissection"].is_object());

    let malformed = run(&["--output", "json", "dissect", "--hex", "not-hex"]);
    assert_eq!(malformed.status.code(), Some(2));
    let malformed_value = parse_json(&malformed);
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
fn destination_bearing_live_commands_keep_public_destinations_behind_policy() {
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
        let value = parse_json(&output);
        assert_eq!(value["status"], "error");
        assert_eq!(value["error"]["code"], "policy.public_destination");
    }
}

#[test]
fn the_tls_protocol_report_names_every_port_bound_to_the_per_frame_layer() {
    let ports = [443_u64, 465, 636, 853, 993, 995, 8443];

    let rendered = String::from_utf8_lossy(&run_success(&["protocols", "tls"]).stdout).into_owned();
    let listed = rendered
        .lines()
        .skip_while(|line| *line != "bindings:")
        .skip(1)
        .take_while(|line| line.starts_with("  "))
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let expected = ports
        .iter()
        .map(|port| format!("  tcp discriminator={port}"))
        .collect::<Vec<_>>();
    assert_eq!(listed, expected, "{rendered}");

    let value = parse_json(&run_success(&["--output", "json", "protocols", "tls"]));
    let bindings = value["result"]["protocol"]["bindings"]
        .as_array()
        .expect("bindings is an array");
    assert_eq!(bindings.len(), ports.len());
    for (binding, port) in bindings.iter().zip(ports) {
        assert_eq!(binding["parent"], "tcp");
        assert_eq!(binding["discriminator"], port);
    }

    // The published detail example carries the same two keys per binding.
    let published = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/documents/output-protocols-detail-success.json");
    let document: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(&published).expect("the published example must be readable"),
    )
    .expect("the published example must be JSON");
    let mut published_keys = document["result"]["protocol"]["bindings"][0]
        .as_object()
        .expect("the published example lists bindings")
        .keys()
        .cloned()
        .collect::<Vec<_>>();
    published_keys.sort();
    let mut reported_keys = bindings[0]
        .as_object()
        .expect("each binding is an object")
        .keys()
        .cloned()
        .collect::<Vec<_>>();
    reported_keys.sort();
    assert_eq!(reported_keys, published_keys);
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

#[test]
fn build_rejects_document_output() {
    let output = run(&[
        "--output",
        "document",
        "build",
        "--packet",
        "raw(text=hello)",
    ]);
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("unsupported output format") || stderr.contains("cli.output_format"),
        "{stderr}"
    );
}

#[test]
fn dissect_document_output_minimized_and_full() {
    // 1. Minimized
    let hex = UDP_CLIENT;
    let output = run_success(&[
        "--output",
        "document",
        "dissect",
        "--hex",
        hex,
        "--link-type",
        "228",
    ]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("- ipv4:"), "{stdout}");
    assert!(!stdout.contains("checksum:"), "{stdout}");
    assert!(!stdout.contains("total_length:"), "{stdout}");
    assert!(
        !stdout.starts_with("---"),
        "dissect should emit bare document without leading ---: {stdout}"
    );

    // 2. Full
    let output_full = run_success(&[
        "--output",
        "document",
        "dissect",
        "--hex",
        hex,
        "--link-type",
        "228",
        "--full",
    ]);
    let stdout_full = String::from_utf8_lossy(&output_full.stdout);
    assert!(stdout_full.contains("checksum:"), "{stdout_full}");
    assert!(stdout_full.contains("total_length:"), "{stdout_full}");

    // 3. Filtered out
    let output_filtered = run_success(&[
        "--output",
        "document",
        "dissect",
        "--hex",
        hex,
        "--link-type",
        "228",
        "--filter",
        "tcp",
    ]);
    let stdout_filtered = String::from_utf8_lossy(&output_filtered.stdout);
    assert!(stdout_filtered.trim().is_empty(), "{stdout_filtered}");
}

#[test]
fn dissect_document_tls_round_trip() {
    let capture_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/captures/tls-handshake.pcapng");
    // Read the TLS frames from the capture
    let doc_output = run_success(&[
        "--output",
        "document",
        "read",
        path_text(&capture_path),
        "--filter",
        "tls",
    ]);
    let stdout = String::from_utf8_lossy(&doc_output.stdout);
    assert!(
        stdout.contains("- raw:"),
        "decode-only TLS layer emitted as raw: {stdout}"
    );

    // Take the first document
    let docs = stdout
        .split("\n---")
        .map(|s| s.trim_start_matches("---").trim())
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>();
    assert!(!docs.is_empty());
    let first_doc = docs[0];

    let temp_doc = tempfile::NamedTempFile::new().expect("temp doc creates");
    std::fs::write(temp_doc.path(), first_doc).expect("write temp doc");

    // Build the document back
    let build_output = run_success(&["build", "--packet-file", path_text(temp_doc.path())]);
    assert!(build_output.status.success());
}

#[test]
fn read_document_output_and_stderr_summary() {
    let capture = write_capture();
    let output = run_success(&["--output", "document", "read", path_text(capture.path())]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Every frame starts with ---
    assert_eq!(stdout.matches("---").count(), 5);
    assert!(
        stderr.contains("minimized 5 frame(s), 0 with literal derived fields"),
        "{stderr}"
    );
}

#[test]
fn read_columns_in_text_and_ndjson() {
    // Build a capture with tunneling: ip#1.dst and ip#2.dst
    let built = run_success(&[
        "--output",
        "hex",
        "build",
        "--packet",
        "ipv4(src=10.0.0.1,dst=10.0.0.2)/ipv4(src=192.168.1.1,dst=192.168.1.2)/udp(sport=1000,dport=2000)/raw(text=tunnel)",
    ]);
    let hex = String::from_utf8_lossy(&built.stdout).trim().to_owned();
    let capture = write_capture_frames(&[&hex]);

    // 1. Text mode with #2 and missing field
    let text_output = run_success(&[
        "read",
        path_text(capture.path()),
        "--columns",
        "ip#1.dst,ip#2.dst,udp.dstport,tcp.dstport",
    ]);
    let text_stdout = String::from_utf8_lossy(&text_output.stdout);
    assert_eq!(text_stdout.trim(), "10.0.0.2\t192.168.1.2\t2000\t-");

    // 2. NDJSON mode
    let ndjson_output = run_success(&[
        "--output",
        "ndjson",
        "read",
        path_text(capture.path()),
        "--columns",
        "ip#1.dst,ip#2.dst,udp.dstport",
    ]);
    let records = parse_ndjson(&ndjson_output);
    assert_eq!(records.len(), 2); // 1 frame event + 1 complete event
    let frame_event = &records[0]["result"];
    assert_eq!(frame_event["event"], "frame");
    let columns = &frame_event["columns"];
    assert_eq!(columns["ip#1.dst"]["value"], "10.0.0.2");
    assert_eq!(columns["ip#2.dst"]["value"], "192.168.1.2");
    assert_eq!(columns["udp.dstport"]["value"], 2000);

    // 3. Unknown path fails with cli.unknown_path before reading capture
    let bad_path = run(&[
        "read",
        path_text(capture.path()),
        "--columns",
        "ipv4.totally_fake_field",
    ]);
    assert_eq!(bad_path.status.code(), Some(2));
    let bad_stderr = String::from_utf8_lossy(&bad_path.stderr);
    assert!(
        bad_stderr.contains("unknown path `ipv4.totally_fake_field`"),
        "{bad_stderr}"
    );
    assert!(
        bad_stderr.contains("packetcraftr protocols"),
        "{bad_stderr}"
    );
}

#[test]
fn protocols_example_and_json_list() {
    // 1. protocols ipv4 --example
    let ipv4_ex = run_success(&["protocols", "ipv4", "--example"]);
    let ipv4_stdout = String::from_utf8_lossy(&ipv4_ex.stdout);
    assert!(ipv4_stdout.contains("- ipv4:"), "{ipv4_stdout}");
    assert!(ipv4_stdout.contains("destination:"), "{ipv4_stdout}");

    // 2. protocols tls --example (decode-only)
    let tls_ex = run_success(&["protocols", "tls", "--example"]);
    let tls_stdout = String::from_utf8_lossy(&tls_ex.stdout);
    assert!(
        tls_stdout.contains("# decode-only: dissect emits this layer as raw bytes"),
        "{tls_stdout}"
    );
    assert!(tls_stdout.contains("- raw: {bytes: 0x}"), "{tls_stdout}");

    // 3. protocols --output json (list form)
    let list_json = run_success(&["--output", "json", "protocols"]);
    let list_val = parse_json(&list_json);
    let protocols = list_val["result"]["protocols"]
        .as_array()
        .expect("protocols list");
    assert!(!protocols.is_empty());
    let tls_proto = protocols
        .iter()
        .find(|p| p["protocol"] == "tls")
        .expect("tls in list");
    assert_eq!(tls_proto["decode_only"], true);
    let ipv4_proto = protocols
        .iter()
        .find(|p| p["protocol"] == "ipv4")
        .expect("ipv4 in list");
    assert_eq!(ipv4_proto["decode_only"], false);
    assert!(ipv4_proto["aliases"].is_array());
}
