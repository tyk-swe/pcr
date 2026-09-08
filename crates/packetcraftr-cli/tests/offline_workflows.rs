// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::io::Write;
use std::path::PathBuf;
use std::time::{Duration, Instant, UNIX_EPOCH};

use packetcraftr_core::Packet;
use packetcraftr_core::analysis::pcap::Format as CaptureFormat;
use packetcraftr_core::analysis::pcap::Writer;
use packetcraftr_core::field::WireValue;
use packetcraftr_core::frame::Frame;
use packetcraftr_core::frame::LinkType;
use packetcraftr_core::layer::Raw;
use packetcraftr_core::protocol::ipv6::Fragment as Ipv6Fragment;
use packetcraftr_core::protocol::network::Ipv6;
#[path = "support/process.rs"]
mod process_support;
mod support;

use process_support::{append_truncated_record, decode_hex, run_with_stdin};
use support::{assert_contiguous, parse_json, parse_ndjson, path_text, run, run_success};

const UDP_CLIENT: &str = "450000210000000040118e95c0000201c633640230390009000d9f8868656c6c6f";

/// `UDP_CLIENT` with its last payload byte flipped, so the UDP checksum fails.
fn damaged_udp_client() -> Vec<u8> {
    let mut frame = decode_hex(UDP_CLIENT);
    *frame.last_mut().expect("UDP payload") ^= 1;
    frame
}
const UDP_SERVER: &str = "450000210000000040118e95c6336402c000020100093039000d957e776f726c64";
const TCP_CLIENT: &str =
    "4500002b0000000040068e96c0000201c63364023039005000000001000000005002ffffb7b80000676574";
const TCP_SERVER: &str =
    "450000280000000040068e99c6336402c0000201005030390000000a000000045012100083040000";
const TCP_DATA: &str =
    "4500002b0000000040068e96c0000201c633640230390050000000040000000b50181000be970000616263";
const IPV4_FRAGMENT_FIRST: &str =
    "45000024002a200040116e68c0000201c63364029c40270f001800006162636465666768";
const IPV4_FRAGMENT_LAST: &str = "4500001c002a000240118e6ec0000201c6336402696a6b6c6d6e6f70";
const IPV4_FRAGMENT_INCOMPLETE: &str =
    "45000024002b200040116e67c0000201c63364029c40270f001800006162636465666768";

fn write_capture() -> tempfile::NamedTempFile {
    write_capture_frames(&[UDP_CLIENT, UDP_SERVER, TCP_CLIENT, TCP_SERVER, TCP_DATA])
}

fn write_capture_frames(frames: &[&str]) -> tempfile::NamedTempFile {
    let frames = frames.iter().copied().map(decode_hex).collect::<Vec<_>>();
    write_capture_byte_frames(&frames)
}

fn write_capture_byte_frames(frames: &[Vec<u8>]) -> tempfile::NamedTempFile {
    let mut file = tempfile::NamedTempFile::new().expect("temporary capture must open");
    file.write_all(&[
        0xd4, 0xc3, 0xb2, 0xa1, // little-endian microsecond PCAP
        2, 0, 4, 0, // version 2.4
        0, 0, 0, 0, 0, 0, 0, 0, // timezone and timestamp accuracy
        0xff, 0xff, 0, 0, // snap length
        228, 0, 0, 0, // DLT_IPV4
    ])
    .expect("global header must write");

    for (index, bytes) in frames.iter().enumerate() {
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
        file.write_all(bytes).expect("frame bytes must write");
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

fn ipv6_fragment_hex() -> String {
    let registry = packetcraftr_core::protocol::builtin::registry();
    let mut packet = Packet::new();
    packet.push(Ipv6 {
        source: "2001:db8::1".parse().expect("documentation source"),
        destination: "2001:db8::2".parse().expect("documentation destination"),
        ..Ipv6::default()
    });
    packet.push(Ipv6Fragment {
        next_header: WireValue::Exact(17),
        fragment_offset: 0,
        more_fragments: true,
        identification: 42,
    });
    packet.push(Raw::new(b"abcdefgh".to_vec()));
    packetcraftr_core::build::Builder::new(registry)
        .build(
            packet,
            packetcraftr_core::build::Context::default(),
            packetcraftr_core::build::Options::default(),
        )
        .expect("IPv6 fragment builds")
        .bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
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

    let limited = run_success(&[
        "--output",
        "json",
        "stats",
        path,
        "--table",
        "protocols",
        "--top",
        "1",
    ]);
    let value = parse_json(&limited);
    assert_eq!(
        value["result"]["protocols"]
            .as_array()
            .expect("protocol rows")
            .len(),
        1
    );
    assert_eq!(value["diagnostics"][0]["code"], "stats.protocols_omitted");

    let limited_text = run_success(&["stats", path, "--table", "protocols", "--top", "0"]);
    assert!(String::from_utf8_lossy(&limited_text.stdout).contains("stats.protocols_omitted"));

    for table in [
        "conversations",
        "endpoints",
        "protocols",
        "ports",
        "io",
        "fragments",
    ] {
        let output = run_success(&["stats", path, "--table", table, "--interval-ms", "500"]);
        assert!(String::from_utf8_lossy(&output.stdout).contains("matched 5 of 5"));
    }
}

#[test]
fn single_frame_fragment_dissection_and_capture_rewrite_remain_physical() {
    for (link_type, hex, expected) in [
        ("228", IPV4_FRAGMENT_FIRST.to_owned(), vec!["ipv4", "raw"]),
        (
            "229",
            ipv6_fragment_hex(),
            vec!["ipv6", "ipv6_fragment", "raw"],
        ),
    ] {
        let output = run_success(&[
            "--output",
            "json",
            "dissect",
            "--link-type",
            link_type,
            "--hex",
            &hex,
        ]);
        let value = parse_json(&output);
        let protocols = value["result"]["dissection"]["packet"]["layers"]
            .as_array()
            .expect("dissection layers are present")
            .iter()
            .map(|layer| layer["protocol"].as_str().expect("protocol is text"))
            .collect::<Vec<_>>();
        assert_eq!(protocols, expected);
        assert!(!protocols.contains(&"udp"));
        assert!(!protocols.contains(&"tcp"));
    }

    let capture = write_capture_frames(&[IPV4_FRAGMENT_FIRST, IPV4_FRAGMENT_LAST]);
    let rewritten = run_success(&["--output", "pcap", "read", path_text(capture.path())]);
    assert_eq!(
        rewritten.stdout,
        std::fs::read(capture.path()).expect("fragment capture reads")
    );
}

#[test]
fn stats_fragments_separates_physical_totals_from_bounded_derived_outcomes() {
    let capture = write_capture_frames(&[
        IPV4_FRAGMENT_FIRST,
        IPV4_FRAGMENT_LAST,
        IPV4_FRAGMENT_INCOMPLETE,
    ]);
    let path = path_text(capture.path());

    let text = run_success(&["stats", path, "--table", "fragments"]);
    let rendered = String::from_utf8_lossy(&text.stdout);
    assert!(
        rendered.contains("matched 3 of 3 frame(s), 100 byte(s)"),
        "{rendered}"
    );
    assert!(
        rendered.contains("ipv4: physical fragments 3"),
        "{rendered}"
    );
    assert!(
        rendered.contains("fragment accounting is capture-global"),
        "{rendered}"
    );
    assert!(
        rendered.contains("derived datagram bytes 44, derived payload bytes 24"),
        "{rendered}"
    );
    assert!(rendered.contains("complete, fragments 2"), "{rendered}");
    assert!(
        rendered.contains("incomplete (end-of-capture), fragments 1"),
        "{rendered}"
    );

    let json = run_success(&["--output", "json", "stats", path, "--table", "fragments"]);
    let value = parse_json(&json);
    assert_eq!(value["result"]["table"], "fragments");
    assert_eq!(value["result"]["frames_read"], 3);
    assert_eq!(value["result"]["frames_matched"], 3);
    assert_eq!(value["result"]["bytes_matched"], 100);
    let fragments = &value["result"]["fragments"];
    assert_eq!(fragments["families"][0]["family"], "ipv4");
    assert_eq!(fragments["families"][0]["physical_fragments"], 3);
    assert_eq!(fragments["families"][0]["completed_datagrams"], 1);
    assert_eq!(fragments["families"][0]["incomplete_datagrams"], 1);
    assert_eq!(fragments["families"][0]["derived_datagram_bytes"], 44);
    assert_eq!(fragments["families"][0]["derived_payload_bytes"], 24);
    assert_eq!(fragments["families"][1]["family"], "ipv6");
    assert_eq!(fragments["families"][1]["physical_fragments"], 0);
    assert_eq!(fragments["outcomes"].as_array().map(Vec::len), Some(2));
    assert_eq!(fragments["outcomes"][0]["status"], "completed");
    assert_eq!(fragments["outcomes"][1]["status"], "incomplete");
    assert_eq!(fragments["outcomes_omitted"], 0);
    for other in ["conversations", "endpoints", "protocols", "ports", "io"] {
        assert!(value["result"].get(other).is_none(), "unexpected {other}");
    }

    let filtered = run_success(&[
        "--output",
        "json",
        "stats",
        path,
        "--table",
        "fragments",
        "--filter",
        "udp",
    ]);
    let filtered = parse_json(&filtered);
    assert_eq!(filtered["result"]["frames_read"], 3);
    assert_eq!(filtered["result"]["frames_matched"], 1);
    assert_eq!(filtered["result"]["bytes_matched"], 28);
    assert_eq!(
        filtered["result"]["fragments"]["families"][0]["physical_fragments"], 3,
        "capture-global reassembly still sees filtered physical fragments"
    );
    assert_eq!(
        filtered["result"]["fragments"]["outcomes"]
            .as_array()
            .map(Vec::len),
        Some(2)
    );

    let bounded = run_success(&[
        "--output",
        "json",
        "stats",
        path,
        "--table",
        "fragments",
        "--max-ip-outcomes",
        "1",
    ]);
    let bounded = parse_json(&bounded);
    let fragments = &bounded["result"]["fragments"];
    assert_eq!(fragments["outcomes"].as_array().map(Vec::len), Some(1));
    assert_eq!(fragments["outcomes_omitted"], 1);
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
fn follow_rejects_absent_tcp_and_udp_streams_in_every_output_format() {
    for capture in [write_capture(), write_capture_frames(&[])] {
        let path = path_text(capture.path());
        for selector in ["tcp:999", "udp:999"] {
            let expected = format!("--stream {selector} is not present");
            for format in ["text", "hex", "raw", "json", "ndjson"] {
                let output = run(&[
                    "--output",
                    format,
                    "follow",
                    path,
                    "--stream",
                    selector,
                    "--direction",
                    "client",
                ]);
                assert_eq!(output.status.code(), Some(2), "{format}: {output:?}");
                if matches!(format, "text" | "hex" | "raw") {
                    assert!(output.stdout.is_empty(), "no success payload: {output:?}");
                    assert!(String::from_utf8_lossy(&output.stderr).contains(&expected));
                    continue;
                }
                let error = if format == "ndjson" {
                    let records = parse_ndjson(&output);
                    assert_contiguous(&records);
                    assert_eq!(records.len(), 1, "only one terminal error");
                    records[0].clone()
                } else {
                    parse_json(&output)
                };
                assert_eq!(error["status"], "error");
                assert_eq!(error["error"]["code"], "cli.error");
                assert_eq!(error["error"]["message"], expected);
                assert!(error.get("result").is_none());
            }
        }
    }
}

#[test]
fn follow_missing_stream_terminates_after_preceding_ip_events() {
    let capture = write_capture_frames(&[IPV4_FRAGMENT_FIRST, IPV4_FRAGMENT_LAST]);
    for selector in ["tcp:999", "udp:999"] {
        let output = run(&[
            "--output",
            "ndjson",
            "follow",
            path_text(capture.path()),
            "--stream",
            selector,
        ]);
        assert_eq!(output.status.code(), Some(2));
        let records = parse_ndjson(&output);
        assert_contiguous(&records);
        assert_eq!(records.len(), 2);
        assert_eq!(records[0]["event"], "ip_datagram_completed");
        assert_eq!(records[1]["status"], "error");
        assert_eq!(records[1]["error"]["code"], "cli.error");
        assert_eq!(
            records
                .iter()
                .filter(|record| record["status"] == "error")
                .count(),
            1
        );
        assert!(
            records
                .iter()
                .all(|record| record["result"].get("frames").is_none())
        );
    }
}

#[test]
fn follow_accepts_payload_free_tcp_and_empty_udp_datagrams() {
    const EMPTY_UDP: &str = "4500001c0000000040118e9ac0000201c63364023039000900080000";
    for (selector, frame, chunks) in [("tcp:0", TCP_SERVER, 0), ("udp:0", EMPTY_UDP, 1)] {
        let capture = write_capture_frames(&[frame]);
        for format in ["text", "hex", "raw", "json", "ndjson"] {
            let output = run_success(&[
                "--output",
                format,
                "follow",
                path_text(capture.path()),
                "--stream",
                selector,
                "--direction",
                "client",
            ]);
            if format == "raw" {
                assert!(output.stdout.is_empty());
            }
            let report = match format {
                "json" => {
                    let value = parse_json(&output);
                    assert_eq!(value["result"]["chunks"].as_array().unwrap().len(), chunks);
                    value
                }
                "ndjson" => {
                    let records = parse_ndjson(&output);
                    assert_contiguous(&records);
                    assert_eq!(records.len(), chunks + 1);
                    assert_eq!(
                        records
                            .iter()
                            .filter(|record| record["result"].get("frames").is_some())
                            .count(),
                        1,
                        "exactly one terminal report"
                    );
                    records.last().unwrap().clone()
                }
                _ => continue,
            };
            assert_eq!(report["status"], "success");
            assert_eq!(report["result"]["frames"], 1);
            assert_eq!(report["result"]["client_bytes"], 0);
            assert_eq!(report["result"]["server_bytes"], 0);
        }
    }
}

#[test]
fn follow_and_expert_stream_ip_lifecycle_before_data_and_single_terminal() {
    let capture = write_capture_frames(&[
        IPV4_FRAGMENT_FIRST,
        IPV4_FRAGMENT_LAST,
        IPV4_FRAGMENT_INCOMPLETE,
    ]);
    let path = path_text(capture.path());

    let follow = run_success(&["--output", "ndjson", "follow", path, "--stream", "udp:0"]);
    let records = parse_ndjson(&follow);
    assert_contiguous(&records);
    assert_eq!(records.len(), 4);
    assert_eq!(records[0]["event"], "ip_datagram_completed");
    assert_eq!(records[0]["result"]["frame"], 2);
    assert_eq!(records[1]["result"]["frame"], 2);
    assert_eq!(
        records[1]["result"]["bytes_hex"],
        "6162636465666768696a6b6c6d6e6f70"
    );
    assert_eq!(records[2]["event"], "ip_datagram_incomplete");
    assert_eq!(records[2]["result"]["frame"], 3);
    assert_eq!(records[3]["result"]["frames"], 1);
    assert_eq!(
        records[3]["result"]["ip_reassembly"]["families"][0]["completed_datagrams"],
        1
    );
    assert_eq!(
        records[3]["result"]["ip_reassembly"]["families"][0]["incomplete_datagrams"],
        1
    );
    assert_eq!(
        records
            .iter()
            .filter(|record| record["sequence"] == 3)
            .count(),
        1,
        "follow has exactly one terminal record"
    );

    let expert = run_success(&["--output", "ndjson", "expert", path]);
    let records = parse_ndjson(&expert);
    assert_contiguous(&records);
    assert_eq!(records.len(), 3);
    assert_eq!(records[0]["event"], "ip_datagram_completed");
    assert_eq!(records[1]["event"], "ip_datagram_incomplete");
    assert_eq!(records[2]["result"]["frames_read"], 3);
    assert_eq!(
        records[2]["result"]["ip_reassembly"]["families"][0]["completed_datagrams"],
        1
    );
    assert_eq!(
        records
            .iter()
            .filter(|record| record["sequence"] == 2)
            .count(),
        1,
        "expert has exactly one terminal record"
    );

    let tls = run_success(&["--output", "ndjson", "tls", path]);
    let records = parse_ndjson(&tls);
    assert_contiguous(&records);
    assert_eq!(records.len(), 3);
    assert_eq!(records[0]["event"], "ip_datagram_completed");
    assert_eq!(records[1]["event"], "ip_datagram_incomplete");
    assert_eq!(records[2]["event"], "complete");
    assert_eq!(records[2]["result"]["sessions"], 0);
    assert_eq!(
        records[2]["result"]["ip_reassembly"]["families"][0]["incomplete_datagrams"],
        1
    );
    assert_eq!(
        records
            .iter()
            .filter(|record| record["event"] == "complete")
            .count(),
        1,
        "TLS has exactly one terminal record"
    );
}

#[test]
fn follow_stream_reports_overlap_resolution_before_completion_and_payload() {
    let first = decode_hex(IPV4_FRAGMENT_FIRST);
    let mut conflict = first.clone();
    conflict[28] = b'X';
    let last = decode_hex(IPV4_FRAGMENT_LAST);
    let capture = write_capture_byte_frames(&[first, conflict, last]);
    let path = path_text(capture.path());
    let output = run_success(&[
        "--output",
        "ndjson",
        "follow",
        path,
        "--stream",
        "udp:0",
        "--ip-overlap",
        "first",
    ]);
    let records = parse_ndjson(&output);
    assert_contiguous(&records);
    assert_eq!(records.len(), 4);
    assert_eq!(records[0]["event"], "ip_overlap_resolved");
    assert_eq!(records[0]["result"]["frame"], 2);
    assert_eq!(records[0]["result"]["affected_bytes"], 1);
    assert_eq!(records[1]["event"], "ip_datagram_completed");
    assert_eq!(records[1]["result"]["frame"], 3);
    assert_eq!(records[2]["result"]["frame"], 3);
    assert_eq!(
        records[3]["result"]["ip_reassembly"]["families"][0]["overlap_bytes"],
        1
    );
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
fn expert_text_lists_one_count_line_per_code_before_the_summary() {
    let capture = write_capture();
    let path = path_text(capture.path());

    let aggregated = run_success(&["--output", "json", "expert", path]);
    let document = parse_json(&aggregated);
    let expected: Vec<String> = document["result"]["codes"]
        .as_array()
        .expect("aggregate expert output lists per-code counts")
        .iter()
        .map(|entry| {
            format!(
                "code={} findings={}",
                entry["code"].as_str().expect("code is a string"),
                entry["findings"].as_u64().expect("count is a number"),
            )
        })
        .collect();
    assert_eq!(
        expected,
        ["code=tcp.retransmission_conflicting findings=1"],
        "the fixture's aggregate code count is part of this contract",
    );

    let text = run_success(&["--output", "text", "expert", path]);
    let stdout = String::from_utf8_lossy(&text.stdout);
    let lines: Vec<&str> = stdout.lines().collect();
    let summary = lines.last().expect("text output ends with a summary");
    assert_eq!(
        *summary,
        "found 1 finding(s) (1 error(s), 0 warning(s), 0 note(s)) in 5 of 5 frame(s)",
    );
    let reported: Vec<String> = lines
        .iter()
        .filter(|line| line.starts_with("code="))
        .map(ToString::to_string)
        .collect();
    assert_eq!(reported, expected);
    assert_eq!(
        &lines[lines.len() - 1 - reported.len()..lines.len() - 1],
        expected.as_slice(),
        "count lines must sit immediately before the final summary",
    );
}

#[test]
fn expert_text_with_zero_findings_adds_no_code_lines() {
    let capture = write_capture();
    let path = path_text(capture.path());

    let output = run_success(&["--output", "text", "expert", path, "--filter", "udp"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.lines().any(|line| line.starts_with("code=")),
        "zero findings must add no lines: {stdout:?}",
    );
    assert_eq!(
        stdout.lines().collect::<Vec<_>>(),
        [
            "capture clock: 0 regressing frame(s), largest rollback 0ns, largest forward step 1s at frame Some(2); expiry follows the high-water mark",
            "found 0 finding(s) (0 error(s), 0 warning(s), 0 note(s)) in 2 of 5 frame(s)",
        ],
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
    assert_eq!(records[2]["event"], "complete");

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
    assert!(filtered.status.success(), "{:?}", filtered.stderr);
    let mut reader =
        packetcraftr_core::analysis::pcap::Reader::new(std::io::Cursor::new(filtered.stdout))
            .unwrap();
    for packet in [UDP_CLIENT, UDP_SERVER] {
        assert_eq!(
            reader.next_frame().unwrap().unwrap().bytes().as_ref(),
            decode_hex(packet)
        );
    }
    assert!(reader.next_frame().unwrap().is_none());
}

#[test]
fn read_dissection_diagnostics_match_ndjson_and_follow_source_frame_filtering() {
    let damaged = damaged_udp_client();
    let capture =
        write_capture_byte_frames(&[decode_hex(UDP_SERVER), damaged, decode_hex(TCP_CLIENT)]);
    let path = path_text(capture.path());

    let ndjson = run_success(&["--output", "ndjson", "read", path, "--dissect"]);
    assert!(ndjson.stderr.is_empty());
    let records = parse_ndjson(&ndjson);
    let diagnostics = records[1]["result"]["decoded"]["diagnostics"]
        .as_array()
        .expect("diagnostics remain in the decoded stack");
    assert_eq!(records[1]["result"]["source_frame"], 2);
    assert_eq!(diagnostics.len(), 1);
    assert_eq!(diagnostics[0]["code"], "decode.udp_checksum");
    assert_eq!(diagnostics[0]["message"], "UDP checksum mismatch");
    assert!(
        records
            .iter()
            .all(|record| record["diagnostics"] == serde_json::json!([]))
    );

    let text = run_success(&["read", path, "--dissect"]);
    assert!(text.stderr.is_empty());
    let text = String::from_utf8(text.stdout).expect("text output");
    let lines = text.lines().collect::<Vec<_>>();
    assert!(lines[0].starts_with("1: dlt="));
    assert!(lines[1].starts_with("2: dlt="));
    assert_eq!(lines[2], "2: diagnostics:");
    assert_eq!(
        lines[3],
        format!(
            "{} {}: {}",
            diagnostics[0]["severity"].as_str().unwrap(),
            diagnostics[0]["code"].as_str().unwrap(),
            diagnostics[0]["message"].as_str().unwrap(),
        )
    );
    assert!(lines[4].starts_with("3: dlt="));
    assert_eq!(lines.len(), 5);

    for format in ["text", "ndjson"] {
        let filtered = run_success(&[
            "--output",
            format,
            "read",
            path,
            "--dissect",
            "--filter",
            "frame.number != 2",
        ]);
        assert!(filtered.stderr.is_empty());
        assert!(!String::from_utf8_lossy(&filtered.stdout).contains("decode.udp_checksum"));
        if format == "text" {
            let text = String::from_utf8(filtered.stdout).unwrap();
            assert!(!text.contains("diagnostics:"));
            assert!(
                text.lines()
                    .all(|line| line.starts_with("1: ") || line.starts_with("3: "))
            );
        } else {
            let records = parse_ndjson(&filtered);
            assert_eq!(records.len(), 3);
            assert_eq!(records[0]["result"]["source_frame"], 1);
            assert_eq!(records[1]["result"]["source_frame"], 3);
        }
    }
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
        assert_eq!(record["event"], "frame");
        assert_eq!(
            record["result"]["source_frame"],
            u64::try_from(index + 1).expect("fixture index fits")
        );
    }
    let complete = &records[3];
    assert_eq!(complete["event"], "complete");
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
        assert_eq!(records[0]["event"], "complete");
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
        assert!(records.iter().all(|record| record["event"] != "complete"));
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
    assert!(records.iter().all(|record| record["event"] != "complete"));
}

#[test]
fn recipe_stdin_matches_files_for_yaml_json_and_expressions() {
    let yaml = include_str!("../../../examples/documents/packet-raw.yaml");
    let commented = format!("# A packet recipe\n\n{yaml}");
    let (schema, layers) = yaml.split_once('\n').unwrap();
    let reordered = format!("{layers}{schema}\n");
    let json = include_str!("../../../examples/documents/packet-ipv4-udp.json");
    for (suffix, input) in [
        (".yaml", yaml),
        (".yaml", commented.as_str()),
        (".yaml", reordered.as_str()),
        (".json", json),
        (".txt", "raw"),
        (".txt", "raw(text=hello) / raw(text=world)"),
        (".txt", "raw(text=\"schema: # ---\")"),
    ] {
        let mut file = tempfile::Builder::new().suffix(suffix).tempfile().unwrap();
        file.write_all(input.as_bytes()).unwrap();
        file.flush().unwrap();
        let from_file = run(&[
            "--output",
            "json",
            "build",
            "--packet-file",
            path_text(file.path()),
        ]);
        let from_stdin = run_with_stdin(&["--output", "json", "build"], input.as_bytes());
        assert!(from_file.status.success(), "{input}: {from_file:?}");
        assert!(from_stdin.status.success(), "{input}: {from_stdin:?}");
        assert_eq!(parse_json(&from_stdin), parse_json(&from_file), "{input}");
    }
}

#[test]
fn malformed_recipe_stdin_retains_document_and_expression_diagnostics() {
    for (suffix, input) in [
        (".yaml", "schema: packetcraftr.packet/v1\nlayers: ["),
        (
            ".yaml",
            "# A broken packet\nschema: packetcraftr.packet/v1\nlayers: [",
        ),
        (".yaml", "layers: [\nschema: packetcraftr.packet/v1"),
        (
            ".json",
            "{\"schema\": \"packetcraftr.packet/v1\", \"layers\": [",
        ),
    ] {
        let mut file = tempfile::Builder::new().suffix(suffix).tempfile().unwrap();
        file.write_all(input.as_bytes()).unwrap();
        file.flush().unwrap();
        let from_file = run(&[
            "--output",
            "json",
            "build",
            "--packet-file",
            path_text(file.path()),
        ]);
        let from_stdin = run_with_stdin(&["--output", "json", "build"], input.as_bytes());
        assert_eq!(from_file.status.code(), Some(2), "{input}");
        assert_eq!(from_stdin.status.code(), Some(2), "{input}");
        let expected = parse_json(&from_file)["error"].clone();
        let actual = parse_json(&from_stdin)["error"].clone();
        assert_eq!(expected["code"], "cli.document_syntax");
        assert!(
            actual["message"] == expected["message"]
                || actual["causes"]
                    .as_array()
                    .is_some_and(|causes| causes.contains(&expected["message"])),
            "file document diagnostic must survive on stdin: {expected:?}, {actual:?}",
        );
    }

    for expression in ["raw(text=", "raw(unknown=value)", "missing_protocol()"] {
        let explicit = run(&["--output", "json", "build", "--packet", expression]);
        let piped = run_with_stdin(&["--output", "json", "build"], expression.as_bytes());
        assert_eq!(explicit.status.code(), Some(2), "{expression}");
        assert_eq!(piped.status.code(), explicit.status.code(), "{expression}");
        let expected = parse_json(&explicit)["error"].clone();
        let actual = parse_json(&piped)["error"].clone();
        assert_eq!(actual["code"], expected["code"], "{expression}");
        assert_eq!(actual["message"], expected["message"], "{expression}");
    }
}

#[test]
fn recipe_stdin_keeps_file_byte_and_build_layer_limits() {
    let limit = packetcraftr_core::document::DEFAULT_MAX_DOCUMENT_BYTES;
    let oversized = vec![b' '; limit + 1];
    let layers = b"# Two layers\nlayers:\n  - protocol: raw\n  - protocol: raw\nschema: packetcraftr.packet/v1\n";
    for (input, code, message) in [
        (
            oversized.as_slice(),
            2,
            format!("packet input exceeds {limit} byte limit"),
        ),
        (layers.as_slice(), 3, "layer".to_owned()),
    ] {
        let mut file = tempfile::Builder::new().suffix(".yaml").tempfile().unwrap();
        file.write_all(input).unwrap();
        file.flush().unwrap();
        let from_file = run(&[
            "--output",
            "json",
            "build",
            "--max-layers",
            "1",
            "--packet-file",
            path_text(file.path()),
        ]);
        let from_stdin = run_with_stdin(&["--output", "json", "build", "--max-layers", "1"], input);
        assert_eq!(from_file.status.code(), Some(code));
        assert_eq!(from_stdin.status.code(), Some(code));
        assert_eq!(parse_json(&from_stdin), parse_json(&from_file));
        assert!(
            parse_json(&from_stdin)["error"]["message"]
                .as_str()
                .unwrap()
                .contains(&message)
        );
    }
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
fn dissect_unmatched_filter_keeps_byte_output_empty_and_reports_on_stderr() {
    let frame = damaged_udp_client();
    for format in ["text", "hex", "raw"] {
        let output = run_with_stdin(
            &[
                "--output",
                format,
                "dissect",
                "--link-type",
                "228",
                "--filter",
                "tcp",
            ],
            &frame,
        );
        assert!(output.status.success(), "{format}: {:?}", output.stderr);
        assert!(
            output.stdout.is_empty(),
            "{format} must keep stdout empty for a miss",
        );
        assert_eq!(
            String::from_utf8_lossy(&output.stderr).trim(),
            "frame did not match the filter",
            "{format} must report the miss on stderr",
        );
    }
}

#[test]
fn dissect_matched_and_json_outputs_are_unchanged_by_the_miss_notice() {
    let frame = decode_hex(UDP_CLIENT);
    for format in ["text", "hex", "raw"] {
        let output = run_with_stdin(
            &[
                "--output",
                format,
                "dissect",
                "--link-type",
                "228",
                "--filter",
                "udp",
            ],
            &frame,
        );
        assert!(output.status.success(), "{format}: {:?}", output.stderr);
        match format {
            "text" => assert_eq!(
                output.stdout,
                b"decoded 33 bytes into 3 layer(s)\n0: ipv4\n1: udp\n2: raw\n"
            ),
            "hex" => assert_eq!(output.stdout, format!("{UDP_CLIENT}\n").as_bytes()),
            "raw" => assert_eq!(output.stdout, frame),
            _ => unreachable!("fixture output formats are exhaustive"),
        }
        assert!(
            output.stderr.is_empty(),
            "{format} must stay silent on stderr for a match: {:?}",
            String::from_utf8_lossy(&output.stderr),
        );
    }

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
    assert!(
        filtered.stderr.is_empty(),
        "JSON keeps the miss in the document, not on stderr: {:?}",
        String::from_utf8_lossy(&filtered.stderr),
    );

    let damaged = damaged_udp_client();
    for filter in ["udp", "tcp"] {
        let output = run_with_stdin(
            &[
                "--output",
                "json",
                "dissect",
                "--link-type",
                "228",
                "--filter",
                filter,
            ],
            &damaged,
        );
        assert!(output.status.success());
        assert!(output.stderr.is_empty());
        let value = parse_json(&output);
        assert_eq!(value["result"]["matched"], filter == "udp");
        assert_eq!(value["result"]["dissection"].is_null(), filter == "tcp");
        assert_eq!(value["diagnostics"].as_array().unwrap().len(), 1);
        assert_eq!(value["diagnostics"][0]["code"], "decode.udp_checksum");
        assert_eq!(value["diagnostics"][0]["message"], "UDP checksum mismatch");
    }
    let text = run_with_stdin(&["dissect", "--link-type", "228"], &damaged);
    assert!(text.status.success());
    assert!(text.stderr.is_empty());
    assert_eq!(
        text.stdout,
        b"decoded 33 bytes into 3 layer(s)\n0: ipv4\n1: udp\n2: raw\nwarning decode.udp_checksum: UDP checksum mismatch\n"
    );
}

#[test]
fn format_and_limit_failures_are_reported_before_offline_work() {
    let missing = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("does-not-exist.pcap");
    let missing = path_text(&missing);
    let unsupported = run(&["--output", "raw", "stats", missing]);
    assert_eq!(unsupported.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&unsupported.stderr).contains("does not support raw"));

    for arguments in [
        vec!["stats", missing, "--max-ip-datagrams", "0"],
        vec!["expert", missing, "--max-ip-fragments-per-datagram", "0"],
        vec![
            "follow",
            missing,
            "--stream",
            "tcp:0",
            "--max-ip-bytes-per-datagram",
            "0",
        ],
        vec!["tls", missing, "--max-ip-reassembly-bytes", "0"],
        vec!["stats", missing, "--max-ip-outcomes", "0"],
        vec!["expert", missing, "--ip-idle-expiry-ms", "0"],
        vec!["stats", missing, "--max-tcp-bytes-per-flow", "0"],
        vec!["expert", missing, "--max-tcp-reassembly-bytes", "0"],
        vec![
            "follow",
            missing,
            "--stream",
            "tcp:0",
            "--max-tcp-segments-per-flow",
            "0",
        ],
        vec!["tls", missing, "--tcp-idle-expiry-ms", "0"],
        // The per-flow window doubles as the reordering window, so the
        // serial half-space is refused before the capture is opened rather
        // than by the first pushed segment.
        vec!["stats", missing, "--max-tcp-bytes-per-flow", "2147483648"],
        vec!["stats", missing, "--ip-overlap", "invalid"],
    ] {
        let output = run(&arguments);
        assert_eq!(output.status.code(), Some(2), "{arguments:?}");
        assert!(
            !String::from_utf8_lossy(&output.stderr).contains("open "),
            "{arguments:?} must fail before opening the capture"
        );
    }
    if Instant::now()
        .checked_add(Duration::from_millis(u64::MAX))
        .is_none()
    {
        let output = run(&[
            "stats",
            missing,
            "--ip-idle-expiry-ms",
            "18446744073709551615",
        ]);
        assert_eq!(output.status.code(), Some(2));
        assert!(!String::from_utf8_lossy(&output.stderr).contains("open "));
    }
    for policy in ["reject", "first", "last"] {
        let output = run(&["stats", missing, "--ip-overlap", policy]);
        assert_eq!(output.status.code(), Some(5), "{policy}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("open "),
            "valid overlap policy {policy} must reach capture opening"
        );
    }

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

// These commands intentionally name a public destination. Keep them in the
// feature profile where the CLI has no native I/O implementation to invoke.
#[cfg(not(any(
    feature = "native-route",
    feature = "native-layer2",
    feature = "native-layer3"
)))]
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
fn read_exports_selected_source_frames_in_both_capture_formats() {
    use packetcraftr_core::analysis::pcap::Reader;
    use std::io::Cursor;
    for (format, capture) in [
        ("pcap", write_capture_frames(&[UDP_CLIENT, UDP_SERVER])),
        ("pcapng", write_capture_with_later_missing_timestamp()),
    ] {
        let path = path_text(capture.path());
        for (filter, selected) in [
            ("frame.number == 2", vec![UDP_SERVER]),
            ("udp", vec![UDP_CLIENT, UDP_SERVER]),
            ("tcp", vec![]),
        ] {
            let output = run_success(&["--output", format, "read", path, "--filter", filter]);
            let mut reader = Reader::new(Cursor::new(output.stdout)).unwrap();
            for packet in selected {
                let frame = reader.next_frame().unwrap().unwrap();
                assert_eq!(frame.bytes().as_ref(), decode_hex(packet));
                if format == "pcapng" && packet == UDP_SERVER {
                    assert!(frame.timestamp.is_none());
                }
            }
            assert!(reader.next_frame().unwrap().is_none());
        }
        let output = run(&[
            "--output",
            format,
            "read",
            path,
            "--filter",
            "tcp",
            "--max-frames",
            "1",
        ]);
        assert_eq!(output.status.code(), Some(6));
        if format == "pcap" {
            let output = run(&[
                "--output",
                format,
                "read",
                path,
                "--filter",
                "tcp",
                "--max-bytes",
                "33",
                "--max-frame-bytes",
                "33",
            ]);
            assert_eq!(output.status.code(), Some(6));
        }
        for filter in ["tcp.stream == 0", "udp.stream == 0", "udp &&"] {
            let output = run(&["--output", format, "read", path, "--filter", filter]);
            assert_eq!(output.status.code(), Some(2));
            assert!(output.stdout.is_empty());
        }
    }
    let capture = write_capture_with_later_missing_timestamp();
    let output = run(&[
        "--output",
        "pcapng",
        "read",
        path_text(capture.path()),
        "--filter",
        "frame.time_epoch >= 0",
    ]);
    assert_eq!(output.status.code(), Some(3));
    assert!(String::from_utf8_lossy(&output.stderr).contains("frame 2"));
    let capture = write_truncated_capture();
    let output = run(&[
        "--output",
        "pcap",
        "read",
        path_text(capture.path()),
        "--filter",
        "frame.number == 99",
    ]);
    assert_eq!(output.status.code(), Some(3));
}

#[test]
fn protocol_details_discover_filter_spellings_and_their_comparison_semantics() {
    for (protocol, required_paths) in [
        (
            "tcp",
            &["tcp.srcport", "tcp.dstport", "tcp.port", "tcp.flags.syn"][..],
        ),
        ("udp", &["udp.srcport", "udp.dstport", "udp.port"][..]),
        ("ETH", &["eth.src", "eth.dst", "eth.addr"][..]),
    ] {
        let text = String::from_utf8(run_success(&["protocols", protocol]).stdout).unwrap();
        let document = parse_json(&run_success(&["--output", "json", "protocols", protocol]));
        let fields = document["result"]["protocol"]["filter_fields"]
            .as_array()
            .unwrap();
        let paths: Vec<_> = fields
            .iter()
            .map(|field| field["path"].as_str().unwrap())
            .collect();
        assert!(paths.windows(2).all(|pair| pair[0] < pair[1]));
        for path in required_paths {
            assert!(paths.contains(path), "{protocol} lists {path}");
        }
        for field in fields {
            let path = field["path"].as_str().unwrap();
            let description = field["description"].as_str().unwrap();
            assert!(text.contains(&format!("  {path}: {description}")));
            match field["kind"].as_str().unwrap() {
                "direct" => assert!(description.contains(field["fields"][0].as_str().unwrap())),
                "either" => {
                    assert!(description.contains("!= matches when any listed field differs"))
                }
                "bits" => {
                    assert!(description.contains("before comparison"));
                    if path == "tcp.flags.syn" {
                        assert_eq!(field["fields"], serde_json::json!(["tcp.flags"]));
                        assert_eq!(field["mask"], 2);
                        assert_eq!(field["shift"], 1);
                    }
                }
                kind => panic!("unexpected binding kind {kind}"),
            }
        }
    }
    let published: serde_json::Value = serde_json::from_str(include_str!(
        "../../../examples/documents/output-protocols-detail-success.json"
    ))
    .unwrap();
    let current = parse_json(&run_success(&["--output", "json", "protocols", "ipv4"]));
    assert_eq!(
        current["result"], published["result"],
        "published detail matches actual discovery"
    );
}

#[test]
fn offline_dns_records_match_aggregate_stream_and_published_example_contracts() {
    let capture =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/captures/dns-response.pcap");
    let stream = parse_ndjson(&run_success(&[
        "--output",
        "ndjson",
        "read",
        path_text(&capture),
        "--dissect",
    ]));
    assert_contiguous(&stream);
    assert_eq!(stream.len(), 2);
    assert_eq!(stream[1]["event"], "complete");
    let frame = &stream[0]["result"]["frame"];
    assert_eq!(
        frame["timestamp"],
        serde_json::json!({"unix_seconds":123,"nanoseconds":456789000})
    );
    let hex = frame["bytes_hex"].as_str().unwrap();
    let aggregate = parse_json(&run_success(&[
        "--output",
        "json",
        "dissect",
        "--link-type",
        "228",
        "--hex",
        hex,
    ]));
    let published: serde_json::Value = serde_json::from_str(include_str!(
        "../../../examples/documents/output-dissect-dns-response.json"
    ))
    .unwrap();
    assert_eq!(aggregate, published);
    let packet = &aggregate["result"]["dissection"]["packet"];
    assert_eq!(packet, &stream[0]["result"]["decoded"]["packet"]);
    let dns = packet["layers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|layer| layer["protocol"] == "dns")
        .unwrap();
    let fields = &dns["fields"];
    assert_eq!(
        fields["answers"]["value"][0]["value"][4]["value"][1]["value"],
        "192.0.2.8"
    );
    assert_eq!(
        fields["authorities"]["value"][0]["value"][4]["value"][1]["value"],
        "ns.example.test."
    );
    assert_eq!(
        fields["additionals"]["value"][0]["value"][4]["value"][1],
        serde_json::json!({"type":"bytes","value":[255,0,192,255]})
    );
    assert_eq!(
        fields["additionals"]["value"][1]["value"][4]["value"][6]["value"][0]["value"][1],
        serde_json::json!({"type":"bytes","value":[0,255,1]})
    );
    let text = run_success(&["read", path_text(&capture), "--dissect"]);
    let text = String::from_utf8(text.stdout).unwrap();
    assert!(
        text.contains("192.0.2.8")
            && text.contains("ns.example.test.")
            && text.contains("ff00c0ff")
    );
    let rewritten = run_success(&["--output", "pcap", "read", path_text(&capture)]);
    assert_eq!(rewritten.stdout, std::fs::read(capture).unwrap());
}
