// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::io::{Cursor, Write};
use std::process::Output;

use packetcraftr::analysis::pcap::{Format, Reader, Writer};
use packetcraftr::core::frame::{Frame, LinkType};

#[path = "support/process.rs"]
mod process_support;
mod support;

use process_support::{append_truncated_record, decode_hex, run_with_stdin};
use support::{assert_contiguous, parse_ndjson, path_text, run};

const COMMANDS: [(&str, &[&str]); 5] = [
    ("read", &[]),
    ("expert", &[]),
    ("follow", &["--stream", "tcp:0"]),
    ("stats", &[]),
    ("tls", &[]),
];

fn handshake_capture(format: Format) -> Vec<u8> {
    let source = include_bytes!("../../../examples/captures/tls-handshake.pcapng");
    if format == Format::PcapNg {
        return source.to_vec();
    }
    let mut reader = Reader::new(Cursor::new(source)).expect("published capture opens");
    let mut first = reader.next_frame().unwrap().expect("handshake has frames");
    first.interface = None;
    first.direction = None;
    let mut bytes = Vec::new();
    {
        let mut writer = Writer::new(&mut bytes, format, first.link_type).unwrap();
        writer.write_frame(&first).unwrap();
        while let Some(mut frame) = reader.next_frame().unwrap() {
            frame.interface = None;
            frame.direction = None;
            writer.write_frame(&frame).unwrap();
        }
        writer.flush().unwrap();
    }
    bytes
}

fn assert_file_stdin_parity(
    input: &[u8],
    command: &str,
    flags: &[&str],
    format: &str,
    exit_code: i32,
) -> Output {
    let mut capture = tempfile::NamedTempFile::new().unwrap();
    capture.write_all(input).unwrap();
    capture.flush().unwrap();
    let mut arguments = vec!["--output", format, command, path_text(capture.path())];
    arguments.extend_from_slice(flags);
    let file = run(&arguments);
    arguments[3] = "-";
    let stdin = run_with_stdin(&arguments, input);
    assert_eq!(
        file.status.code(),
        Some(exit_code),
        "{arguments:?}: {file:?}"
    );
    assert_eq!(
        stdin.status.code(),
        Some(exit_code),
        "{arguments:?}: {stdin:?}"
    );
    assert_eq!(stdin.stdout, file.stdout, "{arguments:?}: stdout differs");
    assert_eq!(stdin.stderr, file.stderr, "{arguments:?}: stderr differs");
    stdin
}

#[test]
fn piped_pcap_and_pcapng_match_all_offline_commands() {
    for capture_format in [Format::Pcap, Format::PcapNg] {
        let bytes = handshake_capture(capture_format);
        for (command, flags) in COMMANDS {
            let formats: &[&str] = match command {
                "read" => &["text", "ndjson", "hex"],
                "stats" => &["text", "json"],
                _ => &["text", "json", "ndjson"],
            };
            for format in formats {
                let output = assert_file_stdin_parity(&bytes, command, flags, format, 0);
                assert!(!output.stdout.is_empty(), "{command} {format}");
                if *format == "ndjson" {
                    let records = parse_ndjson(&output);
                    assert_contiguous(&records);
                    let is_complete = |record: &serde_json::Value| match command {
                        "expert" => record["result"].get("frames_read").is_some(),
                        "follow" => record["result"].get("frames").is_some(),
                        _ => record["result"]["event"] == "complete",
                    };
                    assert!(is_complete(records.last().unwrap()));
                    assert_eq!(
                        records.iter().filter(|record| is_complete(record)).count(),
                        1
                    );
                }
            }
        }
        assert_file_stdin_parity(
            &bytes,
            "read",
            &["--dissect", "--filter", "frame.number == 4"],
            "ndjson",
            0,
        );
        assert_file_stdin_parity(
            &bytes,
            "follow",
            &["--stream", "tcp:0", "--direction", "client"],
            "raw",
            0,
        );
    }
}

#[test]
fn piped_capture_rewrites_preserve_every_source_byte() {
    for (capture_format, output_format) in [(Format::Pcap, "pcap"), (Format::PcapNg, "pcapng")] {
        let bytes = handshake_capture(capture_format);
        let output = assert_file_stdin_parity(&bytes, "read", &[], output_format, 0);
        assert_eq!(output.stdout, bytes);
    }
}

#[test]
fn piped_filtered_capture_exports_match_files_and_keep_source_frame_numbers() {
    for (capture_format, output_format) in [(Format::Pcap, "pcap"), (Format::PcapNg, "pcapng")] {
        let bytes = handshake_capture(capture_format);
        let output = assert_file_stdin_parity(
            &bytes,
            "read",
            &["--filter", "frame.number == 4"],
            output_format,
            0,
        );
        let mut source = Reader::new(Cursor::new(&bytes)).unwrap();
        for _ in 0..3 {
            source.next_frame().unwrap().unwrap();
        }
        let expected = source.next_frame().unwrap().unwrap();
        let mut selected = Reader::new(Cursor::new(&output.stdout)).unwrap();
        assert_eq!(selected.next_frame().unwrap().unwrap(), expected);
        assert!(selected.next_frame().unwrap().is_none());
    }
}

#[test]
fn piped_missing_selectors_fail_after_consuming_the_capture() {
    for capture_format in [Format::Pcap, Format::PcapNg] {
        let bytes = handshake_capture(capture_format);
        for (command, selector) in [
            ("tls", "tcp:999"),
            ("follow", "tcp:999"),
            ("follow", "udp:999"),
        ] {
            for format in ["json", "ndjson"] {
                let output =
                    assert_file_stdin_parity(&bytes, command, &["--stream", selector], format, 2);
                assert!(
                    String::from_utf8_lossy(&output.stdout)
                        .contains(&format!("--stream {selector} is not present"))
                );
                if format == "ndjson" {
                    let records = parse_ndjson(&output);
                    assert_contiguous(&records);
                    assert_eq!(records.len(), 1);
                    assert_eq!(records[0]["status"], "error");
                }
            }
        }
    }
}

#[test]
fn piped_empty_malformed_and_truncated_input_keeps_file_errors() {
    let mut inputs = vec![Vec::new(), b"nope".to_vec(), vec![0xd4, 0xc3, 0xb2]];
    let mut partial = tempfile::NamedTempFile::new().unwrap();
    partial.write_all(&handshake_capture(Format::Pcap)).unwrap();
    append_truncated_record(&mut partial);
    inputs.push(std::fs::read(partial.path()).unwrap());
    for capture_format in [Format::Pcap, Format::PcapNg] {
        let mut bytes = handshake_capture(capture_format);
        bytes.pop();
        inputs.push(bytes);
    }
    for bytes in inputs {
        for (command, flags) in COMMANDS {
            let format = if command == "stats" { "json" } else { "ndjson" };
            let output = assert_file_stdin_parity(&bytes, command, flags, format, 3);
            if format == "ndjson" {
                let records = parse_ndjson(&output);
                assert_contiguous(&records);
                assert_eq!(records.last().unwrap()["status"], "error");
                assert!(
                    !records
                        .iter()
                        .any(|record| record["result"]["event"] == "complete")
                );
            }
        }
    }
}

#[test]
fn piped_empty_containers_complete_or_report_absent_selectors() {
    for capture_format in [Format::Pcap, Format::PcapNg] {
        let mut bytes = Vec::new();
        Writer::new(&mut bytes, capture_format, LinkType::IPV4)
            .unwrap()
            .flush()
            .unwrap();
        for (command, flags) in COMMANDS {
            let format = if command == "stats" { "json" } else { "ndjson" };
            let exit_code = if command == "follow" { 2 } else { 0 };
            assert_file_stdin_parity(&bytes, command, flags, format, exit_code);
        }
        assert_file_stdin_parity(&bytes, "tls", &["--stream", "tcp:0"], "ndjson", 2);
        assert_file_stdin_parity(&bytes, "follow", &["--stream", "udp:0"], "ndjson", 2);
    }
}

#[test]
fn piped_captures_keep_frame_byte_and_per_item_limits() {
    for capture_format in [Format::Pcap, Format::PcapNg] {
        let bytes = handshake_capture(capture_format);
        let mut reader = Reader::new(Cursor::new(&bytes)).unwrap();
        let mut total_bytes = 0;
        while let Some(frame) = reader.next_frame().unwrap() {
            total_bytes += frame.bytes().len();
        }
        let max_bytes = (total_bytes - 1).to_string();
        for (command, flags) in COMMANDS {
            for limits in [
                &["--max-frames", "1"][..],
                &["--max-bytes", &max_bytes, "--max-frame-bytes", &max_bytes][..],
                &["--max-frame-bytes", "32"][..],
            ] {
                let mut flags = flags.to_vec();
                flags.extend_from_slice(limits);
                let format = if command == "stats" { "json" } else { "ndjson" };
                assert_file_stdin_parity(&bytes, command, &flags, format, 6);
            }
        }
    }
}

#[test]
fn piped_pcapng_keeps_interface_limits() {
    let mut bytes = Vec::new();
    {
        let mut writer = Writer::new(&mut bytes, Format::PcapNg, LinkType::IPV4).unwrap();
        writer.add_interface(LinkType::IPV6).unwrap();
        writer.flush().unwrap();
    }
    for (command, flags) in COMMANDS {
        let mut flags = flags.to_vec();
        flags.extend_from_slice(&["--max-interfaces", "1"]);
        let format = if command == "stats" { "json" } else { "ndjson" };
        assert_file_stdin_parity(&bytes, command, &flags, format, 6);
    }
}

#[test]
fn piped_captures_keep_analysis_flow_limits() {
    for capture_format in [Format::Pcap, Format::PcapNg] {
        let mut bytes = Vec::new();
        {
            let mut writer = Writer::new(&mut bytes, capture_format, LinkType::IPV4).unwrap();
            for hex in [
                "450000210000000040118e95c0000201c633640230390009000d000068656c6c6f",
                "450000210000000040118e95c0000201c63364023039000a000d000068656c6c6f",
            ] {
                let frame =
                    Frame::new(std::time::UNIX_EPOCH, LinkType::IPV4, decode_hex(hex)).unwrap();
                writer.write_frame(&frame).unwrap();
            }
            writer.flush().unwrap();
        }
        for (command, flags) in COMMANDS
            .into_iter()
            .filter(|(command, _)| *command != "read")
        {
            let mut flags = flags.to_vec();
            flags.extend_from_slice(&["--max-flows", "1"]);
            assert_file_stdin_parity(&bytes, command, &flags, "json", 6);
        }
    }
}
