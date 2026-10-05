// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::io::{Cursor, Write};

use packetcraftr_core::capture_file::Format;
use packetcraftr_core::capture_file::Reader;
use packetcraftr_core::capture_file::Writer;

use crate::capture_support;
use crate::common;
use crate::process_support;

use capture_support::assert_file_stdin_parity;
use common::{assert_contiguous, parse_ndjson};
use process_support::append_truncated_record;

const COMMANDS: [(&str, &[&str]); 5] = [
    ("read", &[]),
    ("expert", &[]),
    ("follow", &["--stream", "tcp:0"]),
    ("stats", &[]),
    ("tls", &[]),
];

fn handshake_capture(format: Format) -> Vec<u8> {
    let source = include_bytes!("../../../../examples/captures/tls-handshake.pcapng");
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

#[test]
fn piped_empty_bad_trunc_input_file_errors() {
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
                assert!(!records.iter().any(|record| record["event"] == "complete"));
            }
        }
    }
}

#[test]
fn piped_captures_keep_frame_byte_item_limits() {
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
