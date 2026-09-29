// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
#![allow(dead_code)]

// Classic PCAP and pcapng fixtures and the file-versus-stdin parity runner. The
// including test crate root must also declare `common` and `process_support`.

use std::io::Write;
use std::path::Path;
use std::process::Output;

use packetcraftr_core::capture_file::{Interface, TimestampResolution, Writer};
use packetcraftr_core::frame::{Frame, LinkType};
use packetcraftr_core::layer::{Layer, Raw};
use packetcraftr_core::packet::Packet;
use packetcraftr_core::protocol::builtin;
use packetcraftr_core::protocol::link::Ethernet;
use packetcraftr_core::protocol::network::Ipv4;

use crate::common::{path_text, run};
use crate::process_support::{decode_hex, run_with_stdin};

/// 192.0.2.1:12345 → 198.51.100.2:9 UDP carrying "hello", TTL 64.
pub(crate) const UDP_CLIENT: &str =
    "450000210000000040118e95c0000201c633640230390009000d9f8868656c6c6f";
pub(crate) const UDP_SERVER: &str =
    "450000210000000040118e95c6336402c000020100093039000d957e776f726c64";
pub(crate) const TCP_CLIENT: &str =
    "4500002b0000000040068e96c0000201c63364023039005000000001000000005002ffffb7b80000676574";

const GLOBAL_HEADER: [u8; 24] = [
    0xd4, 0xc3, 0xb2, 0xa1, // little-endian microsecond PCAP
    2, 0, 4, 0, // version 2.4
    0, 0, 0, 0, 0, 0, 0, 0, // timezone and timestamp accuracy
    0xff, 0xff, 0, 0, // snap length
    228, 0, 0, 0, // DLT_IPV4
];

/// One DLT_IPV4 record; `captured` may be shorter than the wire length.
pub(crate) struct Record {
    timestamp: (u32, u32),
    captured: Vec<u8>,
    original_length: usize,
}

impl Record {
    pub(crate) fn new(timestamp: (u32, u32), bytes: Vec<u8>) -> Self {
        let original_length = bytes.len();
        Self {
            timestamp,
            captured: bytes,
            original_length,
        }
    }

    /// Keeps the first `captured` bytes and records the full wire length.
    pub(crate) fn truncated(timestamp: (u32, u32), mut bytes: Vec<u8>, captured: usize) -> Self {
        let original_length = bytes.len();
        bytes.truncate(captured);
        Self {
            timestamp,
            captured: bytes,
            original_length,
        }
    }
}

pub(crate) fn write_records(records: &[Record]) -> tempfile::NamedTempFile {
    let mut file = tempfile::NamedTempFile::new().expect("temporary capture must open");
    file.write_all(&GLOBAL_HEADER)
        .expect("global header must write");
    for record in records {
        let (seconds, micros) = record.timestamp;
        let captured = u32::try_from(record.captured.len()).expect("fixture frame fits u32");
        let original = u32::try_from(record.original_length).expect("fixture frame fits u32");
        file.write_all(&seconds.to_le_bytes())
            .expect("timestamp seconds must write");
        file.write_all(&micros.to_le_bytes())
            .expect("timestamp fraction must write");
        file.write_all(&captured.to_le_bytes())
            .expect("captured length must write");
        file.write_all(&original.to_le_bytes())
            .expect("original length must write");
        file.write_all(&record.captured)
            .expect("frame bytes must write");
    }
    file.flush().expect("capture must flush");
    file
}

/// Stamps frame `n` at `n` seconds and 250 ms.
pub(crate) fn write_pcap(frames: &[Vec<u8>]) -> tempfile::NamedTempFile {
    let records = frames
        .iter()
        .enumerate()
        .map(|(index, bytes)| {
            let seconds = u32::try_from(index + 1).expect("fixture index fits u32");
            Record::new((seconds, 250_000), bytes.clone())
        })
        .collect::<Vec<_>>();
    write_records(&records)
}

pub(crate) fn write_pcap_hex(frames: &[&str]) -> tempfile::NamedTempFile {
    let frames = frames.iter().copied().map(decode_hex).collect::<Vec<_>>();
    write_pcap(&frames)
}

/// 192.0.2.1 → 198.51.100.2 carrying `transport` over `payload` bytes of 0x51.
pub(crate) fn ethernet_frame(transport: impl Layer, payload: usize) -> Frame {
    let mut packet = Packet::new();
    packet.push(Ethernet::default());
    packet.push(Ipv4 {
        source: "192.0.2.1".parse().expect("documentation source"),
        destination: "198.51.100.2".parse().expect("documentation target"),
        ..Ipv4::default()
    });
    packet.push(transport);
    packet.push(Raw::new(vec![0x51; payload]));
    let built = packetcraftr_core::build::Builder::new(builtin::registry())
        .build(packet, Default::default(), Default::default())
        .expect("fixture frame builds");
    Frame::new(std::time::UNIX_EPOCH, LinkType::ETHERNET, built.bytes).expect("valid frame")
}

/// One pcapng interface for `link_type`, then every frame in order.
pub(crate) fn write_pcapng(path: &Path, link_type: LinkType, frames: &[Frame]) {
    let mut writer = Writer::pcapng(Vec::new()).expect("pcapng writer must initialize");
    writer
        .add_interface_description(Interface {
            link_type,
            snap_len: 65535,
            timestamp_resolution: TimestampResolution::Decimal(6),
            timestamp_offset: 0,
        })
        .expect("interface description must write");
    for frame in frames {
        writer.write_frame(frame).expect("fixture frame must write");
    }
    std::fs::write(path, writer.into_inner()).expect("capture must write");
}

pub(crate) fn assert_file_stdin_parity(
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
