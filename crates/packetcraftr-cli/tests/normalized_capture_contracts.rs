// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::io::{Cursor, Write};
use std::process::Output;
use std::time::{Duration, UNIX_EPOCH};

use bytes::Bytes;
use packetcraftr_core::capture_file::Format;
use packetcraftr_core::capture_file::Interface;
use packetcraftr_core::capture_file::PcapNgOption;
use packetcraftr_core::capture_file::Reader;
use packetcraftr_core::capture_file::TimestampResolution;
use packetcraftr_core::capture_file::Writer;
use packetcraftr_core::frame::Frame;
use packetcraftr_core::frame::LinkType;

#[path = "common/capture.rs"]
mod capture_support;
mod common;
#[path = "common/process.rs"]
mod process_support;

use capture_support::assert_file_stdin_parity;
use process_support::{append_truncated_record, decode_hex};

const FIRST_FRAGMENT: &str =
    "45000024002a200040116e68c0000201c63364029c40270f001800006162636465666768";
const LAST_FRAGMENT: &str = "4500001c002a000240118e6ec0000201c6336402696a6b6c6d6e6f70";

fn frame(hex: &str) -> Frame {
    Frame::new(
        UNIX_EPOCH + Duration::from_millis(1250),
        LinkType::IPV4,
        decode_hex(hex),
    )
    .unwrap()
}

fn capture(format: Format, frames: &[Frame]) -> Vec<u8> {
    let mut writer = Writer::new(Vec::new(), format, LinkType::IPV4).unwrap();
    for frame in frames {
        writer.write_frame(frame).unwrap();
    }
    writer.into_inner()
}

fn normalize(input: &[u8], flags: &[&str], expected_code: i32) -> Output {
    let mut arguments = vec!["--normalize"];
    arguments.extend_from_slice(flags);
    assert_file_stdin_parity(input, "read", &arguments, "pcapng", expected_code)
}

fn read_frames(bytes: &[u8]) -> (Vec<Frame>, Vec<Interface>) {
    let mut reader = Reader::new(Cursor::new(bytes)).unwrap();
    assert_eq!(reader.format(), Format::PcapNg);
    let mut frames = Vec::new();
    while let Some(frame) = reader.next_frame().unwrap() {
        frames.push(frame);
    }
    (frames, reader.interfaces().to_vec())
}

#[test]
fn normalization_enforces_input_accounting_and_output_block_and_interface_limits() {
    let input = capture(Format::Pcap, &[frame(FIRST_FRAGMENT), frame(LAST_FRAGMENT)]);
    for flags in [
        vec!["--filter", "frame.number == 99", "--max-frames", "1"],
        vec![
            "--filter",
            "frame.number == 99",
            "--max-bytes",
            "63",
            "--max-frame-bytes",
            "63",
        ],
        vec!["--filter", "frame.number == 99", "--max-frame-bytes", "32"],
        vec!["--max-frame-bytes", "64"],
    ] {
        let output = normalize(&input, &flags, 6);
        assert!(String::from_utf8_lossy(&output.stderr).contains("policy.capture_stream_limit"));
        assert!(read_frames(&output.stdout).0.is_empty());
    }
    let section = capture(Format::PcapNg, &[frame(FIRST_FRAGMENT)]);
    let input = [section.as_slice(), section.as_slice()].concat();
    let output = normalize(&input, &["--max-interfaces", "1"], 6);
    assert_eq!(read_frames(&output.stdout).0.len(), 1);
    let selected = normalize(
        &input,
        &["--max-interfaces", "1", "--filter", "frame.number == 2"],
        0,
    );
    assert_eq!(read_frames(&selected.stdout).1.len(), 1);
}

#[test]
fn normalization_fails_on_a_truncated_input_trailer_after_preserving_prior_frames() {
    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(&capture(Format::Pcap, &[frame(FIRST_FRAGMENT)]))
        .unwrap();
    append_truncated_record(&mut file);
    let output = normalize(&std::fs::read(file.path()).unwrap(), &[], 3);
    assert_eq!(read_frames(&output.stdout).0.len(), 1);
    assert!(String::from_utf8_lossy(&output.stderr).contains("truncated"));
}

fn classic_with_network_word(network: u32) -> Vec<u8> {
    let mut classic = capture(Format::Pcap, &[frame(FIRST_FRAGMENT)]);
    classic[20..24].copy_from_slice(&network.to_le_bytes());
    classic
}

fn pcapng_with_fcs_length(value: &'static [u8]) -> Vec<u8> {
    let mut writer = Writer::pcapng(Vec::new()).unwrap();
    writer
        .add_interface_description_with_options(
            Interface {
                link_type: LinkType::IPV4,
                snap_len: 65535,
                timestamp_resolution: TimestampResolution::Decimal(9),
                timestamp_offset: 0,
            },
            &[PcapNgOption {
                code: 13,
                value: Bytes::from_static(value),
            }],
        )
        .unwrap();
    writer.write_frame(&frame(FIRST_FRAGMENT)).unwrap();
    writer.into_inner()
}

#[test]
fn normalization_refuses_input_that_declares_a_frame_check_sequence() {
    // Bit 26 marks the FCS length as present and bits 28..=31 count its 16-bit words.
    let classic = classic_with_network_word(0x2400_0000 | LinkType::IPV4.0);
    let pcapng = pcapng_with_fcs_length(&[32]);
    for input in [classic, pcapng] {
        for flags in [&[][..], &["--filter", "frame.number == 99"][..]] {
            let output = normalize(&input, flags, 3);
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(
                stderr.contains("packet.capture_transform_metadata"),
                "{stderr}"
            );
            assert!(
                stderr.contains("cannot retain declared frame check sequence"),
                "{stderr}"
            );
            if !output.stdout.is_empty() {
                assert!(read_frames(&output.stdout).0.is_empty());
            }
        }
    }
}
