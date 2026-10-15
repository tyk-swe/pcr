// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! `capture_file::inspect` contracts: the metadata pass and its bounds.

use std::io::Cursor;

use packetcraftr_core::capture_file::{
    self, Endianness, Error, Limits, MAX_RETAINED_BLOCK_TYPES, Reader, inspect,
};

use crate::common::pcap;

fn reader(bytes: Vec<u8>) -> Reader<Cursor<Vec<u8>>> {
    Reader::new(Cursor::new(bytes)).expect("fixture capture opens")
}

fn pcapng_capture(blocks: &[Vec<u8>]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for block in blocks {
        bytes.extend_from_slice(block);
    }
    bytes
}

#[test]
fn named_interfaces_and_description_blocks_join_the_global_list() {
    let endianness = Endianness::Little;
    let mut options = pcap::option(endianness, 2, b"eth0");
    options.extend_from_slice(&pcap::option(endianness, 3, b"uplink"));
    let capture = pcapng_capture(&[
        pcap::section_header(endianness, 1, 0, -1, &[]),
        pcap::interface_block(endianness, 1, 65_535, &options),
        pcap::enhanced_packet_block(endianness, 0, 1, 4, &[0x51; 4], &[]),
    ]);
    let report = inspect::inspect(&mut reader(capture), Limits::default()).unwrap();
    assert_eq!(report.format, capture_file::Format::PcapNg);
    assert_eq!(report.pcapng_version, Some((1, 0)));
    assert_eq!(report.frames, 1);
    assert_eq!(report.interfaces.len(), 1);
    let interface = &report.interfaces[0];
    assert_eq!(interface.global_id, 0);
    assert_eq!(interface.section, Some(0));
    assert_eq!(interface.local_id, Some(0));
    assert_eq!(interface.snap_len, 65_535);
    assert_eq!(interface.name.as_deref(), Some("eth0"));
    assert_eq!(interface.description.as_deref(), Some("uplink"));
}

#[test]
fn unknown_block_types_are_counted_per_type_up_to_the_retention_bound() {
    let endianness = Endianness::Little;
    let mut blocks = vec![
        pcap::section_header(endianness, 1, 0, -1, &[]),
        pcap::interface_block(endianness, 1, 65_535, &[]),
    ];
    let unknown_start = 0x0000_1000;
    let distinct = u32::try_from(MAX_RETAINED_BLOCK_TYPES).unwrap() + 3;
    for block_type in unknown_start..unknown_start + distinct {
        blocks.push(pcap::block(endianness, block_type, &[0; 4]));
    }
    let report = inspect::inspect(&mut reader(pcapng_capture(&blocks)), Limits::default()).unwrap();
    // The first sixteen distinct types are retained; the last three are only counted.
    assert_eq!(report.unknown_blocks.len(), MAX_RETAINED_BLOCK_TYPES);
    assert_eq!(report.unknown_block_types_omitted, 3);
    assert_eq!(report.unknown_blocks.values().sum::<u64>(), 16);
}

#[test]
fn a_second_section_counts_and_keeps_its_interfaces_separate() {
    let endianness = Endianness::Little;
    let capture = pcapng_capture(&[
        pcap::section_header(endianness, 1, 0, -1, &[]),
        pcap::interface_block(endianness, 1, 65_535, &[]),
        pcap::section_header(endianness, 1, 0, -1, &[]),
        pcap::interface_block(endianness, 101, 1500, &[]),
        pcap::enhanced_packet_block(endianness, 0, 2, 4, &[0x51; 4], &[]),
    ]);
    let report = inspect::inspect(&mut reader(capture), Limits::default()).unwrap();
    assert_eq!(report.sections, 2);
    assert_eq!(report.interfaces.len(), 2);
    assert_eq!(report.interfaces[0].section, Some(0));
    assert_eq!(report.interfaces[1].section, Some(1));
    assert_eq!(report.interfaces[1].local_id, Some(0));
    assert_eq!(report.frames, 1);
}

#[test]
fn truncated_frames_are_counted_without_failing_the_pass() {
    let endianness = Endianness::Little;
    let capture = pcapng_capture(&[
        pcap::section_header(endianness, 1, 0, -1, &[]),
        pcap::interface_block(endianness, 1, 65_535, &[]),
        pcap::enhanced_packet_block(endianness, 0, 1, 32, &[0x51; 8], &[]),
    ]);
    let report = inspect::inspect(&mut reader(capture), Limits::default()).unwrap();
    assert_eq!(report.frames, 1);
    assert_eq!(report.captured_bytes, 8);
    assert_eq!(report.original_bytes, 32);
    assert_eq!(report.truncated_frames, 1);
}

#[test]
fn frame_ceiling_failures_report_nothing_and_byte_ceilings_too() {
    let endianness = Endianness::Little;
    let capture = pcapng_capture(&[
        pcap::section_header(endianness, 1, 0, -1, &[]),
        pcap::interface_block(endianness, 1, 65_535, &[]),
        pcap::enhanced_packet_block(endianness, 0, 1, 4, &[0x51; 4], &[]),
        pcap::enhanced_packet_block(endianness, 0, 2, 4, &[0x51; 4], &[]),
    ]);
    let error = inspect::inspect(
        &mut reader(capture.clone()),
        Limits {
            max_frames: 1,
            max_bytes: u64::MAX,
        },
    )
    .unwrap_err();
    assert!(matches!(error, Error::FrameLimitExceeded { .. }));
    let error = inspect::inspect(
        &mut reader(capture),
        Limits {
            max_frames: u64::MAX,
            max_bytes: 4,
        },
    )
    .unwrap_err();
    assert!(matches!(error, Error::StreamByteLimitExceeded { .. }));
}

#[test]
fn an_empty_capture_reports_no_timestamps_and_zero_frames() {
    let endianness = Endianness::Little;
    let capture = pcapng_capture(&[
        pcap::section_header(endianness, 1, 0, -1, &[]),
        pcap::interface_block(endianness, 1, 65_535, &[]),
    ]);
    let report = inspect::inspect(&mut reader(capture), Limits::default()).unwrap();
    assert_eq!(report.frames, 0);
    assert_eq!(report.first_timestamp, None);
    assert_eq!(report.last_timestamp, None);
    assert_eq!(report.interfaces.len(), 1);
}
