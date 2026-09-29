// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
mod common;
use common::pcap::{
    block, enhanced_packet_block, interface_block, obsolete_packet_block, option, section_header,
    simple_packet_block, words,
};
use packetcraftr_core::capture_file::{
    DedupLimits, Endianness, Limits, MetadataBlockKind, Reader, RecordKind, SplitLimits,
    SplitSelector, dedup, shift_time, split,
};
use std::{
    io::Cursor,
    time::{Duration, UNIX_EPOCH},
};
fn idb(endian: Endianness, precision: u8) -> Vec<u8> {
    let mut options = option(endian, 1, b"interface bytes");
    options.extend(option(endian, 9, &[precision]));
    options.extend(option(endian, 0, &[]));
    interface_block(endian, 1, 65535, &options)
}
fn section(endian: Endianness) -> Vec<u8> {
    let mut options = option(endian, 1, b"section bytes");
    options.extend(option(endian, 0, &[]));
    section_header(endian, 1, 0, -1, &options)
}
fn packet(endian: Endianness, interface: u32, ticks: u64, data: u8) -> Vec<u8> {
    let mut options = option(endian, 1, b"packet bytes");
    options.extend(option(endian, 0x7777, b"unknown"));
    options.extend(option(endian, 0, &[]));
    enhanced_packet_block(endian, interface, ticks, 1, &[data], &options)
}
fn statistics(endian: Endianness, ticks: u64) -> Vec<u8> {
    let mut body = words(endian, &[0, (ticks >> 32) as u32, ticks as u32]);
    body.extend(option(endian, 2, &words(endian, &[0, ticks as u32])));
    body.extend(option(endian, 3, &words(endian, &[0, ticks as u32 + 2])));
    body.extend(option(endian, 0x1234, b"unknown stats"));
    body.extend(option(endian, 0, &[]));
    block(endian, 5, &body)
}
fn raw_records(bytes: &[u8]) -> Vec<Vec<u8>> {
    let mut reader = Reader::new(Cursor::new(bytes)).unwrap();
    let mut records = Vec::new();
    while let Some(record) = reader.next_record().unwrap() {
        records.push(record.raw_bytes().to_vec());
    }
    records
}
#[test]
fn dedup_retains_raw_options_and_distinguishes_capture_interfaces_and_sections() {
    let endian = Endianness::Little;
    let mut source = section(endian);
    source.extend(idb(endian, 6));
    source.extend(idb(endian, 6));
    source.extend(packet(endian, 0, 1, 7));
    source.extend(packet(endian, 0, 2, 7));
    source.extend(packet(endian, 1, 3, 7));
    source.extend(statistics(endian, 4));
    source.extend(section(Endianness::Big));
    source.extend(idb(Endianness::Big, 6));
    source.extend(packet(Endianness::Big, 0, 5, 7));
    let (output, report) = dedup(
        &mut Reader::new(Cursor::new(&source)).unwrap(),
        Vec::new(),
        Limits::default(),
        DedupLimits::default(),
    )
    .unwrap();
    assert_eq!(report.duplicates, 1);
    assert_eq!(report.selection.frames_selected, 3);
    let expected = raw_records(&source)
        .into_iter()
        .enumerate()
        .filter(|(index, _)| *index != 3)
        .map(|(_, record)| record)
        .collect::<Vec<_>>();
    assert_eq!(raw_records(&output), expected);
    assert!(
        dedup(
            &mut Reader::new(Cursor::new(&source)).unwrap(),
            Vec::new(),
            Limits::default(),
            DedupLimits {
                window_frames: 1024,
                max_retained_bytes: 1
            }
        )
        .is_err()
    );
    let (_, report) = dedup(
        &mut Reader::new(Cursor::new(&source)).unwrap(),
        Vec::new(),
        Limits::default(),
        DedupLimits {
            window_frames: 1,
            max_retained_bytes: 512,
        },
    )
    .unwrap();
    assert_eq!(report.duplicates, 1);
}
#[test]
fn independently_readable_splits_keep_packet_record_bytes_in_mixed_endian_sections() {
    let little = Endianness::Little;
    let big = Endianness::Big;
    let mut source = section(little);
    source.extend(idb(little, 6));
    source.extend(packet(little, 0, 1_000_000, 7));
    source.extend(packet(little, 0, 2_000_000, 8));
    source.extend(section(big));
    source.extend(idb(big, 0x83));
    source.extend(packet(big, 0, 24, 9));
    source.extend(simple_packet_block(big, 1, &[10]));
    let (outputs, report) = split(
        &mut Reader::new(Cursor::new(&source)).unwrap(),
        Limits::default(),
        SplitSelector::Packets(1),
        SplitLimits::default(),
        |_| Ok(Vec::new()),
    )
    .unwrap();
    assert_eq!(report.frames_per_file, [1, 1, 1, 1]);
    let mut packets = Vec::new();
    for output in outputs {
        let mut reader = Reader::new(Cursor::new(&output)).unwrap();
        let mut count = 0;
        while let Some(record) = reader.next_record().unwrap() {
            if record.frame.is_some() {
                packets.push(record.raw_bytes().to_vec());
                count += 1;
            }
        }
        assert_eq!(count, 1);
    }
    let mut reader = Reader::new(Cursor::new(&source)).unwrap();
    let mut expected = Vec::new();
    while let Some(record) = reader.next_record().unwrap() {
        if record.frame.is_some() {
            expected.push(record.raw_bytes().to_vec());
        }
    }
    assert_eq!(packets, expected);
    assert!(
        split(
            &mut Reader::new(Cursor::new(&source)).unwrap(),
            Limits::default(),
            SplitSelector::Packets(1),
            SplitLimits { max_files: 3 },
            |_| Ok(Vec::new())
        )
        .is_err()
    );
    assert!(
        split(
            &mut Reader::new(Cursor::new(&source)).unwrap(),
            Limits::default(),
            SplitSelector::Interval(Duration::from_secs(1)),
            SplitLimits::default(),
            |_| Ok(Vec::new())
        )
        .is_err()
    );
}
#[test]
fn shift_changes_only_packet_and_known_statistics_timestamps_at_source_precision() {
    for endian in [Endianness::Little, Endianness::Big] {
        let mut source = section(endian);
        source.extend(idb(endian, 0x83));
        source.extend(packet(endian, 0, 16, 7));
        source.extend(obsolete_packet_block(endian, 0, 16, &[8], &[]));
        source.extend(simple_packet_block(endian, 1, &[9]));
        source.extend(statistics(endian, 16));
        let (output, report) = shift_time(
            &mut Reader::new(Cursor::new(&source)).unwrap(),
            Vec::new(),
            Limits::default(),
            "0.125".parse().unwrap(),
        )
        .unwrap();
        assert_eq!(report.shifted_packets, 2);
        assert_eq!(report.shifted_statistics, 1);
        let mut reader = Reader::new(Cursor::new(&output)).unwrap();
        let mut frames = Vec::new();
        while let Some(record) = reader.next_record().unwrap() {
            if let Some(frame) = record.frame {
                frames.push(frame);
            } else if matches!(
                record.kind,
                RecordKind::Metadata(MetadataBlockKind::InterfaceStatistics { .. })
            ) {
                assert_eq!(&record.raw_bytes()[16..20], words(endian, &[17]));
                assert_eq!(&record.raw_bytes()[28..32], words(endian, &[17]));
                assert_eq!(&record.raw_bytes()[40..44], words(endian, &[19]));
            }
        }
        assert_eq!(
            frames[0].timestamp,
            Some(UNIX_EPOCH + Duration::new(2, 125_000_000))
        );
        assert_eq!(frames[1].timestamp, frames[0].timestamp);
        assert_eq!(frames[2].timestamp, None);
        let original = raw_records(&source);
        let shifted = raw_records(&output);
        for (index, (mut before, mut after)) in original.into_iter().zip(shifted).enumerate() {
            match index {
                1 | 2 => {
                    before[12..20].fill(0);
                    after[12..20].fill(0);
                }
                4 => {
                    for range in [12..20, 24..32, 36..44] {
                        before[range.clone()].fill(0);
                        after[range].fill(0);
                    }
                }
                _ => {}
            }
            assert_eq!(before, after);
        }
        assert!(
            shift_time(
                &mut Reader::new(Cursor::new(&source)).unwrap(),
                Vec::new(),
                Limits::default(),
                "0.1".parse().unwrap()
            )
            .is_err()
        );
    }
}

#[test]
fn empty_packets_charge_retained_frame_metadata() {
    use packetcraftr_core::{
        capture_file::Writer,
        frame::{Frame, LinkType},
    };
    let mut writer = Writer::pcap(Vec::new(), LinkType::IPV4).unwrap();
    for second in 0..3 {
        writer
            .write_frame(
                &Frame::new(
                    UNIX_EPOCH + Duration::from_secs(second),
                    LinkType::IPV4,
                    Vec::new(),
                )
                .unwrap(),
            )
            .unwrap();
    }
    let source = writer.into_inner();
    assert!(
        dedup(
            &mut Reader::new(Cursor::new(&source)).unwrap(),
            Vec::new(),
            Limits::default(),
            DedupLimits {
                window_frames: usize::MAX,
                max_retained_bytes: 2 * size_of::<Frame>()
            }
        )
        .is_err()
    );
    let (_, report) = dedup(
        &mut Reader::new(Cursor::new(&source)).unwrap(),
        Vec::new(),
        Limits::default(),
        DedupLimits {
            window_frames: 2,
            max_retained_bytes: 2 * size_of::<Frame>(),
        },
    )
    .unwrap();
    assert_eq!(report.duplicates, 2);
}
