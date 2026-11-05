// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::io::Cursor;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::Writer;
use crate::capture_file::{
    DEFAULT_MAX_STREAM_BYTES, DEFAULT_MAX_STREAM_FRAMES, Error, Format, Limits, PcapOptions, Reader,
};
use crate::frame::{Frame, Lengths, LinkType};

fn timestamp(seconds: u64, nanoseconds: u32) -> SystemTime {
    UNIX_EPOCH + Duration::new(seconds, nanoseconds)
}

fn frame(seconds: u64, nanoseconds: u32, fill: u8, length: usize) -> Frame {
    Frame::new(
        Some(timestamp(seconds, nanoseconds)),
        LinkType::ETHERNET,
        vec![fill; length],
    )
    .unwrap()
}

fn truncated_frame(seconds: u64, nanoseconds: u32, fill: u8, captured: usize) -> Frame {
    let captured_length = u32::try_from(captured).unwrap();
    Frame::try_with_optional_timestamp(
        Some(timestamp(seconds, nanoseconds)),
        LinkType::ETHERNET,
        Lengths {
            captured: captured_length,
            original: captured_length + 100,
        },
        vec![fill; captured],
    )
    .unwrap()
}

fn read_frames(bytes: Vec<u8>) -> (Format, Vec<Frame>) {
    let mut reader = Reader::with_limits(Cursor::new(bytes), Default::default()).unwrap();
    let format = reader.format();
    let mut frames = Vec::new();
    while let Some(frame) = reader.next_frame().unwrap() {
        frames.push(frame);
    }
    (format, frames)
}

fn assert_same_packet(actual: &Frame, expected: &Frame) {
    assert_eq!(actual.bytes(), expected.bytes());
    assert_eq!(actual.link_type, expected.link_type);
    assert_eq!(actual.timestamp, expected.timestamp);
    assert_eq!(actual.captured_length(), expected.captured_length());
    assert_eq!(actual.original_length(), expected.original_length());
}

#[test]
fn pcap_frames_round_trip() {
    let expected = vec![
        frame(1_700_000_000, 123_456_789, 0x11, 60),
        truncated_frame(1_700_000_001, 987_654_321, 0x22, 14),
        frame(1_700_000_002, 1, 0x33, 0),
    ];
    let mut writer =
        Writer::pcap_with_options(Vec::new(), LinkType::ETHERNET, Default::default()).unwrap();
    for frame in &expected {
        writer.write_frame(frame).unwrap();
    }
    let captured_bytes: u64 = expected
        .iter()
        .map(|frame| u64::from(frame.captured_length()))
        .sum();
    assert_eq!(writer.frames_written(), expected.len() as u64);
    assert_eq!(writer.captured_bytes_written(), captured_bytes);

    let (format, actual) = read_frames(writer.into_inner());
    assert_eq!(format, Format::Pcap);
    assert_eq!(actual, expected);
}

#[test]
fn pcapng_preserves_bytes_link_type_and_timestamps() {
    let expected = vec![
        frame(1_700_000_100, 123_456_789, 0x44, 61),
        truncated_frame(1_700_000_101, 987_654_321, 0x55, 15),
    ];
    let mut writer = Writer::new(Vec::new(), Format::PcapNg, LinkType::ETHERNET).unwrap();
    for frame in &expected {
        writer.write_frame(frame).unwrap();
    }
    let captured_bytes: u64 = expected
        .iter()
        .map(|frame| u64::from(frame.captured_length()))
        .sum();
    assert_eq!(writer.frames_written(), expected.len() as u64);
    assert_eq!(writer.captured_bytes_written(), captured_bytes);

    let mut reader =
        Reader::with_limits(Cursor::new(writer.into_inner()), Default::default()).unwrap();
    assert_eq!(reader.format(), Format::PcapNg);
    let mut actual = Vec::new();
    while let Some(frame) = reader.next_frame().unwrap() {
        actual.push(frame);
    }
    assert_eq!(actual.len(), expected.len());
    for (actual, expected) in actual.iter().zip(&expected) {
        assert_same_packet(actual, expected);
        assert_eq!(actual.interface, Some(0));
        assert_eq!(actual.direction, None);
    }
    assert_eq!(reader.interfaces().len(), 1);
    assert_eq!(reader.interfaces()[0].link_type, LinkType::ETHERNET);
}

#[test]
fn stream_limits_reject_excess_before_writing() {
    let frames = [
        frame(1_700_000_200, 0, 0x66, 20),
        frame(1_700_000_201, 0, 0x77, 30),
        frame(1_700_000_202, 0, 0x88, 1),
    ];

    let frame_limit = Limits {
        max_frames: 2,
        max_bytes: DEFAULT_MAX_STREAM_BYTES,
    };
    let options = PcapOptions {
        stream_limits: frame_limit,
        ..PcapOptions::default()
    };
    let mut writer = Writer::pcap_with_options(Vec::new(), LinkType::ETHERNET, options).unwrap();
    writer.write_frame(&frames[0]).unwrap();
    writer.write_frame(&frames[1]).unwrap();
    assert!(matches!(
        writer.write_frame(&frames[2]),
        Err(Error::FrameLimitExceeded {
            actual: 3,
            limit: 2
        })
    ));
    assert_eq!(writer.frames_written(), 2);
    let (_, written) = read_frames(writer.into_inner());
    assert_eq!(written.as_slice(), &frames[..2]);

    let exact_bytes =
        u64::from(frames[0].captured_length()) + u64::from(frames[1].captured_length());
    let byte_limit = Limits {
        max_frames: DEFAULT_MAX_STREAM_FRAMES,
        max_bytes: exact_bytes,
    };
    let options = PcapOptions {
        stream_limits: byte_limit,
        ..PcapOptions::default()
    };
    let mut writer = Writer::pcap_with_options(Vec::new(), LinkType::ETHERNET, options).unwrap();
    writer.write_frame(&frames[0]).unwrap();
    writer.write_frame(&frames[1]).unwrap();
    assert_eq!(writer.captured_bytes_written(), exact_bytes);
    assert!(matches!(
        writer.write_frame(&frames[2]),
        Err(Error::StreamByteLimitExceeded { actual, limit })
            if actual == exact_bytes + 1 && limit == exact_bytes
    ));
    assert_eq!(writer.frames_written(), 2);
    assert_eq!(writer.captured_bytes_written(), exact_bytes);
}

#[test]
fn mapped_interface_speeds_keep_their_values_across_byte_orders() {
    use crate::capture_file::{
        Endianness, Interface, MetadataBlockKind, PcapNgOption, PcapNgOptions, RecordKind,
        TimestampResolution, map_frames,
    };

    let speed = 1_000_000_000_u64;
    for target_order in [Endianness::Little, Endianness::Big] {
        for code in [8, 16, 17] {
            let source = [Endianness::Little, Endianness::Big]
                .into_iter()
                .flat_map(|source_order| {
                    let mut writer = Writer::pcapng_with_options(
                        Vec::new(),
                        PcapNgOptions {
                            endianness: source_order,
                            ..Default::default()
                        },
                    )
                    .unwrap();
                    let speed_bytes = match source_order {
                        Endianness::Little => speed.to_le_bytes(),
                        Endianness::Big => speed.to_be_bytes(),
                    };
                    writer
                        .add_interface_description_with_options(
                            Interface {
                                link_type: LinkType::ETHERNET,
                                snap_len: 65_535,
                                timestamp_resolution: TimestampResolution::Decimal(9),
                                timestamp_offset: 0,
                            },
                            &[
                                PcapNgOption {
                                    code,
                                    value: speed_bytes.to_vec().into(),
                                },
                                PcapNgOption {
                                    code: 7,
                                    value: vec![2, 3, 4, 5, 6, 7, 8, 9].into(),
                                },
                            ],
                        )
                        .unwrap();
                    writer.write_frame(&frame(1, 0, 0x11, 60)).unwrap();
                    writer.into_inner()
                })
                .collect::<Vec<_>>();
            let mut reader = Reader::with_limits(Cursor::new(source), Default::default()).unwrap();
            let mut writer = Writer::pcapng_with_options(
                Vec::new(),
                PcapNgOptions {
                    endianness: target_order,
                    ..Default::default()
                },
            )
            .unwrap();
            let report = map_frames(
                &mut reader,
                &mut writer,
                Limits::default(),
                0,
                |_, frame| Ok(frame.clone()),
            )
            .unwrap();
            assert_eq!(report.frames_read, 2);
            let output = writer.into_inner();
            let mut reader = Reader::with_limits(Cursor::new(output), Default::default()).unwrap();
            let mut interfaces = 0;
            while let Some(record) = reader.next_record().unwrap() {
                if let RecordKind::Metadata(MetadataBlockKind::InterfaceDescription {
                    options,
                    ..
                }) = record.kind
                {
                    let value: [u8; 8] = options
                        .iter()
                        .find(|option| option.code == code)
                        .unwrap()
                        .value
                        .as_ref()
                        .try_into()
                        .unwrap();
                    let actual = match reader.endianness() {
                        Endianness::Little => u64::from_le_bytes(value),
                        Endianness::Big => u64::from_be_bytes(value),
                    };
                    assert_eq!(actual, speed, "interface {interfaces}, option {code}");
                    assert_eq!(
                        options
                            .iter()
                            .find(|option| option.code == 7)
                            .unwrap()
                            .value
                            .as_ref(),
                        [2, 3, 4, 5, 6, 7, 8, 9]
                    );
                    interfaces += 1;
                }
            }
            assert_eq!(interfaces, 2);
        }
    }
}
