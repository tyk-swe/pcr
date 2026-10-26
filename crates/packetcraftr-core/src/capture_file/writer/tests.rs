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
        timestamp(seconds, nanoseconds),
        LinkType::ETHERNET,
        vec![fill; length],
    )
    .unwrap()
}

fn truncated_frame(seconds: u64, nanoseconds: u32, fill: u8, captured: usize) -> Frame {
    let captured_length = u32::try_from(captured).unwrap();
    Frame::try_with_lengths(
        timestamp(seconds, nanoseconds),
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
    let mut reader = Reader::new(Cursor::new(bytes)).unwrap();
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
fn pcap_frames_read_back_equal_to_the_frames_written() {
    let expected = vec![
        frame(1_700_000_000, 123_456_789, 0x11, 60),
        truncated_frame(1_700_000_001, 987_654_321, 0x22, 14),
        frame(1_700_000_002, 1, 0x33, 0),
    ];
    let mut writer = Writer::pcap(Vec::new(), LinkType::ETHERNET).unwrap();
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
fn pcapng_frames_read_back_with_the_written_bytes_link_type_and_timestamps() {
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

    let mut reader = Reader::new(Cursor::new(writer.into_inner())).unwrap();
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
fn stream_limits_accept_frames_up_to_the_limit_and_reject_the_next_without_writing_it() {
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
