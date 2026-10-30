// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::io::Cursor;
use std::time::{Duration, UNIX_EPOCH};

use super::Reader;
use crate::capture_file::{Error, Format, ReaderLimits, Writer};
use crate::frame::{Frame, LinkType};

fn frame(seconds: u64, nanoseconds: u32, fill: u8, length: usize) -> Frame {
    Frame::new(
        Some(UNIX_EPOCH + Duration::new(seconds, nanoseconds)),
        LinkType::ETHERNET,
        vec![fill; length],
    )
    .unwrap()
}

fn capture(format: Format, frames: &[Frame]) -> Vec<u8> {
    let mut writer = Writer::new(Vec::new(), format, LinkType::ETHERNET).unwrap();
    for frame in frames {
        writer.write_frame(frame).unwrap();
    }
    writer.into_inner()
}

#[test]
fn empty_captures_read_back_with_zero_frames_in_both_formats() {
    for format in [Format::Pcap, Format::PcapNg] {
        let mut reader =
            Reader::with_limits(Cursor::new(capture(format, &[])), Default::default()).unwrap();
        assert_eq!(reader.format(), format);
        assert_eq!(reader.next_frame().unwrap(), None);
        assert_eq!(reader.next_frame().unwrap(), None);
        assert_eq!(reader.interfaces().len(), 1);
        assert_eq!(reader.interfaces()[0].link_type, LinkType::ETHERNET);
    }
}

#[test]
fn truncated_packet_data_errors_after_complete_frames_without_yielding_a_partial_frame() {
    let complete = frame(1_700_001_000, 123_456_789, 0x11, 32);
    let cut_short = frame(1_700_001_001, 987_654_321, 0x22, 32);
    let mut bytes = capture(Format::Pcap, &[complete.clone(), cut_short]);
    bytes.truncate(bytes.len() - 1);

    let mut reader = Reader::with_limits(Cursor::new(bytes), Default::default()).unwrap();
    assert_eq!(reader.next_frame().unwrap(), Some(complete));
    assert!(matches!(reader.next_frame(), Err(Error::Truncated { .. })));
    assert_eq!(reader.next_frame().unwrap(), None);
}

#[test]
fn corrupt_inputs_are_rejected_instead_of_yielding_frames() {
    assert!(matches!(
        Reader::with_limits(Cursor::new(Vec::new()), Default::default()),
        Err(Error::EmptyInput)
    ));

    let mut garbage = b"NOPE".to_vec();
    garbage.extend_from_slice(&[0; 20]);
    assert!(matches!(
        Reader::with_limits(Cursor::new(garbage), Default::default()),
        Err(Error::UnrecognizedFormat { magic }) if magic == *b"NOPE"
    ));

    let header = capture(Format::Pcap, &[]);
    assert!(matches!(
        Reader::with_limits(Cursor::new(header[..10].to_vec()), Default::default()),
        Err(Error::Truncated { .. })
    ));

    let written = frame(1_700_001_100, 123_456_789, 0x33, 40);
    let mut bytes = capture(Format::PcapNg, &[written]);
    let footer = bytes.len() - 4;
    bytes[footer] ^= 0x01;
    let mut reader = Reader::with_limits(Cursor::new(bytes), Default::default()).unwrap();
    assert!(matches!(
        reader.next_frame(),
        Err(Error::BlockLengthMismatch { .. })
    ));
    assert_eq!(reader.next_frame().unwrap(), None);
}

#[test]
fn reader_limits_accept_input_at_the_limit_and_reject_input_past_it() {
    let written = frame(1_700_001_200, 123_456_789, 0x44, 48);
    let bytes = capture(Format::Pcap, std::slice::from_ref(&written));
    let limit = written.bytes().len();

    let at_limit = ReaderLimits {
        max_size: limit,
        ..ReaderLimits::default()
    };
    let mut reader = Reader::with_limits(Cursor::new(bytes.clone()), at_limit).unwrap();
    assert_eq!(reader.next_frame().unwrap(), Some(written));

    let below_packet = ReaderLimits {
        max_size: limit - 1,
        ..ReaderLimits::default()
    };
    let mut reader = Reader::with_limits(Cursor::new(bytes), below_packet).unwrap();
    assert!(matches!(
        reader.next_frame(),
        Err(Error::SizeLimitExceeded { declared, limit: rejected, .. })
            if declared == limit as u64 && rejected == limit - 1
    ));

    let no_interfaces = ReaderLimits {
        max_total_interfaces: 0,
        ..ReaderLimits::default()
    };
    assert!(matches!(
        Reader::with_limits(Cursor::new(capture(Format::Pcap, &[])), no_interfaces),
        Err(Error::TotalInterfaceLimit { limit: 0 })
    ));
    let one_interface = ReaderLimits {
        max_total_interfaces: 1,
        ..ReaderLimits::default()
    };
    assert!(Reader::with_limits(Cursor::new(capture(Format::Pcap, &[])), one_interface).is_ok());
}
