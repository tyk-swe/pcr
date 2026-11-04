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
fn empty_captures_yield_zero_frames() {
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
fn truncation_errors_after_complete_frames() {
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
fn corrupt_inputs_yield_no_frames() {
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
fn reader_limits_enforce_exact_boundaries() {
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

#[test]
fn buffered_readback_preserves_semantics() {
    use std::cell::Cell;
    use std::io::{BufReader, Read, Seek, SeekFrom};
    use std::rc::Rc;

    struct Counted {
        input: Cursor<Vec<u8>>,
        reads: Rc<Cell<usize>>,
    }

    impl Read for Counted {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            self.reads.set(self.reads.get() + 1);
            self.input.read(buffer)
        }
    }

    impl Seek for Counted {
        fn seek(&mut self, position: SeekFrom) -> std::io::Result<u64> {
            self.input.seek(position)
        }
    }

    for format in [Format::Pcap, Format::PcapNg] {
        let frames = (0..1000)
            .map(|index| frame(index, 0, u8::try_from(index % 256).unwrap(), 64))
            .collect::<Vec<_>>();
        let bytes = capture(format, &frames);
        let direct_reads = Rc::new(Cell::new(0));
        let buffered_reads = Rc::new(Cell::new(0));
        let counted = |reads: Rc<Cell<usize>>, input: Vec<u8>| Counted {
            input: Cursor::new(input),
            reads,
        };
        let mut direct = Reader::with_limits(
            counted(Rc::clone(&direct_reads), bytes.clone()),
            Default::default(),
        )
        .unwrap();
        let mut buffered = Reader::with_limits(
            BufReader::with_capacity(
                64 * 1024,
                counted(Rc::clone(&buffered_reads), bytes.clone()),
            ),
            Default::default(),
        )
        .unwrap();
        for expected in &frames {
            let direct_frame = direct.next_frame().unwrap().unwrap();
            assert_eq!(direct_frame.bytes(), expected.bytes());
            assert_eq!(buffered.next_frame().unwrap(), Some(direct_frame));
        }
        assert_eq!(direct.next_frame().unwrap(), None);
        assert_eq!(buffered.next_frame().unwrap(), None);
        assert!(buffered_reads.get() * 10 < direct_reads.get());
        direct.rewind().unwrap();
        buffered.rewind().unwrap();
        assert_eq!(buffered.next_frame().unwrap(), direct.next_frame().unwrap());

        let mut truncated = bytes;
        truncated.truncate(truncated.len() - 1);
        let mut direct =
            Reader::with_limits(Cursor::new(truncated.clone()), Default::default()).unwrap();
        let mut buffered =
            Reader::with_limits(BufReader::new(Cursor::new(truncated)), Default::default())
                .unwrap();
        for _ in 0..frames.len() - 1 {
            assert_eq!(direct.next_frame().unwrap(), buffered.next_frame().unwrap());
        }
        assert_eq!(
            direct.next_frame().unwrap_err().to_string(),
            buffered.next_frame().unwrap_err().to_string()
        );

        let cancellation = crate::budget::Cancellation::default();
        let mut reader = Reader::with_limits(
            BufReader::new(Cursor::new(capture(format, &frames))),
            Default::default(),
        )
        .unwrap()
        .with_cancellation(cancellation.clone());
        assert!(reader.next_frame().unwrap().is_some());
        cancellation.cancel();
        assert!(matches!(reader.next_frame(), Err(Error::Cancelled(_))));
        assert!(matches!(reader.rewind(), Err(Error::Cancelled(_))));
    }
}
