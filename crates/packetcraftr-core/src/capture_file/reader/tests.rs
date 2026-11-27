// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::io::{self, Cursor, Read};
use std::time::{Duration, UNIX_EPOCH};

use super::Reader;
use crate::capture_file::{Error, Format, ReaderLimits, Writer, compression};
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

struct FailOnce(Option<io::ErrorKind>);

impl Read for FailOnce {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        self.0.take().map_or(Ok(0), |kind| Err(kind.into()))
    }
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
fn capture_inputs_retry_interrupted_reads() {
    use std::io::Write;

    let expected = frame(1_700_001_000, 123_456_789, 0x11, 32);
    let bytes = capture(Format::Pcap, std::slice::from_ref(&expected));
    for format in [
        compression::Format::None,
        compression::Format::Gzip,
        compression::Format::Zstd,
    ] {
        let mut output = compression::Output::new(Vec::new(), format).unwrap();
        output.write_all(&bytes).unwrap();
        let encoded = output.finish().unwrap();
        let limits = compression::Limits {
            max_encoded_bytes: encoded.len() as u64,
            ..compression::Limits::default()
        };

        for offset in [4, encoded.len()] {
            let (before, after) = encoded.split_at(offset);
            let source = before
                .chain(FailOnce(Some(io::ErrorKind::Interrupted)))
                .chain(after);
            let input = compression::Input::new(source, limits).unwrap();
            let mut reader = Reader::with_limits(input, ReaderLimits::default()).unwrap();

            assert_eq!(reader.next_frame().unwrap().as_ref(), Some(&expected));
            assert_eq!(reader.next_frame().unwrap(), None);
        }
    }
}

#[test]
fn capture_inputs_report_other_read_errors() {
    let bytes = capture(Format::Pcap, &[]);
    let (magic, header) = bytes.split_at(4);
    let source = magic
        .chain(FailOnce(Some(io::ErrorKind::PermissionDenied)))
        .chain(header);
    let input = compression::Input::new(source, compression::Limits::default()).unwrap();

    assert!(matches!(
        Reader::with_limits(input, ReaderLimits::default()),
        Err(Error::Io(_))
    ));
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

struct InterruptingInput<F: FnMut()> {
    input: Cursor<Vec<u8>>,
    interrupt: F,
    fail: bool,
}

impl<F: FnMut()> std::io::Read for InterruptingInput<F> {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        (self.interrupt)();
        if self.fail {
            return Err(std::io::Error::other("input failed"));
        }
        std::io::Read::read(&mut self.input, output)
    }
}

impl<F: FnMut()> std::io::Seek for InterruptingInput<F> {
    fn seek(&mut self, position: std::io::SeekFrom) -> std::io::Result<u64> {
        std::io::Seek::seek(&mut self.input, position)
    }
}

#[test]
fn header_control_precedes_input_and_header_failures() {
    use crate::budget::{Cancellation, Deadline};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Instant;

    for format in [Format::Pcap, Format::PcapNg] {
        let cancellation = Cancellation::default();
        cancellation.cancel();
        let input = InterruptingInput {
            input: Cursor::new(capture(format, &[])),
            interrupt: || panic!("cancelled construction read input"),
            fail: false,
        };
        let control = Arc::new(Deadline::new(Duration::MAX).with_cancellation(Some(cancellation)));
        assert!(matches!(
            Reader::with_control(input, ReaderLimits::default(), Some(control)),
            Err(Error::Cancelled(_))
        ));
        for fail in [false, true] {
            for bytes in [capture(format, &[]), vec![0; 4]] {
                let cancellation = Cancellation::default();
                let control = Arc::new(
                    Deadline::new(Duration::MAX).with_cancellation(Some(cancellation.clone())),
                );
                let input = InterruptingInput {
                    input: Cursor::new(bytes.clone()),
                    interrupt: || cancellation.cancel(),
                    fail,
                };
                assert!(matches!(
                    Reader::with_control(input, ReaderLimits::default(), Some(control)),
                    Err(Error::Cancelled(_))
                ));

                let elapsed = Arc::new(AtomicU64::new(0));
                let now = elapsed.clone();
                let start = Instant::now();
                let control = Arc::new(Deadline::with_time_source(
                    Duration::from_secs(1),
                    move || start + Duration::from_secs(now.load(Ordering::Relaxed)),
                ));
                let input = InterruptingInput {
                    input: Cursor::new(bytes),
                    interrupt: || elapsed.store(2, Ordering::Relaxed),
                    fail,
                };
                assert!(matches!(
                    Reader::with_control(input, ReaderLimits::default(), Some(control)),
                    Err(Error::DurationLimit { .. })
                ));
            }
        }
    }
}

#[test]
fn rewind_preserves_independent_cancellation_and_stays_terminal_on_failure() {
    use crate::budget::Cancellation;
    use std::cell::Cell;

    for format in [Format::Pcap, Format::PcapNg] {
        let cancellation = Cancellation::default();
        let interrupt = Cell::new(false);
        let input = InterruptingInput {
            input: Cursor::new(capture(format, &[frame(0, 0, 1, 60)])),
            interrupt: || {
                if interrupt.get() {
                    cancellation.cancel();
                }
            },
            fail: false,
        };
        let mut reader = Reader::with_limits(input, ReaderLimits::default())
            .unwrap()
            .with_cancellation(cancellation.clone());
        interrupt.set(true);
        reader.get_mut().fail = true;
        assert!(matches!(reader.rewind(), Err(Error::Cancelled(_))));
        assert!(reader.next_record().unwrap().is_none());
    }
}

#[test]
fn selection_checks_metadata_runs_after_skipping_packets() {
    use crate::capture_file::{Limits, select};

    let first = capture(Format::PcapNg, &[frame(1, 0, 1, 32)]);
    let second = capture(Format::PcapNg, &[frame(2, 0, 2, 32)]);
    let bytes = [first, second].concat();
    let mut input = Reader::with_limits(bytes.as_slice(), ReaderLimits::default()).unwrap();
    let first_interface = input.next_record().unwrap().unwrap().raw_bytes().len();
    input.next_record().unwrap().unwrap();
    let second_section = input.next_record().unwrap().unwrap().raw_bytes().len();
    let second_interface = input.next_record().unwrap().unwrap().raw_bytes().len();
    let input_run = second_section + second_interface;

    for limits in [
        ReaderLimits {
            max_metadata_blocks_per_frame: 2,
            ..Default::default()
        },
        ReaderLimits {
            max_metadata_bytes_per_frame: input_run,
            ..Default::default()
        },
    ] {
        let mut input = Reader::with_limits(bytes.as_slice(), limits).unwrap();
        let (full, report) =
            select(&mut input, Vec::new(), Limits::default(), |_, _| Ok(true)).unwrap();
        assert_eq!(report.frames_selected, 2);
        let mut copied = Reader::with_limits(full.as_slice(), limits).unwrap();
        assert!(copied.next_frame().unwrap().is_some());
        assert!(copied.next_frame().unwrap().is_some());
        assert!(copied.next_frame().unwrap().is_none());

        let mut input = Reader::with_limits(bytes.as_slice(), limits).unwrap();
        let error = select(&mut input, Vec::new(), Limits::default(), |number, _| {
            Ok(number == 2)
        })
        .unwrap_err();
        match error {
            Error::MetadataBlockLimit { limit } => {
                assert_eq!(limit, limits.max_metadata_blocks_per_frame);
            }
            Error::MetadataByteLimit { limit } => {
                assert_eq!(limit, limits.max_metadata_bytes_per_frame);
            }
            other => panic!("unexpected selection error {other}"),
        }
    }

    let limits = ReaderLimits {
        max_metadata_blocks_per_frame: 3,
        max_metadata_bytes_per_frame: first_interface + input_run,
        ..Default::default()
    };
    let mut input = Reader::with_limits(bytes.as_slice(), limits).unwrap();
    let (subset, report) = select(&mut input, Vec::new(), Limits::default(), |number, _| {
        Ok(number == 2)
    })
    .unwrap();
    let mut copied = Reader::with_limits(subset.as_slice(), limits).unwrap();
    assert_eq!(report.metadata_records, 3);
    assert_eq!(
        copied.next_frame().unwrap().unwrap().bytes().as_ref(),
        &[2; 32]
    );
    assert!(copied.next_frame().unwrap().is_none());
}
