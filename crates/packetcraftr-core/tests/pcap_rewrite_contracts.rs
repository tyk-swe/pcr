// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod common;

use common::pcap::{frame_at, pcap_bytes};
use std::io::{self, Cursor, Write};
use std::time::{Duration, SystemTime};

use packetcraftr_core::analysis::pcap::{
    Endianness, Error, Format, Limits, PcapOptions, Reader, Writer, map_frames, rewrite,
};
use packetcraftr_core::error::{Classified, Kind};
use packetcraftr_core::frame::{Frame, Lengths, LinkType};

#[derive(Debug)]
struct FailAfter {
    bytes: Vec<u8>,
    remaining: usize,
}

impl Write for FailAfter {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        if self.remaining == 0 {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "fixture failure"));
        }
        let written = input.len().min(self.remaining);
        self.bytes.extend_from_slice(&input[..written]);
        self.remaining -= written;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn an_output_failure_poisons_future_writer_operations() {
    let output = FailAfter {
        bytes: Vec::new(),
        remaining: 28,
    };
    let mut writer = Writer::pcap(output, LinkType::ETHERNET).expect("header fits");
    let frame = frame_at(SystemTime::UNIX_EPOCH, LinkType::ETHERNET, b"abc");
    let first = writer.write_frame(&frame).expect_err("record must fail");
    assert!(matches!(first, Error::Io(ref error) if error.kind() == io::ErrorKind::BrokenPipe));
    assert_eq!(writer.frames_written(), 0);
    assert_eq!(writer.captured_bytes_written(), 0);
    assert!(matches!(
        writer.write_frame(&frame),
        Err(Error::Io(ref error)) if error.kind() == io::ErrorKind::BrokenPipe
    ));
    assert!(matches!(
        writer.flush(),
        Err(Error::Io(ref error)) if error.kind() == io::ErrorKind::BrokenPipe
    ));
    assert_eq!(writer.get_ref().bytes.len(), 28);
    assert_eq!(writer.get_mut().remaining, 0);
}

#[test]
fn rewrite_is_same_format_and_enforces_stream_bounds() {
    let frames = [
        frame_at(SystemTime::UNIX_EPOCH, LinkType::ETHERNET, b"one"),
        frame_at(
            SystemTime::UNIX_EPOCH + Duration::from_secs(1),
            LinkType::ETHERNET,
            b"two",
        ),
    ];
    let pcap = pcap_bytes(
        PcapOptions {
            endianness: Endianness::Big,
            ..PcapOptions::default()
        },
        &frames,
    );
    let mut source = Reader::new(Cursor::new(pcap.clone())).expect("source opens");
    let (copy, report) = rewrite(
        &mut source,
        Vec::new(),
        Limits {
            max_frames: 2,
            max_bytes: 6,
        },
    )
    .expect("classic copy works");
    assert_eq!(report.format, Format::Pcap);
    assert_eq!(report.frames, 2);
    assert_eq!(report.captured_bytes, 6);
    assert_eq!(report.interfaces, 1);
    assert_eq!(
        Reader::new(Cursor::new(copy))
            .expect("copy opens")
            .endianness(),
        Endianness::Big
    );

    let mut source = Reader::new(Cursor::new(pcap)).expect("source opens");
    assert!(matches!(
        rewrite(
            &mut source,
            Vec::new(),
            Limits {
                max_frames: 1,
                max_bytes: 99,
            }
        ),
        Err(Error::FrameLimitExceeded {
            actual: 2,
            limit: 1
        })
    ));

    let pcapng = Writer::new(Vec::new(), Format::PcapNg, LinkType::ETHERNET)
        .expect("pcapng initializes")
        .into_inner();
    let mut source = Reader::new(Cursor::new(pcapng.clone())).expect("pcapng opens");
    let (copy, report) =
        rewrite(&mut source, Vec::new(), Limits::default()).expect("pcapng rewrite remains pcapng");
    assert_eq!(copy, pcapng);
    assert_eq!(report.format, Format::PcapNg);
}

#[test]
fn map_frames_counts_length_changes_and_keeps_unchanged_frames_out_of_the_count() {
    let frames = [
        Frame::try_with_lengths(
            SystemTime::UNIX_EPOCH,
            LinkType::ETHERNET,
            Lengths {
                captured: 2,
                original: 2,
            },
            b"ab".as_slice(),
        )
        .expect("first frame lengths are valid"),
        Frame::try_with_lengths(
            SystemTime::UNIX_EPOCH + Duration::from_secs(1),
            LinkType::ETHERNET,
            Lengths {
                captured: 2,
                original: 2,
            },
            b"cd".as_slice(),
        )
        .expect("second frame lengths are valid"),
    ];
    let mut input = Writer::pcapng(Vec::new()).expect("pcapng input initializes");
    for frame in &frames {
        input.write_frame(frame).expect("input frame writes");
    }
    let mut reader = Reader::new(Cursor::new(input.into_inner())).expect("input opens");
    let mut output = Writer::pcapng(Vec::new()).expect("pcapng output initializes");

    let report = map_frames(
        &mut reader,
        &mut output,
        Limits::default(),
        0,
        |number, frame| {
            let original = if number == 1 {
                frame.original_length() + 1
            } else {
                frame.original_length()
            };
            let mut mapped = Frame::try_with_optional_timestamp(
                frame.timestamp,
                frame.link_type,
                Lengths {
                    captured: frame.captured_length(),
                    original,
                },
                frame.bytes().clone(),
            )
            .expect("mapped lengths are valid");
            mapped.interface = frame.interface;
            mapped.direction = frame.direction;
            Ok(mapped)
        },
    )
    .expect("length-only mapping succeeds");

    assert_eq!(report.frames_read, 2);
    assert_eq!(report.frames_changed, 1);

    let mut output_reader = Reader::new(Cursor::new(output.into_inner())).expect("output opens");
    let mapped_frames = [
        output_reader
            .next_frame()
            .expect("first output frame is valid")
            .expect("first output frame exists"),
        output_reader
            .next_frame()
            .expect("second output frame is valid")
            .expect("second output frame exists"),
    ];
    assert_eq!(mapped_frames[0].bytes(), frames[0].bytes());
    assert_eq!(
        mapped_frames[0].captured_length(),
        frames[0].captured_length()
    );
    assert_eq!(mapped_frames[0].original_length(), 3);
    assert_eq!(mapped_frames[1].bytes(), frames[1].bytes());
    assert_eq!(
        mapped_frames[1].captured_length(),
        frames[1].captured_length()
    );
    assert_eq!(
        mapped_frames[1].original_length(),
        frames[1].original_length()
    );
}

#[test]
fn capture_errors_expose_stable_classifications_and_causes() {
    let policy = Error::MetadataBlockLimit { limit: 1 }.classification();
    assert_eq!(policy.kind, Kind::Policy);
    assert_eq!(policy.code, "policy.capture_stream_limit");
    let cli = Error::InvalidTimestampResolution {
        base: 10,
        exponent: 2,
    }
    .classification();
    assert_eq!(cli.kind, Kind::Cli);
    let io = Error::Io(io::Error::other("disk gone"));
    assert_eq!(io.classification().kind, Kind::Io);
    assert_eq!(io.causes(), vec!["disk gone"]);
    assert!(Error::EmptyInput.causes().is_empty());
}

#[test]
fn selection_validates_rejected_input_and_preserves_predicate_failures() {
    use packetcraftr_core::analysis::pcap::{SelectionError, select};
    use packetcraftr_core::error::{BoundaryError, Classification, Coordinate};
    let frame = frame_at(SystemTime::UNIX_EPOCH, LinkType::ETHERNET, b"one");
    let frames = [frame.clone(), frame];
    let input = pcap_bytes(PcapOptions::default(), &frames);
    for limits in [
        Limits {
            max_frames: 1,
            max_bytes: 99,
        },
        Limits {
            max_frames: 99,
            max_bytes: 3,
        },
    ] {
        let mut reader = Reader::new(Cursor::new(&input)).unwrap();
        let mut visited = 0;
        let error = select(&mut reader, Vec::new(), limits, |_, _| {
            visited += 1;
            Ok(false)
        })
        .unwrap_err();
        assert_eq!(error.classification().kind, Kind::Policy);
        assert_eq!(visited, 1);
    }
    let mut malformed = input.clone();
    malformed.push(0);
    let mut reader = Reader::new(Cursor::new(malformed)).unwrap();
    let error = select(&mut reader, Vec::new(), Limits::default(), |_, _| Ok(false)).unwrap_err();
    assert!(matches!(
        error,
        SelectionError::Capture(Error::Truncated { .. })
    ));
    let mut reader = Reader::new(Cursor::new(input)).unwrap();
    let error = select(&mut reader, Vec::new(), Limits::default(), |number, _| {
        if number == 1 {
            return Ok(false);
        }
        Err(BoundaryError::new(
            "predicate failed",
            Classification::new("fixture.policy", Kind::Policy, None),
            vec!["root cause".into()],
        ))
    })
    .unwrap_err();
    assert_eq!(error.classification().code, "fixture.policy");
    assert_eq!(error.context(), Some(Coordinate::SourceFrame(2)));
    assert_eq!(error.causes(), ["predicate failed", "root cause"]);
}

#[test]
fn selection_stops_on_write_and_flush_failures() {
    use packetcraftr_core::analysis::pcap::select;
    #[derive(Debug)]
    struct FlushFailure;
    impl Write for FlushFailure {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::other("flush failed"))
        }
    }
    let frame = frame_at(SystemTime::UNIX_EPOCH, LinkType::ETHERNET, b"one");
    let input = pcap_bytes(PcapOptions::default(), &[frame.clone(), frame]);
    let mut reader = Reader::new(Cursor::new(&input)).unwrap();
    let mut visited = 0;
    let error = select(
        &mut reader,
        FailAfter {
            bytes: Vec::new(),
            remaining: 24,
        },
        Limits::default(),
        |_, _| {
            visited += 1;
            Ok(true)
        },
    )
    .unwrap_err();
    assert_eq!(visited, 1);
    assert_eq!(error.classification().code, "io.capture_file");
    let mut reader = Reader::new(Cursor::new(input)).unwrap();
    let error = select(&mut reader, FlushFailure, Limits::default(), |_, _| {
        Ok(false)
    })
    .unwrap_err();
    assert_eq!(error.classification().kind, Kind::Io);
    assert!(error.to_string().contains("flush failed"));
}
