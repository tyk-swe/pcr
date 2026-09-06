// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
// Test code indexes fixtures and counts by hand; the fail-closed lints are
// for library paths.
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

mod common;

use common::pcap::{frame_at, pcap_bytes};
use std::io::{self, Cursor, Write};
use std::time::{Duration, SystemTime};

use packetcraftr_core::analysis::pcap::{
    Endianness, Error, Format, Limits, PcapOptions, Reader, Writer, rewrite,
};
use packetcraftr_core::error::{Classified, Kind};
use packetcraftr_core::frame::LinkType;

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
    assert_eq!(Format::Pcap.to_string(), "pcap");
    assert_eq!(Format::PcapNg.to_string(), "pcapng");
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
    let mut reader = Reader::new(Cursor::new(input)).unwrap();
    let error = select(&mut reader, FlushFailure, Limits::default(), |_, _| {
        Ok(false)
    })
    .unwrap_err();
    assert_eq!(error.classification().kind, Kind::Io);
    assert!(error.to_string().contains("flush failed"));
}
