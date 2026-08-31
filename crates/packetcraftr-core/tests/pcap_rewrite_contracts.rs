// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
// Test code indexes fixtures and counts by hand; the fail-closed lints are
// for library paths.
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::io::{self, Cursor, Write};
use std::time::{Duration, SystemTime};

use packetcraftr_core::analysis::pcap::{
    Endianness, Error, Format, Limits, PcapOptions, Reader, Writer, rewrite,
};
use packetcraftr_core::error::{Classified, Kind};
use packetcraftr_core::frame::{Frame, LinkType};

fn frame_at(timestamp: SystemTime, link_type: LinkType, bytes: &[u8]) -> Frame {
    Frame::new(timestamp, link_type, bytes.to_vec()).expect("fixture frame must be valid")
}

fn pcap_bytes(options: PcapOptions, frames: &[Frame]) -> Vec<u8> {
    let mut writer = Writer::pcap_with_options(Vec::new(), LinkType::ETHERNET, options)
        .expect("fixture writer must initialize");
    for frame in frames {
        writer.write_frame(frame).expect("fixture frame must write");
    }
    writer.into_inner()
}

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
