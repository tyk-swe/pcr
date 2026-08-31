// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::io::Cursor;
use std::time::UNIX_EPOCH;

use packetcraftr::analysis::pcap::Reader;
use packetcraftr::core::frame::LinkType;

use super::*;

fn frame(link_type: LinkType, bytes: Vec<u8>) -> Frame {
    Frame::new(UNIX_EPOCH, link_type, bytes).expect("valid fixture frame")
}

fn old_encode(format: Format, frames: Vec<Frame>) -> Vec<u8> {
    let mut frames = frames.into_iter();
    let first = frames.next().expect("nonempty fixture");
    let writer = match format {
        Format::Pcap => Writer::new(Vec::new(), format, first.link_type),
        Format::PcapNg => Writer::pcapng(Vec::new()),
    }
    .expect("memory writer");
    let mut output = LinkCaptureWriter::new(writer);
    for frame in std::iter::once(first).chain(frames) {
        output.write_link_mapped(frame).expect("encodable frame");
    }
    output.into_inner()
}

fn render(format: Format, frames: Vec<Frame>) -> Result<Vec<u8>, CliError> {
    let mut destination = Vec::new();
    write_capture_file_with(
        format,
        frames,
        || Ok(Box::new(Cursor::new(Vec::new()))),
        &mut destination,
    )?;
    Ok(destination)
}

#[test]
fn empty_capture_is_rejected_before_spool_creation() {
    let mut created = false;
    let error = write_capture_file_with(
        Format::Pcap,
        Vec::new(),
        || {
            created = true;
            Ok(Box::new(Cursor::new(Vec::new())))
        },
        &mut Vec::new(),
    )
    .expect_err("empty capture");
    assert_eq!(error.exit_code(), 2);
    assert!(!created);
}

#[test]
fn pcap_and_mixed_pcapng_match_the_previous_encoder_bytes() {
    let pcap = vec![frame(LinkType::IPV4, vec![1, 2, 3])];
    assert_eq!(
        render(Format::Pcap, pcap.clone()).unwrap(),
        old_encode(Format::Pcap, pcap)
    );

    let mixed = vec![
        frame(LinkType::ETHERNET, vec![4, 5]),
        frame(LinkType::IPV4, vec![6, 7, 8]),
    ];
    let encoded = render(Format::PcapNg, mixed.clone()).unwrap();
    assert_eq!(encoded, old_encode(Format::PcapNg, mixed));
    let mut reader = Reader::new(Cursor::new(encoded)).expect("pcapng opens");
    assert!(reader.next_frame().unwrap().is_some());
    assert!(reader.next_frame().unwrap().is_some());
}

#[test]
fn encoding_failure_emits_no_stdout_bytes() {
    let frames = vec![
        frame(LinkType::IPV4, vec![1]),
        frame(LinkType::IPV6, vec![2]),
    ];
    let mut destination = Vec::new();
    let error = write_capture_file_with(
        Format::Pcap,
        frames,
        || Ok(Box::new(Cursor::new(Vec::new()))),
        &mut destination,
    )
    .expect_err("mixed classic pcap");
    assert_eq!(error.classification.code, "io.runtime");
    assert!(error.message.starts_with("write capture output failed:"));
    assert!(destination.is_empty());
}

struct ScriptedSpool {
    inner: Cursor<Vec<u8>>,
    fail_write: bool,
    fail_flush: bool,
    fail_seek: bool,
    fail_read: bool,
}

impl Read for ScriptedSpool {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if self.fail_read {
            return Err(io::Error::other("injected spool read failure"));
        }
        self.inner.read(buffer)
    }
}

impl Write for ScriptedSpool {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if self.fail_write {
            return Err(io::Error::other("injected spool write failure"));
        }
        self.inner.write(buffer)
    }

    fn flush(&mut self) -> io::Result<()> {
        if self.fail_flush {
            return Err(io::Error::other("injected spool flush failure"));
        }
        self.inner.flush()
    }
}

impl Seek for ScriptedSpool {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        if self.fail_seek {
            return Err(io::Error::other("injected spool seek failure"));
        }
        self.inner.seek(position)
    }
}

fn scripted(
    fail_write: bool,
    fail_flush: bool,
    fail_seek: bool,
    fail_read: bool,
) -> Box<dyn Spool> {
    Box::new(ScriptedSpool {
        inner: Cursor::new(Vec::new()),
        fail_write,
        fail_flush,
        fail_seek,
        fail_read,
    })
}

fn assert_spool_failure(operation: &str, create: impl FnOnce() -> io::Result<Box<dyn Spool>>) {
    let error = write_capture_file_with(
        Format::Pcap,
        [frame(LinkType::IPV4, vec![1])],
        create,
        &mut Vec::new(),
    )
    .expect_err(operation);
    assert_eq!(error.exit_code(), 5, "{operation}");
    assert_eq!(error.classification.code, "io.capture_file", "{operation}");
    assert!(error.classification.remediation.is_some(), "{operation}");
}

#[test]
fn spool_create_write_flush_seek_and_read_failures_are_classified() {
    assert_spool_failure("create", || {
        Err(io::Error::other("injected create failure"))
    });
    assert_spool_failure("write", || Ok(scripted(true, false, false, false)));
    assert_spool_failure("flush", || Ok(scripted(false, true, false, false)));
    assert_spool_failure("seek", || Ok(scripted(false, false, true, false)));
    assert_spool_failure("read", || Ok(scripted(false, false, false, true)));
}

struct FailingDestination;

impl Write for FailingDestination {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "injected stdout failure",
        ))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn stdout_write_failure_is_classified() {
    let error = write_capture_file_with(
        Format::Pcap,
        [frame(LinkType::IPV4, vec![1])],
        || Ok(Box::new(Cursor::new(Vec::new()))),
        &mut FailingDestination,
    )
    .expect_err("stdout fails");
    assert_eq!(error.classification.code, "io.stdout");
    assert!(error.classification.remediation.is_some());
}

#[test]
fn large_capture_is_spooled_and_copied_in_bounded_chunks() {
    struct ObservedDestination {
        total: usize,
        largest_write: usize,
    }
    impl Write for ObservedDestination {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.total += bytes.len();
            self.largest_write = self.largest_write.max(bytes.len());
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    let frames = (0..512).map(|_| frame(LinkType::IPV4, vec![0x5a; 4_096]));
    let mut destination = ObservedDestination {
        total: 0,
        largest_write: 0,
    };
    write_capture_file_with(
        Format::Pcap,
        frames,
        || tempfile::tempfile().map(|file| Box::new(file) as Box<dyn Spool>),
        &mut destination,
    )
    .unwrap();
    assert!(destination.total > COPY_BUFFER_BYTES);
    assert!(destination.largest_write <= COPY_BUFFER_BYTES);
    assert!(destination.largest_write < destination.total);
}
