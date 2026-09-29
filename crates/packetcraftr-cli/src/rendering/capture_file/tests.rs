// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::io::Cursor;
use std::time::UNIX_EPOCH;

use packetcraftr_core::capture_file::{DEFAULT_MAX_STREAM_FRAMES, Reader};
use packetcraftr_core::frame::LinkType;

use super::*;

fn frame(link_type: LinkType, bytes: Vec<u8>) -> Frame {
    Frame::new(UNIX_EPOCH, link_type, bytes).expect("valid fixture frame")
}

#[test]
fn empty_capture_is_rejected_before_spool_creation() {
    let mut created = false;
    let error = write_capture_file_with(
        Format::Pcap,
        Vec::new(),
        || {
            created = true;
            Ok(Cursor::new(Vec::new()))
        },
        || Ok(Vec::new()),
    )
    .expect_err("empty capture");
    assert_eq!(error.exit_code(), 2);
    assert!(!created);
}

#[test]
fn encoding_failure_emits_no_stdout_bytes() {
    let frames = vec![
        frame(LinkType::IPV4, vec![1]),
        frame(LinkType::IPV6, vec![2]),
    ];
    let mut opened = false;
    let error = write_capture_file_with(
        Format::Pcap,
        frames,
        || Ok(Cursor::new(Vec::new())),
        || {
            opened = true;
            Ok(Vec::new())
        },
    )
    .expect_err("mixed classic pcap");
    assert_eq!(error.classification.code, "packet.capture_file");
    assert_eq!(error.exit_code(), 3);
    assert!(error.classification.remediation.is_some());
    assert!(!opened);
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

fn scripted(fail_write: bool, fail_flush: bool, fail_seek: bool, fail_read: bool) -> ScriptedSpool {
    ScriptedSpool {
        inner: Cursor::new(Vec::new()),
        fail_write,
        fail_flush,
        fail_seek,
        fail_read,
    }
}

fn assert_spool_failure(operation: &str, create: impl FnOnce() -> io::Result<ScriptedSpool>) {
    let error = write_capture_file_with(
        Format::Pcap,
        [frame(LinkType::IPV4, vec![1])],
        create,
        || Ok(Vec::new()),
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

/// Dropping an unfinished gzip compressor still writes a complete, empty
/// container, so a spool failure must leave no compressed bytes behind.
#[test]
fn spool_failure_writes_no_compressed_container() {
    for (operation, spool) in [
        ("write", scripted(true, false, false, false)),
        ("flush", scripted(false, true, false, false)),
        ("seek", scripted(false, false, true, false)),
    ] {
        let mut destination = Vec::new();
        write_capture_file_with(
            Format::Pcap,
            [frame(LinkType::IPV4, vec![1])],
            || Ok(spool),
            || crate::command_options::Compression::Gzip.writer(&mut destination),
        )
        .map(drop)
        .expect_err(operation);
        assert!(destination.is_empty(), "{operation}");
    }
}

#[derive(Debug)]
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
        || Ok(Cursor::new(Vec::new())),
        || Ok(FailingDestination),
    )
    .expect_err("stdout fails");
    assert_eq!(error.classification.code, "io.stdout");
    assert!(error.classification.remediation.is_some());
    assert_eq!(error.message, "write stdout failed");
    assert_eq!(error.causes, ["injected stdout failure"]);
}

#[test]
fn temporary_storage_failure_states_the_io_error_once_as_its_cause() {
    let error = write_capture_file_with(
        Format::Pcap,
        [frame(LinkType::IPV4, vec![1])],
        || Err::<Cursor<Vec<u8>>, _>(io::Error::other("spool unavailable")),
        || Ok(Vec::new()),
    )
    .expect_err("the spool cannot be created");
    assert_eq!(error.classification.code, "io.capture_file");
    assert_eq!(error.message, "create temporary capture output failed");
    assert_eq!(error.causes, ["spool unavailable"]);
}

#[test]
fn capture_larger_than_the_default_stream_limit_is_written_whole() {
    let count = usize::try_from(DEFAULT_MAX_STREAM_FRAMES).unwrap() + 1;
    for format in [Format::Pcap, Format::PcapNg] {
        let frames = (0..count).map(|_| frame(LinkType::IPV4, vec![1]));
        let bytes = write_capture_file_with(
            format,
            frames,
            || Ok(Cursor::new(Vec::new())),
            || Ok(Vec::new()),
        )
        .unwrap_or_else(|error| panic!("{format:?}: {error}"));

        let mut reader = Reader::new(Cursor::new(bytes)).expect("capture opens");
        let mut read = 0;
        while reader.next_frame().expect("capture record").is_some() {
            read += 1;
        }
        assert_eq!(read, count, "{format:?}");
    }
}

#[test]
fn capture_of_empty_frames_has_nonzero_stream_limits() {
    for format in [Format::Pcap, Format::PcapNg] {
        write_capture_file_with(
            format,
            [frame(LinkType::IPV4, Vec::new())],
            || Ok(Cursor::new(Vec::new())),
            || Ok(Vec::new()),
        )
        .unwrap_or_else(|error| panic!("{format:?}: {error}"));
    }
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
    let destination = write_capture_file_with(Format::Pcap, frames, tempfile::tempfile, || {
        Ok(ObservedDestination {
            total: 0,
            largest_write: 0,
        })
    })
    .unwrap();
    assert!(destination.total > COPY_BUFFER_BYTES);
    assert!(destination.largest_write <= COPY_BUFFER_BYTES);
    assert!(destination.largest_write < destination.total);
}
