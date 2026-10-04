// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
#![allow(dead_code)]

use std::io::Cursor;
use std::time::UNIX_EPOCH;

use packetcraftr_core::frame::LinkType;

use super::*;

fn frame(link_type: LinkType, bytes: Vec<u8>) -> Frame {
    Frame::new(UNIX_EPOCH, link_type, bytes).expect("valid fixture frame")
}

#[test]
fn empty_capture_reject_before_spool_creation() {
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
fn large_capture_bounded_chunks() {
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
