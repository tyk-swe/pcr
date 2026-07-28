// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::io::{self, Cursor, Write};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;

use crate::{Direction, Frame, LinkType};

use super::models::{
    DEFAULT_SIZE_LIMIT, Endianness, Error, Format, Interface, Limits, PcapNgOptions, PcapOptions,
    ReaderOptions, TimestampResolution, TranscodeReport,
};
use super::reader::Reader;
use super::transcode::transcode;
use super::wire::{
    PCAP_GLOBAL_HEADER_LEN, system_time_from_signed_unix, timestamp_from_ticks, timestamp_to_ticks,
};
use super::writer::Writer;

#[derive(Debug)]
struct PartialFailSink {
    bytes: Vec<u8>,
    fail_after: usize,
    write_calls: usize,
    flush_calls: usize,
    fail_flush: bool,
}

impl PartialFailSink {
    fn new(fail_after: usize) -> Self {
        Self {
            bytes: Vec::new(),
            fail_after,
            write_calls: 0,
            flush_calls: 0,
            fail_flush: false,
        }
    }
}

impl Write for PartialFailSink {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.write_calls += 1;
        if self.bytes.len() >= self.fail_after {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "deterministic sink failure",
            ));
        }
        let written = buffer.len().min(self.fail_after - self.bytes.len());
        self.bytes.extend_from_slice(&buffer[..written]);
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.flush_calls += 1;
        if self.fail_flush {
            Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "deterministic flush failure",
            ))
        } else {
            Ok(())
        }
    }
}

fn expect_io_error<T>(result: Result<T, Error>) -> io::Error {
    match result {
        Err(Error::Io(error)) => error,
        Err(error) => panic!("expected I/O error, got {error:?}"),
        Ok(_) => panic!("expected I/O error, got success"),
    }
}

fn pcapng_interface_count<W>(writer: &Writer<W>) -> usize {
    match &writer.state {
        super::writer::WriterState::PcapNg { interfaces, .. } => interfaces.len(),
        super::writer::WriterState::Pcap { .. } => panic!("expected pcapng writer"),
    }
}

fn frame(timestamp: SystemTime, link_type: LinkType, bytes: &[u8]) -> Frame {
    Frame::new(timestamp, link_type, Bytes::copy_from_slice(bytes)).unwrap()
}

fn declare_little_endian_section_length(bytes: &mut [u8]) {
    let section_length = i64::try_from(bytes.len() - 28).unwrap();
    bytes[16..24].copy_from_slice(&section_length.to_le_bytes());
}

mod classic_cases;
mod pcapng_reader_cases;
mod transcode_cases;
mod writer_cases;
