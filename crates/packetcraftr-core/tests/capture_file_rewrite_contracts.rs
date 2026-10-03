// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
#![allow(dead_code)]

mod common;

use common::pcap::{frame_at, pcap_bytes};
use std::io::{self, Cursor, Write};
use std::time::{Duration, SystemTime};

use packetcraftr_core::capture_file::{
    Endianness, Error, Format, Limits, PcapOptions, Reader, Writer, rewrite,
};
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
