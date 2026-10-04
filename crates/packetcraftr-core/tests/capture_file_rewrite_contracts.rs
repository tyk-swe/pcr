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
            max_bytes: pcap.len() as u64,
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
fn copy_budget_counts_packet_options_and_metadata() {
    use common::pcap::{enhanced_packet_block, interface_block, option, section_header};
    let endian = Endianness::Little;
    let mut bytes = section_header(endian, 1, 0, -1, &[]);
    bytes.extend(interface_block(endian, 1, 65535, &[]));
    let before_packet = bytes.len();
    bytes.extend(enhanced_packet_block(
        endian,
        0,
        0,
        0,
        &[],
        &option(endian, 1, &[42; 512]),
    ));
    let limit = bytes.len() as u64 - 1;
    for selecting in [false, true] {
        let mut reader = Reader::new(Cursor::new(bytes.clone())).unwrap();
        let mut output = Vec::new();
        let limits = Limits {
            max_frames: 10,
            max_bytes: limit,
        };
        let result = if selecting {
            packetcraftr_core::capture_file::select(&mut reader, &mut output, limits, |_, _| {
                Ok(false)
            })
            .map(|_| ())
        } else {
            rewrite(&mut reader, &mut output, limits).map(|_| ())
        };
        assert!(matches!(result, Err(Error::StreamByteLimitExceeded { .. })));
        assert_eq!(output.len(), before_packet);
    }
}

#[test]
fn selection_omits_noncopyable_metadata_but_rewrite_preserves_it() {
    use common::pcap::{block, section_header};
    use packetcraftr_core::capture_file::{MetadataBlockKind, RecordKind, select};
    for endian in [Endianness::Little, Endianness::Big] {
        let mut bytes = section_header(endian, 1, 0, -1, &[]);
        bytes.extend(block(endian, 0x40000bad, &[0, 0, 0, 0, 1, 2, 3, 4]));
        bytes.extend(block(endian, 0x00000bad, &[0, 0, 0, 0, 5, 6, 7, 8]));
        let (copy, _) = rewrite(
            &mut Reader::new(Cursor::new(bytes.clone())).unwrap(),
            Vec::new(),
            Limits::default(),
        )
        .unwrap();
        assert_eq!(copy, bytes);
        let (selected, report) = select(
            &mut Reader::new(Cursor::new(bytes)).unwrap(),
            Vec::new(),
            Limits::default(),
            |_, _| Ok(false),
        )
        .unwrap();
        assert_eq!(report.metadata_records, 1);
        let mut reader = Reader::new(Cursor::new(selected)).unwrap();
        assert!(matches!(
            reader.next_record().unwrap().unwrap().kind,
            RecordKind::Metadata(MetadataBlockKind::Custom {
                block_type: 0x00000bad,
                ..
            })
        ));
        assert!(reader.next_record().unwrap().is_none());
    }
}
