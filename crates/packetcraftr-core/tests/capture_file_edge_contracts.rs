// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod common;

use common::pcap::{
    block, enhanced_packet_block, frame_at, interface_block, pcap_bytes, put_u32, section_header,
};
use std::io::Cursor;
use std::time::SystemTime;

use packetcraftr_core::capture_file::{
    Endianness, Error, Format, PcapOptions, Reader, ReaderLimits,
};
use packetcraftr_core::frame::LinkType;

fn empty_metadata_block(endianness: Endianness, block_type: u32) -> Vec<u8> {
    block(endianness, block_type, &[])
}

fn pcapng_stream(endianness: Endianness, blocks: &[Vec<u8>]) -> Vec<u8> {
    let mut bytes = section_header(endianness, 1, 0, -1, &[]);
    for block in blocks {
        bytes.extend_from_slice(block);
    }
    bytes
}

#[test]
fn classic_reader_fails_closed_on_truncation_and_limits() {
    let frame = frame_at(SystemTime::UNIX_EPOCH, LinkType::ETHERNET, &[1, 2, 3, 4]);
    let capture = pcap_bytes(PcapOptions::default(), &[frame]);

    let mut truncated = capture.clone();
    truncated.pop();
    let error = Reader::new(Cursor::new(truncated))
        .expect("global header remains valid")
        .next_frame()
        .expect_err("short payload must fail");
    assert!(matches!(error, Error::Truncated { .. }));

    let mut reader = Reader::with_limits(
        Cursor::new(capture),
        ReaderLimits {
            max_size: 3,
            ..ReaderLimits::default()
        },
    )
    .expect("global header remains within the limit");
    assert!(matches!(
        reader.next_frame(),
        Err(Error::SizeLimitExceeded { limit: 3, .. })
    ));
}

#[test]
fn pcapng_reader_enforces_metadata_and_interface_budgets() {
    let endianness = Endianness::Little;
    let bytes = pcapng_stream(
        endianness,
        &[
            empty_metadata_block(endianness, 0xfeed_beef),
            interface_block(endianness, 1, 64, &[]),
            enhanced_packet_block(endianness, 0, 0, 1, b"x", &[]),
        ],
    );
    let mut blocks = Reader::with_limits(
        Cursor::new(bytes.clone()),
        ReaderLimits {
            max_metadata_blocks_per_frame: 0,
            ..ReaderLimits::default()
        },
    )
    .expect("section opens");
    assert!(matches!(
        blocks.next_frame(),
        Err(Error::MetadataBlockLimit { limit: 0 })
    ));

    let mut metadata_bytes = Reader::with_limits(
        Cursor::new(bytes.clone()),
        ReaderLimits {
            max_metadata_bytes_per_frame: 11,
            ..ReaderLimits::default()
        },
    )
    .expect("section opens");
    assert!(matches!(
        metadata_bytes.next_frame(),
        Err(Error::MetadataByteLimit { limit: 11 })
    ));

    let section_limit = ReaderLimits {
        max_interfaces_per_section: 0,
        ..ReaderLimits::default()
    };
    let mut reader = Reader::with_limits(Cursor::new(bytes.clone()), section_limit)
        .expect("section header itself fits");
    assert!(matches!(
        reader.next_frame(),
        Err(Error::InterfaceLimit { limit: 0 })
    ));
    let total_limit = ReaderLimits {
        max_total_interfaces: 0,
        ..ReaderLimits::default()
    };
    let mut reader =
        Reader::with_limits(Cursor::new(bytes), total_limit).expect("section header itself fits");
    assert!(matches!(
        reader.next_frame(),
        Err(Error::TotalInterfaceLimit { limit: 0 })
    ));
}

#[test]
fn pcapng_structural_corruption_fails_closed() {
    let endianness = Endianness::Little;
    let mut bad_bom = section_header(endianness, 1, 0, -1, &[]);
    bad_bom[8..12].copy_from_slice(&[0, 0, 0, 0]);
    assert!(matches!(
        Reader::new(Cursor::new(bad_bom)),
        Err(Error::InvalidData { .. })
    ));
    assert!(matches!(
        Reader::new(Cursor::new(section_header(endianness, 2, 0, -1, &[]))),
        Err(Error::UnsupportedVersion {
            format: Format::PcapNg,
            major: 2,
            minor: 0
        })
    ));
    assert!(matches!(
        Reader::new(Cursor::new(section_header(endianness, 1, 0, -2, &[]))),
        Err(Error::InvalidData { .. })
    ));
    assert!(matches!(
        Reader::new(Cursor::new(section_header(endianness, 1, 0, 3, &[]))),
        Err(Error::InvalidData { .. })
    ));

    let mut mismatch = section_header(endianness, 1, 0, -1, &[]);
    mismatch[24..28].copy_from_slice(&32_u32.to_le_bytes());
    assert!(matches!(
        Reader::new(Cursor::new(mismatch)),
        Err(Error::BlockLengthMismatch {
            leading: 28,
            trailing: 32
        })
    ));
    assert!(matches!(
        Reader::with_limits(
            Cursor::new(section_header(endianness, 1, 0, -1, &[])),
            ReaderLimits {
                max_size: 27,
                ..ReaderLimits::default()
            }
        ),
        Err(Error::SizeLimitExceeded { limit: 27, .. })
    ));

    let mut invalid_block = section_header(endianness, 1, 0, -1, &[]);
    put_u32(&mut invalid_block, endianness, 99);
    put_u32(&mut invalid_block, endianness, 14);
    let mut reader = Reader::new(Cursor::new(invalid_block)).expect("section opens");
    assert!(matches!(
        reader.next_frame(),
        Err(Error::InvalidBlockLength { length: 14 })
    ));

    let mut mismatch_block =
        pcapng_stream(endianness, &[empty_metadata_block(endianness, 0xfeed_beef)]);
    let end = mismatch_block.len();
    mismatch_block[end - 4..].copy_from_slice(&16_u32.to_le_bytes());
    let mut reader = Reader::new(Cursor::new(mismatch_block)).expect("section opens");
    assert!(matches!(
        reader.next_frame(),
        Err(Error::BlockLengthMismatch {
            leading: 12,
            trailing: 16
        })
    ));
}
