// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::io::Cursor;
use std::time::{Duration, SystemTime};

use packetcraftr_core::analysis::pcap::{
    Endianness, Error, Format, PcapOptions, Reader, ReaderOptions, Writer,
};
use packetcraftr_core::frame::{Frame, LinkType};

fn frame() -> Frame {
    Frame::try_with_lengths(
        SystemTime::UNIX_EPOCH + Duration::from_secs(7),
        LinkType::ETHERNET,
        4,
        9,
        vec![1_u8, 2, 3, 4],
    )
    .expect("fixture frame must be valid")
}

fn pcap(endianness: Endianness) -> Vec<u8> {
    let mut writer = Writer::pcap_with_options(
        Vec::new(),
        LinkType::ETHERNET,
        PcapOptions {
            endianness,
            ..PcapOptions::default()
        },
    )
    .expect("writer must initialize");
    writer.write_frame(&frame()).expect("frame must write");
    writer.into_inner()
}

#[test]
fn classic_pcap_round_trips_both_byte_orders_and_truncation_metadata() {
    for endianness in [Endianness::Little, Endianness::Big] {
        let mut reader = Reader::new(Cursor::new(pcap(endianness))).expect("capture must open");
        assert_eq!(reader.format(), Format::Pcap);
        assert_eq!(reader.endianness(), endianness);
        let decoded = reader
            .next_frame()
            .expect("record must parse")
            .expect("record must exist");
        assert_eq!(decoded.bytes().as_ref(), [1, 2, 3, 4]);
        assert_eq!(decoded.captured_length(), 4);
        assert_eq!(decoded.original_length(), 9);
        assert!(reader.next_frame().expect("EOF must be clean").is_none());
    }
}

#[test]
fn truncated_records_and_declared_size_limits_fail_closed() {
    let mut truncated = pcap(Endianness::Little);
    truncated.pop();
    let error = Reader::new(Cursor::new(truncated))
        .expect("global header remains valid")
        .next_frame()
        .expect_err("short payload must fail");
    assert!(matches!(error, Error::Truncated { .. }));

    let mut reader = Reader::with_options(
        Cursor::new(pcap(Endianness::Little)),
        ReaderOptions {
            max_size: 3,
            ..ReaderOptions::default()
        },
    )
    .expect("global header remains within the limit");
    assert!(matches!(
        reader.next_frame(),
        Err(Error::SizeLimitExceeded { limit: 3, .. })
    ));
}
