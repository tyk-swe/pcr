// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::common;

use common::pcap::{
    block, enhanced_packet_block, interface_block, obsolete_packet_block, option, section_header,
    simple_packet_block, words,
};
use std::io::Cursor;

use packetcraftr_core::capture_file::{
    Endianness, Error, PacketBlockKind, Reader, RecordKind, Writer,
};

fn end_options(endianness: Endianness, options: &mut Vec<u8>) {
    options.extend_from_slice(&option(endianness, 0, &[]));
}

fn section_of_length(endianness: Endianness, comment: &[u8], section_length: i64) -> Vec<u8> {
    let mut options = option(endianness, 1, comment);
    end_options(endianness, &mut options);
    section_header(endianness, 1, 0, section_length, &options)
}

fn section(endianness: Endianness, comment: &[u8]) -> Vec<u8> {
    section_of_length(endianness, comment, -1)
}

fn idb(endianness: Endianness) -> Vec<u8> {
    let mut options = Vec::new();
    for (code, value) in [
        (1, b"interface comment".as_slice()),
        (2, b"eth-source".as_slice()),
        (3, b"interface description".as_slice()),
        (11, b"tcp port 443".as_slice()),
        (12, b"TestOS".as_slice()),
        (15, b"TestHardware".as_slice()),
        (0x7777, b"unknown-idb".as_slice()),
    ] {
        options.extend_from_slice(&option(endianness, code, value));
    }
    options.extend_from_slice(&option(endianness, 9, &[6]));
    end_options(endianness, &mut options);
    interface_block(endianness, 1, 65_535, &options)
}

fn epb(endianness: Endianness, ticks: u64) -> Vec<u8> {
    let mut options = option(endianness, 1, b"packet comment");
    options.extend_from_slice(&option(endianness, 2, &words(endianness, &[1])));
    options.extend_from_slice(&option(endianness, 0x7778, b"unknown-epb"));
    options.extend_from_slice(&option(endianness, 2_988, b"custom-epb"));
    end_options(endianness, &mut options);
    enhanced_packet_block(endianness, 0, ticks, 1, &[0xaa], &options)
}

fn obsolete_packet(endianness: Endianness) -> Vec<u8> {
    let mut options = option(endianness, 1, b"obsolete");
    end_options(endianness, &mut options);
    obsolete_packet_block(endianness, 7, 1, &[0xbb], &options)
}

fn simple_packet(endianness: Endianness) -> Vec<u8> {
    simple_packet_block(endianness, 1, &[0xcc])
}

fn metadata_block(endianness: Endianness, block_type: u32, body: &[u8]) -> Vec<u8> {
    let mut padded = body.to_vec();
    padded.resize(padded.len().next_multiple_of(4), 0);
    block(endianness, block_type, &padded)
}

fn adversarial_pcapng() -> Vec<u8> {
    let mut bytes = section(Endianness::Little, b"first section");
    bytes.extend_from_slice(&idb(Endianness::Little));
    bytes.extend_from_slice(&epb(Endianness::Little, 0));
    bytes.extend_from_slice(&simple_packet(Endianness::Little));
    bytes.extend_from_slice(&obsolete_packet(Endianness::Little));
    bytes.extend_from_slice(&metadata_block(Endianness::Little, 4, &[0, 0, 0, 0]));
    bytes.extend_from_slice(&metadata_block(
        Endianness::Little,
        5,
        &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    ));
    bytes.extend_from_slice(&metadata_block(
        Endianness::Little,
        0x0000_0bad,
        &[1, 2, 3, 4, 5],
    ));
    bytes.extend_from_slice(&metadata_block(
        Endianness::Little,
        0x4000_0bad,
        &[6, 7, 8, 9],
    ));
    bytes.extend_from_slice(&metadata_block(
        Endianness::Little,
        0x1234_5678,
        &[9, 8, 7, 6],
    ));
    bytes.extend_from_slice(&section(Endianness::Big, b"second section"));
    bytes.extend_from_slice(&idb(Endianness::Big));
    bytes.extend_from_slice(&epb(Endianness::Big, 0));
    bytes
}

#[test]
fn ts_requiring_reject_time_absence() {
    let input = adversarial_pcapng();
    let mut reader = Reader::new(Cursor::new(input)).expect("pcapng opens");
    let mut simple = loop {
        let record = reader
            .next_record()
            .expect("record is valid")
            .expect("simple packet exists");
        if matches!(
            record.kind,
            RecordKind::Packet {
                block: PacketBlockKind::Simple,
                ..
            }
        ) {
            break record.frame.expect("packet record has a frame");
        }
    };
    simple.interface = None;
    let mut writer = Writer::pcapng(Vec::new()).expect("writer opens");
    assert!(matches!(
        writer.write_frame(&simple),
        Err(Error::TimestampUnavailable { .. })
    ));
    let mut writer = Writer::pcap(Vec::new(), simple.link_type).expect("classic writer opens");
    assert!(matches!(
        writer.write_frame(&simple),
        Err(Error::TimestampUnavailable { .. })
    ));
}
