// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
// Test code indexes fixtures and counts by hand; the fail-closed lints are
// for library paths.
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::io::Cursor;
use std::time::SystemTime;

use packetcraftr_core::analysis::pcap::{
    CaptureHeader, CaptureRecord, Endianness, Error, Limits, MetadataBlockKind, PacketBlockKind,
    Reader, RecordKind, Writer, rewrite,
};
use packetcraftr_core::analysis::run;
use packetcraftr_core::analysis::stats::Collector;
use packetcraftr_core::protocol::builtin;

fn u16_bytes(endianness: Endianness, value: u16) -> [u8; 2] {
    match endianness {
        Endianness::Little => value.to_le_bytes(),
        Endianness::Big => value.to_be_bytes(),
    }
}

fn u32_bytes(endianness: Endianness, value: u32) -> [u8; 4] {
    match endianness {
        Endianness::Little => value.to_le_bytes(),
        Endianness::Big => value.to_be_bytes(),
    }
}

fn i64_bytes(endianness: Endianness, value: i64) -> [u8; 8] {
    match endianness {
        Endianness::Little => value.to_le_bytes(),
        Endianness::Big => value.to_be_bytes(),
    }
}

fn option(endianness: Endianness, code: u16, value: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&u16_bytes(endianness, code));
    bytes.extend_from_slice(&u16_bytes(
        endianness,
        u16::try_from(value.len()).expect("test option length fits u16"),
    ));
    bytes.extend_from_slice(value);
    bytes.resize(bytes.len().next_multiple_of(4), 0);
    bytes
}

fn end_options(endianness: Endianness, options: &mut Vec<u8>) {
    options.extend_from_slice(&u16_bytes(endianness, 0));
    options.extend_from_slice(&u16_bytes(endianness, 0));
}

fn block(endianness: Endianness, block_type: u32, body: &[u8]) -> Vec<u8> {
    assert!(body.len().is_multiple_of(4));
    let length = u32::try_from(body.len() + 12).expect("test block length fits u32");
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&u32_bytes(endianness, block_type));
    bytes.extend_from_slice(&u32_bytes(endianness, length));
    bytes.extend_from_slice(body);
    bytes.extend_from_slice(&u32_bytes(endianness, length));
    bytes
}

fn section(endianness: Endianness, comment: &[u8]) -> Vec<u8> {
    let mut options = option(endianness, 1, comment);
    end_options(endianness, &mut options);
    let mut body = Vec::new();
    body.extend_from_slice(match endianness {
        Endianness::Little => &[0x4d, 0x3c, 0x2b, 0x1a],
        Endianness::Big => &[0x1a, 0x2b, 0x3c, 0x4d],
    });
    body.extend_from_slice(&u16_bytes(endianness, 1));
    body.extend_from_slice(&u16_bytes(endianness, 0));
    body.extend_from_slice(&i64_bytes(endianness, -1));
    body.extend_from_slice(&options);
    block(endianness, 0x0a0d_0d0a, &body)
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
    let mut body = Vec::new();
    body.extend_from_slice(&u16_bytes(endianness, 1));
    body.extend_from_slice(&u16_bytes(endianness, 0));
    body.extend_from_slice(&u32_bytes(endianness, 65_535));
    body.extend_from_slice(&options);
    block(endianness, 1, &body)
}

fn epb(endianness: Endianness, ticks: u64) -> Vec<u8> {
    let mut options = option(endianness, 1, b"packet comment");
    options.extend_from_slice(&option(endianness, 2, &u32_bytes(endianness, 1)));
    options.extend_from_slice(&option(endianness, 0x7778, b"unknown-epb"));
    options.extend_from_slice(&option(endianness, 2_988, b"custom-epb"));
    end_options(endianness, &mut options);
    let mut body = Vec::new();
    body.extend_from_slice(&u32_bytes(endianness, 0));
    body.extend_from_slice(&u32_bytes(endianness, (ticks >> 32) as u32));
    body.extend_from_slice(&u32_bytes(
        endianness,
        u32::try_from(ticks).expect("fixture timestamp fits the low word"),
    ));
    body.extend_from_slice(&u32_bytes(endianness, 1));
    body.extend_from_slice(&u32_bytes(endianness, 1));
    body.extend_from_slice(&[0xaa, 0, 0, 0]);
    body.extend_from_slice(&options);
    block(endianness, 6, &body)
}

fn obsolete_packet(endianness: Endianness) -> Vec<u8> {
    let mut options = option(endianness, 1, b"obsolete");
    end_options(endianness, &mut options);
    let mut body = Vec::new();
    body.extend_from_slice(&u16_bytes(endianness, 0));
    body.extend_from_slice(&u16_bytes(endianness, 7));
    body.extend_from_slice(&u32_bytes(endianness, 0));
    body.extend_from_slice(&u32_bytes(endianness, 1));
    body.extend_from_slice(&u32_bytes(endianness, 1));
    body.extend_from_slice(&u32_bytes(endianness, 1));
    body.extend_from_slice(&[0xbb, 0, 0, 0]);
    body.extend_from_slice(&options);
    block(endianness, 2, &body)
}

fn simple_packet(endianness: Endianness) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&u32_bytes(endianness, 1));
    body.extend_from_slice(&[0xcc, 0, 0, 0]);
    block(endianness, 3, &body)
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

fn classic(endianness: Endianness, network: u32) -> Vec<u8> {
    let mut bytes = match endianness {
        Endianness::Little => vec![0xd4, 0xc3, 0xb2, 0xa1],
        Endianness::Big => vec![0xa1, 0xb2, 0xc3, 0xd4],
    };
    bytes.extend_from_slice(&u16_bytes(endianness, 2));
    bytes.extend_from_slice(&u16_bytes(endianness, 4));
    bytes.extend_from_slice(&u32_bytes(endianness, 0));
    bytes.extend_from_slice(&u32_bytes(endianness, 0));
    bytes.extend_from_slice(&u32_bytes(endianness, 65_535));
    bytes.extend_from_slice(&u32_bytes(endianness, network));
    bytes.extend_from_slice(&u32_bytes(endianness, 0));
    bytes.extend_from_slice(&u32_bytes(endianness, 0));
    bytes.extend_from_slice(&u32_bytes(endianness, 1));
    bytes.extend_from_slice(&u32_bytes(endianness, 1));
    bytes.push(0xdd);
    bytes
}

#[test]
fn classic_network_word_high_bits_survive_both_byte_orders() {
    for endianness in [Endianness::Little, Endianness::Big] {
        let input = classic(endianness, 0xa400_0001);
        let mut reader = Reader::new(Cursor::new(input.clone())).expect("classic capture opens");
        let CaptureHeader::Pcap(header) = reader.header() else {
            panic!("classic header expected");
        };
        assert_eq!(header.network, 0xa400_0001);
        let (output, report) =
            rewrite(&mut reader, Vec::new(), Limits::default()).expect("bounded rewrite succeeds");
        assert_eq!(output, input);
        assert_eq!(report.frames, 1);
    }
}

#[test]
fn pcapng_records_options_sections_and_packet_kinds_are_preserved() {
    let input = adversarial_pcapng();
    let mut reader = Reader::new(Cursor::new(input.clone())).expect("pcapng opens");
    let CaptureHeader::PcapNg(first) = reader.header() else {
        panic!("pcapng header expected");
    };
    assert_eq!(first.endianness, Endianness::Little);
    assert_eq!(first.options[0].code, 1);

    let mut records = Vec::new();
    while let Some(record) = reader.next_record().expect("record is valid") {
        records.push(record);
    }

    assert_interface_records(&records);
    assert_packet_records(&records);
    assert_metadata_records(&records);

    let mut rewritten_reader = Reader::new(Cursor::new(input.clone())).expect("pcapng reopens");
    let (output, report) = rewrite(&mut rewritten_reader, Vec::new(), Limits::default())
        .expect("all validated records rewrite");
    assert_eq!(output, input);
    assert_eq!(report.frames, 4);
    assert_eq!(report.interfaces, 2);
    assert_eq!(report.metadata_records, 8);
}

fn assert_interface_records(records: &[CaptureRecord]) {
    let idbs: Vec<_> = records
        .iter()
        .filter_map(|record| match &record.kind {
            RecordKind::Metadata(MetadataBlockKind::InterfaceDescription {
                section,
                local_id,
                global_id,
                options,
                ..
            }) => Some((*section, *local_id, *global_id, options)),
            _ => None,
        })
        .collect();
    assert_eq!(idbs.len(), 2);
    assert_eq!((idbs[0].0, idbs[0].1, idbs[0].2), (0, 0, 0));
    assert_eq!((idbs[1].0, idbs[1].1, idbs[1].2), (1, 0, 1));
    for (_, _, _, options) in idbs {
        for code in [1, 2, 3, 9, 11, 12, 15, 0x7777] {
            assert!(
                options.iter().any(|option| option.code == code),
                "IDB option {code}"
            );
        }
    }
}

fn assert_packet_records(records: &[CaptureRecord]) {
    let packets: Vec<_> = records
        .iter()
        .filter(|record| matches!(record.kind, RecordKind::Packet { .. }))
        .collect();
    assert_eq!(packets.len(), 4);
    assert!(matches!(
        packets[0].kind,
        RecordKind::Packet {
            block: PacketBlockKind::Enhanced,
            section: Some(0),
            interface_id: Some(0),
            ..
        }
    ));
    assert_eq!(
        packets[0].frame.as_ref().and_then(|frame| frame.timestamp),
        Some(SystemTime::UNIX_EPOCH)
    );
    if let RecordKind::Packet { options, .. } = &packets[0].kind {
        for code in [1, 2, 2_988, 0x7778] {
            assert!(
                options.iter().any(|option| option.code == code),
                "EPB option {code}"
            );
        }
    }
    assert!(matches!(
        packets[1].kind,
        RecordKind::Packet {
            block: PacketBlockKind::Simple,
            ..
        }
    ));
    assert_eq!(
        packets[1].frame.as_ref().and_then(|frame| frame.timestamp),
        None
    );
    assert!(matches!(
        packets[2].kind,
        RecordKind::Packet {
            block: PacketBlockKind::Obsolete,
            ..
        }
    ));
    assert!(matches!(
        packets[3].kind,
        RecordKind::Packet {
            block: PacketBlockKind::Enhanced,
            section: Some(1),
            interface_id: Some(0),
            ..
        }
    ));
    assert_eq!(
        packets[3].frame.as_ref().and_then(|frame| frame.timestamp),
        Some(SystemTime::UNIX_EPOCH)
    );
    assert_eq!(
        packets[0].frame.as_ref().and_then(|frame| frame.interface),
        Some(0)
    );
    assert_eq!(
        packets[3].frame.as_ref().and_then(|frame| frame.interface),
        Some(1)
    );
}

fn assert_metadata_records(records: &[CaptureRecord]) {
    assert!(records.iter().any(|record| matches!(record.kind, RecordKind::Metadata(MetadataBlockKind::Section(ref section)) if section.index == 1 && section.endianness == Endianness::Big)));
    assert!(records.iter().any(|record| matches!(
        record.kind,
        RecordKind::Metadata(MetadataBlockKind::NameResolution { section: 0 })
    )));
    assert!(records.iter().any(|record| matches!(
        record.kind,
        RecordKind::Metadata(MetadataBlockKind::InterfaceStatistics {
            section: 0,
            interface_id: 0
        })
    )));
    assert!(records.iter().any(|record| matches!(
        record.kind,
        RecordKind::Metadata(MetadataBlockKind::Custom {
            section: 0,
            block_type: 0x0000_0bad
        })
    )));
    assert!(records.iter().any(|record| matches!(
        record.kind,
        RecordKind::Metadata(MetadataBlockKind::Custom {
            section: 0,
            block_type: 0x4000_0bad
        })
    )));
    assert!(records.iter().any(|record| matches!(
        record.kind,
        RecordKind::Metadata(MetadataBlockKind::Unknown {
            section: 0,
            block_type: 0x1234_5678
        })
    )));
}

#[test]
fn timestamp_requiring_writer_rejects_simple_packet_time_absence() {
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

#[test]
fn statistics_reject_simple_packet_time_absence_explicitly() {
    let mut input = section(Endianness::Little, b"untimestamped statistics");
    input.extend_from_slice(&idb(Endianness::Little));
    input.extend_from_slice(&simple_packet(Endianness::Little));
    let mut reader = Reader::new(Cursor::new(input)).expect("pcapng opens");
    let registry = builtin::registry();
    let mut collector =
        Collector::new(std::time::Duration::from_secs(1)).expect("statistics interval is valid");
    let mut observed = 0_u32;
    let error = run(
        &mut reader,
        registry,
        &packetcraftr_core::analysis::Options::default(),
        |record| {
            observed += 1;
            collector.observe(&record);
            Ok(())
        },
    )
    .expect_err("statistics require capture time");
    // The collector reads `record.timestamp` and cannot fail; this is the
    // guarantee that makes that sound.
    assert_eq!(
        observed, 0,
        "an untimestamped frame is refused before any sink observes it"
    );
    assert!(matches!(
        error,
        packetcraftr_core::analysis::Error::TimestampUnavailable { number: 1 }
    ));
}
