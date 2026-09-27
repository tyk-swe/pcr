// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod common;

use std::io::Cursor;
use std::time::SystemTime;

use common::pcapng::{
    adversarial_pcapng, classic, epb, i64_bytes, idb, metadata_block, section, simple_packet,
};
use packetcraftr_core::analysis::run;
use packetcraftr_core::analysis::stats::Collector;
use packetcraftr_core::capture_file::{
    CaptureHeader, CaptureRecord, Endianness, Error, Limits, MetadataBlockKind, PacketBlockKind,
    Reader, RecordKind, Writer, rewrite,
};
use packetcraftr_core::protocol::builtin;

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

#[test]
fn selection_preserves_raw_packets_and_metadata_across_sections() {
    use packetcraftr_core::capture_file::select;
    let input = adversarial_pcapng();
    for selected in [vec![], vec![1, 3], vec![2, 4], vec![1, 2, 3, 4]] {
        let mut source = Reader::new(Cursor::new(&input)).unwrap();
        let mut expected = section(Endianness::Little, b"first section");
        let mut number = 0;
        let mut bytes = 0;
        let mut metadata = 0;
        while let Some(record) = source.next_record().unwrap() {
            if let Some(frame) = &record.frame {
                number += 1;
                if !selected.contains(&number) {
                    continue;
                }
                bytes += u64::from(frame.captured_length());
            } else {
                metadata += 1;
            }
            expected.extend_from_slice(record.raw_bytes());
        }
        let mut source = Reader::new(Cursor::new(&input)).unwrap();
        let mut visited = Vec::new();
        let (output, report) = select(&mut source, Vec::new(), Limits::default(), |number, _| {
            visited.push(number);
            Ok(selected.contains(&number))
        })
        .unwrap();
        assert_eq!(visited, [1, 2, 3, 4]);
        assert_eq!(output, expected);
        assert_eq!(report.frames_read, 4);
        assert_eq!(report.frames_selected, selected.len() as u64);
        assert_eq!(report.captured_bytes_selected, bytes);
        assert_eq!(report.metadata_records, metadata);
        assert_eq!(report.interfaces, 2);
        let mut reread = Reader::new(Cursor::new(output)).unwrap();
        let mut count = 0;
        while reread.next_frame().unwrap().is_some() {
            count += 1;
        }
        assert_eq!(count, selected.len());
    }
}

#[test]
fn selection_updates_finite_section_lengths_including_empty_sections() {
    use packetcraftr_core::capture_file::select;
    let mut input = Vec::new();
    let mut expected = Vec::new();
    for endian in [Endianness::Little, Endianness::Big] {
        for empty in [false, true] {
            let mut body = Vec::new();
            if !empty {
                body.extend(idb(endian));
                body.extend(epb(endian, 0));
                body.extend(simple_packet(endian));
            }
            let header = section(endian, b"finite");
            let mut finite = header.clone();
            finite[16..24].copy_from_slice(&i64_bytes(endian, i64::try_from(body.len()).unwrap()));
            input.extend(finite);
            input.extend(body);
            expected.extend(header);
            if !empty {
                expected.extend(idb(endian));
            }
        }
    }
    let mut reader = Reader::new(Cursor::new(&input)).unwrap();
    let (copy, _) = rewrite(&mut reader, Vec::new(), Limits::default()).unwrap();
    assert_eq!(copy, input);
    let mut reader = Reader::new(Cursor::new(&input)).unwrap();
    let (output, report) =
        select(&mut reader, Vec::new(), Limits::default(), |_, _| Ok(false)).unwrap();
    assert_eq!(report.frames_read, 4);
    assert_eq!(output, expected);
    let mut reader = Reader::new(Cursor::new(output)).unwrap();
    assert!(reader.next_frame().unwrap().is_none());
    assert_eq!(reader.interfaces().len(), 2);
}

#[test]
fn selection_preserves_classic_precision_endianness_and_fcs() {
    use packetcraftr_core::capture_file::select;
    for endian in [Endianness::Little, Endianness::Big] {
        for nanos in [false, true] {
            let mut input = classic(endian, 0xa400_0001);
            if nanos {
                input[..4].copy_from_slice(match endian {
                    Endianness::Little => &[0x4d, 0x3c, 0xb2, 0xa1],
                    Endianness::Big => &[0xa1, 0xb2, 0x3c, 0x4d],
                });
            }
            let packet = input[24..].to_vec();
            input.extend(&packet);
            for selected in [vec![], vec![2], vec![1, 2]] {
                let mut expected = input[..24].to_vec();
                for _ in &selected {
                    expected.extend(&packet);
                }
                let mut reader = Reader::new(Cursor::new(&input)).unwrap();
                let (output, report) =
                    select(&mut reader, Vec::new(), Limits::default(), |n, _| {
                        Ok(selected.contains(&n))
                    })
                    .unwrap();
                assert_eq!(output, expected);
                assert_eq!(report.frames_read, 2);
                assert_eq!(report.captured_bytes_read, 2);
                let mut reader = Reader::new(Cursor::new(output)).unwrap();
                let mut count = 0;
                while reader.next_frame().unwrap().is_some() {
                    count += 1;
                }
                assert_eq!(count, selected.len());
            }
        }
    }
}

proptest::proptest! {
    #[test]
    fn generated_sections_preserve_unknown_metadata_and_physical_selection(
        sections in proptest::collection::vec((proptest::bool::ANY,
            proptest::collection::vec(proptest::num::u8::ANY, 0..128)), 1..5),
        mask in proptest::num::u8::ANY,
    ) {
        let mut input = Vec::new();
        let mut expected = Vec::new();
        let mut selected = 0;
        for (index, (big_endian, bytes)) in sections.iter().enumerate() {
            let endian = if *big_endian { Endianness::Big } else { Endianness::Little };
            for block in [section(endian, bytes), idb(endian), metadata_block(endian, 0x0000beef, bytes)] {
                input.extend_from_slice(&block);
                expected.extend_from_slice(&block);
            }
            let packet = epb(endian, index as u64 + 1);
            input.extend_from_slice(&packet);
            if mask & (1 << index) != 0 { expected.extend_from_slice(&packet); selected += 1; }
        }
        let mut source = Reader::new(Cursor::new(&input)).unwrap();
        let (rewritten, _) = rewrite(&mut source, Vec::new(), Limits::default()).unwrap();
        proptest::prop_assert_eq!(&rewritten, &input);
        let mut source = Reader::new(Cursor::new(&input)).unwrap();
        let (filtered, report) = packetcraftr_core::capture_file::select(
            &mut source, Vec::new(), Limits::default(), |number, _| Ok(mask & (1 << (number - 1)) != 0)
        ).unwrap();
        proptest::prop_assert_eq!(filtered, expected);
        proptest::prop_assert_eq!(report.frames_read, sections.len() as u64);
        proptest::prop_assert_eq!(report.frames_selected, selected);
    }
}
