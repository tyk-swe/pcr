// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::*;

#[test]
fn pcapng_reader_keeps_section_interface_namespaces_distinct() {
    let mut first_writer = Writer::new(Vec::new(), Format::PcapNg, LinkType::ETHERNET).unwrap();
    let mut first = frame(UNIX_EPOCH, LinkType::ETHERNET, &[1]);
    first.interface = Some(0);
    first_writer.write_frame(&first).unwrap();

    let mut second_writer = Writer::new(Vec::new(), Format::PcapNg, LinkType::LINUX_SLL).unwrap();
    let mut second = frame(UNIX_EPOCH, LinkType::LINUX_SLL, &[2]);
    second.interface = Some(0);
    second_writer.write_frame(&second).unwrap();

    let mut bytes = first_writer.into_inner();
    bytes.extend_from_slice(&second_writer.into_inner());
    let mut reader = Reader::with_options(
        Cursor::new(bytes.clone()),
        ReaderOptions {
            max_interfaces_per_section: 1,
            ..ReaderOptions::default()
        },
    )
    .unwrap();
    assert_eq!(reader.next_frame().unwrap(), Some(first.clone()));
    let mut global_second = second;
    global_second.interface = Some(1);
    assert_eq!(reader.next_frame().unwrap(), Some(global_second.clone()));
    assert_eq!(reader.next_frame().unwrap(), None);

    let mut source = Reader::with_options(
        Cursor::new(bytes.clone()),
        ReaderOptions {
            max_interfaces_per_section: 1,
            max_total_interfaces: 2,
            ..ReaderOptions::default()
        },
    )
    .unwrap();
    let (transcoded, report) =
        transcode(&mut source, Vec::new(), Format::PcapNg, Limits::default()).unwrap();
    assert_eq!(report.interfaces, 2);
    let mut normalized = Reader::with_options(
        Cursor::new(transcoded),
        ReaderOptions {
            max_interfaces_per_section: 2,
            ..ReaderOptions::default()
        },
    )
    .unwrap();
    assert_eq!(normalized.next_frame().unwrap(), Some(first));
    assert_eq!(normalized.next_frame().unwrap(), Some(global_second));
    assert_eq!(normalized.next_frame().unwrap(), None);

    let mut total_limited = Reader::with_options(
        Cursor::new(bytes),
        ReaderOptions {
            max_interfaces_per_section: 1,
            max_total_interfaces: 1,
            ..ReaderOptions::default()
        },
    )
    .unwrap();
    assert!(total_limited.next_frame().unwrap().is_some());
    assert!(matches!(
        total_limited.next_frame(),
        Err(Error::TotalInterfaceLimit { limit: 1 })
    ));
}

#[test]
fn pcapng_interface_block_honors_writer_size_limit() {
    let mut writer = Writer::pcapng_with_options(
        Vec::new(),
        PcapNgOptions {
            max_size: 31,
            ..PcapNgOptions::default()
        },
    )
    .unwrap();
    assert!(matches!(
        writer.add_interface(LinkType::ETHERNET),
        Err(Error::SizeLimitExceeded {
            declared: 32,
            limit: 31,
            ..
        })
    ));
    assert_eq!(writer.into_inner().len(), 28);

    let mut writer = Writer::pcapng_with_options(
        Vec::new(),
        PcapNgOptions {
            max_size: 43,
            ..PcapNgOptions::default()
        },
    )
    .unwrap();
    assert!(matches!(
        writer.add_interface_description(Interface {
            link_type: LinkType::ETHERNET,
            snap_len: 43,
            timestamp_resolution: TimestampResolution::Decimal(9),
            timestamp_offset: -1,
        }),
        Err(Error::SizeLimitExceeded {
            declared: 44,
            limit: 43,
            ..
        })
    ));
    assert_eq!(writer.into_inner().len(), 28);
}

#[test]
fn pcapng_timestamp_arithmetic_fails_closed() {
    let half_second_before_epoch = UNIX_EPOCH.checked_sub(Duration::from_millis(500)).unwrap();
    assert_eq!(
        timestamp_to_ticks(
            half_second_before_epoch,
            TimestampResolution::Decimal(9),
            -1,
        )
        .unwrap(),
        500_000_000
    );

    assert!(matches!(
        timestamp_to_ticks(UNIX_EPOCH, TimestampResolution::Decimal(9), i64::MIN,),
        Err(Error::TimestampOutOfRange {
            format: Format::PcapNg
        })
    ));
    assert!(matches!(
        timestamp_to_ticks(
            UNIX_EPOCH + Duration::from_secs(1),
            TimestampResolution::Decimal(38),
            0,
        ),
        Err(Error::TimestampOutOfRange {
            format: Format::PcapNg
        })
    ));
    assert!(matches!(
        system_time_from_signed_unix(i128::MIN, 0),
        Err(Error::TimestampOutOfRange {
            format: Format::PcapNg
        })
    ));
    assert!(matches!(
        timestamp_from_ticks(1, TimestampResolution::Decimal(12), 0),
        Err(Error::MetadataNotRepresentable {
            format: Format::PcapNg,
            field: "sub-nanosecond timestamp"
        })
    ));
    assert!(matches!(
        timestamp_to_ticks(
            UNIX_EPOCH + Duration::from_nanos(100),
            TimestampResolution::Binary(10),
            0,
        ),
        Err(Error::MetadataNotRepresentable {
            format: Format::PcapNg,
            field: "timestamp resolution"
        })
    ));
}

#[test]
fn zero_tick_timestamp_round_trips_at_an_unbounded_decimal_denominator() {
    let mut writer = Writer::pcapng(Vec::new()).unwrap();
    writer
        .add_interface_description(Interface {
            link_type: LinkType::ETHERNET,
            snap_len: 64,
            timestamp_resolution: TimestampResolution::Decimal(127),
            timestamp_offset: 0,
        })
        .unwrap();
    let mut original = frame(UNIX_EPOCH, LinkType::ETHERNET, &[1, 2, 3]);
    original.interface = Some(0);
    writer.write_frame(&original).unwrap();

    let mut reader = Reader::new(Cursor::new(writer.into_inner())).unwrap();
    assert_eq!(reader.next_frame().unwrap(), Some(original));
    assert_eq!(reader.next_frame().unwrap(), None);
}

#[test]
fn pcapng_block_limit_is_checked_before_allocation() {
    let writer = Writer::pcapng(Vec::new()).unwrap();
    let mut bytes = writer.into_inner();
    bytes.extend_from_slice(&1_u32.to_le_bytes());
    bytes.extend_from_slice(&2048_u32.to_le_bytes());

    let mut reader = Reader::with_options(
        Cursor::new(bytes),
        ReaderOptions {
            max_size: 1024,
            ..ReaderOptions::default()
        },
    )
    .unwrap();
    assert!(matches!(
        reader.next_frame(),
        Err(Error::SizeLimitExceeded {
            declared: 2048,
            limit: 1024,
            ..
        })
    ));
}

#[test]
fn pcapng_metadata_work_is_bounded_per_read() {
    let section = Writer::pcapng(Vec::new()).unwrap().into_inner();
    let mut bytes = section.clone();
    bytes.extend_from_slice(&section);
    bytes.extend_from_slice(&section);
    let mut reader = Reader::with_options(
        Cursor::new(bytes),
        ReaderOptions {
            max_metadata_blocks_per_frame: 1,
            ..ReaderOptions::default()
        },
    )
    .unwrap();
    assert!(matches!(
        reader.next_frame(),
        Err(Error::MetadataBlockLimit { limit: 1 })
    ));
}

#[test]
fn pcapng_metadata_bytes_are_rejected_before_reading_the_block_body() {
    let mut bytes = Writer::pcapng(Vec::new()).unwrap().into_inner();
    bytes.extend_from_slice(&0x1234_u32.to_le_bytes());
    bytes.extend_from_slice(&32_u32.to_le_bytes());
    let mut reader = Reader::with_options(
        Cursor::new(bytes),
        ReaderOptions {
            max_metadata_bytes_per_frame: 16,
            ..ReaderOptions::default()
        },
    )
    .unwrap();

    assert!(matches!(
        reader.next_frame(),
        Err(Error::MetadataByteLimit { limit: 16 })
    ));
}

#[test]
fn pcapng_ignores_reserved_fields_and_rejects_bad_padding_and_duplicate_singletons() {
    let mut interface_writer = Writer::pcapng(Vec::new()).unwrap();
    interface_writer.add_interface(LinkType::ETHERNET).unwrap();
    let interface_bytes = interface_writer.into_inner();

    let mut bad_interface_reserved = interface_bytes.clone();
    bad_interface_reserved[38] = 1;
    let mut reader = Reader::new(Cursor::new(bad_interface_reserved)).unwrap();
    assert_eq!(reader.next_frame().unwrap(), None);
    assert_eq!(reader.interfaces().len(), 1);

    let mut bad_option_padding = interface_bytes.clone();
    bad_option_padding[49] = 1;
    let mut reader = Reader::new(Cursor::new(bad_option_padding)).unwrap();
    assert!(matches!(
        reader.next_frame(),
        Err(Error::InvalidData {
            format: Format::PcapNg,
            reason: "option padding is non-zero",
        })
    ));

    let mut duplicate_resolution = interface_bytes;
    let duplicate = duplicate_resolution[44..52].to_vec();
    duplicate_resolution.splice(52..52, duplicate);
    duplicate_resolution[32..36].copy_from_slice(&40_u32.to_le_bytes());
    duplicate_resolution[64..68].copy_from_slice(&40_u32.to_le_bytes());
    let mut reader = Reader::new(Cursor::new(duplicate_resolution)).unwrap();
    assert!(matches!(
        reader.next_frame(),
        Err(Error::InvalidData {
            format: Format::PcapNg,
            reason: "if_tsresol option appears more than once",
        })
    ));

    let mut packet_writer = Writer::new(Vec::new(), Format::PcapNg, LinkType::ETHERNET).unwrap();
    let mut packet = frame(UNIX_EPOCH, LinkType::ETHERNET, &[1]);
    packet.interface = Some(0);
    packet_writer.write_frame(&packet).unwrap();
    let mut bad_packet_padding = packet_writer.into_inner();
    bad_packet_padding[89] = 1;
    let mut reader = Reader::new(Cursor::new(bad_packet_padding)).unwrap();
    assert!(matches!(
        reader.next_frame(),
        Err(Error::InvalidData {
            format: Format::PcapNg,
            reason: "packet data padding is non-zero",
        })
    ));
}

#[test]
fn pcapng_rejects_impossible_negative_section_length() {
    let mut bytes = Writer::pcapng(Vec::new()).unwrap().into_inner();
    bytes[16..24].copy_from_slice(&(-2_i64).to_le_bytes());

    assert!(matches!(
        Reader::new(Cursor::new(bytes)),
        Err(Error::InvalidData {
            format: Format::PcapNg,
            reason: "section length is negative but is not the unknown-length sentinel",
        })
    ));
}

#[test]
fn pcapng_accepts_compatible_minor_version_two_and_rejects_unaligned_section_length() {
    let mut compatible = Writer::pcapng(Vec::new()).unwrap().into_inner();
    compatible[14..16].copy_from_slice(&2_u16.to_le_bytes());
    let mut reader = Reader::new(Cursor::new(compatible)).unwrap();
    assert_eq!(reader.next_frame().unwrap(), None);

    let mut unaligned = Writer::pcapng(Vec::new()).unwrap().into_inner();
    unaligned[16..24].copy_from_slice(&1_i64.to_le_bytes());
    assert!(matches!(
        Reader::new(Cursor::new(unaligned)),
        Err(Error::InvalidData {
            format: Format::PcapNg,
            reason: "section length is not a multiple of four",
        })
    ));
}

#[test]
fn pcapng_finite_section_accepts_exact_boundary_at_eof() {
    let mut writer = Writer::pcapng(Vec::new()).unwrap();
    writer.add_interface(LinkType::ETHERNET).unwrap();
    let mut bytes = writer.into_inner();
    declare_little_endian_section_length(&mut bytes);

    let mut reader = Reader::new(Cursor::new(bytes)).unwrap();
    assert_eq!(reader.next_frame().unwrap(), None);
    assert_eq!(reader.interfaces().len(), 1);
}

#[test]
fn pcapng_finite_section_rejects_block_overrun() {
    let mut writer = Writer::pcapng(Vec::new()).unwrap();
    writer.add_interface(LinkType::ETHERNET).unwrap();
    let mut bytes = writer.into_inner();
    bytes[16..24].copy_from_slice(&28_i64.to_le_bytes());

    let mut reader = Reader::new(Cursor::new(bytes)).unwrap();
    assert!(matches!(
        reader.next_frame(),
        Err(Error::BlockCrossesSectionBoundary {
            block_length: 32,
            remaining: 28,
        })
    ));
}

#[test]
fn pcapng_finite_section_rejects_premature_eof() {
    let mut writer = Writer::pcapng(Vec::new()).unwrap();
    writer.add_interface(LinkType::ETHERNET).unwrap();
    let mut bytes = writer.into_inner();
    bytes[16..24].copy_from_slice(&44_i64.to_le_bytes());

    let mut reader = Reader::new(Cursor::new(bytes)).unwrap();
    assert!(matches!(
        reader.next_frame(),
        Err(Error::SectionEndedEarly { remaining: 12 })
    ));
}

#[test]
fn pcapng_finite_section_rejects_new_section_before_boundary() {
    let mut first = Writer::pcapng(Vec::new()).unwrap().into_inner();
    first[16..24].copy_from_slice(&12_i64.to_le_bytes());
    first.extend_from_slice(&Writer::pcapng(Vec::new()).unwrap().into_inner());

    let mut reader = Reader::new(Cursor::new(first)).unwrap();
    assert!(matches!(
        reader.next_frame(),
        Err(Error::SectionHeaderBeforeBoundary { remaining: 12 })
    ));
}

#[test]
fn pcapng_finite_section_rejects_short_remainder_without_reading_past_boundary() {
    let mut bytes = Writer::pcapng(Vec::new()).unwrap().into_inner();
    bytes[16..24].copy_from_slice(&4_i64.to_le_bytes());
    bytes.extend_from_slice(&[0xa5; 8]);

    let mut reader = Reader::new(Cursor::new(bytes)).unwrap();
    assert!(matches!(
        reader.next_frame(),
        Err(Error::SectionRemainderTooSmall { remaining: 4 })
    ));
    assert_eq!(reader.get_ref().position(), 28);
}

#[test]
fn pcapng_finite_sections_can_be_adjacent() {
    let mut first_writer = Writer::new(Vec::new(), Format::PcapNg, LinkType::ETHERNET).unwrap();
    let mut first_frame = frame(UNIX_EPOCH, LinkType::ETHERNET, &[1]);
    first_frame.interface = Some(0);
    first_writer.write_frame(&first_frame).unwrap();
    let mut first = first_writer.into_inner();
    declare_little_endian_section_length(&mut first);

    let mut second_writer = Writer::new(Vec::new(), Format::PcapNg, LinkType::LINUX_SLL).unwrap();
    let mut second_frame = frame(UNIX_EPOCH, LinkType::LINUX_SLL, &[2]);
    second_frame.interface = Some(0);
    second_writer.write_frame(&second_frame).unwrap();
    let mut second = second_writer.into_inner();
    declare_little_endian_section_length(&mut second);
    first.extend_from_slice(&second);

    let mut reader = Reader::new(Cursor::new(first)).unwrap();
    assert_eq!(reader.next_frame().unwrap(), Some(first_frame));
    second_frame.interface = Some(1);
    assert_eq!(reader.next_frame().unwrap(), Some(second_frame));
    assert_eq!(reader.next_frame().unwrap(), None);
}
