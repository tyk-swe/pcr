// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::*;

#[test]
fn pcapng_round_trip_preserves_pre_epoch_timestamps() {
    let whole_second = UNIX_EPOCH.checked_sub(Duration::from_secs(2)).unwrap();
    let fractional = UNIX_EPOCH
        .checked_sub(Duration::new(1, 123_456_789))
        .unwrap();

    for endianness in [Endianness::Little, Endianness::Big] {
        let mut writer = Writer::pcapng_with_options(
            Vec::new(),
            PcapNgOptions {
                endianness,
                ..PcapNgOptions::default()
            },
        )
        .unwrap();
        let interface = writer
            .add_interface_description(Interface {
                link_type: LinkType::ETHERNET,
                snap_len: u32::try_from(DEFAULT_SIZE_LIMIT).unwrap(),
                timestamp_resolution: TimestampResolution::Decimal(9),
                timestamp_offset: -3,
            })
            .unwrap();
        let mut first = frame(whole_second, LinkType::ETHERNET, &[1]);
        first.interface = Some(interface);
        let mut second = frame(fractional, LinkType::ETHERNET, &[2]);
        second.interface = Some(interface);
        writer.write_frame(&first).unwrap();
        writer.write_frame(&second).unwrap();

        let mut reader = Reader::new(Cursor::new(writer.into_inner())).unwrap();
        assert_eq!(reader.next_frame().unwrap(), Some(first));
        assert_eq!(reader.next_frame().unwrap(), Some(second));
        assert_eq!(reader.next_frame().unwrap(), None);
    }
}

#[test]
fn pcapng_writer_rejects_a_timestamp_before_its_interface_offset() {
    let mut writer = Writer::pcapng(Vec::new()).unwrap();
    let interface = writer
        .add_interface_description(Interface {
            link_type: LinkType::ETHERNET,
            snap_len: u32::try_from(DEFAULT_SIZE_LIMIT).unwrap(),
            timestamp_resolution: TimestampResolution::Decimal(9),
            timestamp_offset: -1,
        })
        .unwrap();
    let mut original = frame(
        UNIX_EPOCH.checked_sub(Duration::from_secs(2)).unwrap(),
        LinkType::ETHERNET,
        &[1],
    );
    original.interface = Some(interface);

    assert!(matches!(
        writer.write_frame(&original),
        Err(Error::TimestampOutOfRange {
            format: Format::PcapNg
        })
    ));
}

#[test]
fn rejected_auto_interface_frame_leaves_pcapng_bytes_and_numbering_unchanged() {
    let before_epoch = UNIX_EPOCH.checked_sub(Duration::from_secs(1)).unwrap();
    let mut timestamp_writer = Writer::pcapng(Vec::new()).unwrap();
    let original_len = timestamp_writer.get_ref().len();
    let invalid = frame(before_epoch, LinkType::ETHERNET, &[1]);
    assert!(matches!(
        timestamp_writer.write_frame(&invalid),
        Err(Error::TimestampOutOfRange {
            format: Format::PcapNg
        })
    ));
    assert_eq!(timestamp_writer.get_ref().len(), original_len);
    assert_eq!(
        timestamp_writer.add_interface(LinkType::LINUX_SLL).unwrap(),
        0
    );

    let mut size_writer = Writer::pcapng_with_options(
        Vec::new(),
        PcapNgOptions {
            max_size: 40,
            ..PcapNgOptions::default()
        },
    )
    .unwrap();
    let original_len = size_writer.get_ref().len();
    let mut invalid = frame(UNIX_EPOCH, LinkType::ETHERNET, &[1]);
    invalid.direction = Some(Direction::Inbound);
    assert!(matches!(
        size_writer.write_frame(&invalid),
        Err(Error::SizeLimitExceeded {
            kind: "pcapng enhanced packet block",
            declared: 48,
            limit: 40
        })
    ));
    assert_eq!(size_writer.get_ref().len(), original_len);
    assert_eq!(size_writer.add_interface(LinkType::LINUX_SLL).unwrap(), 0);
}

#[test]
fn pcapng_reader_bounds_interface_descriptions() {
    let mut writer = Writer::pcapng(Vec::new()).unwrap();
    writer.add_interface(LinkType::ETHERNET).unwrap();
    writer.add_interface(LinkType::LINUX_SLL).unwrap();
    let mut reader = Reader::with_options(
        Cursor::new(writer.into_inner()),
        ReaderOptions {
            max_interfaces_per_section: 1,
            ..ReaderOptions::default()
        },
    )
    .unwrap();

    assert!(matches!(
        reader.next_frame(),
        Err(Error::InterfaceLimit { limit: 1 })
    ));
}

#[test]
fn pcapng_writer_bounds_interfaces_atomically() {
    let mut writer = Writer::pcapng_with_options(
        Vec::new(),
        PcapNgOptions {
            max_interfaces: 1,
            ..PcapNgOptions::default()
        },
    )
    .unwrap();
    assert_eq!(writer.add_interface(LinkType::ETHERNET).unwrap(), 0);
    let bytes_after_first = writer.get_ref().len();

    assert!(matches!(
        writer.add_interface(LinkType::LINUX_SLL),
        Err(Error::InterfaceLimit { limit: 1 })
    ));
    assert_eq!(writer.get_ref().len(), bytes_after_first);

    let mut original = frame(UNIX_EPOCH, LinkType::ETHERNET, &[1, 2, 3]);
    original.interface = Some(0);
    writer.write_frame(&original).unwrap();
    let mut reader = Reader::new(Cursor::new(writer.into_inner())).unwrap();
    assert_eq!(reader.next_frame().unwrap(), Some(original));

    let mut zero_limit = Writer::pcapng_with_options(
        Vec::new(),
        PcapNgOptions {
            max_interfaces: 0,
            ..PcapNgOptions::default()
        },
    )
    .unwrap();
    let section_length = zero_limit.get_ref().len();
    assert!(matches!(
        zero_limit.add_interface(LinkType::ETHERNET),
        Err(Error::InterfaceLimit { limit: 0 })
    ));
    assert_eq!(zero_limit.get_ref().len(), section_length);
}

#[test]
fn partial_pcapng_interface_poisons_without_advancing_numbering() {
    let mut writer = Writer::pcapng(PartialFailSink::new(usize::MAX)).unwrap();
    let section_length = writer.get_ref().bytes.len();
    writer.get_mut().fail_after = section_length + 9;

    let first = expect_io_error(writer.add_interface(LinkType::ETHERNET));
    assert_eq!(first.kind(), io::ErrorKind::BrokenPipe);
    assert_eq!(pcapng_interface_count(&writer), 0);

    let bytes_after_failure = writer.get_ref().bytes.len();
    let writes_after_failure = writer.get_ref().write_calls;
    let retained = expect_io_error(writer.add_interface(LinkType(u32::from(u16::MAX) + 1)));
    assert_eq!(retained.kind(), first.kind());
    assert_eq!(retained.to_string(), first.to_string());
    assert_eq!(pcapng_interface_count(&writer), 0);
    assert_eq!(writer.get_ref().bytes.len(), bytes_after_failure);
    assert_eq!(writer.get_ref().write_calls, writes_after_failure);
}

#[test]
fn partial_pcapng_packet_poisons_without_committing_counters() {
    let mut writer = Writer::pcapng(PartialFailSink::new(usize::MAX)).unwrap();
    let interface = writer.add_interface(LinkType::ETHERNET).unwrap();
    let headers_length = writer.get_ref().bytes.len();
    writer.get_mut().fail_after = headers_length + 10;

    let mut original = frame(UNIX_EPOCH, LinkType::ETHERNET, &[1, 2, 3]);
    original.interface = Some(interface);
    let first = expect_io_error(writer.write_frame(&original));
    assert_eq!(first.kind(), io::ErrorKind::BrokenPipe);
    assert_eq!(writer.frames_written(), 0);
    assert_eq!(writer.captured_bytes_written(), 0);
    assert_eq!(pcapng_interface_count(&writer), 1);

    let bytes_after_failure = writer.get_ref().bytes.len();
    let writes_after_failure = writer.get_ref().write_calls;
    let mut invalid = original;
    invalid.interface = Some(99);
    let retained = expect_io_error(writer.write_frame(&invalid));
    assert_eq!(retained.kind(), first.kind());
    assert_eq!(retained.to_string(), first.to_string());
    assert_eq!(writer.get_ref().bytes.len(), bytes_after_failure);
    assert_eq!(writer.get_ref().write_calls, writes_after_failure);
}

#[test]
fn flush_failure_can_be_retried() {
    let mut writer = Writer::pcap(PartialFailSink::new(usize::MAX), LinkType::ETHERNET).unwrap();
    writer.get_mut().fail_flush = true;

    assert_eq!(
        expect_io_error(writer.flush()).kind(),
        io::ErrorKind::BrokenPipe
    );
    assert_eq!(writer.get_ref().flush_calls, 1);

    writer.get_mut().fail_flush = false;
    writer.flush().unwrap();
    writer
        .write_frame(&frame(UNIX_EPOCH, LinkType::ETHERNET, &[1]))
        .unwrap();
    assert_eq!(writer.get_ref().flush_calls, 2);
    assert_eq!(writer.frames_written(), 1);
}

#[test]
fn pcapng_default_interface_constructor_validates_before_writing() {
    let mut invalid_link_type = Vec::new();
    {
        let result = Writer::new(
            &mut invalid_link_type,
            Format::PcapNg,
            LinkType(u32::from(u16::MAX) + 1),
        );
        assert!(matches!(result, Err(Error::LinkTypeOutOfRange { .. })));
    }
    assert!(invalid_link_type.is_empty());
}

#[test]
fn pcapng_writer_emits_standard_section_and_interface_headers() {
    let mut writer = Writer::pcapng(Vec::new()).unwrap();
    writer.add_interface(LinkType::ETHERNET).unwrap();
    let bytes = writer.into_inner();

    assert_eq!(
        &bytes[..28],
        &[
            0x0a, 0x0d, 0x0d, 0x0a, 0x1c, 0x00, 0x00, 0x00, 0x4d, 0x3c, 0x2b, 0x1a, 0x01, 0x00,
            0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x1c, 0x00, 0x00, 0x00,
        ]
    );
    assert_eq!(&bytes[28..36], &[1, 0, 0, 0, 32, 0, 0, 0]);
    assert_eq!(&bytes[36..44], &[1, 0, 0, 0, 0, 0, 0, 1]);
    assert_eq!(&bytes[44..52], &[9, 0, 1, 0, 9, 0, 0, 0]);
    assert_eq!(&bytes[52..60], &[0, 0, 0, 0, 32, 0, 0, 0]);
}
