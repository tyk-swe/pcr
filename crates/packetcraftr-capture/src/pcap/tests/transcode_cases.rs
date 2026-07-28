// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::*;

#[test]
fn pcapng_round_trip_preserves_multiple_interfaces_and_direction() {
    let mut writer = Writer::pcapng_with_options(
        Vec::new(),
        PcapNgOptions {
            endianness: Endianness::Big,
            ..PcapNgOptions::default()
        },
    )
    .unwrap();
    let ethernet = writer.add_interface(LinkType::ETHERNET).unwrap();
    let cooked = writer.add_interface(LinkType::LINUX_SLL2).unwrap();
    assert_eq!((ethernet, cooked), (0, 1));

    let mut first = frame(
        UNIX_EPOCH + Duration::new(10, 111_222_333),
        LinkType::ETHERNET,
        &[0xaa, 0xbb, 0xcc],
    );
    first.interface = Some(ethernet);
    first.direction = Some(Direction::Inbound);
    let mut second = frame(
        UNIX_EPOCH + Duration::new(11, 999_888_777),
        LinkType::LINUX_SLL2,
        &[0, 1, 2, 3, 4, 5, 6],
    );
    second.interface = Some(cooked);
    second.direction = Some(Direction::Outbound);
    writer.write_frame(&first).unwrap();
    writer.write_frame(&second).unwrap();

    let mut reader = Reader::new(Cursor::new(writer.into_inner())).unwrap();
    assert_eq!(reader.format(), Format::PcapNg);
    assert_eq!(reader.endianness(), Endianness::Big);
    assert_eq!(reader.next_frame().unwrap(), Some(first));
    assert_eq!(reader.next_frame().unwrap(), Some(second));
    assert_eq!(reader.next_frame().unwrap(), None);
}

#[test]
fn bounded_transcode_preserves_pcapng_interface_metadata_and_frames() {
    let mut writer = Writer::pcapng_with_options(
        Vec::new(),
        PcapNgOptions {
            endianness: Endianness::Big,
            ..PcapNgOptions::default()
        },
    )
    .unwrap();
    let ethernet = writer
        .add_interface_description(Interface {
            link_type: LinkType::ETHERNET,
            snap_len: 64,
            timestamp_resolution: TimestampResolution::Decimal(6),
            timestamp_offset: 0,
        })
        .unwrap();
    let raw = writer
        .add_interface_description(Interface {
            link_type: LinkType::RAW,
            snap_len: 128,
            timestamp_resolution: TimestampResolution::Binary(10),
            timestamp_offset: -1,
        })
        .unwrap();
    let mut first = Frame::try_with_lengths(
        UNIX_EPOCH + Duration::new(1, 123_456_000),
        LinkType::ETHERNET,
        3,
        60,
        vec![1, 2, 3],
    )
    .unwrap();
    first.interface = Some(ethernet);
    first.direction = Some(Direction::Inbound);
    let mut second = Frame::new(
        UNIX_EPOCH.checked_sub(Duration::from_millis(500)).unwrap(),
        LinkType::RAW,
        vec![4, 5],
    )
    .unwrap();
    second.interface = Some(raw);
    second.direction = Some(Direction::Outbound);
    writer.write_frame(&first).unwrap();
    writer.write_frame(&second).unwrap();

    let mut source = Reader::new(Cursor::new(writer.into_inner())).unwrap();
    let (bytes, report) = transcode(
        &mut source,
        Vec::new(),
        Format::PcapNg,
        Limits {
            max_frames: 2,
            max_bytes: 5,
        },
    )
    .unwrap();
    assert_eq!(
        report,
        TranscodeReport {
            source_format: Format::PcapNg,
            target_format: Format::PcapNg,
            endianness: Endianness::Big,
            frames: 2,
            captured_bytes: 5,
            interfaces: 2,
        }
    );

    let mut copied = Reader::new(Cursor::new(bytes)).unwrap();
    assert_eq!(copied.endianness(), Endianness::Big);
    assert_eq!(copied.next_frame().unwrap(), Some(first));
    assert_eq!(copied.next_frame().unwrap(), Some(second));
    assert_eq!(copied.next_frame().unwrap(), None);
    assert_eq!(
        copied.interfaces(),
        &[
            Interface {
                link_type: LinkType::ETHERNET,
                snap_len: 64,
                timestamp_resolution: TimestampResolution::Decimal(6),
                timestamp_offset: 0,
            },
            Interface {
                link_type: LinkType::RAW,
                snap_len: 128,
                timestamp_resolution: TimestampResolution::Binary(10),
                timestamp_offset: -1,
            },
        ]
    );
}

#[test]
fn bounded_transcode_preserves_snaplen_larger_than_actual_block_limit() {
    let mut writer = Writer::pcapng(Vec::new()).unwrap();
    let interface = writer
        .add_interface_description(Interface {
            link_type: LinkType::ETHERNET,
            snap_len: 65_535,
            timestamp_resolution: TimestampResolution::Decimal(9),
            timestamp_offset: 0,
        })
        .unwrap();
    let mut original = frame(UNIX_EPOCH, LinkType::ETHERNET, &[1, 2, 3]);
    original.interface = Some(interface);
    writer.write_frame(&original).unwrap();

    // The 64-byte processing limit bounds allocated blocks and actual
    // records, not the interface's advertised wire snap length.
    let options = ReaderOptions {
        max_size: 64,
        ..ReaderOptions::default()
    };
    let mut source = Reader::with_options(Cursor::new(writer.into_inner()), options).unwrap();
    let (bytes, report) =
        transcode(&mut source, Vec::new(), Format::PcapNg, Limits::default()).unwrap();
    assert_eq!(report.interfaces, 1);

    let mut copied = Reader::with_options(Cursor::new(bytes), options).unwrap();
    assert_eq!(copied.next_frame().unwrap(), Some(original));
    assert_eq!(copied.interfaces()[0].snap_len, 65_535);
    assert_eq!(copied.next_frame().unwrap(), None);
}

#[test]
fn classic_transcode_preserves_endianness_and_microsecond_resolution() {
    let original = frame(
        UNIX_EPOCH + Duration::new(2, 345_678_000),
        LinkType::ETHERNET,
        &[1, 2, 3],
    );
    let mut writer = Writer::pcap_with_options(
        Vec::new(),
        LinkType::ETHERNET,
        PcapOptions {
            endianness: Endianness::Big,
            timestamp_resolution: TimestampResolution::Decimal(6),
            snap_len: 64,
            max_size: 64,
        },
    )
    .unwrap();
    writer.write_frame(&original).unwrap();

    let mut source = Reader::new(Cursor::new(writer.into_inner())).unwrap();
    let (bytes, report) =
        transcode(&mut source, Vec::new(), Format::Pcap, Limits::default()).unwrap();
    assert_eq!(report.endianness, Endianness::Big);
    assert_eq!(&bytes[..4], &[0xa1, 0xb2, 0xc3, 0xd4]);

    let mut copied = Reader::new(Cursor::new(bytes)).unwrap();
    assert_eq!(copied.next_frame().unwrap(), Some(original));
    assert_eq!(
        copied.interfaces()[0].timestamp_resolution,
        TimestampResolution::Decimal(6)
    );

    let mut writer = Writer::pcap_with_options(
        Vec::new(),
        LinkType::ETHERNET,
        PcapOptions {
            endianness: Endianness::Little,
            timestamp_resolution: TimestampResolution::Decimal(6),
            snap_len: 64,
            max_size: 64,
        },
    )
    .unwrap();
    assert!(matches!(
        writer.write_frame(&frame(
            UNIX_EPOCH + Duration::from_nanos(100),
            LinkType::ETHERNET,
            &[1],
        )),
        Err(Error::MetadataNotRepresentable {
            format: Format::Pcap,
            field: "microsecond timestamp precision"
        })
    ));
    assert_eq!(writer.get_ref().len(), PCAP_GLOBAL_HEADER_LEN);
}

#[test]
fn writer_stream_limits_fail_before_emitting_the_excess_frame() {
    let mut writer = Writer::pcap(Vec::new(), LinkType::ETHERNET).unwrap();
    writer
        .set_stream_limits(Limits {
            max_frames: 1,
            max_bytes: 3,
        })
        .unwrap();
    writer
        .write_frame(&frame(UNIX_EPOCH, LinkType::ETHERNET, &[1, 2, 3]))
        .unwrap();
    let committed = writer.get_ref().len();
    assert!(matches!(
        writer.write_frame(&frame(UNIX_EPOCH, LinkType::ETHERNET, &[4])),
        Err(Error::FrameLimitExceeded {
            actual: 2,
            limit: 1
        })
    ));
    assert_eq!(writer.get_ref().len(), committed);
    assert_eq!(writer.frames_written(), 1);
    assert_eq!(writer.captured_bytes_written(), 3);

    let mut byte_writer = Writer::pcap(Vec::new(), LinkType::ETHERNET).unwrap();
    byte_writer
        .set_stream_limits(Limits {
            max_frames: 3,
            max_bytes: 3,
        })
        .unwrap();
    byte_writer
        .write_frame(&frame(UNIX_EPOCH, LinkType::ETHERNET, &[1, 2]))
        .unwrap();
    byte_writer
        .write_frame(&frame(UNIX_EPOCH, LinkType::ETHERNET, &[3]))
        .unwrap();
    let committed = byte_writer.get_ref().len();
    assert!(matches!(
        byte_writer.write_frame(&frame(UNIX_EPOCH, LinkType::ETHERNET, &[4])),
        Err(Error::StreamByteLimitExceeded {
            actual: 4,
            limit: 3
        })
    ));
    assert_eq!(byte_writer.get_ref().len(), committed);
    assert_eq!(byte_writer.frames_written(), 2);
    assert_eq!(byte_writer.captured_bytes_written(), 3);
}

#[test]
fn pcapng_to_classic_transcode_rejects_metadata_loss() {
    let mut writer = Writer::pcapng(Vec::new()).unwrap();
    writer.add_interface(LinkType::ETHERNET).unwrap();
    let mut source = Reader::new(Cursor::new(writer.into_inner())).unwrap();
    assert!(matches!(
        transcode(&mut source, Vec::new(), Format::Pcap, Limits::default(),),
        Err(Error::MetadataNotRepresentable {
            format: Format::Pcap,
            field: "pcapng interface metadata"
        })
    ));
}
