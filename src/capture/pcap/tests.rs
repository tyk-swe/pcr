#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    fn frame(timestamp: SystemTime, link_type: LinkType, bytes: &[u8]) -> Frame {
        Frame::new(timestamp, link_type, Bytes::copy_from_slice(bytes)).unwrap()
    }

    #[test]
    fn classic_pcap_round_trip_preserves_full_record() {
        let timestamp = UNIX_EPOCH + Duration::new(1_700_000_000, 123_456_789);
        let original = Frame::try_with_lengths(
            timestamp,
            LinkType::ETHERNET,
            5,
            64,
            Bytes::from_static(&[1, 2, 3, 4, 5]),
        )
        .unwrap();
        let mut writer =
            Writer::pcap_with_endianness(Vec::new(), LinkType::ETHERNET, Endianness::Big).unwrap();
        writer.write_frame(&original).unwrap();
        let bytes = writer.into_inner();

        let mut reader = Reader::new(Cursor::new(bytes)).unwrap();
        assert_eq!(reader.format(), Format::Pcap);
        assert_eq!(reader.endianness(), Endianness::Big);
        assert_eq!(reader.next_frame().unwrap(), Some(original));
        assert_eq!(reader.next_frame().unwrap(), None);
    }

    #[test]
    fn classic_pcap_rejects_zero_snapshot_length() {
        assert!(matches!(
            Writer::pcap_with_options(
                Vec::new(),
                LinkType::ETHERNET,
                Endianness::Little,
                0,
                DEFAULT_SIZE_LIMIT,
            ),
            Err(Error::InvalidData {
                format: Format::Pcap,
                reason: "snapshot length must be non-zero",
            })
        ));

        let writer = Writer::pcap(Vec::new(), LinkType::ETHERNET).unwrap();
        let mut bytes = writer.into_inner();
        bytes[16..20].copy_from_slice(&0_u32.to_le_bytes());
        assert!(matches!(
            Reader::new(Cursor::new(bytes)),
            Err(Error::InvalidData {
                format: Format::Pcap,
                reason: "snapshot length must be non-zero",
            })
        ));
    }

    #[test]
    fn reads_independent_little_endian_microsecond_fixture() {
        let fixture = [
            // Classic PCAP global header, version 2.4, snaplen 64, Ethernet.
            0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
            // One packet at 1 second + 2 microseconds, caplen 3, wirelen 5.
            0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x05, 0x00,
            0x00, 0x00, 0xaa, 0xbb, 0xcc,
        ];
        let decoded = Reader::new(Cursor::new(fixture))
            .unwrap()
            .next_frame()
            .unwrap()
            .unwrap();
        assert_eq!(decoded.timestamp, UNIX_EPOCH + Duration::new(1, 2_000));
        assert_eq!(decoded.captured_length, 3);
        assert_eq!(decoded.original_length, 5);
        assert_eq!(decoded.link_type, LinkType::ETHERNET);
        assert_eq!(decoded.bytes.as_ref(), &[0xaa, 0xbb, 0xcc]);
    }

    #[test]
    fn pcapng_round_trip_preserves_multiple_interfaces_and_direction() {
        let mut writer = Writer::pcapng_with_endianness(Vec::new(), Endianness::Big).unwrap();
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
        let mut writer = Writer::pcapng_with_endianness(Vec::new(), Endianness::Big).unwrap();
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
            .add_interface_with_snaplen(LinkType::ETHERNET, 65_535)
            .unwrap();
        let mut original = frame(UNIX_EPOCH, LinkType::ETHERNET, &[1, 2, 3]);
        original.interface = Some(interface);
        writer.write_frame(&original).unwrap();

        // The 64-byte processing limit bounds allocated blocks and actual
        // records, not the interface's advertised wire snap length.
        let mut source = Reader::with_limit(Cursor::new(writer.into_inner()), 64).unwrap();
        let (bytes, report) = transcode(
            &mut source,
            Vec::new(),
            Format::PcapNg,
            Limits::default(),
        )
        .unwrap();
        assert_eq!(report.interfaces, 1);

        let mut copied = Reader::with_limit(Cursor::new(bytes), 64).unwrap();
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
        let mut writer = Writer::pcap_with_metadata(
            Vec::new(),
            LinkType::ETHERNET,
            Endianness::Big,
            TimestampResolution::Decimal(6),
            64,
            64,
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

        let mut writer = Writer::pcap_with_metadata(
            Vec::new(),
            LinkType::ETHERNET,
            Endianness::Little,
            TimestampResolution::Decimal(6),
            64,
            64,
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

    #[test]
    fn pcapng_round_trip_preserves_pre_epoch_timestamps() {
        let whole_second = UNIX_EPOCH.checked_sub(Duration::from_secs(2)).unwrap();
        let fractional = UNIX_EPOCH
            .checked_sub(Duration::new(1, 123_456_789))
            .unwrap();

        for endianness in [Endianness::Little, Endianness::Big] {
            let mut writer = Writer::pcapng_with_endianness(Vec::new(), endianness).unwrap();
            let interface = writer
                .add_interface_with_timestamp_offset(LinkType::ETHERNET, -3)
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
            .add_interface_with_timestamp_offset(LinkType::ETHERNET, -1)
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
        assert_eq!(timestamp_writer.add_interface(LinkType::LINUX_SLL).unwrap(), 0);

        let mut size_writer =
            Writer::pcapng_with_options(Vec::new(), Endianness::Little, 40).unwrap();
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
        let mut reader =
            Reader::with_limits(Cursor::new(writer.into_inner()), DEFAULT_SIZE_LIMIT, 1).unwrap();

        assert!(matches!(
            reader.next_frame(),
            Err(Error::InterfaceLimit { limit: 1 })
        ));
    }

    #[test]
    fn pcapng_writer_bounds_interfaces_atomically() {
        let mut writer = Writer::pcapng_with_resource_limits(
            Vec::new(),
            Endianness::Little,
            DEFAULT_SIZE_LIMIT,
            1,
        )
        .unwrap();
        assert_eq!(writer.interface_limit(), 1);
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

        let mut zero_limit = Writer::pcapng_with_resource_limits(
            Vec::new(),
            Endianness::Little,
            DEFAULT_SIZE_LIMIT,
            0,
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
    fn pcapng_default_interface_constructor_validates_before_writing() {
        let mut undersized = vec![0xaa];
        {
            let result = Writer::with_limits(
                &mut undersized,
                Format::PcapNg,
                LinkType::ETHERNET,
                31,
                DEFAULT_INTERFACE_LIMIT,
            );
            assert!(matches!(
                result,
                Err(Error::SizeLimitExceeded {
                    kind: "pcapng interface description",
                    declared: 32,
                    limit: 31,
                })
            ));
        }
        assert_eq!(undersized, [0xaa]);

        let mut no_interfaces = Vec::new();
        {
            let result = Writer::with_limits(
                &mut no_interfaces,
                Format::PcapNg,
                LinkType::ETHERNET,
                64,
                0,
            );
            assert!(matches!(result, Err(Error::InterfaceLimit { limit: 0 })));
        }
        assert!(no_interfaces.is_empty());

        let mut invalid_link_type = Vec::new();
        {
            let result = Writer::with_limits(
                &mut invalid_link_type,
                Format::PcapNg,
                LinkType(u32::from(u16::MAX) + 1),
                64,
                DEFAULT_INTERFACE_LIMIT,
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

    #[test]
    fn pcapng_reader_keeps_section_interface_namespaces_distinct() {
        let mut first_writer = Writer::new(Vec::new(), Format::PcapNg, LinkType::ETHERNET).unwrap();
        let mut first = frame(UNIX_EPOCH, LinkType::ETHERNET, &[1]);
        first.interface = Some(0);
        first_writer.write_frame(&first).unwrap();

        let mut second_writer =
            Writer::new(Vec::new(), Format::PcapNg, LinkType::LINUX_SLL).unwrap();
        let mut second = frame(UNIX_EPOCH, LinkType::LINUX_SLL, &[2]);
        second.interface = Some(0);
        second_writer.write_frame(&second).unwrap();

        let mut bytes = first_writer.into_inner();
        bytes.extend_from_slice(&second_writer.into_inner());
        let mut reader =
            Reader::with_limits(Cursor::new(bytes.clone()), DEFAULT_SIZE_LIMIT, 1).unwrap();
        assert_eq!(reader.next_frame().unwrap(), Some(first.clone()));
        let mut global_second = second;
        global_second.interface = Some(1);
        assert_eq!(reader.next_frame().unwrap(), Some(global_second.clone()));
        assert_eq!(reader.next_frame().unwrap(), None);

        let mut source = Reader::with_all_resource_limits(
            Cursor::new(bytes.clone()),
            DEFAULT_SIZE_LIMIT,
            1,
            2,
            DEFAULT_METADATA_BLOCK_LIMIT,
        )
        .unwrap();
        let (transcoded, report) =
            transcode(&mut source, Vec::new(), Format::PcapNg, Limits::default()).unwrap();
        assert_eq!(report.interfaces, 2);
        let mut normalized =
            Reader::with_limits(Cursor::new(transcoded), DEFAULT_SIZE_LIMIT, 2).unwrap();
        assert_eq!(normalized.next_frame().unwrap(), Some(first));
        assert_eq!(normalized.next_frame().unwrap(), Some(global_second));
        assert_eq!(normalized.next_frame().unwrap(), None);

        let mut total_limited = Reader::with_all_resource_limits(
            Cursor::new(bytes),
            DEFAULT_SIZE_LIMIT,
            1,
            1,
            DEFAULT_METADATA_BLOCK_LIMIT,
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
        let mut writer = Writer::pcapng_with_options(Vec::new(), Endianness::Little, 31).unwrap();
        assert!(matches!(
            writer.add_interface(LinkType::ETHERNET),
            Err(Error::SizeLimitExceeded {
                declared: 32,
                limit: 31,
                ..
            })
        ));
        assert_eq!(writer.into_inner().len(), 28);

        let mut writer = Writer::pcapng_with_options(Vec::new(), Endianness::Little, 43).unwrap();
        assert!(matches!(
            writer.add_interface_with_timestamp_offset(LinkType::ETHERNET, -1),
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

        let mut reader = Reader::with_limit(Cursor::new(bytes), 1024).unwrap();
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
        let mut reader = Reader::with_resource_limits(
            Cursor::new(bytes),
            DEFAULT_SIZE_LIMIT,
            DEFAULT_INTERFACE_LIMIT,
            1,
        )
        .unwrap();
        assert!(matches!(
            reader.next_frame(),
            Err(Error::MetadataBlockLimit { limit: 1 })
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

        let mut packet_writer = Writer::new(
            Vec::new(),
            Format::PcapNg,
            LinkType::ETHERNET,
        )
        .unwrap();
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
    fn unknown_classic_link_type_is_preserved() {
        let unknown = LinkType(0xfedc);
        let original = frame(UNIX_EPOCH, unknown, &[9, 8, 7]);
        let mut writer = Writer::pcap(Vec::new(), unknown).unwrap();
        writer.write_frame(&original).unwrap();

        let decoded = Reader::new(Cursor::new(writer.into_inner()))
            .unwrap()
            .next_frame()
            .unwrap()
            .unwrap();
        assert_eq!(decoded.link_type, unknown);
        assert_eq!(decoded.bytes, original.bytes);
    }

    #[test]
    fn classic_pcap_fcs_metadata_does_not_change_link_type() {
        let original = frame(UNIX_EPOCH, LinkType::ETHERNET, &[1, 2, 3]);
        let mut writer = Writer::pcap(Vec::new(), LinkType::ETHERNET).unwrap();
        writer.write_frame(&original).unwrap();
        let mut bytes = writer.into_inner();
        bytes[20..24].copy_from_slice(&0x2400_0001_u32.to_le_bytes());

        let decoded = Reader::new(Cursor::new(bytes))
            .unwrap()
            .next_frame()
            .unwrap()
            .unwrap();
        assert_eq!(decoded.link_type, LinkType::ETHERNET);
        assert_eq!(decoded.bytes, original.bytes);
    }

    #[test]
    fn limit_is_checked_before_packet_allocation() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&[0x4d, 0x3c, 0xb2, 0xa1]);
        bytes.extend_from_slice(&2_u16.to_le_bytes());
        bytes.extend_from_slice(&4_u16.to_le_bytes());
        bytes.extend_from_slice(&0_u32.to_le_bytes());
        bytes.extend_from_slice(&0_u32.to_le_bytes());
        bytes.extend_from_slice(&u32::MAX.to_le_bytes());
        bytes.extend_from_slice(&1_u32.to_le_bytes());
        bytes.extend_from_slice(&0_u32.to_le_bytes());
        bytes.extend_from_slice(&0_u32.to_le_bytes());
        bytes.extend_from_slice(&1025_u32.to_le_bytes());
        bytes.extend_from_slice(&1025_u32.to_le_bytes());

        let mut reader = Reader::with_limit(Cursor::new(bytes), 1024).unwrap();
        assert!(matches!(
            reader.next_frame(),
            Err(Error::SizeLimitExceeded {
                declared: 1025,
                limit: 1024,
                ..
            })
        ));
    }

    #[test]
    fn truncated_records_are_not_reported_as_clean_eof() {
        let mut writer = Writer::pcap(Vec::new(), LinkType::ETHERNET).unwrap();
        writer
            .write_frame(&frame(UNIX_EPOCH, LinkType::ETHERNET, &[1, 2, 3, 4]))
            .unwrap();
        let mut bytes = writer.into_inner();
        bytes.pop();

        let mut reader = Reader::new(Cursor::new(bytes)).unwrap();
        assert!(matches!(
            reader.next_frame(),
            Err(Error::Truncated {
                context: "pcap packet data",
                ..
            })
        ));
    }

    #[test]
    fn classic_format_rejects_metadata_it_cannot_preserve() {
        let mut writer = Writer::pcap(Vec::new(), LinkType::ETHERNET).unwrap();
        let mut original = frame(UNIX_EPOCH, LinkType::ETHERNET, &[1]);
        original.interface = Some(0);
        assert!(matches!(
            writer.write_frame(&original),
            Err(Error::MetadataNotRepresentable {
                field: "interface",
                ..
            })
        ));
    }
}
