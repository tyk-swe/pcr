// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use crate::FrameError;

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
    let mut writer = Writer::pcap_with_options(
        Vec::new(),
        LinkType::ETHERNET,
        PcapOptions {
            endianness: Endianness::Big,
            ..PcapOptions::default()
        },
    )
    .unwrap();
    writer.write_frame(&original).unwrap();
    let bytes = writer.into_inner();

    let mut reader = Reader::new(Cursor::new(bytes)).unwrap();
    assert_eq!(reader.format(), Format::Pcap);
    assert_eq!(reader.endianness(), Endianness::Big);
    assert_eq!(reader.next_frame().unwrap(), Some(original));
    assert_eq!(reader.next_frame().unwrap(), None);
}

#[test]
fn partial_container_headers_return_io_errors() {
    let mut pcap_sink = PartialFailSink::new(10);
    let error = expect_io_error(Writer::pcap(&mut pcap_sink, LinkType::ETHERNET));
    assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
    assert_eq!(pcap_sink.bytes.len(), 10);

    let mut pcapng_sink = PartialFailSink::new(13);
    let error = expect_io_error(Writer::pcapng(&mut pcapng_sink));
    assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
    assert_eq!(pcapng_sink.bytes.len(), 13);
}

#[test]
fn partial_classic_record_poisons_writer_without_committing_counters() {
    let mut writer = Writer::pcap(PartialFailSink::new(usize::MAX), LinkType::ETHERNET).unwrap();
    writer.get_mut().fail_after = PCAP_GLOBAL_HEADER_LEN + 10;

    let original = frame(UNIX_EPOCH, LinkType::ETHERNET, &[1, 2, 3]);
    let first = expect_io_error(writer.write_frame(&original));
    assert_eq!(first.kind(), io::ErrorKind::BrokenPipe);
    assert_eq!(writer.frames_written(), 0);
    assert_eq!(writer.captured_bytes_written(), 0);

    let bytes_after_failure = writer.get_ref().bytes.len();
    let writes_after_failure = writer.get_ref().write_calls;
    let mut invalid = original;
    invalid.interface = Some(0);
    let retained = expect_io_error(writer.write_frame(&invalid));
    assert_eq!(retained.kind(), first.kind());
    assert_eq!(retained.to_string(), first.to_string());
    assert_eq!(writer.get_ref().bytes.len(), bytes_after_failure);
    assert_eq!(writer.get_ref().write_calls, writes_after_failure);

    expect_io_error(writer.flush());
    assert_eq!(writer.get_ref().flush_calls, 0);
}

#[test]
fn prewrite_validation_error_does_not_poison_writer() {
    let mut writer = Writer::pcap(PartialFailSink::new(usize::MAX), LinkType::ETHERNET).unwrap();
    writer.get_mut().fail_after = PCAP_GLOBAL_HEADER_LEN;
    let writes_before_validation = writer.get_ref().write_calls;

    let mut invalid = frame(UNIX_EPOCH, LinkType::ETHERNET, &[1]);
    invalid.interface = Some(0);
    assert!(matches!(
        writer.write_frame(&invalid),
        Err(Error::MetadataNotRepresentable {
            format: Format::Pcap,
            field: "interface",
        })
    ));
    assert_eq!(writer.get_ref().write_calls, writes_before_validation);
    assert_eq!(writer.frames_written(), 0);

    writer.get_mut().fail_after = usize::MAX;
    writer
        .write_frame(&frame(UNIX_EPOCH, LinkType::ETHERNET, &[1]))
        .unwrap();
    assert_eq!(writer.frames_written(), 1);
    assert_eq!(writer.captured_bytes_written(), 1);
}

#[test]
fn classic_pcap_rejects_zero_snapshot_length() {
    assert!(matches!(
        Writer::pcap_with_options(
            Vec::new(),
            LinkType::ETHERNET,
            PcapOptions {
                snap_len: 0,
                ..PcapOptions::default()
            },
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
fn classic_pcap_reads_little_endian_microsecond_fixture() {
    let pcap_bytes = [
        // Classic PCAP global header, version 2.4, snaplen 64, Ethernet.
        0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x40, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        // One packet at 1 second + 2 microseconds, caplen 3, wirelen 5.
        0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00,
        0x00, 0xaa, 0xbb, 0xcc,
    ];
    let decoded = Reader::new(Cursor::new(pcap_bytes))
        .unwrap()
        .next_frame()
        .unwrap()
        .unwrap();
    assert_eq!(decoded.timestamp, UNIX_EPOCH + Duration::new(1, 2_000));
    assert_eq!(decoded.captured_length(), 3);
    assert_eq!(decoded.original_length(), 5);
    assert_eq!(decoded.link_type, LinkType::ETHERNET);
    assert_eq!(decoded.bytes().as_ref(), &[0xaa, 0xbb, 0xcc]);
}

#[test]
fn classic_pcap_reads_big_endian_nanosecond_records_and_rejects_bad_lengths() {
    let pcap_bytes = [
        // Classic PCAP global header, version 2.4, snaplen 64, Ethernet.
        0xa1, 0xb2, 0x3c, 0x4d, 0x00, 0x02, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x01,
        // One packet at 1 second + 123,456,789 nanoseconds, caplen 2, wirelen 5.
        0x00, 0x00, 0x00, 0x01, 0x07, 0x5b, 0xcd, 0x15, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
        0x05, 0xaa, 0xbb,
    ];
    let decoded = Reader::new(Cursor::new(pcap_bytes))
        .unwrap()
        .next_frame()
        .unwrap()
        .unwrap();
    assert_eq!(
        decoded.timestamp,
        UNIX_EPOCH + Duration::new(1, 123_456_789)
    );
    assert_eq!(decoded.captured_length(), 2);
    assert_eq!(decoded.original_length(), 5);
    assert_eq!(decoded.link_type, LinkType::ETHERNET);
    assert_eq!(decoded.bytes().as_ref(), &[0xaa, 0xbb]);

    let mut invalid = pcap_bytes.to_vec();
    invalid[32..36].copy_from_slice(&5_u32.to_be_bytes());
    invalid[36..40].copy_from_slice(&3_u32.to_be_bytes());
    let mut reader = Reader::new(Cursor::new(invalid)).unwrap();
    assert!(matches!(
        reader.next_frame(),
        Err(Error::Frame(FrameError::OriginalLengthTooSmall {
            captured: 5,
            original: 3
        }))
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
    assert_eq!(decoded.bytes(), original.bytes());
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
    assert_eq!(decoded.bytes(), original.bytes());
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
