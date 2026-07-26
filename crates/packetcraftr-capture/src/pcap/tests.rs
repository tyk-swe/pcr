// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::io::{self, Cursor, Write};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;

use crate::{Direction, Frame, LinkType};

use super::models::{
    Comment, CommentScope, DEFAULT_SIZE_LIMIT, Endianness, Error, Format, Interface,
    InterfaceStatistics, Limits, MAX_METADATA_TEXT_BYTES, NameRecord, PcapNgOptions, PcapOptions,
    ReaderOptions, TimestampResolution, TranscodeReport,
};
use super::reader::Reader;
use super::transcode::transcode;
use super::wire::{
    PCAP_GLOBAL_HEADER_LEN, PCAPNG_BYTE_ORDER_MAGIC, PCAPNG_ENHANCED_PACKET_BLOCK,
    PCAPNG_INTERFACE_DESCRIPTION_BLOCK, PCAPNG_INTERFACE_STATISTICS_BLOCK, PCAPNG_OPTION_COMMENT,
    PCAPNG_OPTION_END, PCAPNG_OPTION_ISB_IFRECV, PCAPNG_PACKET_BLOCK, PCAPNG_SECTION_HEADER_BLOCK,
    PCAPNG_SIMPLE_PACKET_BLOCK, system_time_from_signed_unix, timestamp_from_ticks,
    timestamp_to_ticks,
};
use super::writer::Writer;

#[derive(Debug)]
struct PartialFailSink {
    bytes: Vec<u8>,
    fail_after: usize,
    write_calls: usize,
    flush_calls: usize,
    fail_flush: bool,
}

impl PartialFailSink {
    fn new(fail_after: usize) -> Self {
        Self {
            bytes: Vec::new(),
            fail_after,
            write_calls: 0,
            flush_calls: 0,
            fail_flush: false,
        }
    }
}

impl Write for PartialFailSink {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.write_calls += 1;
        if self.bytes.len() >= self.fail_after {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "deterministic sink failure",
            ));
        }
        let written = buffer.len().min(self.fail_after - self.bytes.len());
        self.bytes.extend_from_slice(&buffer[..written]);
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.flush_calls += 1;
        if self.fail_flush {
            Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "deterministic flush failure",
            ))
        } else {
            Ok(())
        }
    }
}

fn expect_io_error<T>(result: Result<T, Error>) -> io::Error {
    match result {
        Err(Error::Io(error)) => error,
        Err(error) => panic!("expected I/O error, got {error:?}"),
        Ok(_) => panic!("expected I/O error, got success"),
    }
}

fn pcapng_interface_count<W>(writer: &Writer<W>) -> usize {
    match &writer.state {
        super::writer::WriterState::PcapNg { interfaces, .. } => interfaces.len(),
        super::writer::WriterState::Pcap { .. } => panic!("expected pcapng writer"),
    }
}

fn frame(timestamp: SystemTime, link_type: LinkType, bytes: &[u8]) -> Frame {
    Frame::new(timestamp, link_type, Bytes::copy_from_slice(bytes)).unwrap()
}

fn declare_little_endian_section_length(bytes: &mut [u8]) {
    let section_length = i64::try_from(bytes.len() - 28).unwrap();
    bytes[16..24].copy_from_slice(&section_length.to_le_bytes());
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
        Err(Error::OriginalLengthTooSmall {
            captured: 5,
            original: 3
        })
    ));
}

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
            dropped_metadata: Default::default(),
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
                snap_len: DEFAULT_SIZE_LIMIT as u32,
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
            snap_len: DEFAULT_SIZE_LIMIT as u32,
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
fn flush_failure_poisons_writer() {
    let mut writer = Writer::pcap(PartialFailSink::new(usize::MAX), LinkType::ETHERNET).unwrap();
    writer.get_mut().fail_flush = true;

    let first = expect_io_error(writer.flush());
    assert_eq!(first.kind(), io::ErrorKind::BrokenPipe);
    assert_eq!(writer.get_ref().flush_calls, 1);
    let writes_after_failure = writer.get_ref().write_calls;

    writer.get_mut().fail_flush = false;
    let retained =
        expect_io_error(writer.write_frame(&frame(UNIX_EPOCH, LinkType::ETHERNET, &[1])));
    assert_eq!(retained.kind(), first.kind());
    assert_eq!(retained.to_string(), first.to_string());
    assert_eq!(writer.get_ref().write_calls, writes_after_failure);
    assert_eq!(writer.frames_written(), 0);
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
fn writer_option_defaults_match_convenience_constructors() {
    let pcap = Writer::pcap(Vec::new(), LinkType::ETHERNET)
        .unwrap()
        .into_inner();
    let configured_pcap =
        Writer::pcap_with_options(Vec::new(), LinkType::ETHERNET, PcapOptions::default())
            .unwrap()
            .into_inner();
    assert_eq!(configured_pcap, pcap);

    let pcapng = Writer::pcapng(Vec::new()).unwrap().into_inner();
    let configured_pcapng = Writer::pcapng_with_options(Vec::new(), PcapNgOptions::default())
        .unwrap()
        .into_inner();
    assert_eq!(configured_pcapng, pcapng);
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

fn annotated_fixture() -> Vec<u8> {
    std::fs::read(
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/captures/pcapng/annotated.pcapng"),
    )
    .unwrap()
}

/// Frames one little-endian PCAPNG block around a body.
///
/// The committed fixture cannot express the shapes the retention bounds have to
/// survive — a section header carrying more comments than the bound allows, or
/// a file mixing packet block kinds — so those cases are assembled here.
fn pcapng_block(block_type: u32, body: &[u8]) -> Vec<u8> {
    let total = (12 + body.len()) as u32;
    let mut block = Vec::with_capacity(total as usize);
    block.extend_from_slice(&block_type.to_le_bytes());
    block.extend_from_slice(&total.to_le_bytes());
    block.extend_from_slice(body);
    block.extend_from_slice(&total.to_le_bytes());
    block
}

fn pcapng_option(code: u16, value: &[u8]) -> Vec<u8> {
    let mut option = Vec::new();
    option.extend_from_slice(&code.to_le_bytes());
    option.extend_from_slice(&(value.len() as u16).to_le_bytes());
    option.extend_from_slice(value);
    option.resize(option.len().next_multiple_of(4), 0);
    option
}

fn pcapng_option_end() -> Vec<u8> {
    pcapng_option(PCAPNG_OPTION_END, &[])
}

/// A section header carrying the given comments, followed by one interface.
fn pcapng_section(comments: &[&[u8]]) -> Vec<u8> {
    let mut header = Vec::new();
    header.extend_from_slice(&PCAPNG_BYTE_ORDER_MAGIC.to_le_bytes());
    header.extend_from_slice(&1_u16.to_le_bytes());
    header.extend_from_slice(&0_u16.to_le_bytes());
    header.extend_from_slice(&(-1_i64).to_le_bytes());
    for comment in comments {
        header.extend_from_slice(&pcapng_option(PCAPNG_OPTION_COMMENT, comment));
    }
    if !comments.is_empty() {
        header.extend_from_slice(&pcapng_option_end());
    }

    let mut interface = Vec::new();
    interface.extend_from_slice(&1_u16.to_le_bytes());
    interface.extend_from_slice(&0_u16.to_le_bytes());
    interface.extend_from_slice(&65_535_u32.to_le_bytes());

    let mut capture = pcapng_block(PCAPNG_SECTION_HEADER_BLOCK, &header);
    capture.extend_from_slice(&pcapng_block(
        PCAPNG_INTERFACE_DESCRIPTION_BLOCK,
        &interface,
    ));
    capture
}

#[test]
fn section_header_comments_obey_the_metadata_bound() {
    let capture = pcapng_section(&[b"one", b"two", b"three"]);
    let reader = Reader::with_options(
        Cursor::new(capture),
        ReaderOptions {
            max_metadata_records: 2,
            ..ReaderOptions::default()
        },
    )
    .unwrap();

    // The opening section header is parsed while the reader is built, before
    // any frame is asked for, so it is the one place retention could bypass the
    // bound entirely rather than merely exceed it.
    let metadata = reader.metadata();
    assert_eq!(metadata.comments.len(), 2);
    assert_eq!(metadata.dropped, 1);
    assert_eq!(metadata.observed(), 3);
}

#[test]
fn an_invalid_comment_is_bounded_by_the_text_it_retains() {
    // `from_utf8_lossy` widens every invalid byte into a three-byte replacement
    // character, so a bound checked against the source slice would let this
    // comment reach three times the documented limit.
    let source = vec![0xff_u8; MAX_METADATA_TEXT_BYTES];
    let reader = Reader::new(Cursor::new(pcapng_section(&[&source]))).unwrap();

    let comment = &reader.metadata().comments[0];
    assert!(
        comment.text.len() <= MAX_METADATA_TEXT_BYTES,
        "retained {} bytes",
        comment.text.len()
    );
    assert!(comment.truncated);
}

#[test]
fn a_multibyte_comment_at_the_metadata_limit_is_preserved() {
    let mut retained = vec![b'a'; MAX_METADATA_TEXT_BYTES - 2];
    retained.extend_from_slice(&[0xc3, 0xa9]);
    let mut source = retained.clone();
    source.push(b'z');
    let reader = Reader::new(Cursor::new(pcapng_section(&[&source]))).unwrap();

    let comment = &reader.metadata().comments[0];
    assert_eq!(comment.text.as_bytes(), retained);
    assert!(comment.truncated);
}

#[test]
fn frame_comment_scope_counts_every_packet_block_kind() {
    let mut capture = pcapng_section(&[]);

    let mut obsolete = Vec::new();
    obsolete.extend_from_slice(&0_u16.to_le_bytes());
    obsolete.extend_from_slice(&0_u16.to_le_bytes());
    obsolete.extend_from_slice(&0_u32.to_le_bytes());
    obsolete.extend_from_slice(&0_u32.to_le_bytes());
    obsolete.extend_from_slice(&4_u32.to_le_bytes());
    obsolete.extend_from_slice(&4_u32.to_le_bytes());
    obsolete.extend_from_slice(&[1, 2, 3, 4]);
    obsolete.extend_from_slice(&pcapng_option(PCAPNG_OPTION_COMMENT, b"first"));
    obsolete.extend_from_slice(&pcapng_option_end());
    capture.extend_from_slice(&pcapng_block(PCAPNG_PACKET_BLOCK, &obsolete));

    let mut simple = Vec::new();
    simple.extend_from_slice(&4_u32.to_le_bytes());
    simple.extend_from_slice(&[5, 6, 7, 8]);
    capture.extend_from_slice(&pcapng_block(PCAPNG_SIMPLE_PACKET_BLOCK, &simple));

    let mut enhanced = Vec::new();
    enhanced.extend_from_slice(&0_u32.to_le_bytes());
    enhanced.extend_from_slice(&0_u32.to_le_bytes());
    enhanced.extend_from_slice(&0_u32.to_le_bytes());
    enhanced.extend_from_slice(&4_u32.to_le_bytes());
    enhanced.extend_from_slice(&4_u32.to_le_bytes());
    enhanced.extend_from_slice(&[9, 10, 11, 12]);
    enhanced.extend_from_slice(&pcapng_option(PCAPNG_OPTION_COMMENT, b"third"));
    enhanced.extend_from_slice(&pcapng_option_end());
    capture.extend_from_slice(&pcapng_block(PCAPNG_ENHANCED_PACKET_BLOCK, &enhanced));

    let mut reader = Reader::new(Cursor::new(capture)).unwrap();
    let frames = std::iter::from_fn(|| reader.next_frame().transpose())
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    // A comment names its frame by stream position, so obsolete and simple
    // packet blocks have to advance that position like any other frame.
    assert_eq!(frames.len(), 3);
    assert_eq!(
        reader.metadata().comments,
        vec![
            Comment {
                scope: CommentScope::Frame { sequence: 0 },
                text: "first".to_owned(),
                truncated: false,
            },
            Comment {
                scope: CommentScope::Frame { sequence: 2 },
                text: "third".to_owned(),
                truncated: false,
            },
        ]
    );
}

#[test]
fn interface_statistics_use_global_interface_ids_across_sections() {
    let mut capture = pcapng_section(&[]);
    capture.extend_from_slice(&pcapng_section(&[]));

    let mut statistics = Vec::new();
    statistics.extend_from_slice(&0_u32.to_le_bytes());
    statistics.extend_from_slice(&0_u32.to_le_bytes());
    statistics.extend_from_slice(&0_u32.to_le_bytes());
    statistics.extend_from_slice(&pcapng_option(
        PCAPNG_OPTION_ISB_IFRECV,
        &7_u64.to_le_bytes(),
    ));
    statistics.extend_from_slice(&pcapng_option_end());
    capture.extend_from_slice(&pcapng_block(
        PCAPNG_INTERFACE_STATISTICS_BLOCK,
        &statistics,
    ));

    let mut reader = Reader::new(Cursor::new(capture)).unwrap();
    assert_eq!(reader.next_frame().unwrap(), None);

    assert_eq!(
        reader.metadata().interface_statistics,
        vec![InterfaceStatistics {
            interface: 1,
            received: Some(7),
            dropped: None,
            filter_accepted: None,
        }]
    );
}

#[test]
fn pcapng_comments_names_and_statistics_are_retained_with_their_scope() {
    let mut reader = Reader::new(Cursor::new(annotated_fixture())).unwrap();
    // The section comment is available before any block is consumed.
    assert_eq!(
        reader.metadata().comments,
        vec![Comment {
            scope: CommentScope::Section,
            text: "lab capture with annotations".to_owned(),
            truncated: false,
        }]
    );

    let frames = std::iter::from_fn(|| reader.next_frame().transpose())
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(frames.len(), 2);

    let metadata = reader.metadata();
    assert_eq!(metadata.dropped, 0);
    assert_eq!(
        metadata.comments,
        vec![
            Comment {
                scope: CommentScope::Section,
                text: "lab capture with annotations".to_owned(),
                truncated: false,
            },
            Comment {
                scope: CommentScope::Interface { interface: 0 },
                text: "span port on lab0".to_owned(),
                truncated: false,
            },
            Comment {
                scope: CommentScope::Frame { sequence: 0 },
                text: "first probe".to_owned(),
                truncated: false,
            },
        ]
    );
    assert_eq!(
        metadata.name_records,
        vec![
            NameRecord {
                address: "192.0.2.1".parse().unwrap(),
                names: vec!["alpha.lab".to_owned()],
            },
            NameRecord {
                address: "2001:db8::1".parse().unwrap(),
                names: vec!["beta.lab".to_owned(), "beta".to_owned()],
            },
        ]
    );
    assert_eq!(
        metadata.interface_statistics,
        vec![InterfaceStatistics {
            interface: 0,
            received: Some(2),
            dropped: Some(1),
            filter_accepted: Some(3),
        }]
    );
    assert_eq!(metadata.observed(), 6);
    assert!(!metadata.is_empty());
}

#[test]
fn metadata_retention_is_bounded_and_reports_what_it_dropped() {
    let mut reader = Reader::with_options(
        Cursor::new(annotated_fixture()),
        ReaderOptions {
            max_metadata_records: 2,
            ..ReaderOptions::default()
        },
    )
    .unwrap();
    while reader.next_frame().unwrap().is_some() {}

    let metadata = reader.metadata();
    let retained =
        metadata.comments.len() + metadata.name_records.len() + metadata.interface_statistics.len();
    assert_eq!(retained, 2);
    // Everything past the bound is counted, so the loss is visible.
    assert_eq!(metadata.dropped, 4);
    assert_eq!(metadata.observed(), 6);
}

#[test]
fn a_lossy_transcode_reports_the_metadata_it_could_not_carry() {
    let mut reader = Reader::new(Cursor::new(annotated_fixture())).unwrap();
    let (bytes, report) =
        transcode(&mut reader, Vec::new(), Format::PcapNg, Limits::default()).unwrap();

    assert_eq!(report.frames, 2);
    // The writer emits frames and interface descriptions only, so every
    // annotation the source carried is reported rather than silently dropped.
    assert_eq!(report.dropped_metadata.comments, 3);
    assert_eq!(report.dropped_metadata.name_records, 2);
    assert_eq!(report.dropped_metadata.interface_statistics, 1);
    assert_eq!(report.dropped_metadata.total(), 6);
    assert!(!report.dropped_metadata.is_empty());

    // The copied frames themselves are unaffected.
    let mut copied = Reader::new(Cursor::new(bytes)).unwrap();
    assert_eq!(copied.next_frame().unwrap().unwrap().captured_length(), 47);
    assert!(copied.metadata().is_empty());
}

#[test]
fn a_lossy_transcode_also_reports_what_the_reader_never_retained() {
    let mut reader = Reader::with_options(
        Cursor::new(annotated_fixture()),
        ReaderOptions {
            max_metadata_records: 2,
            ..ReaderOptions::default()
        },
    )
    .unwrap();
    let (_bytes, report) =
        transcode(&mut reader, Vec::new(), Format::PcapNg, Limits::default()).unwrap();

    // Two records reached memory and four never did. The copy carries neither
    // kind, so counting only the retained two would understate the loss by two
    // thirds — the opposite of what the report exists to say.
    assert_eq!(report.dropped_metadata.comments, 2);
    assert_eq!(report.dropped_metadata.unretained, 4);
    assert_eq!(report.dropped_metadata.total(), 6);
}

#[test]
fn an_unannotated_capture_reports_no_metadata_loss() {
    let mut writer = Writer::pcap(Vec::new(), LinkType::ETHERNET).unwrap();
    writer
        .write_frame(&Frame::new(UNIX_EPOCH, LinkType::ETHERNET, vec![1, 2, 3, 4]).unwrap())
        .unwrap();
    let mut reader = Reader::new(Cursor::new(writer.into_inner())).unwrap();
    let (_bytes, report) =
        transcode(&mut reader, Vec::new(), Format::PcapNg, Limits::default()).unwrap();

    assert!(report.dropped_metadata.is_empty());
    assert_eq!(report.dropped_metadata.total(), 0);
}

/// Counts how many calls reach the destination, which is the property a
/// buffered sink actually changes. Wall-clock timing against memory would not
/// show it, so this is asserted rather than benchmarked.
#[derive(Debug, Default)]
struct CountingSink {
    bytes: Vec<u8>,
    calls: usize,
}

impl Write for CountingSink {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.calls += 1;
        self.bytes.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn a_buffered_destination_collapses_per_frame_writer_calls() {
    const FRAMES: usize = 64;
    let frame = Frame::new(UNIX_EPOCH, LinkType::ETHERNET, vec![0xa5; 1_472]).unwrap();

    let mut direct = Writer::pcap(CountingSink::default(), LinkType::ETHERNET).unwrap();
    for _ in 0..FRAMES {
        direct.write_frame(&frame).unwrap();
    }
    direct.flush().unwrap();
    let direct = direct.into_inner();

    let mut buffered = Writer::pcap(
        std::io::BufWriter::with_capacity(128 * 1024, CountingSink::default()),
        LinkType::ETHERNET,
    )
    .unwrap();
    for _ in 0..FRAMES {
        buffered.write_frame(&frame).unwrap();
    }
    buffered.flush().unwrap();
    let buffered = buffered.into_inner().into_inner().unwrap();

    // The bytes are identical; only the call pattern differs.
    assert_eq!(direct.bytes, buffered.bytes);
    assert!(direct.calls >= FRAMES, "{} calls", direct.calls);
    assert!(
        buffered.calls * 8 < direct.calls,
        "buffered {} calls vs direct {} calls",
        buffered.calls,
        direct.calls
    );
}
