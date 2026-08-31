// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
// Test code indexes fixtures and counts by hand; the fail-closed lints are
// for library paths.
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::io::Cursor;
use std::time::{Duration, SystemTime};

use packetcraftr_core::analysis::pcap::{
    Endianness, Error, Format, Interface, Limits, PcapNgOptions, PcapOptions, Reader,
    ReaderOptions, TimestampResolution, Writer,
};
use packetcraftr_core::frame::{Direction, Frame, LinkType};

fn frame_at(timestamp: SystemTime, link_type: LinkType, bytes: &[u8]) -> Frame {
    Frame::new(timestamp, link_type, bytes.to_vec()).expect("fixture frame must be valid")
}

fn pcap_bytes(options: PcapOptions, frames: &[Frame]) -> Vec<u8> {
    let mut writer = Writer::pcap_with_options(Vec::new(), LinkType::ETHERNET, options)
        .expect("fixture writer must initialize");
    for frame in frames {
        writer.write_frame(frame).expect("fixture frame must write");
    }
    writer.into_inner()
}

fn push_u16(bytes: &mut Vec<u8>, endianness: Endianness, value: u16) {
    let encoded = match endianness {
        Endianness::Little => value.to_le_bytes(),
        Endianness::Big => value.to_be_bytes(),
    };
    bytes.extend_from_slice(&encoded);
}

fn push_u32(bytes: &mut Vec<u8>, endianness: Endianness, value: u32) {
    let encoded = match endianness {
        Endianness::Little => value.to_le_bytes(),
        Endianness::Big => value.to_be_bytes(),
    };
    bytes.extend_from_slice(&encoded);
}

fn push_i64(bytes: &mut Vec<u8>, endianness: Endianness, value: i64) {
    let encoded = match endianness {
        Endianness::Little => value.to_le_bytes(),
        Endianness::Big => value.to_be_bytes(),
    };
    bytes.extend_from_slice(&encoded);
}

fn section_header(
    endianness: Endianness,
    major: u16,
    minor: u16,
    section_length: i64,
    options: &[u8],
) -> Vec<u8> {
    assert!(options.len().is_multiple_of(4));
    let length = u32::try_from(28 + options.len()).expect("small fixture block");
    let mut bytes = Vec::new();
    push_u32(&mut bytes, endianness, 0x0a0d_0d0a);
    push_u32(&mut bytes, endianness, length);
    push_u32(&mut bytes, endianness, 0x1a2b_3c4d);
    push_u16(&mut bytes, endianness, major);
    push_u16(&mut bytes, endianness, minor);
    push_i64(&mut bytes, endianness, section_length);
    bytes.extend_from_slice(options);
    push_u32(&mut bytes, endianness, length);
    bytes
}

fn interface_block(endianness: Endianness, link_type: u16, snap_len: u32) -> Vec<u8> {
    let mut bytes = Vec::new();
    push_u32(&mut bytes, endianness, 1);
    push_u32(&mut bytes, endianness, 20);
    push_u16(&mut bytes, endianness, link_type);
    push_u16(&mut bytes, endianness, 0);
    push_u32(&mut bytes, endianness, snap_len);
    push_u32(&mut bytes, endianness, 20);
    bytes
}

fn enhanced_packet_block(
    endianness: Endianness,
    interface: u32,
    ticks: u64,
    original_length: u32,
    payload: &[u8],
    options: &[u8],
) -> Vec<u8> {
    assert!(options.len().is_multiple_of(4));
    let padded = (payload.len() + 3) & !3;
    let length = u32::try_from(32 + padded + options.len()).expect("small fixture block");
    let mut bytes = Vec::new();
    push_u32(&mut bytes, endianness, 6);
    push_u32(&mut bytes, endianness, length);
    push_u32(&mut bytes, endianness, interface);
    let high = u32::try_from(ticks >> 32).expect("shifted timestamp half fits u32");
    let low = u32::try_from(ticks & u64::from(u32::MAX)).expect("masked timestamp half fits u32");
    push_u32(&mut bytes, endianness, high);
    push_u32(&mut bytes, endianness, low);
    push_u32(
        &mut bytes,
        endianness,
        u32::try_from(payload.len()).expect("small payload"),
    );
    push_u32(&mut bytes, endianness, original_length);
    bytes.extend_from_slice(payload);
    bytes.resize(bytes.len() + padded - payload.len(), 0);
    bytes.extend_from_slice(options);
    push_u32(&mut bytes, endianness, length);
    bytes
}

fn obsolete_packet_block(endianness: Endianness, payload: &[u8]) -> Vec<u8> {
    let padded = (payload.len() + 3) & !3;
    let length = u32::try_from(32 + padded).expect("small fixture block");
    let mut bytes = Vec::new();
    push_u32(&mut bytes, endianness, 2);
    push_u32(&mut bytes, endianness, length);
    push_u16(&mut bytes, endianness, 0);
    push_u16(&mut bytes, endianness, 0);
    push_u32(&mut bytes, endianness, 0);
    push_u32(&mut bytes, endianness, 1_500_000);
    push_u32(
        &mut bytes,
        endianness,
        u32::try_from(payload.len()).expect("small payload"),
    );
    push_u32(
        &mut bytes,
        endianness,
        u32::try_from(payload.len()).expect("small payload"),
    );
    bytes.extend_from_slice(payload);
    bytes.resize(bytes.len() + padded - payload.len(), 0);
    push_u32(&mut bytes, endianness, length);
    bytes
}

fn simple_packet_block(endianness: Endianness, original_length: u32, captured: &[u8]) -> Vec<u8> {
    let padded = (captured.len() + 3) & !3;
    let length = u32::try_from(16 + padded).expect("small fixture block");
    let mut bytes = Vec::new();
    push_u32(&mut bytes, endianness, 3);
    push_u32(&mut bytes, endianness, length);
    push_u32(&mut bytes, endianness, original_length);
    bytes.extend_from_slice(captured);
    bytes.resize(bytes.len() + padded - captured.len(), 0);
    push_u32(&mut bytes, endianness, length);
    bytes
}

fn metadata_block(endianness: Endianness, block_type: u32) -> Vec<u8> {
    let mut bytes = Vec::new();
    push_u32(&mut bytes, endianness, block_type);
    push_u32(&mut bytes, endianness, 12);
    push_u32(&mut bytes, endianness, 12);
    bytes
}

fn pcapng_stream(endianness: Endianness, blocks: &[Vec<u8>]) -> Vec<u8> {
    let mut bytes = section_header(endianness, 1, 0, -1, &[]);
    for block in blocks {
        bytes.extend_from_slice(block);
    }
    bytes
}

#[test]
fn pcap_writer_options_and_metadata_rejections_are_atomic() {
    assert_invalid_pcap_writer_options();

    let mut writer = Writer::pcap_with_options(
        Vec::new(),
        LinkType::ETHERNET,
        PcapOptions {
            timestamp_resolution: TimestampResolution::Decimal(6),
            snap_len: 4,
            max_size: 8,
            ..PcapOptions::default()
        },
    )
    .expect("valid writer");
    assert_eq!(writer.format(), Format::Pcap);
    assert_eq!(writer.size_limit(), 8);
    assert!(matches!(
        writer.add_interface(LinkType::ETHERNET),
        Err(Error::WrongWriterFormat { .. })
    ));

    let mut wrong_link = frame_at(SystemTime::UNIX_EPOCH, LinkType::IPV4, b"x");
    assert!(matches!(
        writer.write_frame(&wrong_link),
        Err(Error::InterfaceLinkTypeMismatch { .. })
    ));
    wrong_link.link_type = LinkType::ETHERNET;
    wrong_link.interface = Some(0);
    assert!(matches!(
        writer.write_frame(&wrong_link),
        Err(Error::MetadataNotRepresentable {
            field: "interface",
            ..
        })
    ));
    wrong_link.interface = None;
    wrong_link.direction = Some(Direction::Inbound);
    assert!(matches!(
        writer.write_frame(&wrong_link),
        Err(Error::MetadataNotRepresentable {
            field: "direction",
            ..
        })
    ));
    wrong_link.direction = None;

    // Stay below microsecond precision while respecting Windows' 100 ns system-time ticks.
    let imprecise = frame_at(
        SystemTime::UNIX_EPOCH + Duration::from_nanos(100),
        LinkType::ETHERNET,
        b"x",
    );
    assert!(matches!(
        writer.write_frame(&imprecise),
        Err(Error::MetadataNotRepresentable {
            field: "microsecond timestamp precision",
            ..
        })
    ));
    let before_epoch = frame_at(
        SystemTime::UNIX_EPOCH - Duration::from_secs(1),
        LinkType::ETHERNET,
        b"x",
    );
    assert!(matches!(
        writer.write_frame(&before_epoch),
        Err(Error::TimestampOutOfRange {
            format: Format::Pcap
        })
    ));
    let too_large = frame_at(SystemTime::UNIX_EPOCH, LinkType::ETHERNET, b"12345");
    assert!(matches!(
        writer.write_frame(&too_large),
        Err(Error::SizeLimitExceeded {
            kind: "pcap captured packet",
            limit: 4,
            ..
        })
    ));
    // Every rejection above was atomic: none of them reached the output.
    assert_eq!(writer.frames_written(), 0);
    assert_eq!(writer.captured_bytes_written(), 0);
}

fn assert_invalid_pcap_writer_options() {
    assert!(matches!(
        Writer::pcap(Vec::new(), LinkType(u32::from(u16::MAX) + 1)),
        Err(Error::LinkTypeOutOfRange { .. })
    ));
    assert!(matches!(
        Writer::pcap_with_options(
            Vec::new(),
            LinkType::ETHERNET,
            PcapOptions {
                timestamp_resolution: TimestampResolution::Decimal(7),
                ..PcapOptions::default()
            }
        ),
        Err(Error::InvalidTimestampResolution {
            base: 10,
            exponent: 7
        })
    ));
    assert!(matches!(
        Writer::pcap_with_options(
            Vec::new(),
            LinkType::ETHERNET,
            PcapOptions {
                timestamp_resolution: TimestampResolution::Binary(6),
                ..PcapOptions::default()
            }
        ),
        Err(Error::InvalidTimestampResolution { base: 2, .. })
    ));
    assert!(matches!(
        Writer::pcap_with_options(
            Vec::new(),
            LinkType::ETHERNET,
            PcapOptions {
                snap_len: 0,
                ..PcapOptions::default()
            }
        ),
        Err(Error::InvalidData {
            format: Format::Pcap,
            ..
        })
    ));
}

#[test]
fn writer_stream_limits_are_fixed_at_construction_and_account_committed_output() {
    let first = frame_at(SystemTime::UNIX_EPOCH, LinkType::ETHERNET, b"abc");
    let second = frame_at(
        SystemTime::UNIX_EPOCH + Duration::from_secs(1),
        LinkType::ETHERNET,
        b"de",
    );
    let limits = Limits {
        max_frames: 2,
        max_bytes: 4,
    };
    let mut writer = Writer::pcap_with_options(
        Vec::new(),
        LinkType::ETHERNET,
        PcapOptions {
            stream_limits: limits,
            ..PcapOptions::default()
        },
    )
    .expect("valid writer");
    assert_eq!(writer.stream_limits(), limits);
    writer.write_frame(&first).expect("first frame fits");
    // A refused frame commits nothing, so the byte total still reflects only
    // what was written.
    assert!(matches!(
        writer.write_frame(&second),
        Err(Error::StreamByteLimitExceeded {
            actual: 5,
            limit: 4
        })
    ));
    assert_eq!(writer.stream_limits(), limits);
    assert_eq!(writer.frames_written(), 1);
    assert_eq!(writer.captured_bytes_written(), 3);

    let mut bounded = Writer::pcap_with_options(
        Vec::new(),
        LinkType::ETHERNET,
        PcapOptions {
            stream_limits: Limits {
                max_frames: 1,
                max_bytes: 16,
            },
            ..PcapOptions::default()
        },
    )
    .expect("valid writer");
    bounded.write_frame(&first).expect("first frame fits");
    assert!(matches!(
        bounded.write_frame(&frame_at(SystemTime::UNIX_EPOCH, LinkType::ETHERNET, b"")),
        Err(Error::FrameLimitExceeded {
            actual: 2,
            limit: 1
        })
    ));
}

#[test]
fn pcapng_round_trip_preserves_interfaces_directions_and_signed_time() {
    for endianness in [Endianness::Little, Endianness::Big] {
        let mut writer = Writer::pcapng_with_options(
            Vec::new(),
            PcapNgOptions {
                endianness,
                max_size: 256,
                max_interfaces: 3,
                ..PcapNgOptions::default()
            },
        )
        .expect("valid pcapng writer");
        assert_eq!(writer.format(), Format::PcapNg);
        assert_eq!(writer.endianness(), endianness);
        assert_eq!(writer.size_limit(), 256);
        let description = Interface {
            link_type: LinkType::ETHERNET,
            snap_len: 64,
            timestamp_resolution: TimestampResolution::Binary(3),
            timestamp_offset: -2,
        };
        assert_eq!(
            writer
                .add_interface_description(description.clone())
                .expect("interface fits"),
            0
        );
        let mut inbound = frame_at(
            SystemTime::UNIX_EPOCH - Duration::from_millis(1_500),
            LinkType::ETHERNET,
            b"abc",
        );
        inbound.interface = Some(0);
        inbound.direction = Some(Direction::Inbound);
        writer.write_frame(&inbound).expect("binary timestamp fits");

        let mut outbound = frame_at(
            SystemTime::UNIX_EPOCH + Duration::from_millis(250),
            LinkType::IPV4,
            b"1234",
        );
        outbound.direction = Some(Direction::Outbound);
        writer
            .write_frame(&outbound)
            .expect("missing link type gets an automatic interface");
        assert_eq!(writer.frames_written(), 2);
        assert_eq!(writer.captured_bytes_written(), 7);
        writer.flush().expect("memory flush succeeds");

        let bytes = writer.into_inner();
        let mut reader = Reader::new(Cursor::new(bytes)).expect("capture opens");
        assert_eq!(reader.format(), Format::PcapNg);
        assert_eq!(reader.endianness(), endianness);
        let decoded_inbound = reader
            .next_frame()
            .expect("frame parses")
            .expect("frame exists");
        assert_eq!(decoded_inbound.timestamp, inbound.timestamp);
        assert_eq!(decoded_inbound.direction, Some(Direction::Inbound));
        assert_eq!(decoded_inbound.interface, Some(0));
        let decoded_outbound = reader
            .next_frame()
            .expect("frame parses")
            .expect("frame exists");
        assert_eq!(decoded_outbound.timestamp, outbound.timestamp);
        assert_eq!(decoded_outbound.direction, Some(Direction::Outbound));
        assert_eq!(decoded_outbound.interface, Some(1));
        assert_eq!(reader.interfaces().len(), 2);
        assert_eq!(reader.interfaces()[0], description);
        assert!(reader.next_frame().expect("clean EOF").is_none());
        assert!(reader.next_frame().expect("EOF stays terminal").is_none());
    }
}

#[test]
fn pcapng_interface_selection_and_declarations_enforce_contracts() {
    assert!(matches!(
        Writer::pcapng_with_options(
            Vec::new(),
            PcapNgOptions {
                max_size: 27,
                ..PcapNgOptions::default()
            }
        ),
        Err(Error::SizeLimitExceeded {
            kind: "pcapng section header",
            ..
        })
    ));
    assert!(matches!(
        Writer::new(
            Vec::new(),
            Format::PcapNg,
            LinkType(u32::from(u16::MAX) + 1)
        ),
        Err(Error::LinkTypeOutOfRange { .. })
    ));

    let mut writer = Writer::pcapng_with_options(
        Vec::new(),
        PcapNgOptions {
            max_size: 64,
            max_interfaces: 2,
            ..PcapNgOptions::default()
        },
    )
    .expect("writer initializes");
    assert!(matches!(
        writer.add_interface_description(Interface {
            link_type: LinkType::ETHERNET,
            snap_len: 64,
            timestamp_resolution: TimestampResolution::Decimal(128),
            timestamp_offset: 0,
        }),
        Err(Error::InvalidTimestampResolution { .. })
    ));
    assert!(matches!(
        writer.add_interface(LinkType(u32::from(u16::MAX) + 1)),
        Err(Error::LinkTypeOutOfRange { .. })
    ));
    writer
        .add_interface(LinkType::ETHERNET)
        .expect("first interface fits");
    writer
        .add_interface(LinkType::ETHERNET)
        .expect("second interface fits");
    assert!(matches!(
        writer.add_interface(LinkType::IPV4),
        Err(Error::InterfaceLimit { limit: 2 })
    ));

    let unselected = frame_at(SystemTime::UNIX_EPOCH, LinkType::ETHERNET, b"a");
    assert!(matches!(
        writer.write_frame(&unselected),
        Err(Error::AmbiguousInterface { .. })
    ));
    let mut undefined = unselected.clone();
    undefined.interface = Some(7);
    assert!(matches!(
        writer.write_frame(&undefined),
        Err(Error::UndefinedInterface {
            interface: 7,
            available: 2
        })
    ));
    let mut wrong = frame_at(SystemTime::UNIX_EPOCH, LinkType::IPV4, b"a");
    wrong.interface = Some(0);
    assert!(matches!(
        writer.write_frame(&wrong),
        Err(Error::InterfaceLinkTypeMismatch { interface: 0, .. })
    ));
}

#[test]
fn classic_reader_rejects_header_and_record_corruption_then_stays_finished() {
    assert!(matches!(
        Reader::new(Cursor::new(Vec::<u8>::new())),
        Err(Error::EmptyInput)
    ));
    assert!(matches!(
        Reader::new(Cursor::new(vec![1, 2, 3, 4])),
        Err(Error::UnrecognizedFormat {
            magic: [1, 2, 3, 4]
        })
    ));
    assert!(matches!(
        Reader::new(Cursor::new(vec![0x4d, 0x3c, 0xb2, 0xa1, 2])),
        Err(Error::Truncated {
            context: "pcap global header",
            ..
        })
    ));

    let base_frame = frame_at(SystemTime::UNIX_EPOCH, LinkType::ETHERNET, b"abc");
    let base = pcap_bytes(PcapOptions::default(), &[base_frame]);

    let mut unsupported = base.clone();
    unsupported[4..6].copy_from_slice(&3_u16.to_le_bytes());
    assert!(matches!(
        Reader::new(Cursor::new(unsupported)),
        Err(Error::UnsupportedVersion {
            format: Format::Pcap,
            major: 3,
            minor: 4
        })
    ));
    let mut zero_snap = base.clone();
    zero_snap[16..20].copy_from_slice(&0_u32.to_le_bytes());
    assert!(matches!(
        Reader::new(Cursor::new(zero_snap)),
        Err(Error::InvalidData { .. })
    ));

    let mut invalid_fraction = base.clone();
    invalid_fraction[28..32].copy_from_slice(&1_000_000_000_u32.to_le_bytes());
    let mut reader = Reader::new(Cursor::new(invalid_fraction)).expect("header remains valid");
    assert!(matches!(
        reader.next_frame(),
        Err(Error::InvalidTimestampFraction { .. })
    ));
    assert!(reader.next_frame().expect("reader is terminal").is_none());

    let mut invalid_lengths = base.clone();
    invalid_lengths[36..40].copy_from_slice(&2_u32.to_le_bytes());
    let mut reader = Reader::new(Cursor::new(invalid_lengths)).expect("header remains valid");
    assert!(matches!(reader.next(), Some(Err(Error::Frame(_)))));
    assert!(reader.next().is_none());

    let mut over_snap = base.clone();
    over_snap[16..20].copy_from_slice(&2_u32.to_le_bytes());
    let mut reader = Reader::new(Cursor::new(over_snap)).expect("header remains valid");
    assert!(matches!(
        reader.next_frame(),
        Err(Error::InvalidData {
            format: Format::Pcap,
            ..
        })
    ));

    let mut flagged_link = base;
    flagged_link[20..24].copy_from_slice(&0xabcd_0001_u32.to_le_bytes());
    let reader = Reader::new(Cursor::new(flagged_link)).expect("flagged network word is valid");
    assert_eq!(reader.interfaces()[0].link_type, LinkType::ETHERNET);
    assert!(matches!(
        Reader::with_options(
            Cursor::new(reader.into_inner().into_inner()),
            ReaderOptions {
                max_total_interfaces: 0,
                ..ReaderOptions::default()
            }
        ),
        Err(Error::TotalInterfaceLimit { limit: 0 })
    ));
}

#[test]
fn reader_accessors_and_microsecond_precision_work_with_chunked_input() {
    let timestamp = SystemTime::UNIX_EPOCH + Duration::new(9, 123_456_000);
    let bytes = pcap_bytes(
        PcapOptions {
            endianness: Endianness::Big,
            timestamp_resolution: TimestampResolution::Decimal(6),
            ..PcapOptions::default()
        },
        &[frame_at(timestamp, LinkType::ETHERNET, b"payload")],
    );
    let mut reader = Reader::new(Cursor::new(bytes)).expect("capture opens");
    assert_eq!(reader.endianness(), Endianness::Big);
    assert_eq!(
        reader.interfaces()[0].timestamp_resolution,
        TimestampResolution::Decimal(6)
    );
    assert_eq!(reader.get_ref().position(), 24);
    reader.get_mut().set_position(24);
    let decoded = reader.next().expect("one item").expect("valid item");
    assert_eq!(decoded.timestamp, Some(timestamp));
    assert_eq!(decoded.bytes().as_ref(), b"payload");
    assert!(reader.next().is_none());
}

#[test]
fn pcapng_reader_supports_obsolete_simple_and_multiple_sections() {
    let little = Endianness::Little;
    let first = pcapng_stream(
        little,
        &[
            interface_block(little, 1, 64),
            obsolete_packet_block(little, b"old"),
            simple_packet_block(little, 6, b"abcdef"),
        ],
    );
    let big = Endianness::Big;
    let second = pcapng_stream(
        big,
        &[
            interface_block(
                big,
                u16::try_from(LinkType::IPV4.0).expect("IPv4 link type fits the interface field"),
                64,
            ),
            enhanced_packet_block(big, 0, 2_000_000, 2, b"ip", &[]),
        ],
    );
    let mut bytes = first;
    bytes.extend_from_slice(&second);

    let mut reader = Reader::new(Cursor::new(bytes)).expect("first section opens");
    let old = reader
        .next_frame()
        .expect("obsolete parses")
        .expect("exists");
    assert_eq!(old.bytes().as_ref(), b"old");
    assert_eq!(old.interface, Some(0));
    assert_eq!(
        old.timestamp,
        Some(SystemTime::UNIX_EPOCH + Duration::from_millis(1_500))
    );
    let simple = reader.next_frame().expect("simple parses").expect("exists");
    assert_eq!(simple.timestamp, None);
    assert_eq!(simple.original_length(), 6);
    let second = reader
        .next_frame()
        .expect("second section parses")
        .expect("exists");
    assert_eq!(second.bytes().as_ref(), b"ip");
    assert_eq!(second.interface, Some(1));
    assert_eq!(second.link_type, LinkType::IPV4);
    assert_eq!(reader.endianness(), Endianness::Big);
    assert_eq!(reader.interfaces().len(), 2);
    assert!(reader.next_frame().expect("clean EOF").is_none());
}

#[test]
fn pcapng_reader_enforces_metadata_and_interface_budgets() {
    let endianness = Endianness::Little;
    let bytes = pcapng_stream(
        endianness,
        &[
            metadata_block(endianness, 0xfeed_beef),
            interface_block(endianness, 1, 64),
            enhanced_packet_block(endianness, 0, 0, 1, b"x", &[]),
        ],
    );
    let mut blocks = Reader::with_options(
        Cursor::new(bytes.clone()),
        ReaderOptions {
            max_metadata_blocks_per_frame: 0,
            ..ReaderOptions::default()
        },
    )
    .expect("section opens");
    assert!(matches!(
        blocks.next_frame(),
        Err(Error::MetadataBlockLimit { limit: 0 })
    ));

    let mut metadata_bytes = Reader::with_options(
        Cursor::new(bytes.clone()),
        ReaderOptions {
            max_metadata_bytes_per_frame: 11,
            ..ReaderOptions::default()
        },
    )
    .expect("section opens");
    assert!(matches!(
        metadata_bytes.next_frame(),
        Err(Error::MetadataByteLimit { limit: 11 })
    ));

    for options in [
        ReaderOptions {
            max_interfaces_per_section: 0,
            ..ReaderOptions::default()
        },
        ReaderOptions {
            max_total_interfaces: 0,
            ..ReaderOptions::default()
        },
    ] {
        let mut reader = Reader::with_options(Cursor::new(bytes.clone()), options)
            .expect("section header itself fits");
        assert!(matches!(
            reader.next_frame(),
            Err(Error::InterfaceLimit { limit: 0 } | Error::TotalInterfaceLimit { limit: 0 })
        ));
    }
}

#[test]
fn pcapng_structural_corruption_fails_closed() {
    let endianness = Endianness::Little;
    let mut bad_bom = section_header(endianness, 1, 0, -1, &[]);
    bad_bom[8..12].copy_from_slice(&[0, 0, 0, 0]);
    assert!(matches!(
        Reader::new(Cursor::new(bad_bom)),
        Err(Error::InvalidData { .. })
    ));
    assert!(matches!(
        Reader::new(Cursor::new(section_header(endianness, 2, 0, -1, &[]))),
        Err(Error::UnsupportedVersion {
            format: Format::PcapNg,
            major: 2,
            minor: 0
        })
    ));
    assert!(matches!(
        Reader::new(Cursor::new(section_header(endianness, 1, 0, -2, &[]))),
        Err(Error::InvalidData { .. })
    ));
    assert!(matches!(
        Reader::new(Cursor::new(section_header(endianness, 1, 0, 3, &[]))),
        Err(Error::InvalidData { .. })
    ));

    let mut mismatch = section_header(endianness, 1, 0, -1, &[]);
    mismatch[24..28].copy_from_slice(&32_u32.to_le_bytes());
    assert!(matches!(
        Reader::new(Cursor::new(mismatch)),
        Err(Error::BlockLengthMismatch {
            leading: 28,
            trailing: 32
        })
    ));
    assert!(matches!(
        Reader::with_options(
            Cursor::new(section_header(endianness, 1, 0, -1, &[])),
            ReaderOptions {
                max_size: 27,
                ..ReaderOptions::default()
            }
        ),
        Err(Error::SizeLimitExceeded { limit: 27, .. })
    ));

    let mut invalid_block = section_header(endianness, 1, 0, -1, &[]);
    push_u32(&mut invalid_block, endianness, 99);
    push_u32(&mut invalid_block, endianness, 14);
    let mut reader = Reader::new(Cursor::new(invalid_block)).expect("section opens");
    assert!(matches!(
        reader.next_frame(),
        Err(Error::InvalidBlockLength { length: 14 })
    ));

    let mut mismatch_block = pcapng_stream(endianness, &[metadata_block(endianness, 0xfeed_beef)]);
    let end = mismatch_block.len();
    mismatch_block[end - 4..].copy_from_slice(&16_u32.to_le_bytes());
    let mut reader = Reader::new(Cursor::new(mismatch_block)).expect("section opens");
    assert!(matches!(
        reader.next_frame(),
        Err(Error::BlockLengthMismatch {
            leading: 12,
            trailing: 16
        })
    ));
}

#[test]
fn finite_sections_detect_early_end_boundary_crossing_and_remainders() {
    let endianness = Endianness::Little;
    let early = section_header(endianness, 1, 0, 12, &[]);
    let mut reader = Reader::new(Cursor::new(early)).expect("section opens");
    assert!(matches!(
        reader.next_frame(),
        Err(Error::SectionEndedEarly { remaining: 12 })
    ));

    let remainder = section_header(endianness, 1, 0, 4, &[]);
    let mut reader = Reader::new(Cursor::new(remainder)).expect("section opens");
    assert!(matches!(
        reader.next_frame(),
        Err(Error::SectionRemainderTooSmall { remaining: 4 })
    ));

    let mut crossing = section_header(endianness, 1, 0, 12, &[]);
    crossing.extend_from_slice(&interface_block(endianness, 1, 64));
    let mut reader = Reader::new(Cursor::new(crossing)).expect("section opens");
    assert!(matches!(
        reader.next_frame(),
        Err(Error::BlockCrossesSectionBoundary {
            block_length: 20,
            remaining: 12
        })
    ));

    let mut premature = section_header(endianness, 1, 0, 12, &[]);
    premature.extend_from_slice(&section_header(endianness, 1, 0, -1, &[]));
    let mut reader = Reader::new(Cursor::new(premature)).expect("section opens");
    assert!(matches!(
        reader.next_frame(),
        Err(Error::SectionHeaderBeforeBoundary { remaining: 12 })
    ));
}

#[test]
fn malformed_pcapng_packets_and_options_are_rejected() {
    let endianness = Endianness::Little;
    let mut undefined = Reader::new(Cursor::new(pcapng_stream(
        endianness,
        &[enhanced_packet_block(endianness, 0, 0, 1, b"x", &[])],
    )))
    .expect("section opens");
    assert!(matches!(
        undefined.next_frame(),
        Err(Error::UndefinedInterface {
            interface: 0,
            available: 0
        })
    ));

    let bad_end_option = [0, 0, 1, 0, 0, 0, 0, 0];
    let bytes = pcapng_stream(
        endianness,
        &[
            interface_block(endianness, 1, 64),
            enhanced_packet_block(endianness, 0, 0, 1, b"x", &bad_end_option),
        ],
    );
    let mut reader = Reader::new(Cursor::new(bytes)).expect("section opens");
    assert!(matches!(
        reader.next_frame(),
        Err(Error::InvalidData { .. })
    ));

    let duplicate_flags = [2, 0, 4, 0, 1, 0, 0, 0, 2, 0, 4, 0, 2, 0, 0, 0];
    let bytes = pcapng_stream(
        endianness,
        &[
            interface_block(endianness, 1, 64),
            enhanced_packet_block(endianness, 0, 0, 1, b"x", &duplicate_flags),
        ],
    );
    let mut reader = Reader::new(Cursor::new(bytes)).expect("section opens");
    assert!(matches!(
        reader.next_frame(),
        Err(Error::InvalidData { .. })
    ));

    let malformed_simple = simple_packet_block(endianness, 8, b"abcd");
    let bytes = pcapng_stream(
        endianness,
        &[interface_block(endianness, 1, 64), malformed_simple],
    );
    let mut reader = Reader::new(Cursor::new(bytes)).expect("section opens");
    assert!(matches!(
        reader.next_frame(),
        Err(Error::InvalidData { .. })
    ));

    for block_type in [6, 2] {
        let bytes = pcapng_stream(endianness, &[metadata_block(endianness, block_type)]);
        let mut reader = Reader::new(Cursor::new(bytes)).expect("section opens");
        assert!(matches!(
            reader.next_frame(),
            Err(Error::InvalidData {
                format: Format::PcapNg,
                ..
            })
        ));
    }
}
