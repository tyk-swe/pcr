// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::io::{self, Cursor, Write};
use std::time::{Duration, Instant, UNIX_EPOCH};

use packetcraftr_core::analysis::pcap::{
    Endianness, Error, Format, Interface, Limits, PcapNgOptions, PcapOptions, Reader,
    TimestampResolution, Writer,
};
use packetcraftr_core::frame::{Direction, Frame, Lengths, LinkType};

fn frame(length: usize) -> Frame {
    Frame::try_with_lengths(
        UNIX_EPOCH + Duration::new(7, 125_000_000),
        LinkType::ETHERNET,
        Lengths {
            captured: length as u32,
            original: length as u32 + 17,
        },
        (0..length).map(|index| index as u8).collect::<Vec<_>>(),
    )
    .unwrap()
}

fn interface(resolution: TimestampResolution, offset: i64) -> Interface {
    Interface {
        link_type: LinkType::ETHERNET,
        snap_len: 0,
        timestamp_resolution: resolution,
        timestamp_offset: offset,
    }
}

// Independent wire fixtures, checked against the base encoder before optimization.
fn words(order: Endianness, values: &[u32]) -> Vec<u8> {
    values
        .iter()
        .flat_map(|value| match order {
            Endianness::Little => value.to_le_bytes(),
            Endianness::Big => value.to_be_bytes(),
        })
        .collect()
}

fn option(order: Endianness, code: u16, value: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for field in [code, value.len() as u16] {
        bytes.extend(match order {
            Endianness::Little => field.to_le_bytes(),
            Endianness::Big => field.to_be_bytes(),
        });
    }
    bytes.extend(value);
    bytes.resize(bytes.len().next_multiple_of(4), 0);
    bytes
}

fn expected_interface(order: Endianness, description: &Interface) -> Vec<u8> {
    let length = if description.timestamp_offset == 0 {
        32
    } else {
        44
    };
    let mut bytes = words(order, &[1, length]);
    bytes.extend(match order {
        Endianness::Little => (description.link_type.0 as u16).to_le_bytes(),
        Endianness::Big => (description.link_type.0 as u16).to_be_bytes(),
    });
    bytes.extend([0, 0]);
    bytes.extend(words(order, &[description.snap_len]));
    let resolution = match description.timestamp_resolution {
        TimestampResolution::Decimal(exponent) => exponent,
        TimestampResolution::Binary(exponent) => exponent | 0x80,
    };
    bytes.extend(option(order, 9, &[resolution]));
    if description.timestamp_offset != 0 {
        bytes.extend(option(
            order,
            14,
            &match order {
                Endianness::Little => description.timestamp_offset.to_le_bytes(),
                Endianness::Big => description.timestamp_offset.to_be_bytes(),
            },
        ));
    }
    bytes.extend(option(order, 0, &[]));
    bytes.extend(words(order, &[length]));
    bytes
}

fn expected_packet(order: Endianness, frame: &Frame, id: u32, ticks: u64) -> Vec<u8> {
    let padded = frame.captured_length().next_multiple_of(4);
    let length = 32 + padded + if frame.direction.is_some() { 12 } else { 0 };
    let mut bytes = words(
        order,
        &[
            6,
            length,
            id,
            (ticks >> 32) as u32,
            ticks as u32,
            frame.captured_length(),
            frame.original_length(),
        ],
    );
    bytes.extend_from_slice(frame.bytes());
    bytes.resize(28 + padded as usize, 0);
    if let Some(direction) = frame.direction {
        let flags = match direction {
            Direction::Unknown => 0,
            Direction::Inbound => 1,
            Direction::Outbound => 2,
        };
        bytes.extend(option(order, 2, &words(order, &[flags])));
        bytes.extend(option(order, 0, &[]));
    }
    bytes.extend(words(order, &[length]));
    bytes
}

fn preview_and_write(writer: &mut Writer<Vec<u8>>, frame: &Frame, expected: &[u8]) {
    let before = writer.get_ref().clone();
    let counts = (writer.frames_written(), writer.captured_bytes_written());
    for _ in 0..4 {
        assert_eq!(writer.encoded_frame_size(frame).unwrap(), expected.len());
        assert_eq!(writer.get_ref(), &before);
        assert_eq!(
            (writer.frames_written(), writer.captured_bytes_written()),
            counts
        );
    }
    writer.write_frame(frame).unwrap();
    assert_eq!(&writer.get_ref()[before.len()..], expected);
    assert_eq!(writer.frames_written(), counts.0 + 1);
    assert_eq!(
        writer.captured_bytes_written(),
        counts.1 + u64::from(frame.captured_length())
    );
}

#[test]
fn classic_preview_matches_exact_bytes_and_metadata() {
    for order in [Endianness::Little, Endianness::Big] {
        for (resolution, fraction) in [(6, 125_000), (9, 125_000_000)] {
            let mut writer = Writer::pcap_with_options(
                Vec::new(),
                LinkType::ETHERNET,
                PcapOptions {
                    endianness: order,
                    timestamp_resolution: TimestampResolution::Decimal(resolution),
                    snap_len: 64,
                    ..PcapOptions::default()
                },
            )
            .unwrap();
            let mut expected = Vec::new();
            for length in 0..=4 {
                let packet = frame(length);
                let mut bytes = words(order, &[7, fraction, length as u32, length as u32 + 17]);
                bytes.extend_from_slice(packet.bytes());
                preview_and_write(&mut writer, &packet, &bytes);
                expected.push(packet);
            }
            let mut reader = Reader::new(Cursor::new(writer.into_inner())).unwrap();
            assert_eq!(reader.endianness(), order);
            for packet in expected {
                assert_eq!(reader.next_frame().unwrap().unwrap(), packet);
            }
            assert!(reader.next_frame().unwrap().is_none());
        }
    }
}

#[test]
fn pcapng_preview_matches_padding_directions_interfaces_and_timestamps() {
    for order in [Endianness::Little, Endianness::Big] {
        for (resolution, offset, timestamp, ticks) in [
            (
                TimestampResolution::Decimal(6),
                0,
                UNIX_EPOCH + Duration::new(7, 125_000_000),
                7_125_000,
            ),
            (
                TimestampResolution::Decimal(9),
                2,
                UNIX_EPOCH + Duration::new(7, 125_000_000),
                5_125_000_000,
            ),
            (
                TimestampResolution::Binary(3),
                -2,
                UNIX_EPOCH - Duration::from_millis(1500),
                4,
            ),
            (
                TimestampResolution::Decimal(127),
                -2,
                UNIX_EPOCH - Duration::from_secs(2),
                0,
            ),
            (
                TimestampResolution::Binary(127),
                2,
                UNIX_EPOCH + Duration::from_secs(2),
                0,
            ),
        ] {
            let mut writer = Writer::pcapng_with_options(
                Vec::new(),
                PcapNgOptions {
                    endianness: order,
                    ..PcapNgOptions::default()
                },
            )
            .unwrap();
            let description = interface(resolution, offset);
            let before = writer.get_ref().len();
            assert_eq!(
                writer
                    .add_interface_description(description.clone())
                    .unwrap(),
                0
            );
            assert_eq!(
                &writer.get_ref()[before..],
                expected_interface(order, &description)
            );
            let mut other = description.clone();
            other.link_type = LinkType::RAW;
            writer.add_interface_description(other.clone()).unwrap();
            let mut expected = Vec::new();
            for explicit in [false, true] {
                for direction in [
                    None,
                    Some(Direction::Unknown),
                    Some(Direction::Inbound),
                    Some(Direction::Outbound),
                ] {
                    for length in 0..=4 {
                        let mut packet = frame(length);
                        packet.timestamp = Some(timestamp);
                        packet.interface = explicit.then_some(0);
                        packet.direction = direction;
                        preview_and_write(
                            &mut writer,
                            &packet,
                            &expected_packet(order, &packet, 0, ticks),
                        );
                        packet.interface = Some(0);
                        expected.push(packet);
                    }
                }
            }
            let mut reader = Reader::new(Cursor::new(writer.into_inner())).unwrap();
            for packet in expected {
                assert_eq!(reader.next_frame().unwrap().unwrap(), packet);
            }
            assert!(reader.next_frame().unwrap().is_none());
            assert_eq!(reader.interfaces(), &[description, other]);
        }
    }
}

#[test]
fn automatic_interfaces_are_included_once_and_previews_do_not_claim_ids() {
    for order in [Endianness::Little, Endianness::Big] {
        let mut writer = Writer::pcapng_with_options(
            Vec::new(),
            PcapNgOptions {
                endianness: order,
                max_size: 128,
                max_interfaces: 2,
                ..PcapNgOptions::default()
            },
        )
        .unwrap();
        let packet = frame(3);
        let mut description = interface(TimestampResolution::Decimal(9), 0);
        description.snap_len = 128;
        let mut bytes = expected_interface(order, &description);
        bytes.extend(expected_packet(order, &packet, 0, 7_125_000_000));
        for _ in 0..4 {
            assert_eq!(writer.encoded_frame_size(&packet).unwrap(), bytes.len());
        }
        // A declaration between preview and write still gets the first ID.
        let mut other = description.clone();
        other.link_type = LinkType::RAW;
        assert_eq!(writer.add_interface_description(other.clone()).unwrap(), 0);
        let mut bytes = expected_interface(order, &description);
        bytes.extend(expected_packet(order, &packet, 1, 7_125_000_000));
        preview_and_write(&mut writer, &packet, &bytes);
        preview_and_write(
            &mut writer,
            &packet,
            &expected_packet(order, &packet, 1, 7_125_000_000),
        );
        let mut reader = Reader::new(Cursor::new(writer.into_inner())).unwrap();
        for _ in 0..2 {
            let mut expected = packet.clone();
            expected.interface = Some(1);
            assert_eq!(reader.next_frame().unwrap().unwrap(), expected);
        }
        assert!(reader.next_frame().unwrap().is_none());
        assert_eq!(reader.interfaces(), &[other, description]);
    }
}

fn rejected(writer: &mut Writer<Vec<u8>>, frame: &Frame, expected: Error) {
    let before = writer.get_ref().clone();
    let counts = (writer.frames_written(), writer.captured_bytes_written());
    for _ in 0..3 {
        assert_eq!(
            format!("{:?}", writer.encoded_frame_size(frame).unwrap_err()),
            format!("{expected:?}")
        );
    }
    assert_eq!(
        format!("{:?}", writer.write_frame(frame).unwrap_err()),
        format!("{expected:?}")
    );
    assert_eq!(writer.get_ref(), &before);
    assert_eq!(
        (writer.frames_written(), writer.captured_bytes_written()),
        counts
    );
    writer.flush().unwrap();
}

#[test]
fn preview_preserves_classic_rejections_and_error_precedence() {
    let mut writer = Writer::pcap_with_options(
        Vec::new(),
        LinkType::ETHERNET,
        PcapOptions {
            timestamp_resolution: TimestampResolution::Decimal(6),
            max_size: 8,
            snap_len: 4,
            ..PcapOptions::default()
        },
    )
    .unwrap();
    let mut packet = frame(9);
    packet.interface = Some(0);
    packet.direction = Some(Direction::Unknown);
    packet.timestamp = None;
    rejected(
        &mut writer,
        &packet,
        Error::SizeLimitExceeded {
            kind: "captured packet",
            declared: 9,
            limit: 8,
        },
    );
    packet = frame(5);
    packet.interface = Some(0);
    packet.direction = Some(Direction::Unknown);
    packet.link_type = LinkType::RAW;
    packet.timestamp = None;
    rejected(
        &mut writer,
        &packet,
        Error::MetadataNotRepresentable {
            format: Format::Pcap,
            field: "interface",
        },
    );
    packet.interface = None;
    rejected(
        &mut writer,
        &packet,
        Error::MetadataNotRepresentable {
            format: Format::Pcap,
            field: "direction",
        },
    );
    packet.direction = None;
    rejected(
        &mut writer,
        &packet,
        Error::InterfaceLinkTypeMismatch {
            interface: 0,
            expected: 1,
            actual: 101,
        },
    );
    packet.link_type = LinkType::ETHERNET;
    rejected(
        &mut writer,
        &packet,
        Error::SizeLimitExceeded {
            kind: "pcap captured packet",
            declared: 5,
            limit: 4,
        },
    );
    packet = frame(1);
    packet.timestamp = None;
    rejected(
        &mut writer,
        &packet,
        Error::TimestampUnavailable {
            format: Format::Pcap,
        },
    );
    for time in [
        UNIX_EPOCH - Duration::from_secs(1),
        UNIX_EPOCH + Duration::from_secs(u64::from(u32::MAX) + 1),
    ] {
        packet.timestamp = Some(time);
        rejected(
            &mut writer,
            &packet,
            Error::TimestampOutOfRange {
                format: Format::Pcap,
            },
        );
    }
    packet.timestamp = Some(UNIX_EPOCH + Duration::from_nanos(100));
    rejected(
        &mut writer,
        &packet,
        Error::MetadataNotRepresentable {
            format: Format::Pcap,
            field: "microsecond timestamp precision",
        },
    );
    let mut last = frame(0);
    last.timestamp = Some(UNIX_EPOCH + Duration::new(u64::from(u32::MAX), 999_999_000));
    preview_and_write(
        &mut writer,
        &last,
        &words(Endianness::Little, &[u32::MAX, 999_999, 0, 17]),
    );
}

#[test]
fn preview_preserves_pcapng_selection_and_limits_before_automatic_output() {
    let mut writer = Writer::pcapng_with_options(
        Vec::new(),
        PcapNgOptions {
            max_size: 48,
            max_interfaces: 2,
            ..PcapNgOptions::default()
        },
    )
    .unwrap();
    let mut packet = frame(1);
    packet.timestamp = None;
    rejected(
        &mut writer,
        &packet,
        Error::TimestampUnavailable {
            format: Format::PcapNg,
        },
    );
    let mut oversized = frame(17);
    rejected(
        &mut writer,
        &oversized,
        Error::SizeLimitExceeded {
            kind: "pcapng enhanced packet block",
            declared: 52,
            limit: 48,
        },
    );
    oversized = frame(5);
    oversized.direction = Some(Direction::Unknown);
    rejected(
        &mut writer,
        &oversized,
        Error::SizeLimitExceeded {
            kind: "pcapng enhanced packet block",
            declared: 52,
            limit: 48,
        },
    );
    let mut invalid_link = frame(1);
    invalid_link.link_type = LinkType(65_536);
    rejected(
        &mut writer,
        &invalid_link,
        Error::LinkTypeOutOfRange { link_type: 65_536 },
    );
    let mut description = interface(TimestampResolution::Binary(3), -2);
    description.snap_len = 4;
    assert_eq!(
        writer
            .add_interface_description(description.clone())
            .unwrap(),
        0
    );
    assert_eq!(writer.add_interface_description(description).unwrap(), 1);
    rejected(
        &mut writer,
        &packet,
        Error::AmbiguousInterface { link_type: 1 },
    );
    packet.interface = Some(2);
    rejected(
        &mut writer,
        &packet,
        Error::UndefinedInterface {
            interface: 2,
            available: 2,
        },
    );
    packet.interface = Some(1);
    packet.link_type = LinkType::RAW;
    rejected(
        &mut writer,
        &packet,
        Error::InterfaceLinkTypeMismatch {
            interface: 1,
            expected: 1,
            actual: 101,
        },
    );
    packet.interface = None;
    rejected(&mut writer, &packet, Error::InterfaceLimit { limit: 2 });
    invalid_link.timestamp = None;
    rejected(
        &mut writer,
        &invalid_link,
        Error::InterfaceLimit { limit: 2 },
    );
    oversized.interface = Some(0);
    oversized.timestamp = None;
    rejected(
        &mut writer,
        &oversized,
        Error::SizeLimitExceeded {
            kind: "pcapng captured packet",
            declared: 5,
            limit: 4,
        },
    );
    packet = frame(4);
    packet.interface = Some(1);
    packet.direction = Some(Direction::Unknown);
    preview_and_write(
        &mut writer,
        &packet,
        &expected_packet(Endianness::Little, &packet, 1, 73),
    );

    let mut small = Writer::pcapng_with_options(
        Vec::new(),
        PcapNgOptions {
            max_size: 28,
            max_interfaces: 0,
            ..PcapNgOptions::default()
        },
    )
    .unwrap();
    rejected(
        &mut small,
        &frame(0),
        Error::SizeLimitExceeded {
            kind: "pcapng interface description",
            declared: 32,
            limit: 28,
        },
    );
}

#[test]
fn preview_checks_pcapng_timestamp_ranges_and_resolutions() {
    for (resolution, offset, timestamp, error) in [
        (
            TimestampResolution::Decimal(9),
            0,
            UNIX_EPOCH - Duration::from_secs(1),
            Error::TimestampOutOfRange {
                format: Format::PcapNg,
            },
        ),
        (
            TimestampResolution::Decimal(9),
            2,
            UNIX_EPOCH + Duration::from_secs(1),
            Error::TimestampOutOfRange {
                format: Format::PcapNg,
            },
        ),
        (
            TimestampResolution::Binary(3),
            -2,
            UNIX_EPOCH + Duration::from_millis(1),
            Error::MetadataNotRepresentable {
                format: Format::PcapNg,
                field: "timestamp resolution",
            },
        ),
        (
            TimestampResolution::Decimal(6),
            0,
            UNIX_EPOCH + Duration::from_nanos(100),
            Error::MetadataNotRepresentable {
                format: Format::PcapNg,
                field: "timestamp resolution",
            },
        ),
        (
            TimestampResolution::Decimal(20),
            0,
            UNIX_EPOCH + Duration::from_secs(1),
            Error::TimestampOutOfRange {
                format: Format::PcapNg,
            },
        ),
        (
            TimestampResolution::Decimal(127),
            0,
            UNIX_EPOCH + Duration::from_secs(1),
            Error::TimestampOutOfRange {
                format: Format::PcapNg,
            },
        ),
        (
            TimestampResolution::Binary(127),
            0,
            UNIX_EPOCH + Duration::from_nanos(100),
            Error::TimestampOutOfRange {
                format: Format::PcapNg,
            },
        ),
    ] {
        let mut writer = Writer::pcapng(Vec::new()).unwrap();
        writer
            .add_interface_description(interface(resolution, offset))
            .unwrap();
        let mut packet = frame(1);
        packet.interface = Some(0);
        packet.timestamp = Some(timestamp);
        rejected(&mut writer, &packet, error);
    }
}

#[test]
fn previews_do_not_consume_stream_budgets_and_keep_limit_precedence() {
    for format in [Format::Pcap, Format::PcapNg] {
        let limits = Limits {
            max_frames: 1,
            max_bytes: 1,
        };
        let mut writer = match format {
            Format::Pcap => Writer::pcap_with_options(
                Vec::new(),
                LinkType::ETHERNET,
                PcapOptions {
                    max_size: 64,
                    stream_limits: limits,
                    ..PcapOptions::default()
                },
            )
            .unwrap(),
            Format::PcapNg => Writer::pcapng_with_options(
                Vec::new(),
                PcapNgOptions {
                    max_size: 64,
                    stream_limits: limits,
                    ..PcapNgOptions::default()
                },
            )
            .unwrap(),
        };
        let mut missing = frame(2);
        missing.timestamp = None;
        rejected(
            &mut writer,
            &missing,
            Error::StreamByteLimitExceeded {
                actual: 2,
                limit: 1,
            },
        );
        for _ in 0..4 {
            writer.encoded_frame_size(&frame(1)).unwrap();
        }
        writer.write_frame(&frame(1)).unwrap();
        rejected(
            &mut writer,
            &missing,
            Error::FrameLimitExceeded {
                actual: 2,
                limit: 1,
            },
        );
        rejected(
            &mut writer,
            &frame(0),
            Error::FrameLimitExceeded {
                actual: 2,
                limit: 1,
            },
        );
        rejected(
            &mut writer,
            &frame(65),
            Error::SizeLimitExceeded {
                kind: "captured packet",
                declared: 65,
                limit: 64,
            },
        );
        assert_eq!(writer.frames_written(), 1);
        assert_eq!(writer.captured_bytes_written(), 1);
    }
}

#[derive(Default)]
struct Counted<W> {
    inner: W,
    calls: usize,
    bytes: usize,
}

impl<W: Write> Write for Counted<W> {
    #[inline(never)]
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.calls += 1;
        let written = self.inner.write(bytes)?;
        self.bytes += written;
        Ok(written)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

#[test]
fn fully_accepting_writer_counts_packet_calls_separately_from_setup() {
    for format in [Format::Pcap, Format::PcapNg] {
        for length in 0..=4 {
            for direction in [
                None,
                Some(Direction::Unknown),
                Some(Direction::Inbound),
                Some(Direction::Outbound),
            ] {
                if format == Format::Pcap && direction.is_some() {
                    continue;
                }
                let mut writer =
                    Writer::new(Counted::<Vec<u8>>::default(), format, LinkType::ETHERNET).unwrap();
                let mut packet = frame(length);
                packet.direction = direction;
                let calls = writer.get_ref().calls;
                let bytes = writer.get_ref().bytes;
                let size = writer.encoded_frame_size(&packet).unwrap();
                assert_eq!(writer.get_ref().calls, calls);
                writer.write_frame(&packet).unwrap();
                assert_eq!(writer.get_ref().bytes - bytes, size);
                // Fixed headers and tails are batched; empty payloads make no call.
                let expected = match format {
                    Format::Pcap => 1 + usize::from(length != 0),
                    Format::PcapNg => 2 + usize::from(length != 0),
                };
                assert_eq!(writer.get_ref().calls - calls, expected);
            }
        }
    }
}

struct FaultWriter {
    bytes: Vec<u8>,
    max_write: usize,
    interrupt_at: Option<usize>,
    stop_at: Option<(usize, io::ErrorKind)>,
    calls: usize,
    flushes: usize,
}

impl FaultWriter {
    fn new() -> Self {
        Self {
            bytes: Vec::new(),
            max_write: 3,
            interrupt_at: None,
            stop_at: None,
            calls: 0,
            flushes: 0,
        }
    }
}

impl Write for FaultWriter {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        self.calls += 1;
        if self.interrupt_at == Some(self.bytes.len()) {
            self.interrupt_at = None;
            return Err(io::ErrorKind::Interrupted.into());
        }
        let mut count = input.len().min(self.max_write);
        if let Some(offset) = self.interrupt_at {
            count = count.min(offset - self.bytes.len());
        }
        if let Some((offset, kind)) = self.stop_at {
            if self.bytes.len() == offset {
                return if kind == io::ErrorKind::WriteZero {
                    Ok(0)
                } else {
                    Err(io::Error::new(kind, "byte-offset failure"))
                };
            }
            count = count.min(offset - self.bytes.len());
        }
        self.bytes.extend_from_slice(&input[..count]);
        Ok(count)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.flushes += 1;
        Ok(())
    }
}

#[test]
fn short_writes_interruptions_and_byte_offset_failures_preserve_prefixes_and_poisoning() {
    for order in [Endianness::Little, Endianness::Big] {
        for format in [Format::Pcap, Format::PcapNg] {
            let open = || match format {
                Format::Pcap => Writer::pcap_with_options(
                    FaultWriter::new(),
                    LinkType::ETHERNET,
                    PcapOptions {
                        endianness: order,
                        ..PcapOptions::default()
                    },
                )
                .unwrap(),
                Format::PcapNg => Writer::pcapng_with_options(
                    FaultWriter::new(),
                    PcapNgOptions {
                        endianness: order,
                        ..PcapNgOptions::default()
                    },
                )
                .unwrap(),
            };
            let mut packet = frame(3);
            if format == Format::PcapNg {
                packet.direction = Some(Direction::Outbound);
            }
            let mut reference = open();
            let header = reference.get_ref().bytes.len();
            reference.write_frame(&packet).unwrap();
            let complete = reference.into_inner().bytes;
            // Every byte boundary in the automatic IDB, packet header, payload,
            // padding, options and footer, independent of write-call grouping.
            for offset in header..complete.len() {
                let mut writer = open();
                writer.get_mut().interrupt_at = Some(offset);
                writer.write_frame(&packet).unwrap();
                assert_eq!(writer.get_ref().bytes, complete);
                assert_eq!(writer.get_ref().flushes, 0);
                writer.flush().unwrap();
                assert_eq!(writer.get_ref().flushes, 1);
                for kind in [io::ErrorKind::BrokenPipe, io::ErrorKind::WriteZero] {
                    let mut writer = open();
                    writer.get_mut().stop_at = Some((offset, kind));
                    writer.get_mut().interrupt_at = Some(offset);
                    assert!(
                        matches!(writer.write_frame(&packet), Err(Error::Io(error)) if error.kind() == kind)
                    );
                    assert_eq!(writer.get_ref().bytes, complete[..offset]);
                    assert_eq!(
                        (writer.frames_written(), writer.captured_bytes_written()),
                        (0, 0)
                    );
                    let calls = writer.get_ref().calls;
                    let mut invalid = packet.clone();
                    invalid.timestamp = None;
                    for error in [
                        writer.encoded_frame_size(&invalid).unwrap_err(),
                        writer.encoded_frame_size(&packet).unwrap_err(),
                        writer.write_frame(&packet).unwrap_err(),
                        writer.add_interface(LinkType::RAW).unwrap_err(),
                        writer.flush().unwrap_err(),
                    ] {
                        assert!(matches!(error, Error::Io(error) if error.kind() == kind));
                    }
                    assert_eq!(writer.get_ref().calls, calls);
                    assert_eq!(writer.get_ref().flushes, 0);
                    assert_eq!(writer.into_inner().bytes, complete[..offset]);
                }
            }
        }
    }
}

fn measured_capture<W: Write>(
    destination: W,
    format: Format,
    interfaces: usize,
    length: usize,
    frames: u64,
) -> (Duration, usize) {
    let packet = frame(length);
    let limits = Limits {
        max_frames: frames,
        max_bytes: frames * length as u64,
    };
    let counted = Counted {
        inner: destination,
        calls: 0,
        bytes: 0,
    };
    let mut writer = match format {
        Format::Pcap => Writer::pcap_with_options(
            counted,
            LinkType::ETHERNET,
            PcapOptions {
                stream_limits: limits,
                ..PcapOptions::default()
            },
        )
        .unwrap(),
        Format::PcapNg => Writer::pcapng_with_options(
            counted,
            PcapNgOptions {
                stream_limits: limits,
                ..PcapNgOptions::default()
            },
        )
        .unwrap(),
    };
    let mut packet = packet;
    if format == Format::PcapNg {
        for _ in 0..interfaces {
            writer.add_interface(LinkType::ETHERNET).unwrap();
        }
        packet.interface = Some(interfaces as u32 - 1);
        packet.direction = Some(Direction::Inbound);
    }
    let calls = writer.get_ref().calls;
    let start = Instant::now();
    for _ in 0..frames {
        let packet = std::hint::black_box(&packet);
        std::hint::black_box(writer.encoded_frame_size(packet).unwrap());
        writer.write_frame(packet).unwrap();
    }
    let elapsed = start.elapsed();
    let calls = writer.get_ref().calls - calls;
    writer.flush().unwrap();
    assert_eq!(writer.frames_written(), frames);
    (elapsed, calls)
}

#[test]
#[ignore = "release measurement; no wall-clock assertions"]
fn measure_capture_preview_and_output() {
    for format in [Format::Pcap, Format::PcapNg] {
        let tables: &[usize] = if format == Format::Pcap {
            &[0]
        } else {
            &[1, 64, 1024, 4096]
        };
        for &interfaces in tables {
            for length in [64, 1500, 32768] {
                for file in [false, true] {
                    let frames = if file { 2_000 } else { 20_000 };
                    let mut samples = Vec::new();
                    let mut calls = 0;
                    for _ in 0..5 {
                        // File creation, frame allocation and interface population precede timing.
                        let measured = if file {
                            measured_capture(
                                tempfile::tempfile_in(env!("CARGO_MANIFEST_DIR")).unwrap(),
                                format,
                                interfaces,
                                length,
                                frames,
                            )
                        } else {
                            measured_capture(io::sink(), format, interfaces, length, frames)
                        };
                        samples.push(measured.0.as_nanos() as f64 / frames as f64);
                        calls = measured.1;
                    }
                    samples.sort_by(f64::total_cmp);
                    println!(
                        "capture,{format:?},interfaces={interfaces},payload={length},file={file},frames={frames},ns/frame={:.1},calls/frame={:.1}",
                        samples[2],
                        calls as f64 / frames as f64
                    );
                }
            }
        }
    }
}
