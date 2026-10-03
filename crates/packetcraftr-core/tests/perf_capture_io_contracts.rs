// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
#![allow(dead_code)]

mod common;

use std::io::{self, Write};
use std::time::{Duration, UNIX_EPOCH};

use packetcraftr_core::capture_file::{
    Endianness, Error, Format, Limits, PcapNgOptions, PcapOptions, Writer,
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
