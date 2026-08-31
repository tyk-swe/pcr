// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::io::{self, Write};

use crate::frame::{Frame, LinkType};

use super::classic::{write_pcap_frame, write_pcap_header};
use super::error::Error;
use super::model::{
    DEFAULT_INTERFACE_LIMIT, Endianness, Format, Interface, Limits, PcapNgOptions, PcapOptions,
    TimestampPrecision, TimestampResolution,
};
use super::pcapng::{
    select_interface, validate_new_interface, write_enhanced_packet, write_interface_description,
    write_section_header,
};
use super::wire::{align_to_u32, timestamp_to_ticks, usize_to_u32_limit, validate_frame_size};

pub(super) enum WriterState {
    Pcap {
        endianness: Endianness,
        precision: TimestampPrecision,
        snap_len: u32,
        link_type: LinkType,
    },
    PcapNg {
        endianness: Endianness,
        interfaces: Vec<Interface>,
    },
}

#[derive(Debug)]
struct OutputFailure {
    kind: io::ErrorKind,
    raw_os_error: Option<i32>,
    message: String,
}

impl OutputFailure {
    fn from_error(error: &io::Error) -> Self {
        Self {
            kind: error.kind(),
            raw_os_error: error.raw_os_error(),
            message: error.to_string(),
        }
    }

    fn to_error(&self) -> Error {
        let error = match self.raw_os_error {
            Some(code) => io::Error::from_raw_os_error(code),
            None => io::Error::new(self.kind, self.message.clone()),
        };
        Error::Io(error)
    }
}

/// A streaming writer that creates a new capture from frames.
///
/// It emits generated classic packet records or PCAPNG Enhanced Packet Blocks;
/// use [`super::rewrite`] when source block structure must be retained.
pub struct Writer<W> {
    inner: W,
    pub(super) state: WriterState,
    max_size: usize,
    max_interfaces: usize,
    stream_limits: Limits,
    frames_written: u64,
    captured_bytes_written: u64,
    output_failure: Option<OutputFailure>,
}

impl<W: Write> Writer<W> {
    /// Creates a writer with the default format configuration.
    ///
    /// A PCAPNG writer created this way starts with interface zero. Use
    /// [`pcapng`](Self::pcapng) followed by [`add_interface`](Self::add_interface)
    /// when all interface descriptions need to be declared explicitly.
    pub fn new(inner: W, format: Format, link_type: LinkType) -> Result<Self, Error> {
        match format {
            Format::Pcap => Self::pcap(inner, link_type),
            Format::PcapNg => {
                // Validate the default interface before writing the section header.
                if link_type.0 > u16::MAX as u32 {
                    return Err(Error::LinkTypeOutOfRange {
                        link_type: link_type.0,
                    });
                }
                let mut writer = Self::pcapng(inner)?;
                writer.add_interface(link_type)?;
                Ok(writer)
            }
        }
    }

    /// Creates a little-endian, nanosecond-resolution classic PCAP writer.
    pub fn pcap(inner: W, link_type: LinkType) -> Result<Self, Error> {
        Self::pcap_with_options(inner, link_type, PcapOptions::default())
    }

    /// Creates a classic PCAP writer with explicit format options.
    pub fn pcap_with_options(
        mut inner: W,
        link_type: LinkType,
        options: PcapOptions,
    ) -> Result<Self, Error> {
        let PcapOptions {
            endianness,
            timestamp_resolution,
            snap_len,
            max_size,
            stream_limits,
        } = options;
        if link_type.0 > u16::MAX as u32 {
            return Err(Error::LinkTypeOutOfRange {
                link_type: link_type.0,
            });
        }
        let precision = match timestamp_resolution {
            TimestampResolution::Decimal(6) => TimestampPrecision::Microseconds,
            TimestampResolution::Decimal(9) => TimestampPrecision::Nanoseconds,
            TimestampResolution::Decimal(exponent) => {
                return Err(Error::InvalidTimestampResolution { base: 10, exponent });
            }
            TimestampResolution::Binary(exponent) => {
                return Err(Error::InvalidTimestampResolution { base: 2, exponent });
            }
        };
        let snap_len_u32 = usize_to_u32_limit(snap_len)?;
        if snap_len_u32 == 0 {
            return Err(Error::InvalidData {
                format: Format::Pcap,
                reason: "snapshot length must be non-zero",
            });
        }
        write_pcap_header(&mut inner, endianness, precision, snap_len_u32, link_type)?;
        Ok(Self::from_state(
            inner,
            WriterState::Pcap {
                endianness,
                precision,
                snap_len: snap_len_u32,
                link_type,
            },
            max_size,
            DEFAULT_INTERFACE_LIMIT,
            stream_limits,
        ))
    }

    /// Creates a little-endian PCAPNG writer without an interface block.
    pub fn pcapng(inner: W) -> Result<Self, Error> {
        Self::pcapng_with_options(inner, PcapNgOptions::default())
    }

    /// Creates a PCAPNG writer without an interface block using explicit options.
    pub fn pcapng_with_options(mut inner: W, options: PcapNgOptions) -> Result<Self, Error> {
        let PcapNgOptions {
            endianness,
            max_size,
            max_interfaces,
            stream_limits,
        } = options;
        if max_size < 28 {
            return Err(Error::SizeLimitExceeded {
                kind: "pcapng section header",
                declared: 28,
                limit: max_size,
            });
        }
        write_section_header(&mut inner, endianness)?;
        Ok(Self::from_state(
            inner,
            WriterState::PcapNg {
                endianness,
                interfaces: Vec::new(),
            },
            max_size,
            max_interfaces,
            stream_limits,
        ))
    }

    fn from_state(
        inner: W,
        state: WriterState,
        max_size: usize,
        max_interfaces: usize,
        stream_limits: Limits,
    ) -> Self {
        Self {
            inner,
            state,
            max_size,
            max_interfaces,
            stream_limits,
            frames_written: 0,
            captured_bytes_written: 0,
            output_failure: None,
        }
    }

    pub fn format(&self) -> Format {
        match self.state {
            WriterState::Pcap { .. } => Format::Pcap,
            WriterState::PcapNg { .. } => Format::PcapNg,
        }
    }

    pub fn endianness(&self) -> Endianness {
        match self.state {
            WriterState::Pcap { endianness, .. } | WriterState::PcapNg { endianness, .. } => {
                endianness
            }
        }
    }

    pub fn size_limit(&self) -> usize {
        self.max_size
    }

    /// The aggregate ceilings this writer was opened under. They are fixed
    /// at construction: a stream's budget cannot be raised part-way through
    /// the output it already committed.
    pub fn stream_limits(&self) -> Limits {
        self.stream_limits
    }

    /// Frames committed to the output so far.
    ///
    /// A record refused for any reason — an exhausted budget, a metadata
    /// mismatch, or an output failure — commits neither a frame nor a byte,
    /// and this pair is how a caller observes that.
    pub fn frames_written(&self) -> u64 {
        self.frames_written
    }

    /// Captured payload bytes committed to the output so far.
    pub fn captured_bytes_written(&self) -> u64 {
        self.captured_bytes_written
    }

    /// Adds a PCAPNG interface using the writer's configured size limit as
    /// its snap length and returns its numeric interface ID.
    pub fn add_interface(&mut self, link_type: LinkType) -> Result<u32, Error> {
        self.ensure_output_available()?;
        let snap_len = usize_to_u32_limit(self.max_size)?;
        self.add_interface_description(Interface {
            link_type,
            snap_len,
            timestamp_resolution: super::wire::WRITER_TIMESTAMP_RESOLUTION,
            timestamp_offset: 0,
        })
    }

    /// Adds one PCAPNG interface while retaining its timestamp metadata.
    pub fn add_interface_description(&mut self, description: Interface) -> Result<u32, Error> {
        self.ensure_output_available()?;
        let (endianness, interface_id) = match &self.state {
            WriterState::Pcap { .. } => {
                return Err(Error::WrongWriterFormat {
                    expected: Format::PcapNg,
                    actual: Format::Pcap,
                });
            }
            WriterState::PcapNg {
                endianness,
                interfaces,
            } => (
                *endianness,
                validate_new_interface(
                    &description,
                    interfaces,
                    self.max_size,
                    self.max_interfaces,
                )?,
            ),
        };

        self.write_output(|inner| {
            write_interface_description(
                inner,
                endianness,
                description.link_type,
                description.snap_len,
                description.timestamp_resolution,
                description.timestamp_offset,
            )
        })?;
        match &mut self.state {
            WriterState::PcapNg { interfaces, .. } => {
                interfaces.push(description);
            }
            WriterState::Pcap { .. } => unreachable!("format checked above"),
        }
        Ok(interface_id)
    }

    /// Writes one frame, validating all representability and length invariants
    /// before emitting any bytes for it.
    pub fn write_frame(&mut self, frame: &Frame) -> Result<(), Error> {
        self.ensure_output_available()?;
        validate_frame_size(frame, self.max_size)?;

        let (next_frames, next_bytes) = self.stream_limits.advance(
            self.frames_written,
            self.captured_bytes_written,
            frame.captured_length(),
        )?;

        match &self.state {
            WriterState::Pcap {
                endianness,
                precision,
                snap_len,
                link_type,
            } => {
                let file_endianness = *endianness;
                let timestamp_precision = *precision;
                let snapshot_length = *snap_len;
                let file_link_type = *link_type;
                self.write_output(|inner| {
                    write_pcap_frame(
                        inner,
                        file_endianness,
                        timestamp_precision,
                        snapshot_length,
                        file_link_type,
                        frame,
                    )
                })
            }
            WriterState::PcapNg { .. } => self.write_pcapng_frame(frame),
        }?;
        self.frames_written = next_frames;
        self.captured_bytes_written = next_bytes;
        Ok(())
    }

    fn write_pcapng_frame(&mut self, frame: &Frame) -> Result<(), Error> {
        let interfaces = match &self.state {
            WriterState::PcapNg { interfaces, .. } => interfaces,
            WriterState::Pcap { .. } => unreachable!("format checked by caller"),
        };
        let plan = select_interface(frame, interfaces, self.max_size, self.max_interfaces)?;
        let interface_id = plan.id;
        let interface = plan.description;
        let endianness = self.endianness();

        if interface.snap_len != 0 && frame.captured_length() > interface.snap_len {
            return Err(Error::SizeLimitExceeded {
                kind: "pcapng captured packet",
                declared: u64::from(frame.captured_length()),
                limit: interface.snap_len as usize,
            });
        }

        let captured_time = frame.timestamp.ok_or(Error::TimestampUnavailable {
            format: Format::PcapNg,
        })?;
        let timestamp = timestamp_to_ticks(
            captured_time,
            interface.timestamp_resolution,
            interface.timestamp_offset,
        )?;
        let padded_packet_length = align_to_u32(frame.captured_length())?;
        let option_length = if frame.direction.is_some() { 12_u32 } else { 0 };
        let block_length = 32_u32
            .checked_add(padded_packet_length)
            .and_then(|length| length.checked_add(option_length))
            .ok_or(Error::InvalidBlockLength { length: u32::MAX })?;
        if block_length as usize > self.max_size {
            return Err(Error::SizeLimitExceeded {
                kind: "pcapng enhanced packet block",
                declared: u64::from(block_length),
                limit: self.max_size,
            });
        }

        if plan.requires_description_block {
            let committed = self.add_interface_description(interface)?;
            debug_assert_eq!(committed, interface_id);
        }

        self.write_output(|inner| {
            write_enhanced_packet(
                inner,
                endianness,
                interface_id,
                timestamp,
                block_length,
                frame,
            )
        })
    }

    pub fn flush(&mut self) -> Result<(), Error> {
        self.ensure_output_available()?;
        self.inner.flush().map_err(Error::from)
    }

    fn ensure_output_available(&self) -> Result<(), Error> {
        match &self.output_failure {
            Some(failure) => Err(failure.to_error()),
            None => Ok(()),
        }
    }

    fn write_output<T>(
        &mut self,
        operation: impl FnOnce(&mut W) -> Result<T, Error>,
    ) -> Result<T, Error> {
        self.ensure_output_available()?;
        match operation(&mut self.inner) {
            Err(Error::Io(error)) => {
                self.output_failure = Some(OutputFailure::from_error(&error));
                Err(Error::Io(error))
            }
            result => result,
        }
    }

    pub fn get_ref(&self) -> &W {
        &self.inner
    }

    pub fn get_mut(&mut self) -> &mut W {
        &mut self.inner
    }

    pub fn into_inner(self) -> W {
        self.inner
    }
}
