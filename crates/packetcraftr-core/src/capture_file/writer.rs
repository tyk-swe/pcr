// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::fmt;
use std::io::{self, Write};
use std::sync::Arc;
use std::time::UNIX_EPOCH;

use crate::frame::{Frame, LinkType};

use super::classic::{write_pcap_frame, write_pcap_header};
use super::error::Error;
use super::format::{Endianness, Format, TimestampPrecision, TimestampResolution};
use super::header::{Interface, Section};
use super::limits::{
    Budget, DEFAULT_MAX_INTERFACES_PER_SECTION, DEFAULT_MAX_OPTIONS_PER_BLOCK,
    DEFAULT_MAX_TOTAL_INTERFACES, Limits, MetadataRun, ReaderLimits,
};
use super::pcapng::{
    interface_description_base_length, next_interface_id, select_interface,
    simple_packet_captured_length, validate_new_interface, write_enhanced_packet,
    write_interface_description, write_mapped_interface, write_mapped_packet,
    write_rewritten_section, write_section_header, write_simple_packet,
};
use super::wire::{
    DEFAULT_TIMESTAMP_RESOLUTION, PCAP_RECORD_HEADER_LEN, PCAPNG_OPTION_END,
    PCAPNG_OPTION_IF_TSOFFSET, PCAPNG_OPTION_IF_TSRESOL, align_to_u32, align_to_usize,
    timestamp_to_ticks, usize_to_u32_limit, validate_frame_size,
};
use super::{PcapNgOptions, PcapOptions};

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
        section_base: u32,
    },
}

struct FramePlan {
    encoding: FrameEncoding,
    encoded_size: usize,
    budget: Budget,
}

enum FrameEncoding {
    Pcap {
        seconds: u32,
        fraction: u32,
    },
    PcapNg {
        interface_id: u32,
        timestamp: u64,
        block_length: u32,
        new_interface: Option<Interface>,
    },
}

#[derive(Debug)]
struct ChainSnapshot {
    message: String,
    source: Option<Arc<Self>>,
}

impl ChainSnapshot {
    fn of(error: &(dyn std::error::Error + 'static)) -> Arc<Self> {
        Arc::new(Self {
            message: error.to_string(),
            source: error.source().map(Self::of),
        })
    }
}

impl fmt::Display for ChainSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.message.fmt(formatter)
    }
}

impl std::error::Error for ChainSnapshot {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source
            .as_deref()
            .map(|source| source as &(dyn std::error::Error + 'static))
    }
}

#[derive(Debug)]
struct OutputFailure {
    kind: io::ErrorKind,
    raw_os_error: Option<i32>,
    source: Option<Arc<ChainSnapshot>>,
}

impl OutputFailure {
    fn to_error(&self) -> Error {
        let error = if let Some(code) = self.raw_os_error {
            io::Error::from_raw_os_error(code)
        } else if let Some(source) = &self.source {
            io::Error::new(self.kind, Arc::clone(source))
        } else {
            self.kind.into()
        };
        Error::Io(error)
    }
}

pub struct Writer<W> {
    inner: W,
    pub(super) state: WriterState,
    max_size: usize,
    max_interfaces: usize,
    budget: Budget,
    output_failure: Option<OutputFailure>,
    metadata: MetadataRun,
}

impl<W: Write> Writer<W> {
    /// Creates a writer with default settings and, for PCAPNG, interface zero.
    pub fn new(inner: W, format: Format, link_type: LinkType) -> Result<Self, Error> {
        match format {
            Format::Pcap => Self::pcap_with_options(inner, link_type, Default::default()),
            Format::PcapNg => {
                if link_type.0 > u16::MAX as u32 {
                    return Err(Error::LinkTypeOutOfRange {
                        link_type: link_type.0,
                    });
                }
                let mut writer = Self::pcapng_with_options(inner, Default::default())?;
                writer.add_interface(link_type)?;
                Ok(writer)
            }
        }
    }

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
        let budget = Budget::new(stream_limits)?;
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
            DEFAULT_MAX_INTERFACES_PER_SECTION,
            budget,
        ))
    }

    pub fn pcapng_with_options(inner: W, options: PcapNgOptions) -> Result<Self, Error> {
        Self::pcapng_with_section(inner, options, None)
    }

    pub(super) fn pcapng_with_section(
        mut inner: W,
        options: PcapNgOptions,
        section: Option<&Section>,
    ) -> Result<Self, Error> {
        let PcapNgOptions {
            endianness,
            max_size,
            max_interfaces,
            stream_limits,
        } = options;
        let budget = Budget::new(stream_limits)?;
        let endianness = section.map_or(endianness, |section| section.endianness);
        let length = section.map_or(28, |section| section.raw.len());
        check_block_size(length, max_size, "pcapng section header")?;
        write_section(&mut inner, endianness, section)?;
        Ok(Self::from_state(
            inner,
            WriterState::PcapNg {
                endianness,
                interfaces: Vec::new(),
                section_base: 0,
            },
            max_size,
            max_interfaces,
            budget,
        ))
    }

    fn from_state(
        inner: W,
        state: WriterState,
        max_size: usize,
        max_interfaces: usize,
        budget: Budget,
    ) -> Self {
        Self {
            inner,
            state,
            max_size,
            max_interfaces,
            budget,
            output_failure: None,
            metadata: MetadataRun::default(),
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

    pub fn stream_limits(&self) -> Limits {
        self.budget.limits()
    }

    pub fn frames_written(&self) -> u64 {
        self.budget.frames()
    }

    pub fn captured_bytes_written(&self) -> u64 {
        self.budget.captured_bytes()
    }

    pub fn add_interface(&mut self, link_type: LinkType) -> Result<u32, Error> {
        self.ensure_output_available()?;
        let snap_len = usize_to_u32_limit(self.max_size)?;
        self.add_interface_description_with_options(
            Interface {
                link_type,
                snap_len,
                timestamp_resolution: super::wire::WRITER_TIMESTAMP_RESOLUTION,
                timestamp_offset: 0,
            },
            &[],
        )
    }

    pub fn add_interface_description_with_options(
        &mut self,
        description: Interface,
        options: &[super::PcapNgOption],
    ) -> Result<u32, Error> {
        self.ensure_output_available()?;
        let options_written = options.len()
            + usize::from(description.timestamp_resolution != DEFAULT_TIMESTAMP_RESOLUTION)
            + usize::from(description.timestamp_offset != 0);
        if options_written > DEFAULT_MAX_OPTIONS_PER_BLOCK {
            return Err(Error::OptionLimit {
                limit: DEFAULT_MAX_OPTIONS_PER_BLOCK,
            });
        }
        let mut length = interface_description_base_length(&description);
        for option in options {
            if matches!(
                option.code,
                PCAPNG_OPTION_END | PCAPNG_OPTION_IF_TSRESOL | PCAPNG_OPTION_IF_TSOFFSET
            ) || option.value.len() > u16::MAX as usize
            {
                return Err(Error::InvalidData {
                    format: Format::PcapNg,
                    reason: "custom interface options conflict with generated metadata or exceed wire length",
                });
            }
            length = length.saturating_add(4 + option.value.len().div_ceil(4) * 4);
        }
        if length > self.max_size {
            return Err(Error::SizeLimitExceeded {
                kind: "interface description",
                declared: u64::try_from(length).unwrap_or(u64::MAX),
                limit: self.max_size,
            });
        }
        let (section_base, interfaces) = self.pcapng_section()?;
        let local_id =
            validate_new_interface(&description, interfaces, self.max_size, self.max_interfaces)?;
        let id = global_interface_id(section_base, local_id)?;
        self.write_interface(description, options, length)?;
        Ok(id)
    }

    fn write_interface(
        &mut self,
        description: Interface,
        options: &[super::PcapNgOption],
        length: usize,
    ) -> Result<(), Error> {
        let block_length = usize_to_u32_limit(length)?;
        let endianness = self.endianness();
        self.record_interface(description, length, |inner, description| {
            write_interface_description(inner, endianness, description, options, block_length)
        })
    }

    pub(super) fn copy_interface_block(
        &mut self,
        description: Interface,
        raw: &[u8],
    ) -> Result<u32, Error> {
        check_block_size(raw.len(), self.max_size, "pcapng interface description")?;
        let (section_base, interfaces) = self.pcapng_section()?;
        let id = global_interface_id(
            section_base,
            next_interface_id(interfaces, self.max_interfaces)?,
        )?;
        let endianness = self.endianness();
        self.record_interface(description, raw.len(), |inner, description| {
            write_mapped_interface(inner, endianness, raw, description.snap_len)
        })?;
        Ok(id)
    }

    fn record_interface(
        &mut self,
        description: Interface,
        length: usize,
        write: impl FnOnce(&mut W, &Interface) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let metadata = self.metadata.after(length, ReaderLimits::default())?;
        self.write_output(|inner| write(inner, &description))?;
        if let WriterState::PcapNg { interfaces, .. } = &mut self.state {
            interfaces.push(description);
        }
        self.metadata = metadata;
        Ok(())
    }

    pub(super) fn pcapng_section(&self) -> Result<(u32, &[Interface]), Error> {
        match &self.state {
            WriterState::PcapNg {
                interfaces,
                section_base,
                ..
            } => Ok((*section_base, interfaces)),
            WriterState::Pcap { .. } => Err(Error::WrongWriterFormat {
                expected: Format::PcapNg,
                actual: Format::Pcap,
            }),
        }
    }

    pub(super) fn section_interface_limit(&self) -> usize {
        self.max_interfaces
    }

    pub(super) fn start_section(&mut self) -> Result<(), Error> {
        self.start_section_with(None)
    }

    pub(super) fn start_section_with(&mut self, section: Option<&Section>) -> Result<(), Error> {
        let (section_base, interfaces) = self.pcapng_section()?;
        let next_base = section_base + interfaces.len() as u32;
        let length = section.map_or(28, |section| section.raw.len());
        check_block_size(length, self.max_size, "pcapng section header")?;
        let metadata = self.metadata.after(length, ReaderLimits::default())?;
        let endianness = section.map_or(self.endianness(), |section| section.endianness);
        self.write_output(|inner| write_section(inner, endianness, section))?;
        self.state = WriterState::PcapNg {
            endianness,
            interfaces: Vec::new(),
            section_base: next_base,
        };
        self.metadata = metadata;
        Ok(())
    }

    pub(super) fn copy_metadata_block(&mut self, raw: &[u8]) -> Result<(), Error> {
        check_block_size(raw.len(), self.max_size, "pcapng metadata block")?;
        let metadata = self.metadata.after(raw.len(), ReaderLimits::default())?;
        self.write_output(|inner| inner.write_all(raw).map_err(Error::from))?;
        self.metadata = metadata;
        Ok(())
    }

    pub(super) fn write_mapped_frame(
        &mut self,
        frame: &Frame,
        original: &Frame,
        raw: &[u8],
        changed: bool,
    ) -> Result<(), Error> {
        validate_frame_size(frame, self.max_size)?;
        let (section_base, interfaces) = self.pcapng_section()?;
        let interface = select_interface(
            frame,
            interfaces,
            section_base,
            self.max_size,
            self.max_interfaces,
        )?
        .description;
        validate_capture_length(frame, &interface)?;
        let budget = self.budget.after(frame.captured_length())?;
        if changed {
            // The reader validated the shared fixed header and option offsets for both packet layouts.
            let options = &raw[28 + align_to_usize(original.bytes().len())?..raw.len() - 4];
            let length = 32_u32
                .checked_add(align_to_u32(frame.captured_length())?)
                .and_then(|length| length.checked_add(options.len() as u32))
                .ok_or(Error::InvalidBlockLength { length: u32::MAX })?;
            check_block_size(length as usize, self.max_size, "pcapng packet block")?;
            let endianness = self.endianness();
            self.write_output(|inner| {
                write_mapped_packet(inner, endianness, raw, options, length, frame)
            })?;
        } else {
            check_block_size(raw.len(), self.max_size, "pcapng packet block")?;
            self.write_output(|inner| inner.write_all(raw).map_err(Error::from))?;
        }
        self.budget = budget;
        self.metadata = MetadataRun::default();
        Ok(())
    }

    pub(super) fn write_simple_frame(&mut self, frame: &Frame) -> Result<(), Error> {
        self.ensure_output_available()?;
        validate_frame_size(frame, self.max_size)?;
        let (section_base, interfaces) = self.pcapng_section()?;
        let first = interfaces.first().ok_or(Error::UndefinedInterface {
            interface: section_base,
            available: 0,
        })?;
        if frame.timestamp.is_some()
            || frame.direction.is_some()
            || frame.interface != Some(section_base)
            || frame.link_type != first.link_type
            || frame.captured_length()
                != simple_packet_captured_length(frame.original_length(), first.snap_len)
        {
            return Err(Error::MetadataNotRepresentable {
                format: Format::PcapNg,
                field: "simple packet block",
            });
        }
        let block_length = 16_u32
            .checked_add(align_to_u32(frame.captured_length())?)
            .ok_or(Error::InvalidBlockLength { length: u32::MAX })?;
        if block_length as usize > self.max_size {
            return Err(Error::SizeLimitExceeded {
                kind: "pcapng simple packet block",
                declared: u64::from(block_length),
                limit: self.max_size,
            });
        }
        let budget = self.budget.after(frame.captured_length())?;
        let endianness = self.endianness();
        self.write_output(|inner| write_simple_packet(inner, endianness, block_length, frame))?;
        self.budget = budget;
        self.metadata = MetadataRun::default();
        Ok(())
    }

    /// Counts the uncompressed capture bytes a frame would add under the current
    /// interface and resource state, including any automatic interface block.
    pub fn encoded_frame_size(&self, frame: &Frame) -> Result<usize, Error> {
        Ok(self.prepare_frame(frame)?.encoded_size)
    }

    pub fn write_frame(&mut self, frame: &Frame) -> Result<(), Error> {
        let plan = self.prepare_frame(frame)?;
        let endianness = self.endianness();
        match plan.encoding {
            FrameEncoding::Pcap { seconds, fraction } => {
                self.write_output(|inner| {
                    write_pcap_frame(inner, endianness, seconds, fraction, frame)
                })?;
            }
            FrameEncoding::PcapNg {
                interface_id,
                timestamp,
                block_length,
                new_interface,
            } => {
                if let Some(description) = new_interface {
                    // Commit it after its own output, even if the following packet fails.
                    self.write_interface(
                        description,
                        &[],
                        plan.encoded_size - block_length as usize,
                    )?;
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
                })?;
            }
        }
        self.budget = plan.budget;
        self.metadata = MetadataRun::default();
        Ok(())
    }

    fn prepare_frame(&self, frame: &Frame) -> Result<FramePlan, Error> {
        self.ensure_output_available()?;
        validate_frame_size(frame, self.max_size)?;
        let budget = self.budget.after(frame.captured_length())?;
        let (encoding, record_size, prefix_size) = match &self.state {
            WriterState::Pcap {
                precision,
                snap_len,
                link_type,
                ..
            } => {
                let (seconds, fraction) =
                    validate_pcap_frame(frame, *precision, *snap_len, *link_type)?;
                (
                    FrameEncoding::Pcap { seconds, fraction },
                    frame.bytes().len(),
                    PCAP_RECORD_HEADER_LEN,
                )
            }
            WriterState::PcapNg {
                interfaces,
                section_base,
                ..
            } => {
                let plan = select_interface(
                    frame,
                    interfaces,
                    *section_base,
                    self.max_size,
                    self.max_interfaces,
                )?;
                let prefix_size = plan.description_block_length();
                if plan.requires_description_block {
                    global_interface_id(*section_base, plan.id)?;
                    self.metadata.after(prefix_size, ReaderLimits::default())?;
                }
                let interface = plan.description;
                validate_capture_length(frame, &interface)?;
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
                (
                    FrameEncoding::PcapNg {
                        interface_id: plan.id,
                        timestamp,
                        block_length,
                        new_interface: plan.requires_description_block.then_some(interface),
                    },
                    block_length as usize,
                    prefix_size,
                )
            }
        };
        let encoded_size = record_size
            .checked_add(prefix_size)
            .ok_or_else(|| io::Error::other("capture size preview overflow"))?;
        Ok(FramePlan {
            encoding,
            encoded_size,
            budget,
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
                // An `io::Error` payload cannot be cloned; the sticky state keeps a chain snapshot.
                self.output_failure = Some(OutputFailure {
                    kind: error.kind(),
                    raw_os_error: error.raw_os_error(),
                    source: error.get_ref().map(|payload| ChainSnapshot::of(payload)),
                });
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

fn write_section<W: Write>(
    inner: &mut W,
    endianness: Endianness,
    source: Option<&Section>,
) -> Result<(), Error> {
    match source {
        Some(section) => write_rewritten_section(inner, &section.raw),
        None => write_section_header(inner, endianness),
    }
}

fn check_block_size(length: usize, limit: usize, kind: &'static str) -> Result<(), Error> {
    if length > limit {
        return Err(Error::SizeLimitExceeded {
            kind,
            declared: u64::try_from(length).unwrap_or(u64::MAX),
            limit,
        });
    }
    Ok(())
}

fn validate_capture_length(frame: &Frame, interface: &Interface) -> Result<(), Error> {
    if interface.snap_len != 0 && frame.captured_length() > interface.snap_len {
        return Err(Error::SizeLimitExceeded {
            kind: "pcapng captured packet",
            declared: u64::from(frame.captured_length()),
            limit: interface.snap_len as usize,
        });
    }
    Ok(())
}

fn global_interface_id(section_base: u32, local_id: u32) -> Result<u32, Error> {
    let id = section_base + local_id;
    if id as usize >= DEFAULT_MAX_TOTAL_INTERFACES {
        return Err(Error::TotalInterfaceLimit {
            limit: DEFAULT_MAX_TOTAL_INTERFACES,
        });
    }
    Ok(id)
}

fn validate_pcap_frame(
    frame: &Frame,
    precision: TimestampPrecision,
    snap_len: u32,
    link_type: LinkType,
) -> Result<(u32, u32), Error> {
    if frame.interface.is_some() {
        return Err(Error::MetadataNotRepresentable {
            format: Format::Pcap,
            field: "interface",
        });
    }
    if frame.direction.is_some() {
        return Err(Error::MetadataNotRepresentable {
            format: Format::Pcap,
            field: "direction",
        });
    }
    if frame.link_type != link_type {
        return Err(Error::InterfaceLinkTypeMismatch {
            interface: 0,
            expected: link_type.0,
            actual: frame.link_type.0,
        });
    }
    if frame.captured_length() > snap_len {
        return Err(Error::SizeLimitExceeded {
            kind: "pcap captured packet",
            declared: u64::from(frame.captured_length()),
            limit: snap_len as usize,
        });
    }

    let timestamp = frame.timestamp.ok_or(Error::TimestampUnavailable {
        format: Format::Pcap,
    })?;
    let elapsed = timestamp
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::TimestampOutOfRange {
            format: Format::Pcap,
        })?;
    let seconds = u32::try_from(elapsed.as_secs()).map_err(|_| Error::TimestampOutOfRange {
        format: Format::Pcap,
    })?;

    let fraction = match precision {
        TimestampPrecision::Microseconds if !elapsed.subsec_nanos().is_multiple_of(1_000) => {
            return Err(Error::MetadataNotRepresentable {
                format: Format::Pcap,
                field: "microsecond timestamp precision",
            });
        }
        TimestampPrecision::Microseconds => elapsed.subsec_micros(),
        TimestampPrecision::Nanoseconds => elapsed.subsec_nanos(),
    };

    Ok((seconds, fraction))
}

#[cfg(test)]
mod tests;
