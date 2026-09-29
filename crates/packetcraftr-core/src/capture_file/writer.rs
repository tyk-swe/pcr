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
use super::header::Interface;
use super::limits::{Budget, DEFAULT_MAX_INTERFACES_PER_SECTION, Limits};
use super::pcapng::{
    interface_description_base_length, select_interface, validate_new_interface,
    write_enhanced_packet, write_interface_description, write_section_header,
};
use super::wire::{
    PCAP_RECORD_HEADER_LEN, PCAPNG_OPTION_END, PCAPNG_OPTION_IF_TSOFFSET, PCAPNG_OPTION_IF_TSRESOL,
    align_to_u32, timestamp_to_ticks, usize_to_u32_limit, validate_frame_size,
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
}

impl<W: Write> Writer<W> {
    /// Creates a writer with default settings and, for PCAPNG, interface zero.
    pub fn new(inner: W, format: Format, link_type: LinkType) -> Result<Self, Error> {
        match format {
            Format::Pcap => Self::pcap(inner, link_type),
            Format::PcapNg => {
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

    pub fn pcap(inner: W, link_type: LinkType) -> Result<Self, Error> {
        Self::pcap_with_options(inner, link_type, PcapOptions::default())
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

    pub fn pcapng(inner: W) -> Result<Self, Error> {
        Self::pcapng_with_options(inner, PcapNgOptions::default())
    }

    pub fn pcapng_with_options(mut inner: W, options: PcapNgOptions) -> Result<Self, Error> {
        let PcapNgOptions {
            endianness,
            max_size,
            max_interfaces,
            stream_limits,
        } = options;
        let budget = Budget::new(stream_limits)?;
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
        self.add_interface_description(Interface {
            link_type,
            snap_len,
            timestamp_resolution: super::wire::WRITER_TIMESTAMP_RESOLUTION,
            timestamp_offset: 0,
        })
    }

    pub fn add_interface_description(&mut self, description: Interface) -> Result<u32, Error> {
        self.add_interface_description_with_options(description, &[])
    }

    pub fn add_interface_description_with_options(
        &mut self,
        description: Interface,
        options: &[super::PcapNgOption],
    ) -> Result<u32, Error> {
        self.ensure_output_available()?;
        let mut length = interface_description_base_length(description.timestamp_offset);
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
        if !options.is_empty() && length > self.max_size {
            return Err(Error::SizeLimitExceeded {
                kind: "interface description",
                declared: u64::try_from(length).unwrap_or(u64::MAX),
                limit: self.max_size,
            });
        }
        let (max_size, max_interfaces) = (self.max_size, self.max_interfaces);
        let interface_id = validate_new_interface(
            &description,
            self.pcapng_interfaces()?,
            max_size,
            max_interfaces,
        )?;
        self.write_interface(description, options)?;
        Ok(interface_id)
    }

    fn write_interface(
        &mut self,
        description: Interface,
        options: &[super::PcapNgOption],
    ) -> Result<(), Error> {
        let endianness = self.endianness();
        self.write_output(|inner| {
            write_interface_description(
                inner,
                endianness,
                description.link_type,
                description.snap_len,
                description.timestamp_resolution,
                description.timestamp_offset,
                options,
            )
        })?;
        self.pcapng_interfaces()?.push(description);
        Ok(())
    }

    fn pcapng_interfaces(&mut self) -> Result<&mut Vec<Interface>, Error> {
        match &mut self.state {
            WriterState::PcapNg { interfaces, .. } => Ok(interfaces),
            WriterState::Pcap { .. } => Err(Error::WrongWriterFormat {
                expected: Format::PcapNg,
                actual: Format::Pcap,
            }),
        }
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
                    self.write_interface(description, &[])?;
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
            WriterState::PcapNg { interfaces, .. } => {
                let plan = select_interface(frame, interfaces, self.max_size, self.max_interfaces)?;
                let prefix_size = plan.description_block_length();
                let interface = plan.description;
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
mod tests {
    use super::*;

    #[test]
    fn preview_and_write_preserve_overflowed_stream_state() {
        let frame = Frame::new(UNIX_EPOCH, LinkType::ETHERNET, vec![1]).unwrap();
        for format in [Format::Pcap, Format::PcapNg] {
            let limits = Limits {
                max_frames: u64::MAX,
                max_bytes: u64::MAX,
            };
            let mut writer = match format {
                Format::Pcap => Writer::pcap_with_options(
                    Vec::new(),
                    LinkType::ETHERNET,
                    PcapOptions {
                        stream_limits: limits,
                        ..PcapOptions::default()
                    },
                )
                .unwrap(),
                Format::PcapNg => Writer::pcapng_with_options(
                    Vec::new(),
                    PcapNgOptions {
                        stream_limits: limits,
                        ..PcapNgOptions::default()
                    },
                )
                .unwrap(),
            };
            let before = writer.get_ref().clone();
            writer.budget = Budget::charged(limits, u64::MAX, 0);
            for error in [
                writer.encoded_frame_size(&frame).unwrap_err(),
                writer.write_frame(&frame).unwrap_err(),
            ] {
                assert!(matches!(
                    error,
                    Error::FrameLimitExceeded {
                        actual: u64::MAX,
                        limit: u64::MAX
                    }
                ));
            }
            assert_eq!(writer.frames_written(), u64::MAX);
            writer.budget = Budget::charged(limits, 0, u64::MAX);
            for error in [
                writer.encoded_frame_size(&frame).unwrap_err(),
                writer.write_frame(&frame).unwrap_err(),
            ] {
                assert!(matches!(
                    error,
                    Error::StreamByteLimitExceeded {
                        actual: u64::MAX,
                        limit: u64::MAX
                    }
                ));
            }
            assert_eq!(writer.captured_bytes_written(), u64::MAX);
            assert_eq!(writer.frames_written(), 0);
            assert_eq!(writer.get_ref(), &before);
            assert!(writer.output_failure.is_none());
        }
    }

    struct FailAt {
        bytes: Vec<u8>,
        offset: usize,
    }

    impl Write for FailAt {
        fn write(&mut self, input: &[u8]) -> io::Result<usize> {
            let count = input.len().min(self.offset - self.bytes.len());
            if count == 0 {
                return Err(io::ErrorKind::BrokenPipe.into());
            }
            self.bytes.extend_from_slice(&input[..count]);
            Ok(count)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn automatic_interface_commits_only_its_successful_block_on_packet_failure() {
        let first = Frame::new(UNIX_EPOCH, LinkType::RAW, vec![7]).unwrap();
        let second = Frame::new(UNIX_EPOCH, LinkType::ETHERNET, vec![8]).unwrap();
        for added in 0..(32 + 36) {
            let mut writer = Writer::pcapng(FailAt {
                bytes: Vec::new(),
                offset: usize::MAX,
            })
            .unwrap();
            writer.write_frame(&first).unwrap();
            let before = writer.get_ref().bytes.len();
            writer.get_mut().offset = before + added;
            assert_eq!(writer.encoded_frame_size(&second).unwrap(), 32 + 36);
            assert!(
                matches!(writer.write_frame(&second), Err(Error::Io(error)) if error.kind() == io::ErrorKind::BrokenPipe)
            );
            assert_eq!(writer.frames_written(), 1);
            assert_eq!(writer.captured_bytes_written(), 1);
            assert_eq!(writer.get_ref().bytes.len(), before + added);
            let WriterState::PcapNg { interfaces, .. } = &writer.state else {
                unreachable!()
            };
            assert_eq!(interfaces.len(), if added < 32 { 1 } else { 2 });
            assert_eq!(interfaces[0].link_type, LinkType::RAW);
            if added >= 32 {
                assert_eq!(interfaces[1].link_type, LinkType::ETHERNET);
            }
            assert!(writer.output_failure.is_some());
        }
    }

    #[derive(Debug)]
    struct Layered(io::Error);

    impl fmt::Display for Layered {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("outer")
        }
    }

    impl std::error::Error for Layered {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            Some(&self.0)
        }
    }

    struct Failing(Option<fn() -> io::Error>);

    impl Write for Failing {
        fn write(&mut self, input: &[u8]) -> io::Result<usize> {
            match self.0 {
                Some(failure) => Err(failure()),
                None => Ok(input.len()),
            }
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn describe(error: &io::Error) -> (io::ErrorKind, Option<i32>, Vec<String>) {
        let mut chain = vec![error.to_string()];
        let mut next = std::error::Error::source(error);
        while let Some(source) = next {
            chain.push(source.to_string());
            next = source.source();
        }
        (error.kind(), error.raw_os_error(), chain)
    }

    #[test]
    fn later_operations_repeat_the_output_failure_kind_os_code_and_message_chain() {
        let failures: [fn() -> io::Error; 3] = [
            || {
                io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    Layered(io::Error::other("inner")),
                )
            },
            || io::Error::from_raw_os_error(28),
            || io::ErrorKind::BrokenPipe.into(),
        ];
        let frame = Frame::new(UNIX_EPOCH, LinkType::ETHERNET, vec![1]).unwrap();
        for failure in failures {
            let expected = describe(&failure());
            let mut writer = Writer::pcap(Failing(None), LinkType::ETHERNET).unwrap();
            writer.get_mut().0 = Some(failure);
            for result in [
                writer.write_frame(&frame).map(|_| ()),
                writer.write_frame(&frame).map(|_| ()),
                writer.flush(),
            ] {
                let Err(Error::Io(error)) = result else {
                    panic!("output failure expected");
                };
                assert_eq!(describe(&error), expected);
            }
        }
    }

    #[test]
    fn oversized_interface_options_report_the_computed_block_length() {
        let mut writer = Writer::pcapng_with_options(
            Vec::new(),
            PcapNgOptions {
                max_size: 40,
                ..PcapNgOptions::default()
            },
        )
        .unwrap();
        let before = writer.get_ref().clone();
        let description = Interface {
            link_type: LinkType::ETHERNET,
            snap_len: 40,
            timestamp_resolution: TimestampResolution::Decimal(6),
            timestamp_offset: 0,
        };
        let options = [
            crate::capture_file::PcapNgOption {
                code: 2,
                value: vec![0; 5].into(),
            },
            crate::capture_file::PcapNgOption {
                code: 3,
                value: vec![0; 3].into(),
            },
        ];
        let error = writer
            .add_interface_description_with_options(description, &options)
            .unwrap_err();
        assert!(
            matches!(
                error,
                Error::SizeLimitExceeded {
                    kind: "interface description",
                    declared: 52,
                    limit: 40,
                }
            ),
            "{error:?}"
        );
        assert_eq!(writer.get_ref(), &before);
    }
}
