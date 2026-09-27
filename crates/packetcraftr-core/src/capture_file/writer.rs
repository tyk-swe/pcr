// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::fmt;
use std::io::{self, Write};
use std::sync::Arc;
use std::time::UNIX_EPOCH;

use crate::frame::{Frame, LinkType};

use super::classic::{write_pcap_frame, write_pcap_header};
use super::error::Error;
use super::model::{
    Budget, DEFAULT_INTERFACE_LIMIT, Endianness, Format, Interface, Limits, PcapNgOptions,
    PcapOptions, TimestampPrecision, TimestampResolution,
};
use super::pcapng::{
    interface_description_base_length, select_interface, validate_new_interface,
    write_enhanced_packet, write_interface_description, write_section_header,
};
use super::wire::{
    PCAP_RECORD_HEADER_LEN, PCAPNG_OPTION_END, PCAPNG_OPTION_IF_TSOFFSET, PCAPNG_OPTION_IF_TSRESOL,
    align_to_u32, timestamp_to_ticks, usize_to_u32_limit, validate_frame_size,
};

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

// A private, destination-free plan: preview and output use exactly the same
// validation and sizes. It owns at most one small interface, never the table or payload.
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

/// A `dyn Error`'s rendered chain, retained for re-reporting: `&dyn Error`
/// cannot be cloned, so the sticky failure keeps each link's message and
/// shape rather than only the outermost string.
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

/// The shared retained payload a re-reported `io::Error` carries, so the
/// same chain backs every later report.
#[derive(Debug)]
struct SharedIo(Arc<dyn std::error::Error + Send + Sync>);

impl fmt::Display for SharedIo {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl std::error::Error for SharedIo {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.0.source()
    }
}

#[derive(Debug)]
struct OutputFailure {
    kind: io::ErrorKind,
    raw_os_error: Option<i32>,
    /// The original payload's retained chain, when the failure carried one.
    /// OS and simple `io::Error`s reproduce exactly from `kind` and
    /// `raw_os_error` and need none.
    source: Option<Arc<dyn std::error::Error + Send + Sync>>,
}

impl OutputFailure {
    fn to_error(&self) -> Error {
        let error = if let Some(code) = self.raw_os_error {
            io::Error::from_raw_os_error(code)
        } else if let Some(source) = &self.source {
            io::Error::new(self.kind, SharedIo(Arc::clone(source)))
        } else {
            self.kind.into()
        };
        Error::Io(error)
    }
}

/// A streaming writer that creates a new capture from frames.
///
/// It emits generated classic packet records or PCAPNG Enhanced Packet Blocks;
/// use [`rewrite`](fn@super::rewrite) when source block structure must be
/// retained.
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
    /// Use [`pcapng`](Self::pcapng) and [`add_interface`](Self::add_interface)
    /// to declare all interfaces explicitly.
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
            DEFAULT_INTERFACE_LIMIT,
            budget,
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

    /// The aggregate ceilings this writer was opened under. They are fixed
    /// at construction: a stream's limits cannot be raised part-way through
    /// the output it already committed.
    pub fn stream_limits(&self) -> Limits {
        self.budget.limits()
    }

    /// Frames committed to the output so far.
    ///
    /// A record refused for any reason — an exhausted budget, a metadata
    /// mismatch, or an output failure — commits neither a frame nor a byte,
    /// and this pair is how a caller observes that.
    pub fn frames_written(&self) -> u64 {
        self.budget.frames()
    }

    pub fn captured_bytes_written(&self) -> u64 {
        self.budget.captured_bytes()
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
        self.add_interface_description_with_options(description, &[])
    }

    /// Adds bounded interface options, excluding the timestamp fields owned by `description`.
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
        // Without custom options, `validate_new_interface` checks the base
        // length along with the rest of the interface metadata.
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

    /// The PCAPNG interface table, or `WrongWriterFormat` on a classic writer.
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
    /// This performs the same validation as `write_frame` without changing this
    /// writer, its counters, or its destination.
    pub fn encoded_frame_size(&self, frame: &Frame) -> Result<usize, Error> {
        Ok(self.prepare_frame(frame)?.encoded_size)
    }

    /// Writes one frame, validating all representability and length invariants
    /// before emitting any bytes for it.
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
                    // The plan already validated this declaration. Commit it after
                    // its own successful output, even if the following packet fails.
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
                let (kind, raw_os_error) = (error.kind(), error.raw_os_error());
                // An `io::Error` payload cannot be cloned: the error returned
                // now keeps it so `get_ref` downcasts and the typed chain stay
                // intact, while the sticky state retains a shareable snapshot
                // of the same chain for every later report.
                let (source, error) = match error.into_inner() {
                    Some(payload) => {
                        let snapshot: Arc<dyn std::error::Error + Send + Sync> =
                            ChainSnapshot::of(&*payload);
                        (Some(snapshot), io::Error::new(kind, payload))
                    }
                    None => (
                        None,
                        match raw_os_error {
                            Some(code) => io::Error::from_raw_os_error(code),
                            None => kind.into(),
                        },
                    ),
                };
                self.output_failure = Some(OutputFailure {
                    kind,
                    raw_os_error,
                    source,
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
        // Every cut in the second IDB or EPB, after an already committed frame.
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
        // The 32-byte base block, plus 4 + 8 and 4 + 4 bytes of padded options.
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
