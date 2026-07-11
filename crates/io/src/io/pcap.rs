// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Pure-Rust, streaming PCAP and PCAPNG support.
//!
//! The implementation deliberately depends only on [`std::io`].  Native
//! libpcap/Npcap is a live-I/O concern and is not required for reading or
//! writing capture files.

use std::fmt;
use std::io::{self, Read, Write};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::error::{ClassifiedError, ErrorClassification, FailureKind};

use super::{CaptureDirection, CapturedFrame, LinkType};

const PCAP_GLOBAL_HEADER_LEN: usize = 24;
const PCAP_RECORD_HEADER_LEN: usize = 16;
const PCAPNG_SECTION_HEADER: [u8; 4] = [0x0a, 0x0d, 0x0d, 0x0a];
const PCAPNG_BYTE_ORDER_MAGIC: u32 = 0x1a2b_3c4d;
const PCAPNG_SECTION_HEADER_BLOCK: u32 = 0x0a0d_0d0a;
const PCAPNG_INTERFACE_DESCRIPTION_BLOCK: u32 = 0x0000_0001;
const PCAPNG_PACKET_BLOCK: u32 = 0x0000_0002;
const PCAPNG_SIMPLE_PACKET_BLOCK: u32 = 0x0000_0003;
const PCAPNG_ENHANCED_PACKET_BLOCK: u32 = 0x0000_0006;
const PCAPNG_OPTION_END: u16 = 0;
const PCAPNG_OPTION_EPB_FLAGS: u16 = 2;
const PCAPNG_OPTION_IF_TSRESOL: u16 = 9;
const PCAPNG_OPTION_IF_TSOFFSET: u16 = 14;
const DEFAULT_TIMESTAMP_RESOLUTION: TimestampResolution = TimestampResolution::Decimal(6);
const WRITER_TIMESTAMP_RESOLUTION: TimestampResolution = TimestampResolution::Decimal(9);

/// Default maximum size of an offline packet or a PCAPNG block (16 MiB).
pub const DEFAULT_CAPTURE_SIZE_LIMIT: usize = 16 * 1024 * 1024;
/// Default maximum number of interface descriptions retained per PCAPNG section.
pub const DEFAULT_PCAPNG_INTERFACE_LIMIT: usize = 4_096;
/// Default maximum metadata blocks consumed before one packet is returned.
pub const DEFAULT_PCAPNG_METADATA_BLOCK_LIMIT: usize = 4_096;
/// Default maximum frames accepted by one streaming capture writer or copy.
pub const DEFAULT_CAPTURE_STREAM_FRAMES: u64 = 10_000;
/// Default maximum captured payload bytes accepted by one streaming writer or copy.
pub const DEFAULT_CAPTURE_STREAM_BYTES: u64 = 256 * 1024 * 1024;

/// Aggregate frame and captured-byte ceilings for a streaming capture operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureStreamLimits {
    pub max_frames: u64,
    pub max_bytes: u64,
}

impl Default for CaptureStreamLimits {
    fn default() -> Self {
        Self {
            max_frames: DEFAULT_CAPTURE_STREAM_FRAMES,
            max_bytes: DEFAULT_CAPTURE_STREAM_BYTES,
        }
    }
}

/// Capture container format.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureFileFormat {
    /// The classic libpcap file format.
    Pcap,
    /// The extensible pcapng file format.
    PcapNg,
}

impl fmt::Display for CaptureFileFormat {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Pcap => "pcap",
            Self::PcapNg => "pcapng",
        })
    }
}

/// Byte order used by a capture file.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PcapEndianness {
    #[default]
    Little,
    Big,
}

/// Timestamp tick resolution declared by classic PCAP or one PCAPNG interface.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureTimestampResolution {
    Decimal(u8),
    Binary(u8),
}

type TimestampResolution = CaptureTimestampResolution;

/// Metadata associated with one capture interface.
///
/// The index in [`CaptureReader::interfaces`] is the global interface ID used
/// by [`CapturedFrame::interface`]. Multiple PCAPNG sections are normalized to
/// one monotonically increasing namespace.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureInterface {
    pub link_type: LinkType,
    pub snap_len: u32,
    pub timestamp_resolution: CaptureTimestampResolution,
    pub timestamp_offset: i64,
}

/// Result of a bounded streaming capture copy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureTranscodeReport {
    pub source_format: CaptureFileFormat,
    pub target_format: CaptureFileFormat,
    pub endianness: PcapEndianness,
    pub frames: u64,
    pub captured_bytes: u64,
    pub interfaces: usize,
}

/// Timing policy used when replaying captured frames.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum ReplayTiming {
    /// Preserve the inter-frame timing in the capture.
    Original,
    /// Multiply each captured inter-frame delay by this positive factor.
    Scaled(f64),
    /// Emit frames at this positive number of frames per second.
    FixedRate(f64),
    /// Emit frames without intentional delays.
    Immediate,
}

impl ReplayTiming {
    /// Validates any numeric replay timing parameter before frames are read.
    pub fn validate(self) -> Result<Self, CaptureError> {
        match self {
            Self::Scaled(value) if !value.is_finite() || value <= 0.0 => {
                Err(CaptureError::InvalidReplayTiming {
                    mode: "scaled",
                    value,
                })
            }
            Self::FixedRate(value) if !value.is_finite() || value <= 0.0 => {
                Err(CaptureError::InvalidReplayTiming {
                    mode: "fixed_rate",
                    value,
                })
            }
            timing => Ok(timing),
        }
    }

    /// Calculates the delay before a frame under this timing policy.
    ///
    /// Captures are allowed to contain non-monotonic timestamps.  Such a
    /// timestamp produces a zero original delay instead of wrapping.
    pub fn delay_between(
        self,
        previous: SystemTime,
        current: SystemTime,
    ) -> Result<Duration, CaptureError> {
        self.validate()?;
        let original = current.duration_since(previous).unwrap_or(Duration::ZERO);
        match self {
            Self::Original => Ok(original),
            Self::Scaled(factor) if factor.is_finite() && factor > 0.0 => {
                Duration::try_from_secs_f64(original.as_secs_f64() * factor).map_err(|_| {
                    CaptureError::InvalidReplayTiming {
                        mode: "scaled",
                        value: factor,
                    }
                })
            }
            Self::FixedRate(rate) if rate.is_finite() && rate > 0.0 => {
                Duration::try_from_secs_f64(1.0 / rate).map_err(|_| {
                    CaptureError::InvalidReplayTiming {
                        mode: "fixed_rate",
                        value: rate,
                    }
                })
            }
            Self::Immediate => Ok(Duration::ZERO),
            Self::Scaled(value) => Err(CaptureError::InvalidReplayTiming {
                mode: "scaled",
                value,
            }),
            Self::FixedRate(value) => Err(CaptureError::InvalidReplayTiming {
                mode: "fixed_rate",
                value,
            }),
        }
    }
}

/// An error while reading or writing an offline capture.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CaptureError {
    #[error("capture I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("capture input is empty")]
    EmptyInput,
    #[error("unrecognized capture magic {magic:02x?}")]
    UnrecognizedFormat { magic: [u8; 4] },
    #[error("truncated {context}: expected {expected} bytes, found {actual}")]
    Truncated {
        context: &'static str,
        expected: usize,
        actual: usize,
    },
    #[error("unsupported {format} version {major}.{minor}")]
    UnsupportedVersion {
        format: CaptureFileFormat,
        major: u16,
        minor: u16,
    },
    #[error("invalid {format} data: {reason}")]
    InvalidData {
        format: CaptureFileFormat,
        reason: &'static str,
    },
    #[error("{kind} declares {declared} bytes, exceeding the configured limit of {limit}")]
    SizeLimitExceeded {
        kind: &'static str,
        declared: u64,
        limit: usize,
    },
    #[error("pcapng block has invalid length {length}")]
    InvalidBlockLength { length: u32 },
    #[error("pcapng block length footer {trailing} does not match header {leading}")]
    BlockLengthMismatch { leading: u32, trailing: u32 },
    #[error("frame captured length says {declared} bytes but contains {actual}")]
    CapturedLengthMismatch { declared: u32, actual: usize },
    #[error("frame original length {original} is smaller than captured length {captured}")]
    OriginalLengthTooSmall { captured: u32, original: u32 },
    #[error("timestamp cannot be represented in {format}")]
    TimestampOutOfRange { format: CaptureFileFormat },
    #[error("timestamp fraction {fraction} is invalid for a denominator of {denominator}")]
    InvalidTimestampFraction { fraction: u32, denominator: u32 },
    #[error("link type {link_type} cannot be represented in pcapng")]
    LinkTypeOutOfRange { link_type: u32 },
    #[error("interface {interface} is not defined (the section has {available} interfaces)")]
    UndefinedInterface { interface: u32, available: usize },
    #[error("pcapng section exceeds the configured interface limit of {limit}")]
    InterfaceLimit { limit: usize },
    #[error("pcapng stream exceeded {limit} metadata blocks before the next packet")]
    MetadataBlockLimit { limit: usize },
    #[error("frame link type {actual} does not match interface {interface} link type {expected}")]
    InterfaceLinkTypeMismatch {
        interface: u32,
        expected: u32,
        actual: u32,
    },
    #[error("no pcapng interface is registered for link type {link_type}")]
    NoInterfaceForLinkType { link_type: u32 },
    #[error("more than one pcapng interface uses link type {link_type}; select one explicitly")]
    AmbiguousInterface { link_type: u32 },
    #[error("{field} metadata cannot be represented in {format}")]
    MetadataNotRepresentable {
        format: CaptureFileFormat,
        field: &'static str,
    },
    #[error("this operation requires {expected}, but the writer is configured for {actual}")]
    WrongWriterFormat {
        expected: CaptureFileFormat,
        actual: CaptureFileFormat,
    },
    #[error("invalid replay {mode} value {value}")]
    InvalidReplayTiming { mode: &'static str, value: f64 },
    #[error("capture stream frame count {actual} exceeds the configured limit of {limit}")]
    FrameLimitExceeded { actual: u64, limit: u64 },
    #[error("capture stream payload bytes {actual} exceed the configured limit of {limit}")]
    StreamByteLimitExceeded { actual: u64, limit: u64 },
    #[error("capture timestamp resolution {base}^{exponent} cannot be represented")]
    InvalidTimestampResolution { base: u8, exponent: u8 },
}

impl ClassifiedError for CaptureError {
    fn classification(&self) -> ErrorClassification {
        match self {
            Self::Io(_) => ErrorClassification::new(
                "io.capture_file",
                FailureKind::Io,
                Some("inspect the capture input/output stream and retry from a known record boundary"),
            ),
            Self::InvalidReplayTiming { .. } | Self::InvalidTimestampResolution { .. } => {
                ErrorClassification::new(
                    "cli.capture_option",
                    FailureKind::Cli,
                    Some("use a supported finite capture timestamp or replay timing option"),
                )
            }
            Self::FrameLimitExceeded { .. } | Self::StreamByteLimitExceeded { .. } => {
                ErrorClassification::new(
                    "policy.capture_stream_limit",
                    FailureKind::Policy,
                    Some("reduce the capture stream or deliberately raise its finite frame/byte budget"),
                )
            }
            _ => ErrorClassification::new(
                "packet.capture_file",
                FailureKind::Packet,
                Some("repair the malformed or unrepresentable capture record before processing it"),
            ),
        }
    }

    fn causes(&self) -> Vec<String> {
        match self {
            Self::Io(source) => vec![source.to_string()],
            _ => Vec::new(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PcapTimestampPrecision {
    Microseconds,
    Nanoseconds,
}

type InterfaceDescription = CaptureInterface;

enum ReaderState {
    Pcap {
        endianness: PcapEndianness,
        precision: PcapTimestampPrecision,
        snap_len: u32,
        link_type: LinkType,
    },
    PcapNg {
        endianness: PcapEndianness,
        interfaces: Vec<InterfaceDescription>,
        interface_base: u32,
    },
}

/// A streaming capture reader over any [`Read`] implementation.
///
/// Construction consumes only the container header.  Each call to
/// [`next_frame`](Self::next_frame) then reads at most one packet plus any
/// intervening metadata blocks.
pub struct CaptureReader<R> {
    inner: R,
    state: ReaderState,
    interfaces: Vec<CaptureInterface>,
    max_size: usize,
    max_interfaces: usize,
    max_metadata_blocks_per_frame: usize,
    finished: bool,
}

impl<R: Read> CaptureReader<R> {
    /// Opens a capture with the default 16 MiB packet/block limit.
    pub fn new(inner: R) -> Result<Self, CaptureError> {
        Self::with_limit(inner, DEFAULT_CAPTURE_SIZE_LIMIT)
    }

    /// Opens a capture with a caller-provided packet/block size limit.
    pub fn with_limit(inner: R, max_size: usize) -> Result<Self, CaptureError> {
        Self::with_limits(inner, max_size, DEFAULT_PCAPNG_INTERFACE_LIMIT)
    }

    /// Opens a capture with caller-provided packet/block and interface limits.
    pub fn with_limits(
        inner: R,
        max_size: usize,
        max_interfaces: usize,
    ) -> Result<Self, CaptureError> {
        Self::with_resource_limits(
            inner,
            max_size,
            max_interfaces,
            DEFAULT_PCAPNG_METADATA_BLOCK_LIMIT,
        )
    }

    pub fn with_resource_limits(
        mut inner: R,
        max_size: usize,
        max_interfaces: usize,
        max_metadata_blocks_per_frame: usize,
    ) -> Result<Self, CaptureError> {
        let mut magic = [0_u8; 4];
        if !read_exact_or_eof(&mut inner, &mut magic, "capture magic")? {
            return Err(CaptureError::EmptyInput);
        }

        let state = match magic {
            [0xd4, 0xc3, 0xb2, 0xa1] => read_pcap_header(
                &mut inner,
                PcapEndianness::Little,
                PcapTimestampPrecision::Microseconds,
            )?,
            [0xa1, 0xb2, 0xc3, 0xd4] => read_pcap_header(
                &mut inner,
                PcapEndianness::Big,
                PcapTimestampPrecision::Microseconds,
            )?,
            [0x4d, 0x3c, 0xb2, 0xa1] => read_pcap_header(
                &mut inner,
                PcapEndianness::Little,
                PcapTimestampPrecision::Nanoseconds,
            )?,
            [0xa1, 0xb2, 0x3c, 0x4d] => read_pcap_header(
                &mut inner,
                PcapEndianness::Big,
                PcapTimestampPrecision::Nanoseconds,
            )?,
            PCAPNG_SECTION_HEADER => {
                let endianness = read_section_header_after_type(&mut inner, max_size)?;
                ReaderState::PcapNg {
                    endianness,
                    interfaces: Vec::new(),
                    interface_base: 0,
                }
            }
            magic => return Err(CaptureError::UnrecognizedFormat { magic }),
        };

        let interfaces = match &state {
            ReaderState::Pcap {
                precision,
                snap_len,
                link_type,
                ..
            } => vec![CaptureInterface {
                link_type: *link_type,
                snap_len: *snap_len,
                timestamp_resolution: match precision {
                    PcapTimestampPrecision::Microseconds => CaptureTimestampResolution::Decimal(6),
                    PcapTimestampPrecision::Nanoseconds => CaptureTimestampResolution::Decimal(9),
                },
                timestamp_offset: 0,
            }],
            ReaderState::PcapNg { .. } => Vec::new(),
        };

        Ok(Self {
            inner,
            state,
            interfaces,
            max_size,
            max_interfaces,
            max_metadata_blocks_per_frame,
            finished: false,
        })
    }

    /// Returns the detected capture format.
    pub fn format(&self) -> CaptureFileFormat {
        match self.state {
            ReaderState::Pcap { .. } => CaptureFileFormat::Pcap,
            ReaderState::PcapNg { .. } => CaptureFileFormat::PcapNg,
        }
    }

    /// Returns the capture byte order.
    pub fn endianness(&self) -> PcapEndianness {
        match self.state {
            ReaderState::Pcap { endianness, .. } | ReaderState::PcapNg { endianness, .. } => {
                endianness
            }
        }
    }

    /// Returns the configured packet/block limit.
    pub fn size_limit(&self) -> usize {
        self.max_size
    }

    /// Interface metadata parsed so far.
    ///
    /// Classic PCAP exposes its single global interface immediately. PCAPNG
    /// descriptions are appended while [`next_frame`](Self::next_frame)
    /// advances the stream, before any frame that references them is returned.
    pub fn interfaces(&self) -> &[CaptureInterface] {
        &self.interfaces
    }

    /// Reads the next frame, or `None` after a clean end of file.
    pub fn next_frame(&mut self) -> Result<Option<CapturedFrame>, CaptureError> {
        if self.finished {
            return Ok(None);
        }

        let result = match &mut self.state {
            ReaderState::Pcap {
                endianness,
                precision,
                snap_len,
                link_type,
            } => read_next_pcap_frame(
                &mut self.inner,
                *endianness,
                *precision,
                *snap_len,
                *link_type,
                self.max_size,
            ),
            ReaderState::PcapNg { .. } => self.next_pcapng_frame(),
        };

        match result {
            Ok(result) => {
                if result.is_none() {
                    self.finished = true;
                }
                Ok(result)
            }
            Err(error) => {
                self.finished = true;
                Err(error)
            }
        }
    }

    /// Alias for [`next_frame`](Self::next_frame).
    pub fn read_frame(&mut self) -> Result<Option<CapturedFrame>, CaptureError> {
        self.next_frame()
    }

    fn next_pcapng_frame(&mut self) -> Result<Option<CapturedFrame>, CaptureError> {
        let mut metadata_blocks = 0usize;
        loop {
            let (endianness, interfaces, interface_base) = match &self.state {
                ReaderState::PcapNg {
                    endianness,
                    interfaces,
                    interface_base,
                } => (*endianness, interfaces, *interface_base),
                ReaderState::Pcap { .. } => unreachable!("state checked by caller"),
            };

            let Some(raw_header) = read_pcapng_block_header(&mut self.inner)? else {
                return Ok(None);
            };

            if raw_header[..4] == PCAPNG_SECTION_HEADER {
                metadata_blocks = metadata_blocks.saturating_add(1);
                if metadata_blocks > self.max_metadata_blocks_per_frame {
                    return Err(CaptureError::MetadataBlockLimit {
                        limit: self.max_metadata_blocks_per_frame,
                    });
                }
                let new_endianness = read_section_header_with_length(
                    &mut self.inner,
                    raw_header[4..8].try_into().expect("four-byte slice"),
                    self.max_size,
                )?;
                match &mut self.state {
                    ReaderState::PcapNg {
                        endianness,
                        interfaces,
                        interface_base,
                    } => {
                        *interface_base = interface_base
                            .checked_add(u32::try_from(interfaces.len()).map_err(|_| {
                                CaptureError::InterfaceLimit {
                                    limit: self.max_interfaces,
                                }
                            })?)
                            .ok_or(CaptureError::InterfaceLimit {
                                limit: self.max_interfaces,
                            })?;
                        *endianness = new_endianness;
                        interfaces.clear();
                    }
                    ReaderState::Pcap { .. } => unreachable!("state checked by caller"),
                }
                continue;
            }

            let block_type = decode_u32(endianness, &raw_header[..4]);
            let block_length = decode_u32(endianness, &raw_header[4..8]);
            validate_pcapng_block_length(block_length, self.max_size)?;
            let remaining =
                usize::try_from(block_length).map_err(|_| CaptureError::InvalidBlockLength {
                    length: block_length,
                })? - 8;
            let mut block = vec![0_u8; remaining];
            read_exact_counted(&mut self.inner, &mut block, "pcapng block")?;

            let body_length = block.len() - 4;
            let trailing_length = decode_u32(endianness, &block[body_length..]);
            if trailing_length != block_length {
                return Err(CaptureError::BlockLengthMismatch {
                    leading: block_length,
                    trailing: trailing_length,
                });
            }
            let body = &block[..body_length];

            if !matches!(
                block_type,
                PCAPNG_ENHANCED_PACKET_BLOCK | PCAPNG_PACKET_BLOCK | PCAPNG_SIMPLE_PACKET_BLOCK
            ) {
                metadata_blocks = metadata_blocks.saturating_add(1);
                if metadata_blocks > self.max_metadata_blocks_per_frame {
                    return Err(CaptureError::MetadataBlockLimit {
                        limit: self.max_metadata_blocks_per_frame,
                    });
                }
            }

            match block_type {
                PCAPNG_INTERFACE_DESCRIPTION_BLOCK => {
                    let description = parse_interface_description(body, endianness)?;
                    match &mut self.state {
                        ReaderState::PcapNg {
                            interfaces,
                            interface_base,
                            ..
                        } => {
                            if (*interface_base as usize)
                                .checked_add(interfaces.len())
                                .is_none_or(|count| count >= self.max_interfaces)
                            {
                                return Err(CaptureError::InterfaceLimit {
                                    limit: self.max_interfaces,
                                });
                            }
                            interfaces.push(description);
                            self.interfaces.push(description);
                        }
                        ReaderState::Pcap { .. } => unreachable!("state checked by caller"),
                    }
                }
                PCAPNG_ENHANCED_PACKET_BLOCK => {
                    return parse_enhanced_packet(
                        body,
                        endianness,
                        interfaces,
                        interface_base,
                        self.max_size,
                    )
                    .map(Some);
                }
                PCAPNG_PACKET_BLOCK => {
                    return parse_obsolete_packet(
                        body,
                        endianness,
                        interfaces,
                        interface_base,
                        self.max_size,
                    )
                    .map(Some);
                }
                PCAPNG_SIMPLE_PACKET_BLOCK => {
                    return parse_simple_packet(
                        body,
                        endianness,
                        interfaces,
                        interface_base,
                        self.max_size,
                    )
                    .map(Some);
                }
                _ => {
                    // Metadata and extension blocks are length-delimited, so an
                    // unknown block can be skipped without guessing its layout.
                }
            }
        }
    }

    pub fn get_ref(&self) -> &R {
        &self.inner
    }

    pub fn get_mut(&mut self) -> &mut R {
        &mut self.inner
    }

    pub fn into_inner(self) -> R {
        self.inner
    }
}

impl<R: Read> Iterator for CaptureReader<R> {
    type Item = Result<CapturedFrame, CaptureError>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.next_frame() {
            Ok(Some(frame)) => Some(Ok(frame)),
            Ok(None) => None,
            Err(error) => {
                self.finished = true;
                Some(Err(error))
            }
        }
    }
}

enum WriterState {
    Pcap {
        endianness: PcapEndianness,
        precision: PcapTimestampPrecision,
        snap_len: u32,
        link_type: LinkType,
    },
    PcapNg {
        endianness: PcapEndianness,
        interfaces: Vec<InterfaceDescription>,
    },
}

/// A streaming capture writer over any [`Write`] implementation.
pub struct CaptureWriter<W> {
    inner: W,
    state: WriterState,
    max_size: usize,
    max_interfaces: usize,
    stream_limits: CaptureStreamLimits,
    frames_written: u64,
    captured_bytes_written: u64,
}

impl<W: Write> CaptureWriter<W> {
    /// Creates a writer with a default interface and the 16 MiB size limit.
    ///
    /// A PCAPNG writer created this way starts with interface zero.  Use
    /// [`pcapng`](Self::pcapng) followed by [`add_interface`](Self::add_interface)
    /// when all interface descriptions need to be declared explicitly.
    pub fn new(
        inner: W,
        format: CaptureFileFormat,
        link_type: LinkType,
    ) -> Result<Self, CaptureError> {
        Self::with_limit(inner, format, link_type, DEFAULT_CAPTURE_SIZE_LIMIT)
    }

    /// Creates a writer with a default interface and a caller-provided limit.
    pub fn with_limit(
        inner: W,
        format: CaptureFileFormat,
        link_type: LinkType,
        max_size: usize,
    ) -> Result<Self, CaptureError> {
        Self::with_limits(
            inner,
            format,
            link_type,
            max_size,
            DEFAULT_PCAPNG_INTERFACE_LIMIT,
        )
    }

    /// Creates a writer with caller-provided packet/block and PCAPNG
    /// interface limits.
    pub fn with_limits(
        inner: W,
        format: CaptureFileFormat,
        link_type: LinkType,
        max_size: usize,
        max_interfaces: usize,
    ) -> Result<Self, CaptureError> {
        match format {
            CaptureFileFormat::Pcap => Self::pcap_with_options(
                inner,
                link_type,
                PcapEndianness::Little,
                max_size,
                max_size,
            ),
            CaptureFileFormat::PcapNg => {
                let mut writer = Self::pcapng_with_resource_limits(
                    inner,
                    PcapEndianness::Little,
                    max_size,
                    max_interfaces,
                )?;
                writer.add_interface_with_snaplen(link_type, usize_to_u32_limit(max_size)?)?;
                Ok(writer)
            }
        }
    }

    /// Creates a little-endian, nanosecond-resolution classic PCAP writer.
    pub fn pcap(inner: W, link_type: LinkType) -> Result<Self, CaptureError> {
        Self::pcap_with_endianness(inner, link_type, PcapEndianness::Little)
    }

    /// Creates a nanosecond-resolution classic PCAP writer.
    pub fn pcap_with_endianness(
        inner: W,
        link_type: LinkType,
        endianness: PcapEndianness,
    ) -> Result<Self, CaptureError> {
        Self::pcap_with_options(
            inner,
            link_type,
            endianness,
            DEFAULT_CAPTURE_SIZE_LIMIT,
            DEFAULT_CAPTURE_SIZE_LIMIT,
        )
    }

    /// Creates a classic PCAP writer with explicit byte order, snap length,
    /// and packet limit.
    pub fn pcap_with_options(
        inner: W,
        link_type: LinkType,
        endianness: PcapEndianness,
        snap_len: usize,
        max_size: usize,
    ) -> Result<Self, CaptureError> {
        Self::pcap_with_metadata(
            inner,
            link_type,
            endianness,
            CaptureTimestampResolution::Decimal(9),
            snap_len,
            max_size,
        )
    }

    /// Creates a classic PCAP writer with explicit byte order, timestamp
    /// resolution, snap length, and packet limit.
    pub fn pcap_with_metadata(
        mut inner: W,
        link_type: LinkType,
        endianness: PcapEndianness,
        timestamp_resolution: CaptureTimestampResolution,
        snap_len: usize,
        max_size: usize,
    ) -> Result<Self, CaptureError> {
        if link_type.0 > u16::MAX as u32 {
            return Err(CaptureError::LinkTypeOutOfRange {
                link_type: link_type.0,
            });
        }
        let precision = match timestamp_resolution {
            CaptureTimestampResolution::Decimal(6) => PcapTimestampPrecision::Microseconds,
            CaptureTimestampResolution::Decimal(9) => PcapTimestampPrecision::Nanoseconds,
            CaptureTimestampResolution::Decimal(exponent) => {
                return Err(CaptureError::InvalidTimestampResolution { base: 10, exponent })
            }
            CaptureTimestampResolution::Binary(exponent) => {
                return Err(CaptureError::InvalidTimestampResolution { base: 2, exponent })
            }
        };
        let snap_len = usize_to_u32_limit(snap_len)?;
        write_pcap_header(&mut inner, endianness, precision, snap_len, link_type)?;
        Ok(Self {
            inner,
            state: WriterState::Pcap {
                endianness,
                precision,
                snap_len,
                link_type,
            },
            max_size,
            max_interfaces: DEFAULT_PCAPNG_INTERFACE_LIMIT,
            stream_limits: CaptureStreamLimits::default(),
            frames_written: 0,
            captured_bytes_written: 0,
        })
    }

    /// Creates a little-endian PCAPNG writer without an interface block.
    pub fn pcapng(inner: W) -> Result<Self, CaptureError> {
        Self::pcapng_with_endianness(inner, PcapEndianness::Little)
    }

    /// Creates a PCAPNG writer without an interface block.
    pub fn pcapng_with_endianness(
        inner: W,
        endianness: PcapEndianness,
    ) -> Result<Self, CaptureError> {
        Self::pcapng_with_options(inner, endianness, DEFAULT_CAPTURE_SIZE_LIMIT)
    }

    /// Creates a PCAPNG writer with explicit byte order and block limit.
    pub fn pcapng_with_options(
        inner: W,
        endianness: PcapEndianness,
        max_size: usize,
    ) -> Result<Self, CaptureError> {
        Self::pcapng_with_resource_limits(
            inner,
            endianness,
            max_size,
            DEFAULT_PCAPNG_INTERFACE_LIMIT,
        )
    }

    /// Creates a PCAPNG writer with explicit byte-order, block-size, and
    /// per-stream interface limits.
    pub fn pcapng_with_resource_limits(
        mut inner: W,
        endianness: PcapEndianness,
        max_size: usize,
        max_interfaces: usize,
    ) -> Result<Self, CaptureError> {
        if max_size < 28 {
            return Err(CaptureError::SizeLimitExceeded {
                kind: "pcapng section header",
                declared: 28,
                limit: max_size,
            });
        }
        write_section_header(&mut inner, endianness)?;
        Ok(Self {
            inner,
            state: WriterState::PcapNg {
                endianness,
                interfaces: Vec::new(),
            },
            max_size,
            max_interfaces,
            stream_limits: CaptureStreamLimits::default(),
            frames_written: 0,
            captured_bytes_written: 0,
        })
    }

    pub fn format(&self) -> CaptureFileFormat {
        match self.state {
            WriterState::Pcap { .. } => CaptureFileFormat::Pcap,
            WriterState::PcapNg { .. } => CaptureFileFormat::PcapNg,
        }
    }

    pub fn endianness(&self) -> PcapEndianness {
        match self.state {
            WriterState::Pcap { endianness, .. } | WriterState::PcapNg { endianness, .. } => {
                endianness
            }
        }
    }

    pub fn size_limit(&self) -> usize {
        self.max_size
    }

    /// Returns the configured PCAPNG interface limit.
    pub fn interface_limit(&self) -> usize {
        self.max_interfaces
    }

    /// Applies aggregate frame and captured-payload limits to future writes.
    ///
    /// Lowering a limit below already committed output is rejected without
    /// changing the writer configuration.
    pub fn set_stream_limits(&mut self, limits: CaptureStreamLimits) -> Result<(), CaptureError> {
        if self.frames_written > limits.max_frames {
            return Err(CaptureError::FrameLimitExceeded {
                actual: self.frames_written,
                limit: limits.max_frames,
            });
        }
        if self.captured_bytes_written > limits.max_bytes {
            return Err(CaptureError::StreamByteLimitExceeded {
                actual: self.captured_bytes_written,
                limit: limits.max_bytes,
            });
        }
        self.stream_limits = limits;
        Ok(())
    }

    pub fn stream_limits(&self) -> CaptureStreamLimits {
        self.stream_limits
    }

    pub fn frames_written(&self) -> u64 {
        self.frames_written
    }

    pub fn captured_bytes_written(&self) -> u64 {
        self.captured_bytes_written
    }

    /// Adds a PCAPNG interface using the writer's configured size limit as
    /// its snap length and returns its numeric interface ID.
    pub fn add_interface(&mut self, link_type: LinkType) -> Result<u32, CaptureError> {
        let snap_len = usize_to_u32_limit(self.max_size)?;
        self.add_interface_with_snaplen(link_type, snap_len)
    }

    /// Adds a PCAPNG interface with a signed timestamp offset in seconds.
    ///
    /// PCAPNG packet timestamps are unsigned counters relative to the
    /// interface's `if_tsoffset`.  Choose an offset no later than the earliest
    /// frame that will use this interface to represent pre-Unix-epoch times.
    /// An offset of zero produces the same interface block as
    /// [`add_interface`](Self::add_interface).
    pub fn add_interface_with_timestamp_offset(
        &mut self,
        link_type: LinkType,
        timestamp_offset: i64,
    ) -> Result<u32, CaptureError> {
        let snap_len = usize_to_u32_limit(self.max_size)?;
        self.add_interface_with_snaplen_and_timestamp_offset(link_type, snap_len, timestamp_offset)
    }

    /// Adds a PCAPNG interface with an explicit snap length.
    pub fn add_interface_with_snaplen(
        &mut self,
        link_type: LinkType,
        snap_len: u32,
    ) -> Result<u32, CaptureError> {
        self.add_interface_with_snaplen_and_timestamp_offset(link_type, snap_len, 0)
    }

    /// Adds a PCAPNG interface with an explicit snap length and signed
    /// timestamp offset in seconds.
    pub fn add_interface_with_snaplen_and_timestamp_offset(
        &mut self,
        link_type: LinkType,
        snap_len: u32,
        timestamp_offset: i64,
    ) -> Result<u32, CaptureError> {
        self.add_interface_description(CaptureInterface {
            link_type,
            snap_len,
            timestamp_resolution: WRITER_TIMESTAMP_RESOLUTION,
            timestamp_offset,
        })
    }

    /// Adds one PCAPNG interface while retaining its timestamp metadata.
    pub fn add_interface_description(
        &mut self,
        description: CaptureInterface,
    ) -> Result<u32, CaptureError> {
        validate_timestamp_resolution(description.timestamp_resolution)?;
        let block_length = if description.timestamp_offset == 0 {
            32
        } else {
            44
        };
        if self.max_size < block_length {
            return Err(CaptureError::SizeLimitExceeded {
                kind: "pcapng interface description",
                declared: block_length as u64,
                limit: self.max_size,
            });
        }
        let (endianness, interface_id) = match &self.state {
            WriterState::Pcap { .. } => {
                return Err(CaptureError::WrongWriterFormat {
                    expected: CaptureFileFormat::PcapNg,
                    actual: CaptureFileFormat::Pcap,
                });
            }
            WriterState::PcapNg {
                endianness,
                interfaces,
            } => {
                let next_count =
                    interfaces
                        .len()
                        .checked_add(1)
                        .ok_or(CaptureError::InterfaceLimit {
                            limit: self.max_interfaces,
                        })?;
                if next_count > self.max_interfaces {
                    return Err(CaptureError::InterfaceLimit {
                        limit: self.max_interfaces,
                    });
                }
                (
                    *endianness,
                    u32::try_from(interfaces.len()).map_err(|_| CaptureError::InterfaceLimit {
                        limit: self.max_interfaces.min(u32::MAX as usize),
                    })?,
                )
            }
        };

        if description.link_type.0 > u16::MAX as u32 {
            return Err(CaptureError::LinkTypeOutOfRange {
                link_type: description.link_type.0,
            });
        }
        if description.snap_len as usize > self.max_size {
            return Err(CaptureError::SizeLimitExceeded {
                kind: "pcapng interface snap length",
                declared: u64::from(description.snap_len),
                limit: self.max_size,
            });
        }

        write_interface_description(
            &mut self.inner,
            endianness,
            description.link_type,
            description.snap_len,
            description.timestamp_resolution,
            description.timestamp_offset,
        )?;
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
    pub fn write_frame(&mut self, frame: &CapturedFrame) -> Result<(), CaptureError> {
        validate_frame_lengths(frame, self.max_size)?;

        let next_frames =
            self.frames_written
                .checked_add(1)
                .ok_or(CaptureError::FrameLimitExceeded {
                    actual: u64::MAX,
                    limit: self.stream_limits.max_frames,
                })?;
        if next_frames > self.stream_limits.max_frames {
            return Err(CaptureError::FrameLimitExceeded {
                actual: next_frames,
                limit: self.stream_limits.max_frames,
            });
        }
        let next_bytes = self
            .captured_bytes_written
            .checked_add(u64::from(frame.captured_length))
            .ok_or(CaptureError::StreamByteLimitExceeded {
                actual: u64::MAX,
                limit: self.stream_limits.max_bytes,
            })?;
        if next_bytes > self.stream_limits.max_bytes {
            return Err(CaptureError::StreamByteLimitExceeded {
                actual: next_bytes,
                limit: self.stream_limits.max_bytes,
            });
        }

        match &self.state {
            WriterState::Pcap {
                endianness,
                precision,
                snap_len,
                link_type,
            } => {
                let endianness = *endianness;
                let precision = *precision;
                let snap_len = *snap_len;
                let link_type = *link_type;
                self.write_pcap_frame(frame, endianness, precision, snap_len, link_type)
            }
            WriterState::PcapNg { .. } => self.write_pcapng_frame(frame),
        }?;
        self.frames_written = next_frames;
        self.captured_bytes_written = next_bytes;
        Ok(())
    }

    /// Alias for [`write_frame`](Self::write_frame).
    pub fn write(&mut self, frame: &CapturedFrame) -> Result<(), CaptureError> {
        self.write_frame(frame)
    }

    fn write_pcap_frame(
        &mut self,
        frame: &CapturedFrame,
        endianness: PcapEndianness,
        precision: PcapTimestampPrecision,
        snap_len: u32,
        link_type: LinkType,
    ) -> Result<(), CaptureError> {
        if frame.interface.is_some() {
            return Err(CaptureError::MetadataNotRepresentable {
                format: CaptureFileFormat::Pcap,
                field: "interface",
            });
        }
        if frame.direction.is_some() {
            return Err(CaptureError::MetadataNotRepresentable {
                format: CaptureFileFormat::Pcap,
                field: "direction",
            });
        }
        if frame.link_type != link_type {
            return Err(CaptureError::InterfaceLinkTypeMismatch {
                interface: 0,
                expected: link_type.0,
                actual: frame.link_type.0,
            });
        }
        if snap_len != 0 && frame.captured_length > snap_len {
            return Err(CaptureError::SizeLimitExceeded {
                kind: "pcap captured packet",
                declared: u64::from(frame.captured_length),
                limit: snap_len as usize,
            });
        }

        let elapsed = frame.timestamp.duration_since(UNIX_EPOCH).map_err(|_| {
            CaptureError::TimestampOutOfRange {
                format: CaptureFileFormat::Pcap,
            }
        })?;
        let seconds =
            u32::try_from(elapsed.as_secs()).map_err(|_| CaptureError::TimestampOutOfRange {
                format: CaptureFileFormat::Pcap,
            })?;

        let fraction = match precision {
            PcapTimestampPrecision::Microseconds
                if !elapsed.subsec_nanos().is_multiple_of(1_000) =>
            {
                return Err(CaptureError::MetadataNotRepresentable {
                    format: CaptureFileFormat::Pcap,
                    field: "microsecond timestamp precision",
                });
            }
            PcapTimestampPrecision::Microseconds => elapsed.subsec_micros(),
            PcapTimestampPrecision::Nanoseconds => elapsed.subsec_nanos(),
        };

        write_u32(&mut self.inner, endianness, seconds)?;
        write_u32(&mut self.inner, endianness, fraction)?;
        write_u32(&mut self.inner, endianness, frame.captured_length)?;
        write_u32(&mut self.inner, endianness, frame.original_length)?;
        self.inner.write_all(&frame.bytes)?;
        Ok(())
    }

    fn write_pcapng_frame(&mut self, frame: &CapturedFrame) -> Result<(), CaptureError> {
        let interface_id = self.select_interface(frame)?;
        let (endianness, interface) = match &self.state {
            WriterState::PcapNg {
                endianness,
                interfaces,
            } => (*endianness, interfaces[interface_id as usize]),
            WriterState::Pcap { .. } => unreachable!("format checked by caller"),
        };

        if interface.snap_len != 0 && frame.captured_length > interface.snap_len {
            return Err(CaptureError::SizeLimitExceeded {
                kind: "pcapng captured packet",
                declared: u64::from(frame.captured_length),
                limit: interface.snap_len as usize,
            });
        }

        let timestamp = timestamp_to_ticks(
            frame.timestamp,
            interface.timestamp_resolution,
            interface.timestamp_offset,
        )?;
        let padded_packet_length = align_to_u32(frame.captured_length)?;
        let option_length = if frame.direction.is_some() { 12_u32 } else { 0 };
        let block_length = 32_u32
            .checked_add(padded_packet_length)
            .and_then(|length| length.checked_add(option_length))
            .ok_or(CaptureError::InvalidBlockLength { length: u32::MAX })?;
        if block_length as usize > self.max_size {
            return Err(CaptureError::SizeLimitExceeded {
                kind: "pcapng enhanced packet block",
                declared: u64::from(block_length),
                limit: self.max_size,
            });
        }

        write_u32(&mut self.inner, endianness, PCAPNG_ENHANCED_PACKET_BLOCK)?;
        write_u32(&mut self.inner, endianness, block_length)?;
        write_u32(&mut self.inner, endianness, interface_id)?;
        write_u32(&mut self.inner, endianness, (timestamp >> 32) as u32)?;
        write_u32(&mut self.inner, endianness, timestamp as u32)?;
        write_u32(&mut self.inner, endianness, frame.captured_length)?;
        write_u32(&mut self.inner, endianness, frame.original_length)?;
        self.inner.write_all(&frame.bytes)?;
        write_padding(&mut self.inner, frame.captured_length)?;

        if let Some(direction) = frame.direction {
            write_u16(&mut self.inner, endianness, PCAPNG_OPTION_EPB_FLAGS)?;
            write_u16(&mut self.inner, endianness, 4)?;
            let flags = match direction {
                CaptureDirection::Unknown => 0,
                CaptureDirection::Inbound => 1,
                CaptureDirection::Outbound => 2,
            };
            write_u32(&mut self.inner, endianness, flags)?;
            write_u16(&mut self.inner, endianness, PCAPNG_OPTION_END)?;
            write_u16(&mut self.inner, endianness, 0)?;
        }
        write_u32(&mut self.inner, endianness, block_length)?;
        Ok(())
    }

    fn select_interface(&mut self, frame: &CapturedFrame) -> Result<u32, CaptureError> {
        if let Some(interface_id) = frame.interface {
            let interfaces = match &self.state {
                WriterState::PcapNg { interfaces, .. } => interfaces,
                WriterState::Pcap { .. } => unreachable!("format checked by caller"),
            };
            let interface =
                interfaces
                    .get(interface_id as usize)
                    .ok_or(CaptureError::UndefinedInterface {
                        interface: interface_id,
                        available: interfaces.len(),
                    })?;
            if interface.link_type != frame.link_type {
                return Err(CaptureError::InterfaceLinkTypeMismatch {
                    interface: interface_id,
                    expected: interface.link_type.0,
                    actual: frame.link_type.0,
                });
            }
            return Ok(interface_id);
        }

        let matches = match &self.state {
            WriterState::PcapNg { interfaces, .. } => interfaces
                .iter()
                .enumerate()
                .filter(|(_, interface)| interface.link_type == frame.link_type)
                .map(|(index, _)| index as u32)
                .collect::<Vec<_>>(),
            WriterState::Pcap { .. } => unreachable!("format checked by caller"),
        };

        match matches.as_slice() {
            [interface] => Ok(*interface),
            [] => self.add_interface(frame.link_type),
            _ => Err(CaptureError::AmbiguousInterface {
                link_type: frame.link_type.0,
            }),
        }
    }

    pub fn flush(&mut self) -> Result<(), CaptureError> {
        self.inner.flush().map_err(CaptureError::from)
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

/// Copies one capture stream into a bounded writer without retaining packet
/// payloads between records.
///
/// PCAPNG output normalizes multiple source sections into one section while
/// preserving the open link type, snap length, timestamp resolution/offset,
/// globalized interface identity, direction, captured length, original wire
/// length, and complete captured bytes. Classic PCAP can only be copied from
/// classic PCAP because its container cannot represent PCAPNG interfaces or
/// packet directions.
pub fn transcode_capture<R: Read, W: Write>(
    reader: &mut CaptureReader<R>,
    output: W,
    target_format: CaptureFileFormat,
    limits: CaptureStreamLimits,
) -> Result<(W, CaptureTranscodeReport), CaptureError> {
    let source_format = reader.format();
    let endianness = reader.endianness();
    let mut writer = match target_format {
        CaptureFileFormat::Pcap => {
            if source_format != CaptureFileFormat::Pcap {
                return Err(CaptureError::MetadataNotRepresentable {
                    format: CaptureFileFormat::Pcap,
                    field: "pcapng interface metadata",
                });
            }
            let interface =
                reader
                    .interfaces()
                    .first()
                    .copied()
                    .ok_or(CaptureError::InvalidData {
                        format: CaptureFileFormat::Pcap,
                        reason: "classic capture has no global interface metadata",
                    })?;
            CaptureWriter::pcap_with_metadata(
                output,
                interface.link_type,
                endianness,
                interface.timestamp_resolution,
                interface.snap_len as usize,
                reader.size_limit(),
            )?
        }
        CaptureFileFormat::PcapNg => CaptureWriter::pcapng_with_resource_limits(
            output,
            endianness,
            reader.size_limit(),
            reader.max_interfaces,
        )?,
    };
    writer.set_stream_limits(limits)?;

    while let Some(mut frame) = reader.next_frame()? {
        if target_format == CaptureFileFormat::PcapNg {
            copy_new_interfaces(reader, &mut writer)?;
            if source_format == CaptureFileFormat::Pcap {
                frame.interface = Some(0);
            }
        }
        writer.write_frame(&frame)?;
    }
    if target_format == CaptureFileFormat::PcapNg {
        copy_new_interfaces(reader, &mut writer)?;
    }
    writer.flush()?;

    let report = CaptureTranscodeReport {
        source_format,
        target_format,
        endianness,
        frames: writer.frames_written(),
        captured_bytes: writer.captured_bytes_written(),
        interfaces: writer_interface_count(&writer),
    };
    Ok((writer.into_inner(), report))
}

fn copy_new_interfaces<R: Read, W: Write>(
    reader: &CaptureReader<R>,
    writer: &mut CaptureWriter<W>,
) -> Result<(), CaptureError> {
    while writer_interface_count(writer) < reader.interfaces().len() {
        let next = reader.interfaces()[writer_interface_count(writer)];
        writer.add_interface_description(next)?;
    }
    Ok(())
}

fn writer_interface_count<W>(writer: &CaptureWriter<W>) -> usize {
    match &writer.state {
        WriterState::Pcap { .. } => 1,
        WriterState::PcapNg { interfaces, .. } => interfaces.len(),
    }
}

fn read_pcap_header<R: Read>(
    reader: &mut R,
    endianness: PcapEndianness,
    precision: PcapTimestampPrecision,
) -> Result<ReaderState, CaptureError> {
    let mut remaining = [0_u8; PCAP_GLOBAL_HEADER_LEN - 4];
    read_exact_counted(reader, &mut remaining, "pcap global header")?;
    let major = decode_u16(endianness, &remaining[0..2]);
    let minor = decode_u16(endianness, &remaining[2..4]);
    if (major, minor) != (2, 4) {
        return Err(CaptureError::UnsupportedVersion {
            format: CaptureFileFormat::Pcap,
            major,
            minor,
        });
    }
    let snap_len = decode_u32(endianness, &remaining[12..16]);
    // The classic-PCAP network word uses its low 16 bits for LINKTYPE and may
    // carry standardized FCS metadata in the high bits. Do not misclassify a
    // flagged Ethernet capture as an unknown 32-bit DLT.
    let network_word = decode_u32(endianness, &remaining[16..20]);
    let link_type = LinkType(network_word & 0xffff);
    Ok(ReaderState::Pcap {
        endianness,
        precision,
        snap_len,
        link_type,
    })
}

fn read_next_pcap_frame<R: Read>(
    reader: &mut R,
    endianness: PcapEndianness,
    precision: PcapTimestampPrecision,
    snap_len: u32,
    link_type: LinkType,
    max_size: usize,
) -> Result<Option<CapturedFrame>, CaptureError> {
    let mut header = [0_u8; PCAP_RECORD_HEADER_LEN];
    if !read_exact_or_eof(reader, &mut header, "pcap packet header")? {
        return Ok(None);
    }

    let seconds = decode_u32(endianness, &header[0..4]);
    let fraction = decode_u32(endianness, &header[4..8]);
    let captured_length = decode_u32(endianness, &header[8..12]);
    let original_length = decode_u32(endianness, &header[12..16]);
    let denominator = match precision {
        PcapTimestampPrecision::Microseconds => 1_000_000,
        PcapTimestampPrecision::Nanoseconds => 1_000_000_000,
    };
    if fraction >= denominator {
        return Err(CaptureError::InvalidTimestampFraction {
            fraction,
            denominator,
        });
    }
    validate_declared_lengths(captured_length, original_length, max_size, "pcap packet")?;
    if snap_len != 0 && captured_length > snap_len {
        return Err(CaptureError::InvalidData {
            format: CaptureFileFormat::Pcap,
            reason: "captured packet exceeds the file snap length",
        });
    }

    let mut bytes = vec![0_u8; captured_length as usize];
    read_exact_counted(reader, &mut bytes, "pcap packet data")?;
    let nanoseconds = match precision {
        PcapTimestampPrecision::Microseconds => fraction * 1_000,
        PcapTimestampPrecision::Nanoseconds => fraction,
    };
    let timestamp = UNIX_EPOCH
        .checked_add(Duration::new(u64::from(seconds), nanoseconds))
        .ok_or(CaptureError::TimestampOutOfRange {
            format: CaptureFileFormat::Pcap,
        })?;

    Ok(Some(CapturedFrame {
        timestamp,
        captured_length,
        original_length,
        link_type,
        interface: None,
        direction: None,
        bytes: Bytes::from(bytes),
    }))
}

fn read_pcapng_block_header<R: Read>(reader: &mut R) -> Result<Option<[u8; 8]>, CaptureError> {
    let mut header = [0_u8; 8];
    if read_exact_or_eof(reader, &mut header, "pcapng block header")? {
        Ok(Some(header))
    } else {
        Ok(None)
    }
}

fn read_section_header_after_type<R: Read>(
    reader: &mut R,
    max_size: usize,
) -> Result<PcapEndianness, CaptureError> {
    let mut length = [0_u8; 4];
    read_exact_counted(reader, &mut length, "pcapng section header length")?;
    read_section_header_with_length(reader, length, max_size)
}

fn read_section_header_with_length<R: Read>(
    reader: &mut R,
    raw_length: [u8; 4],
    max_size: usize,
) -> Result<PcapEndianness, CaptureError> {
    let mut raw_bom = [0_u8; 4];
    read_exact_counted(reader, &mut raw_bom, "pcapng byte-order magic")?;
    let endianness = match raw_bom {
        [0x4d, 0x3c, 0x2b, 0x1a] => PcapEndianness::Little,
        [0x1a, 0x2b, 0x3c, 0x4d] => PcapEndianness::Big,
        _ => {
            return Err(CaptureError::InvalidData {
                format: CaptureFileFormat::PcapNg,
                reason: "invalid section byte-order magic",
            });
        }
    };
    let block_length = decode_u32(endianness, &raw_length);
    validate_pcapng_block_length(block_length, max_size)?;
    if block_length < 28 {
        return Err(CaptureError::InvalidBlockLength {
            length: block_length,
        });
    }

    let remaining_length = block_length as usize - 12;
    let mut remaining = vec![0_u8; remaining_length];
    read_exact_counted(reader, &mut remaining, "pcapng section header")?;
    let footer_offset = remaining.len() - 4;
    let trailing_length = decode_u32(endianness, &remaining[footer_offset..]);
    if trailing_length != block_length {
        return Err(CaptureError::BlockLengthMismatch {
            leading: block_length,
            trailing: trailing_length,
        });
    }

    let major = decode_u16(endianness, &remaining[0..2]);
    let minor = decode_u16(endianness, &remaining[2..4]);
    if (major, minor) != (1, 0) {
        return Err(CaptureError::UnsupportedVersion {
            format: CaptureFileFormat::PcapNg,
            major,
            minor,
        });
    }
    visit_options(
        &remaining[12..footer_offset],
        endianness,
        "pcapng section options",
        |_, _| Ok(()),
    )?;
    Ok(endianness)
}

fn validate_pcapng_block_length(length: u32, max_size: usize) -> Result<(), CaptureError> {
    if length < 12 || !length.is_multiple_of(4) {
        return Err(CaptureError::InvalidBlockLength { length });
    }
    if length as usize > max_size {
        return Err(CaptureError::SizeLimitExceeded {
            kind: "pcapng block",
            declared: u64::from(length),
            limit: max_size,
        });
    }
    Ok(())
}

fn parse_interface_description(
    body: &[u8],
    endianness: PcapEndianness,
) -> Result<InterfaceDescription, CaptureError> {
    if body.len() < 8 {
        return Err(CaptureError::InvalidData {
            format: CaptureFileFormat::PcapNg,
            reason: "interface description block is shorter than 8 bytes",
        });
    }
    let link_type = LinkType(u32::from(decode_u16(endianness, &body[0..2])));
    let snap_len = decode_u32(endianness, &body[4..8]);
    let mut timestamp_resolution = DEFAULT_TIMESTAMP_RESOLUTION;
    let mut timestamp_offset = 0_i64;
    visit_options(
        &body[8..],
        endianness,
        "pcapng interface options",
        |code, value| {
            match code {
                PCAPNG_OPTION_IF_TSRESOL if value.len() == 1 => {
                    let resolution = value[0];
                    timestamp_resolution = if resolution & 0x80 == 0 {
                        TimestampResolution::Decimal(resolution)
                    } else {
                        TimestampResolution::Binary(resolution & 0x7f)
                    };
                }
                PCAPNG_OPTION_IF_TSRESOL => {
                    return Err(CaptureError::InvalidData {
                        format: CaptureFileFormat::PcapNg,
                        reason: "if_tsresol option must contain one byte",
                    });
                }
                PCAPNG_OPTION_IF_TSOFFSET if value.len() == 8 => {
                    timestamp_offset = decode_i64(endianness, value);
                }
                PCAPNG_OPTION_IF_TSOFFSET => {
                    return Err(CaptureError::InvalidData {
                        format: CaptureFileFormat::PcapNg,
                        reason: "if_tsoffset option must contain eight bytes",
                    });
                }
                _ => {}
            }
            Ok(())
        },
    )?;
    Ok(InterfaceDescription {
        link_type,
        snap_len,
        timestamp_resolution,
        timestamp_offset,
    })
}

fn parse_enhanced_packet(
    body: &[u8],
    endianness: PcapEndianness,
    interfaces: &[InterfaceDescription],
    interface_base: u32,
    max_size: usize,
) -> Result<CapturedFrame, CaptureError> {
    if body.len() < 20 {
        return Err(CaptureError::InvalidData {
            format: CaptureFileFormat::PcapNg,
            reason: "enhanced packet block is shorter than 20 bytes",
        });
    }
    let interface_id = decode_u32(endianness, &body[0..4]);
    let timestamp = (u64::from(decode_u32(endianness, &body[4..8])) << 32)
        | u64::from(decode_u32(endianness, &body[8..12]));
    let captured_length = decode_u32(endianness, &body[12..16]);
    let original_length = decode_u32(endianness, &body[16..20]);
    parse_pcapng_packet_body(
        body,
        20,
        interface_id,
        timestamp,
        captured_length,
        original_length,
        endianness,
        interfaces,
        interface_base,
        max_size,
    )
}

fn parse_obsolete_packet(
    body: &[u8],
    endianness: PcapEndianness,
    interfaces: &[InterfaceDescription],
    interface_base: u32,
    max_size: usize,
) -> Result<CapturedFrame, CaptureError> {
    if body.len() < 20 {
        return Err(CaptureError::InvalidData {
            format: CaptureFileFormat::PcapNg,
            reason: "packet block is shorter than 20 bytes",
        });
    }
    let interface_id = u32::from(decode_u16(endianness, &body[0..2]));
    let timestamp = (u64::from(decode_u32(endianness, &body[4..8])) << 32)
        | u64::from(decode_u32(endianness, &body[8..12]));
    let captured_length = decode_u32(endianness, &body[12..16]);
    let original_length = decode_u32(endianness, &body[16..20]);
    parse_pcapng_packet_body(
        body,
        20,
        interface_id,
        timestamp,
        captured_length,
        original_length,
        endianness,
        interfaces,
        interface_base,
        max_size,
    )
}

#[allow(clippy::too_many_arguments)]
fn parse_pcapng_packet_body(
    body: &[u8],
    data_offset: usize,
    interface_id: u32,
    timestamp_ticks: u64,
    captured_length: u32,
    original_length: u32,
    endianness: PcapEndianness,
    interfaces: &[InterfaceDescription],
    interface_base: u32,
    max_size: usize,
) -> Result<CapturedFrame, CaptureError> {
    validate_declared_lengths(captured_length, original_length, max_size, "pcapng packet")?;
    let interface =
        interfaces
            .get(interface_id as usize)
            .ok_or(CaptureError::UndefinedInterface {
                interface: interface_id,
                available: interfaces.len(),
            })?;
    if interface.snap_len != 0 && captured_length > interface.snap_len {
        return Err(CaptureError::InvalidData {
            format: CaptureFileFormat::PcapNg,
            reason: "captured packet exceeds its interface snap length",
        });
    }
    let padded_length = align_to_usize(captured_length as usize)?;
    let data_end = data_offset
        .checked_add(padded_length)
        .ok_or(CaptureError::InvalidData {
            format: CaptureFileFormat::PcapNg,
            reason: "packet data offset overflow",
        })?;
    if data_end > body.len() {
        return Err(CaptureError::Truncated {
            context: "pcapng packet data",
            expected: data_end,
            actual: body.len(),
        });
    }
    let actual_data_end = data_offset + captured_length as usize;
    let direction = parse_packet_direction(&body[data_end..], endianness)?;
    let timestamp = timestamp_from_ticks(
        timestamp_ticks,
        interface.timestamp_resolution,
        interface.timestamp_offset,
    )?;
    let global_interface = interface_base
        .checked_add(interface_id)
        .ok_or(CaptureError::InterfaceLimit { limit: usize::MAX })?;
    Ok(CapturedFrame {
        timestamp,
        captured_length,
        original_length,
        link_type: interface.link_type,
        interface: Some(global_interface),
        direction,
        bytes: Bytes::copy_from_slice(&body[data_offset..actual_data_end]),
    })
}

fn parse_simple_packet(
    body: &[u8],
    endianness: PcapEndianness,
    interfaces: &[InterfaceDescription],
    interface_base: u32,
    max_size: usize,
) -> Result<CapturedFrame, CaptureError> {
    if body.len() < 4 {
        return Err(CaptureError::InvalidData {
            format: CaptureFileFormat::PcapNg,
            reason: "simple packet block is shorter than four bytes",
        });
    }
    let interface = interfaces.first().ok_or(CaptureError::UndefinedInterface {
        interface: 0,
        available: 0,
    })?;
    let original_length = decode_u32(endianness, &body[0..4]);
    let captured_length = if interface.snap_len == 0 {
        original_length
    } else {
        original_length.min(interface.snap_len)
    };
    validate_declared_lengths(
        captured_length,
        original_length,
        max_size,
        "pcapng simple packet",
    )?;
    let padded_length = align_to_usize(captured_length as usize)?;
    let expected = 4_usize
        .checked_add(padded_length)
        .ok_or(CaptureError::InvalidData {
            format: CaptureFileFormat::PcapNg,
            reason: "simple packet data offset overflow",
        })?;
    if body.len() != expected {
        return Err(CaptureError::InvalidData {
            format: CaptureFileFormat::PcapNg,
            reason: "simple packet block length does not match its packet length",
        });
    }
    Ok(CapturedFrame {
        // A Simple Packet Block has no timestamp field.  UNIX_EPOCH is the
        // deterministic sentinel used by the raw capture record model.
        timestamp: UNIX_EPOCH,
        captured_length,
        original_length,
        link_type: interface.link_type,
        interface: Some(interface_base),
        direction: None,
        bytes: Bytes::copy_from_slice(&body[4..4 + captured_length as usize]),
    })
}

fn parse_packet_direction(
    options: &[u8],
    endianness: PcapEndianness,
) -> Result<Option<CaptureDirection>, CaptureError> {
    let mut direction = None;
    visit_options(
        options,
        endianness,
        "pcapng packet options",
        |code, value| {
            if code == PCAPNG_OPTION_EPB_FLAGS {
                if value.len() != 4 {
                    return Err(CaptureError::InvalidData {
                        format: CaptureFileFormat::PcapNg,
                        reason: "epb_flags option must contain four bytes",
                    });
                }
                direction = Some(match decode_u32(endianness, value) & 0b11 {
                    1 => CaptureDirection::Inbound,
                    2 => CaptureDirection::Outbound,
                    _ => CaptureDirection::Unknown,
                });
            }
            Ok(())
        },
    )?;
    Ok(direction)
}

fn visit_options<F>(
    options: &[u8],
    endianness: PcapEndianness,
    context: &'static str,
    mut visitor: F,
) -> Result<(), CaptureError>
where
    F: FnMut(u16, &[u8]) -> Result<(), CaptureError>,
{
    let mut offset = 0_usize;
    while offset < options.len() {
        if options.len() - offset < 4 {
            return Err(CaptureError::Truncated {
                context,
                expected: offset + 4,
                actual: options.len(),
            });
        }
        let code = decode_u16(endianness, &options[offset..offset + 2]);
        let length = usize::from(decode_u16(endianness, &options[offset + 2..offset + 4]));
        offset += 4;
        if code == PCAPNG_OPTION_END {
            if length != 0 {
                return Err(CaptureError::InvalidData {
                    format: CaptureFileFormat::PcapNg,
                    reason: "end-of-options marker has a non-zero length",
                });
            }
            if options[offset..].iter().any(|byte| *byte != 0) {
                return Err(CaptureError::InvalidData {
                    format: CaptureFileFormat::PcapNg,
                    reason: "non-zero bytes follow the end-of-options marker",
                });
            }
            return Ok(());
        }
        let padded_length = align_to_usize(length)?;
        let end = offset
            .checked_add(padded_length)
            .ok_or(CaptureError::InvalidData {
                format: CaptureFileFormat::PcapNg,
                reason: "option length overflow",
            })?;
        if end > options.len() {
            return Err(CaptureError::Truncated {
                context,
                expected: end,
                actual: options.len(),
            });
        }
        visitor(code, &options[offset..offset + length])?;
        offset = end;
    }
    Ok(())
}

fn write_pcap_header<W: Write>(
    writer: &mut W,
    endianness: PcapEndianness,
    precision: PcapTimestampPrecision,
    snap_len: u32,
    link_type: LinkType,
) -> Result<(), CaptureError> {
    let magic = match (endianness, precision) {
        (PcapEndianness::Little, PcapTimestampPrecision::Microseconds) => [0xd4, 0xc3, 0xb2, 0xa1],
        (PcapEndianness::Big, PcapTimestampPrecision::Microseconds) => [0xa1, 0xb2, 0xc3, 0xd4],
        (PcapEndianness::Little, PcapTimestampPrecision::Nanoseconds) => [0x4d, 0x3c, 0xb2, 0xa1],
        (PcapEndianness::Big, PcapTimestampPrecision::Nanoseconds) => [0xa1, 0xb2, 0x3c, 0x4d],
    };
    writer.write_all(&magic)?;
    write_u16(writer, endianness, 2)?;
    write_u16(writer, endianness, 4)?;
    write_u32(writer, endianness, 0)?;
    write_u32(writer, endianness, 0)?;
    write_u32(writer, endianness, snap_len)?;
    write_u32(writer, endianness, link_type.0)?;
    Ok(())
}

fn write_section_header<W: Write>(
    writer: &mut W,
    endianness: PcapEndianness,
) -> Result<(), CaptureError> {
    write_u32(writer, endianness, PCAPNG_SECTION_HEADER_BLOCK)?;
    write_u32(writer, endianness, 28)?;
    write_u32(writer, endianness, PCAPNG_BYTE_ORDER_MAGIC)?;
    write_u16(writer, endianness, 1)?;
    write_u16(writer, endianness, 0)?;
    write_i64(writer, endianness, -1)?;
    write_u32(writer, endianness, 28)?;
    Ok(())
}

fn write_interface_description<W: Write>(
    writer: &mut W,
    endianness: PcapEndianness,
    link_type: LinkType,
    snap_len: u32,
    timestamp_resolution: TimestampResolution,
    timestamp_offset: i64,
) -> Result<(), CaptureError> {
    let block_length = if timestamp_offset == 0 { 32 } else { 44 };
    write_u32(writer, endianness, PCAPNG_INTERFACE_DESCRIPTION_BLOCK)?;
    write_u32(writer, endianness, block_length)?;
    write_u16(writer, endianness, link_type.0 as u16)?;
    write_u16(writer, endianness, 0)?;
    write_u32(writer, endianness, snap_len)?;
    write_u16(writer, endianness, PCAPNG_OPTION_IF_TSRESOL)?;
    write_u16(writer, endianness, 1)?;
    let resolution = match timestamp_resolution {
        TimestampResolution::Decimal(exponent) if exponent <= 0x7f => exponent,
        TimestampResolution::Binary(exponent) if exponent <= 0x7f => exponent | 0x80,
        TimestampResolution::Decimal(exponent) => {
            return Err(CaptureError::InvalidTimestampResolution { base: 10, exponent })
        }
        TimestampResolution::Binary(exponent) => {
            return Err(CaptureError::InvalidTimestampResolution { base: 2, exponent })
        }
    };
    writer.write_all(&[resolution, 0, 0, 0])?;
    if timestamp_offset != 0 {
        write_u16(writer, endianness, PCAPNG_OPTION_IF_TSOFFSET)?;
        write_u16(writer, endianness, 8)?;
        write_i64(writer, endianness, timestamp_offset)?;
    }
    write_u16(writer, endianness, PCAPNG_OPTION_END)?;
    write_u16(writer, endianness, 0)?;
    write_u32(writer, endianness, block_length)?;
    Ok(())
}

fn validate_timestamp_resolution(resolution: TimestampResolution) -> Result<(), CaptureError> {
    match resolution {
        TimestampResolution::Decimal(exponent) if exponent <= 0x7f => Ok(()),
        TimestampResolution::Binary(exponent) if exponent <= 0x7f => Ok(()),
        TimestampResolution::Decimal(exponent) => {
            Err(CaptureError::InvalidTimestampResolution { base: 10, exponent })
        }
        TimestampResolution::Binary(exponent) => {
            Err(CaptureError::InvalidTimestampResolution { base: 2, exponent })
        }
    }
}

fn validate_frame_lengths(frame: &CapturedFrame, max_size: usize) -> Result<(), CaptureError> {
    if frame.bytes.len() != frame.captured_length as usize {
        return Err(CaptureError::CapturedLengthMismatch {
            declared: frame.captured_length,
            actual: frame.bytes.len(),
        });
    }
    validate_declared_lengths(
        frame.captured_length,
        frame.original_length,
        max_size,
        "captured packet",
    )
}

fn validate_declared_lengths(
    captured_length: u32,
    original_length: u32,
    max_size: usize,
    kind: &'static str,
) -> Result<(), CaptureError> {
    if original_length < captured_length {
        return Err(CaptureError::OriginalLengthTooSmall {
            captured: captured_length,
            original: original_length,
        });
    }
    if captured_length as usize > max_size {
        return Err(CaptureError::SizeLimitExceeded {
            kind,
            declared: u64::from(captured_length),
            limit: max_size,
        });
    }
    Ok(())
}

fn timestamp_from_ticks(
    ticks: u64,
    resolution: TimestampResolution,
    offset_seconds: i64,
) -> Result<SystemTime, CaptureError> {
    let denominator = match resolution {
        TimestampResolution::Decimal(exponent) => 10_u128.checked_pow(u32::from(exponent)),
        TimestampResolution::Binary(exponent) => 1_u128.checked_shl(u32::from(exponent)),
    };
    let (seconds, nanoseconds) = match denominator {
        Some(denominator) => {
            let ticks = u128::from(ticks);
            let seconds = ticks / denominator;
            let remainder = ticks % denominator;
            let scaled = remainder
                .checked_mul(1_000_000_000)
                .expect("u64 ticks multiplied by one billion fit in u128");
            if !scaled.is_multiple_of(denominator) {
                return Err(CaptureError::MetadataNotRepresentable {
                    format: CaptureFileFormat::PcapNg,
                    field: "sub-nanosecond timestamp",
                });
            }
            let nanoseconds = scaled / denominator;
            (seconds, nanoseconds as u32)
        }
        None => {
            // Any denominator too large for u128 is also much larger than a
            // u64 timestamp. Only zero ticks are exactly representable.
            if ticks != 0 {
                return Err(CaptureError::MetadataNotRepresentable {
                    format: CaptureFileFormat::PcapNg,
                    field: "sub-nanosecond timestamp",
                });
            }
            (0, 0)
        }
    };
    let seconds = i128::try_from(seconds)
        .ok()
        .and_then(|seconds| seconds.checked_add(i128::from(offset_seconds)))
        .ok_or(CaptureError::TimestampOutOfRange {
            format: CaptureFileFormat::PcapNg,
        })?;
    system_time_from_signed_unix(seconds, nanoseconds)
}

fn timestamp_to_ticks(
    timestamp: SystemTime,
    resolution: TimestampResolution,
    offset_seconds: i64,
) -> Result<u64, CaptureError> {
    let (unix_seconds, nanoseconds) = match timestamp.duration_since(UNIX_EPOCH) {
        Ok(elapsed) => (i128::from(elapsed.as_secs()), elapsed.subsec_nanos()),
        Err(error) => {
            let elapsed = error.duration();
            if elapsed.subsec_nanos() == 0 {
                (-i128::from(elapsed.as_secs()), 0)
            } else {
                (
                    -i128::from(elapsed.as_secs()) - 1,
                    1_000_000_000 - elapsed.subsec_nanos(),
                )
            }
        }
    };
    let seconds = unix_seconds.checked_sub(i128::from(offset_seconds)).ok_or(
        CaptureError::TimestampOutOfRange {
            format: CaptureFileFormat::PcapNg,
        },
    )?;
    if seconds < 0 {
        return Err(CaptureError::TimestampOutOfRange {
            format: CaptureFileFormat::PcapNg,
        });
    }
    let denominator = match resolution {
        TimestampResolution::Decimal(exponent) => 10_u128.checked_pow(u32::from(exponent)),
        TimestampResolution::Binary(exponent) => 1_u128.checked_shl(u32::from(exponent)),
    }
    .ok_or(CaptureError::TimestampOutOfRange {
        format: CaptureFileFormat::PcapNg,
    })?;
    let seconds = u128::try_from(seconds).map_err(|_| CaptureError::TimestampOutOfRange {
        format: CaptureFileFormat::PcapNg,
    })?;
    let fractional_numerator = u128::from(nanoseconds).checked_mul(denominator).ok_or(
        CaptureError::TimestampOutOfRange {
            format: CaptureFileFormat::PcapNg,
        },
    )?;
    if !fractional_numerator.is_multiple_of(1_000_000_000) {
        return Err(CaptureError::MetadataNotRepresentable {
            format: CaptureFileFormat::PcapNg,
            field: "timestamp resolution",
        });
    }
    let fractional = fractional_numerator / 1_000_000_000;
    let ticks = seconds
        .checked_mul(denominator)
        .and_then(|ticks| ticks.checked_add(fractional))
        .ok_or(CaptureError::TimestampOutOfRange {
            format: CaptureFileFormat::PcapNg,
        })?;
    u64::try_from(ticks).map_err(|_| CaptureError::TimestampOutOfRange {
        format: CaptureFileFormat::PcapNg,
    })
}

fn system_time_from_signed_unix(
    seconds: i128,
    nanoseconds: u32,
) -> Result<SystemTime, CaptureError> {
    let out_of_range = || CaptureError::TimestampOutOfRange {
        format: CaptureFileFormat::PcapNg,
    };
    if seconds >= 0 {
        let seconds = u64::try_from(seconds).map_err(|_| out_of_range())?;
        UNIX_EPOCH
            .checked_add(Duration::new(seconds, nanoseconds))
            .ok_or_else(out_of_range)
    } else if nanoseconds == 0 {
        let magnitude = seconds
            .checked_neg()
            .and_then(|magnitude| u64::try_from(magnitude).ok())
            .ok_or_else(out_of_range)?;
        UNIX_EPOCH
            .checked_sub(Duration::from_secs(magnitude))
            .ok_or_else(out_of_range)
    } else {
        let whole_seconds = seconds
            .checked_neg()
            .and_then(|magnitude| magnitude.checked_sub(1))
            .and_then(|magnitude| u64::try_from(magnitude).ok())
            .ok_or_else(out_of_range)?;
        UNIX_EPOCH
            .checked_sub(Duration::new(whole_seconds, 1_000_000_000 - nanoseconds))
            .ok_or_else(out_of_range)
    }
}

fn read_exact_or_eof<R: Read>(
    reader: &mut R,
    buffer: &mut [u8],
    context: &'static str,
) -> Result<bool, CaptureError> {
    let mut offset = 0;
    while offset < buffer.len() {
        match reader.read(&mut buffer[offset..]) {
            Ok(0) if offset == 0 => return Ok(false),
            Ok(0) => {
                return Err(CaptureError::Truncated {
                    context,
                    expected: buffer.len(),
                    actual: offset,
                });
            }
            Ok(read) => offset += read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(CaptureError::Io(error)),
        }
    }
    Ok(true)
}

fn read_exact_counted<R: Read>(
    reader: &mut R,
    buffer: &mut [u8],
    context: &'static str,
) -> Result<(), CaptureError> {
    if read_exact_or_eof(reader, buffer, context)? {
        Ok(())
    } else {
        Err(CaptureError::Truncated {
            context,
            expected: buffer.len(),
            actual: 0,
        })
    }
}

fn usize_to_u32_limit(value: usize) -> Result<u32, CaptureError> {
    u32::try_from(value).map_err(|_| CaptureError::SizeLimitExceeded {
        kind: "capture size",
        declared: value as u64,
        limit: u32::MAX as usize,
    })
}

fn align_to_usize(value: usize) -> Result<usize, CaptureError> {
    value
        .checked_add(3)
        .map(|value| value & !3)
        .ok_or(CaptureError::InvalidData {
            format: CaptureFileFormat::PcapNg,
            reason: "aligned length overflow",
        })
}

fn align_to_u32(value: u32) -> Result<u32, CaptureError> {
    value
        .checked_add(3)
        .map(|value| value & !3)
        .ok_or(CaptureError::InvalidBlockLength { length: value })
}

fn write_padding<W: Write>(writer: &mut W, unpadded_length: u32) -> Result<(), CaptureError> {
    let padding = (4 - (unpadded_length % 4)) % 4;
    writer.write_all(&[0_u8; 3][..padding as usize])?;
    Ok(())
}

fn decode_u16(endianness: PcapEndianness, bytes: &[u8]) -> u16 {
    let bytes: [u8; 2] = bytes[..2].try_into().expect("two-byte slice");
    match endianness {
        PcapEndianness::Little => u16::from_le_bytes(bytes),
        PcapEndianness::Big => u16::from_be_bytes(bytes),
    }
}

fn decode_u32(endianness: PcapEndianness, bytes: &[u8]) -> u32 {
    let bytes: [u8; 4] = bytes[..4].try_into().expect("four-byte slice");
    match endianness {
        PcapEndianness::Little => u32::from_le_bytes(bytes),
        PcapEndianness::Big => u32::from_be_bytes(bytes),
    }
}

fn decode_i64(endianness: PcapEndianness, bytes: &[u8]) -> i64 {
    let bytes: [u8; 8] = bytes[..8].try_into().expect("eight-byte slice");
    match endianness {
        PcapEndianness::Little => i64::from_le_bytes(bytes),
        PcapEndianness::Big => i64::from_be_bytes(bytes),
    }
}

fn write_u16<W: Write>(
    writer: &mut W,
    endianness: PcapEndianness,
    value: u16,
) -> Result<(), CaptureError> {
    let bytes = match endianness {
        PcapEndianness::Little => value.to_le_bytes(),
        PcapEndianness::Big => value.to_be_bytes(),
    };
    writer.write_all(&bytes)?;
    Ok(())
}

fn write_u32<W: Write>(
    writer: &mut W,
    endianness: PcapEndianness,
    value: u32,
) -> Result<(), CaptureError> {
    let bytes = match endianness {
        PcapEndianness::Little => value.to_le_bytes(),
        PcapEndianness::Big => value.to_be_bytes(),
    };
    writer.write_all(&bytes)?;
    Ok(())
}

fn write_i64<W: Write>(
    writer: &mut W,
    endianness: PcapEndianness,
    value: i64,
) -> Result<(), CaptureError> {
    let bytes = match endianness {
        PcapEndianness::Little => value.to_le_bytes(),
        PcapEndianness::Big => value.to_be_bytes(),
    };
    writer.write_all(&bytes)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    fn frame(timestamp: SystemTime, link_type: LinkType, bytes: &[u8]) -> CapturedFrame {
        CapturedFrame::new(timestamp, link_type, Bytes::copy_from_slice(bytes)).unwrap()
    }

    #[test]
    fn classic_pcap_round_trip_preserves_full_record() {
        let timestamp = UNIX_EPOCH + Duration::new(1_700_000_000, 123_456_789);
        let original = CapturedFrame::try_with_lengths(
            timestamp,
            LinkType::ETHERNET,
            5,
            64,
            Bytes::from_static(&[1, 2, 3, 4, 5]),
        )
        .unwrap();
        let mut writer = CaptureWriter::pcap_with_endianness(
            Vec::new(),
            LinkType::ETHERNET,
            PcapEndianness::Big,
        )
        .unwrap();
        writer.write_frame(&original).unwrap();
        let bytes = writer.into_inner();

        let mut reader = CaptureReader::new(Cursor::new(bytes)).unwrap();
        assert_eq!(reader.format(), CaptureFileFormat::Pcap);
        assert_eq!(reader.endianness(), PcapEndianness::Big);
        assert_eq!(reader.next_frame().unwrap(), Some(original));
        assert_eq!(reader.next_frame().unwrap(), None);
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
        let decoded = CaptureReader::new(Cursor::new(fixture))
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
        let mut writer =
            CaptureWriter::pcapng_with_endianness(Vec::new(), PcapEndianness::Big).unwrap();
        let ethernet = writer.add_interface(LinkType::ETHERNET).unwrap();
        let cooked = writer.add_interface(LinkType::LINUX_SLL2).unwrap();
        assert_eq!((ethernet, cooked), (0, 1));

        let mut first = frame(
            UNIX_EPOCH + Duration::new(10, 111_222_333),
            LinkType::ETHERNET,
            &[0xaa, 0xbb, 0xcc],
        );
        first.interface = Some(ethernet);
        first.direction = Some(CaptureDirection::Inbound);
        let mut second = frame(
            UNIX_EPOCH + Duration::new(11, 999_888_777),
            LinkType::LINUX_SLL2,
            &[0, 1, 2, 3, 4, 5, 6],
        );
        second.interface = Some(cooked);
        second.direction = Some(CaptureDirection::Outbound);
        writer.write_frame(&first).unwrap();
        writer.write_frame(&second).unwrap();

        let mut reader = CaptureReader::new(Cursor::new(writer.into_inner())).unwrap();
        assert_eq!(reader.format(), CaptureFileFormat::PcapNg);
        assert_eq!(reader.endianness(), PcapEndianness::Big);
        assert_eq!(reader.next_frame().unwrap(), Some(first));
        assert_eq!(reader.next_frame().unwrap(), Some(second));
        assert_eq!(reader.next_frame().unwrap(), None);
    }

    #[test]
    fn bounded_transcode_preserves_pcapng_interface_metadata_and_frames() {
        let mut writer =
            CaptureWriter::pcapng_with_endianness(Vec::new(), PcapEndianness::Big).unwrap();
        let ethernet = writer
            .add_interface_description(CaptureInterface {
                link_type: LinkType::ETHERNET,
                snap_len: 64,
                timestamp_resolution: CaptureTimestampResolution::Decimal(6),
                timestamp_offset: 0,
            })
            .unwrap();
        let raw = writer
            .add_interface_description(CaptureInterface {
                link_type: LinkType::RAW,
                snap_len: 128,
                timestamp_resolution: CaptureTimestampResolution::Binary(10),
                timestamp_offset: -1,
            })
            .unwrap();
        let mut first = CapturedFrame::try_with_lengths(
            UNIX_EPOCH + Duration::new(1, 123_456_000),
            LinkType::ETHERNET,
            3,
            60,
            vec![1, 2, 3],
        )
        .unwrap();
        first.interface = Some(ethernet);
        first.direction = Some(CaptureDirection::Inbound);
        let mut second = CapturedFrame::new(
            UNIX_EPOCH.checked_sub(Duration::from_millis(500)).unwrap(),
            LinkType::RAW,
            vec![4, 5],
        )
        .unwrap();
        second.interface = Some(raw);
        second.direction = Some(CaptureDirection::Outbound);
        writer.write_frame(&first).unwrap();
        writer.write_frame(&second).unwrap();

        let mut source = CaptureReader::new(Cursor::new(writer.into_inner())).unwrap();
        let (bytes, report) = transcode_capture(
            &mut source,
            Vec::new(),
            CaptureFileFormat::PcapNg,
            CaptureStreamLimits {
                max_frames: 2,
                max_bytes: 5,
            },
        )
        .unwrap();
        assert_eq!(
            report,
            CaptureTranscodeReport {
                source_format: CaptureFileFormat::PcapNg,
                target_format: CaptureFileFormat::PcapNg,
                endianness: PcapEndianness::Big,
                frames: 2,
                captured_bytes: 5,
                interfaces: 2,
            }
        );

        let mut copied = CaptureReader::new(Cursor::new(bytes)).unwrap();
        assert_eq!(copied.endianness(), PcapEndianness::Big);
        assert_eq!(copied.next_frame().unwrap(), Some(first));
        assert_eq!(copied.next_frame().unwrap(), Some(second));
        assert_eq!(copied.next_frame().unwrap(), None);
        assert_eq!(
            copied.interfaces(),
            &[
                CaptureInterface {
                    link_type: LinkType::ETHERNET,
                    snap_len: 64,
                    timestamp_resolution: CaptureTimestampResolution::Decimal(6),
                    timestamp_offset: 0,
                },
                CaptureInterface {
                    link_type: LinkType::RAW,
                    snap_len: 128,
                    timestamp_resolution: CaptureTimestampResolution::Binary(10),
                    timestamp_offset: -1,
                },
            ]
        );
    }

    #[test]
    fn classic_transcode_preserves_endianness_and_microsecond_resolution() {
        let original = frame(
            UNIX_EPOCH + Duration::new(2, 345_678_000),
            LinkType::ETHERNET,
            &[1, 2, 3],
        );
        let mut writer = CaptureWriter::pcap_with_metadata(
            Vec::new(),
            LinkType::ETHERNET,
            PcapEndianness::Big,
            CaptureTimestampResolution::Decimal(6),
            64,
            64,
        )
        .unwrap();
        writer.write_frame(&original).unwrap();

        let mut source = CaptureReader::new(Cursor::new(writer.into_inner())).unwrap();
        let (bytes, report) = transcode_capture(
            &mut source,
            Vec::new(),
            CaptureFileFormat::Pcap,
            CaptureStreamLimits::default(),
        )
        .unwrap();
        assert_eq!(report.endianness, PcapEndianness::Big);
        assert_eq!(&bytes[..4], &[0xa1, 0xb2, 0xc3, 0xd4]);

        let mut copied = CaptureReader::new(Cursor::new(bytes)).unwrap();
        assert_eq!(copied.next_frame().unwrap(), Some(original));
        assert_eq!(
            copied.interfaces()[0].timestamp_resolution,
            CaptureTimestampResolution::Decimal(6)
        );

        let mut writer = CaptureWriter::pcap_with_metadata(
            Vec::new(),
            LinkType::ETHERNET,
            PcapEndianness::Little,
            CaptureTimestampResolution::Decimal(6),
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
            Err(CaptureError::MetadataNotRepresentable {
                format: CaptureFileFormat::Pcap,
                field: "microsecond timestamp precision"
            })
        ));
        assert_eq!(writer.get_ref().len(), PCAP_GLOBAL_HEADER_LEN);
    }

    #[test]
    fn writer_stream_limits_fail_before_emitting_the_excess_frame() {
        let mut writer = CaptureWriter::pcap(Vec::new(), LinkType::ETHERNET).unwrap();
        writer
            .set_stream_limits(CaptureStreamLimits {
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
            Err(CaptureError::FrameLimitExceeded {
                actual: 2,
                limit: 1
            })
        ));
        assert_eq!(writer.get_ref().len(), committed);
        assert_eq!(writer.frames_written(), 1);
        assert_eq!(writer.captured_bytes_written(), 3);

        let mut byte_writer = CaptureWriter::pcap(Vec::new(), LinkType::ETHERNET).unwrap();
        byte_writer
            .set_stream_limits(CaptureStreamLimits {
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
            Err(CaptureError::StreamByteLimitExceeded {
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
        let mut writer = CaptureWriter::pcapng(Vec::new()).unwrap();
        writer.add_interface(LinkType::ETHERNET).unwrap();
        let mut source = CaptureReader::new(Cursor::new(writer.into_inner())).unwrap();
        assert!(matches!(
            transcode_capture(
                &mut source,
                Vec::new(),
                CaptureFileFormat::Pcap,
                CaptureStreamLimits::default(),
            ),
            Err(CaptureError::MetadataNotRepresentable {
                format: CaptureFileFormat::Pcap,
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

        for endianness in [PcapEndianness::Little, PcapEndianness::Big] {
            let mut writer = CaptureWriter::pcapng_with_endianness(Vec::new(), endianness).unwrap();
            let interface = writer
                .add_interface_with_timestamp_offset(LinkType::ETHERNET, -3)
                .unwrap();
            let mut first = frame(whole_second, LinkType::ETHERNET, &[1]);
            first.interface = Some(interface);
            let mut second = frame(fractional, LinkType::ETHERNET, &[2]);
            second.interface = Some(interface);
            writer.write_frame(&first).unwrap();
            writer.write_frame(&second).unwrap();

            let mut reader = CaptureReader::new(Cursor::new(writer.into_inner())).unwrap();
            assert_eq!(reader.next_frame().unwrap(), Some(first));
            assert_eq!(reader.next_frame().unwrap(), Some(second));
            assert_eq!(reader.next_frame().unwrap(), None);
        }
    }

    #[test]
    fn pcapng_writer_rejects_a_timestamp_before_its_interface_offset() {
        let mut writer = CaptureWriter::pcapng(Vec::new()).unwrap();
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
            Err(CaptureError::TimestampOutOfRange {
                format: CaptureFileFormat::PcapNg
            })
        ));
    }

    #[test]
    fn pcapng_reader_bounds_interface_descriptions() {
        let mut writer = CaptureWriter::pcapng(Vec::new()).unwrap();
        writer.add_interface(LinkType::ETHERNET).unwrap();
        writer.add_interface(LinkType::LINUX_SLL).unwrap();
        let mut reader = CaptureReader::with_limits(
            Cursor::new(writer.into_inner()),
            DEFAULT_CAPTURE_SIZE_LIMIT,
            1,
        )
        .unwrap();

        assert!(matches!(
            reader.next_frame(),
            Err(CaptureError::InterfaceLimit { limit: 1 })
        ));
    }

    #[test]
    fn pcapng_writer_bounds_interfaces_atomically() {
        let mut writer = CaptureWriter::pcapng_with_resource_limits(
            Vec::new(),
            PcapEndianness::Little,
            DEFAULT_CAPTURE_SIZE_LIMIT,
            1,
        )
        .unwrap();
        assert_eq!(writer.interface_limit(), 1);
        assert_eq!(writer.add_interface(LinkType::ETHERNET).unwrap(), 0);
        let bytes_after_first = writer.get_ref().len();

        assert!(matches!(
            writer.add_interface(LinkType::LINUX_SLL),
            Err(CaptureError::InterfaceLimit { limit: 1 })
        ));
        assert_eq!(writer.get_ref().len(), bytes_after_first);

        let mut original = frame(UNIX_EPOCH, LinkType::ETHERNET, &[1, 2, 3]);
        original.interface = Some(0);
        writer.write_frame(&original).unwrap();
        let mut reader = CaptureReader::new(Cursor::new(writer.into_inner())).unwrap();
        assert_eq!(reader.next_frame().unwrap(), Some(original));

        let mut zero_limit = CaptureWriter::pcapng_with_resource_limits(
            Vec::new(),
            PcapEndianness::Little,
            DEFAULT_CAPTURE_SIZE_LIMIT,
            0,
        )
        .unwrap();
        let section_length = zero_limit.get_ref().len();
        assert!(matches!(
            zero_limit.add_interface(LinkType::ETHERNET),
            Err(CaptureError::InterfaceLimit { limit: 0 })
        ));
        assert_eq!(zero_limit.get_ref().len(), section_length);
    }

    #[test]
    fn pcapng_writer_emits_standard_section_and_interface_headers() {
        let mut writer = CaptureWriter::pcapng(Vec::new()).unwrap();
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
        let mut first_writer =
            CaptureWriter::new(Vec::new(), CaptureFileFormat::PcapNg, LinkType::ETHERNET).unwrap();
        let mut first = frame(UNIX_EPOCH, LinkType::ETHERNET, &[1]);
        first.interface = Some(0);
        first_writer.write_frame(&first).unwrap();

        let mut second_writer =
            CaptureWriter::new(Vec::new(), CaptureFileFormat::PcapNg, LinkType::LINUX_SLL).unwrap();
        let mut second = frame(UNIX_EPOCH, LinkType::LINUX_SLL, &[2]);
        second.interface = Some(0);
        second_writer.write_frame(&second).unwrap();

        let mut bytes = first_writer.into_inner();
        bytes.extend_from_slice(&second_writer.into_inner());
        let mut reader = CaptureReader::new(Cursor::new(bytes)).unwrap();
        assert_eq!(reader.next_frame().unwrap(), Some(first));
        let mut global_second = second;
        global_second.interface = Some(1);
        assert_eq!(reader.next_frame().unwrap(), Some(global_second));
        assert_eq!(reader.next_frame().unwrap(), None);
    }

    #[test]
    fn pcapng_interface_block_honors_writer_size_limit() {
        let mut writer =
            CaptureWriter::pcapng_with_options(Vec::new(), PcapEndianness::Little, 31).unwrap();
        assert!(matches!(
            writer.add_interface(LinkType::ETHERNET),
            Err(CaptureError::SizeLimitExceeded {
                declared: 32,
                limit: 31,
                ..
            })
        ));
        assert_eq!(writer.into_inner().len(), 28);

        let mut writer =
            CaptureWriter::pcapng_with_options(Vec::new(), PcapEndianness::Little, 43).unwrap();
        assert!(matches!(
            writer.add_interface_with_timestamp_offset(LinkType::ETHERNET, -1),
            Err(CaptureError::SizeLimitExceeded {
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
            Err(CaptureError::TimestampOutOfRange {
                format: CaptureFileFormat::PcapNg
            })
        ));
        assert!(matches!(
            timestamp_to_ticks(
                UNIX_EPOCH + Duration::from_secs(1),
                TimestampResolution::Decimal(38),
                0,
            ),
            Err(CaptureError::TimestampOutOfRange {
                format: CaptureFileFormat::PcapNg
            })
        ));
        assert!(matches!(
            system_time_from_signed_unix(i128::MIN, 0),
            Err(CaptureError::TimestampOutOfRange {
                format: CaptureFileFormat::PcapNg
            })
        ));
        assert!(matches!(
            timestamp_from_ticks(1, TimestampResolution::Decimal(12), 0),
            Err(CaptureError::MetadataNotRepresentable {
                format: CaptureFileFormat::PcapNg,
                field: "sub-nanosecond timestamp"
            })
        ));
        assert!(matches!(
            timestamp_to_ticks(
                UNIX_EPOCH + Duration::from_nanos(100),
                TimestampResolution::Binary(10),
                0,
            ),
            Err(CaptureError::MetadataNotRepresentable {
                format: CaptureFileFormat::PcapNg,
                field: "timestamp resolution"
            })
        ));
    }

    #[test]
    fn pcapng_block_limit_is_checked_before_allocation() {
        let writer = CaptureWriter::pcapng(Vec::new()).unwrap();
        let mut bytes = writer.into_inner();
        bytes.extend_from_slice(&1_u32.to_le_bytes());
        bytes.extend_from_slice(&2048_u32.to_le_bytes());

        let mut reader = CaptureReader::with_limit(Cursor::new(bytes), 1024).unwrap();
        assert!(matches!(
            reader.next_frame(),
            Err(CaptureError::SizeLimitExceeded {
                declared: 2048,
                limit: 1024,
                ..
            })
        ));
    }

    #[test]
    fn pcapng_metadata_work_is_bounded_per_read() {
        let section = CaptureWriter::pcapng(Vec::new()).unwrap().into_inner();
        let mut bytes = section.clone();
        bytes.extend_from_slice(&section);
        bytes.extend_from_slice(&section);
        let mut reader = CaptureReader::with_resource_limits(
            Cursor::new(bytes),
            DEFAULT_CAPTURE_SIZE_LIMIT,
            DEFAULT_PCAPNG_INTERFACE_LIMIT,
            1,
        )
        .unwrap();
        assert!(matches!(
            reader.next_frame(),
            Err(CaptureError::MetadataBlockLimit { limit: 1 })
        ));
    }

    #[test]
    fn unknown_classic_link_type_is_preserved() {
        let unknown = LinkType(0xfedc);
        let original = frame(UNIX_EPOCH, unknown, &[9, 8, 7]);
        let mut writer = CaptureWriter::pcap(Vec::new(), unknown).unwrap();
        writer.write_frame(&original).unwrap();

        let decoded = CaptureReader::new(Cursor::new(writer.into_inner()))
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
        let mut writer = CaptureWriter::pcap(Vec::new(), LinkType::ETHERNET).unwrap();
        writer.write_frame(&original).unwrap();
        let mut bytes = writer.into_inner();
        bytes[20..24].copy_from_slice(&0x2400_0001_u32.to_le_bytes());

        let decoded = CaptureReader::new(Cursor::new(bytes))
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

        let mut reader = CaptureReader::with_limit(Cursor::new(bytes), 1024).unwrap();
        assert!(matches!(
            reader.next_frame(),
            Err(CaptureError::SizeLimitExceeded {
                declared: 1025,
                limit: 1024,
                ..
            })
        ));
    }

    #[test]
    fn truncated_records_are_not_reported_as_clean_eof() {
        let mut writer = CaptureWriter::pcap(Vec::new(), LinkType::ETHERNET).unwrap();
        writer
            .write_frame(&frame(UNIX_EPOCH, LinkType::ETHERNET, &[1, 2, 3, 4]))
            .unwrap();
        let mut bytes = writer.into_inner();
        bytes.pop();

        let mut reader = CaptureReader::new(Cursor::new(bytes)).unwrap();
        assert!(matches!(
            reader.next_frame(),
            Err(CaptureError::Truncated {
                context: "pcap packet data",
                ..
            })
        ));
    }

    #[test]
    fn classic_format_rejects_metadata_it_cannot_preserve() {
        let mut writer = CaptureWriter::pcap(Vec::new(), LinkType::ETHERNET).unwrap();
        let mut original = frame(UNIX_EPOCH, LinkType::ETHERNET, &[1]);
        original.interface = Some(0);
        assert!(matches!(
            writer.write_frame(&original),
            Err(CaptureError::MetadataNotRepresentable {
                field: "interface",
                ..
            })
        ));
    }

    #[test]
    fn replay_timing_is_bounded_and_validated() {
        let previous = UNIX_EPOCH + Duration::from_secs(1);
        let current = previous + Duration::from_millis(250);
        assert_eq!(
            ReplayTiming::Original
                .delay_between(previous, current)
                .unwrap(),
            Duration::from_millis(250)
        );
        assert_eq!(
            ReplayTiming::Scaled(2.0)
                .delay_between(previous, current)
                .unwrap(),
            Duration::from_millis(500)
        );
        assert_eq!(
            ReplayTiming::FixedRate(4.0)
                .delay_between(previous, current)
                .unwrap(),
            Duration::from_millis(250)
        );
        assert_eq!(
            ReplayTiming::Immediate
                .delay_between(previous, current)
                .unwrap(),
            Duration::ZERO
        );
        assert!(ReplayTiming::Scaled(0.0)
            .delay_between(previous, current)
            .is_err());
    }
}
