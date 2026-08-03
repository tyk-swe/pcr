// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::{fmt, io};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::LinkType;
use packetcraftr_core::error::{Classification, Classified, Kind};
use packetcraftr_core::frame::FrameError;

/// Default maximum size of an offline packet or a PCAPNG block (16 MiB).
pub use packetcraftr_core::frame::DEFAULT_SIZE_LIMIT;
/// Default maximum number of interface descriptions retained per PCAPNG section.
pub const DEFAULT_INTERFACE_LIMIT: usize = 4_096;
/// Default maximum interface descriptions retained across all PCAPNG sections.
pub const DEFAULT_TOTAL_INTERFACE_LIMIT: usize = 65_536;
/// Default maximum metadata blocks consumed before one packet is returned.
pub const DEFAULT_METADATA_BLOCK_LIMIT: usize = 4_096;
/// Default maximum metadata bytes consumed before one packet is returned.
pub const DEFAULT_METADATA_BYTE_LIMIT: usize = 64 * 1024 * 1024;
/// Default maximum frames accepted by one streaming capture writer or copy.
pub const DEFAULT_STREAM_FRAMES: u64 = 10_000;
/// Default maximum captured payload bytes accepted by one streaming writer or copy.
pub const DEFAULT_STREAM_BYTES: u64 = 256 * 1024 * 1024;

/// Aggregate frame and captured-byte ceilings for a streaming capture operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Limits {
    pub max_frames: u64,
    pub max_bytes: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_frames: DEFAULT_STREAM_FRAMES,
            max_bytes: DEFAULT_STREAM_BYTES,
        }
    }
}

/// Resource ceilings applied while streaming an offline capture.
///
/// Limits are enforced where their corresponding input is encountered. A zero
/// value therefore disables that class of input rather than being rejected
/// uniformly during construction.
///
/// ```
/// use std::io::Cursor;
/// use packetcraftr_capture::{LinkType, Reader, ReaderOptions, Writer};
///
/// # fn example() -> Result<(), packetcraftr_capture::Error> {
/// let bytes = Writer::pcap(Vec::new(), LinkType::ETHERNET)?.into_inner();
/// let options = ReaderOptions {
///     max_size: 64 * 1024,
///     ..ReaderOptions::default()
/// };
/// let _reader = Reader::with_options(Cursor::new(bytes), options)?;
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReaderOptions {
    /// Maximum packet or PCAPNG block size, in bytes.
    pub max_size: usize,
    /// Maximum interface descriptions retained from one PCAPNG section.
    pub max_interfaces_per_section: usize,
    /// Maximum interface descriptions retained across all PCAPNG sections.
    pub max_total_interfaces: usize,
    /// Maximum metadata blocks consumed while seeking the next frame.
    pub max_metadata_blocks_per_frame: usize,
    /// Maximum metadata bytes consumed while seeking the next frame.
    pub max_metadata_bytes_per_frame: usize,
}

impl Default for ReaderOptions {
    fn default() -> Self {
        Self {
            max_size: DEFAULT_SIZE_LIMIT,
            max_interfaces_per_section: DEFAULT_INTERFACE_LIMIT,
            max_total_interfaces: DEFAULT_TOTAL_INTERFACE_LIMIT,
            max_metadata_blocks_per_frame: DEFAULT_METADATA_BLOCK_LIMIT,
            max_metadata_bytes_per_frame: DEFAULT_METADATA_BYTE_LIMIT,
        }
    }
}

/// Classic PCAP file configuration.
///
/// ```
/// use packetcraftr_capture::{Endianness, LinkType, PcapOptions, Writer};
///
/// # fn example() -> Result<(), packetcraftr_capture::Error> {
/// let options = PcapOptions {
///     endianness: Endianness::Big,
///     snap_len: 65_535,
///     max_size: 65_535,
///     ..PcapOptions::default()
/// };
/// let _writer = Writer::pcap_with_options(Vec::new(), LinkType::ETHERNET, options)?;
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PcapOptions {
    /// Byte order used for the global header and every packet record.
    pub endianness: Endianness,
    /// Timestamp precision. Classic PCAP supports decimal microseconds or nanoseconds.
    pub timestamp_resolution: TimestampResolution,
    /// Snapshot length written to the global header, in bytes.
    pub snap_len: usize,
    /// Maximum captured packet size accepted by the writer, in bytes.
    pub max_size: usize,
}

impl Default for PcapOptions {
    fn default() -> Self {
        Self {
            endianness: Endianness::Little,
            timestamp_resolution: TimestampResolution::Decimal(9),
            snap_len: DEFAULT_SIZE_LIMIT,
            max_size: DEFAULT_SIZE_LIMIT,
        }
    }
}

/// PCAPNG section configuration.
///
/// ```
/// use packetcraftr_capture::{LinkType, PcapNgOptions, Writer};
///
/// # fn example() -> Result<(), packetcraftr_capture::Error> {
/// let options = PcapNgOptions {
///     max_interfaces: 8,
///     ..PcapNgOptions::default()
/// };
/// let mut writer = Writer::pcapng_with_options(Vec::new(), options)?;
/// writer.add_interface(LinkType::ETHERNET)?;
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PcapNgOptions {
    /// Byte order used for the section and its blocks.
    pub endianness: Endianness,
    /// Maximum block and captured packet size, in bytes.
    pub max_size: usize,
    /// Maximum number of interface descriptions in the section.
    pub max_interfaces: usize,
}

impl Default for PcapNgOptions {
    fn default() -> Self {
        Self {
            endianness: Endianness::Little,
            max_size: DEFAULT_SIZE_LIMIT,
            max_interfaces: DEFAULT_INTERFACE_LIMIT,
        }
    }
}

/// Capture container format.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Format {
    /// The classic libpcap file format.
    Pcap,
    /// The extensible pcapng file format.
    PcapNg,
}

impl fmt::Display for Format {
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
pub enum Endianness {
    #[default]
    Little,
    Big,
}

/// Timestamp tick resolution declared by classic PCAP or one PCAPNG interface.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TimestampResolution {
    Decimal(u8),
    Binary(u8),
}

/// Metadata associated with one capture interface.
///
/// The index in [`crate::Reader::interfaces`] is the global interface
/// ID used by [`crate::Frame::interface`]. Multiple PCAPNG sections are normalized to
/// one monotonically increasing namespace.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Interface {
    pub link_type: LinkType,
    pub snap_len: u32,
    pub timestamp_resolution: TimestampResolution,
    pub timestamp_offset: i64,
}

/// Result of a bounded streaming capture copy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TranscodeReport {
    pub source_format: Format,
    pub target_format: Format,
    pub endianness: Endianness,
    pub frames: u64,
    pub captured_bytes: u64,
    pub interfaces: usize,
}

/// An error while reading or writing an offline capture.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    #[error(transparent)]
    Frame(#[from] FrameError),
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
        format: Format,
        major: u16,
        minor: u16,
    },
    #[error("invalid {format} data: {reason}")]
    InvalidData {
        format: Format,
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
    #[error(
        "pcapng block of {block_length} bytes crosses the section boundary with {remaining} bytes remaining"
    )]
    BlockCrossesSectionBoundary { block_length: u32, remaining: u64 },
    #[error("pcapng section ended with {remaining} declared bytes remaining")]
    SectionEndedEarly { remaining: u64 },
    #[error("new pcapng section begins with {remaining} declared bytes remaining")]
    SectionHeaderBeforeBoundary { remaining: u64 },
    #[error("pcapng section has {remaining} bytes remaining, fewer than a complete block header")]
    SectionRemainderTooSmall { remaining: u64 },
    #[error("timestamp cannot be represented in {format}")]
    TimestampOutOfRange { format: Format },
    #[error("timestamp fraction {fraction} is invalid for a denominator of {denominator}")]
    InvalidTimestampFraction { fraction: u32, denominator: u32 },
    #[error("link type {link_type} cannot be represented in a capture interface header")]
    LinkTypeOutOfRange { link_type: u32 },
    #[error("interface {interface} is not defined (the section has {available} interfaces)")]
    UndefinedInterface { interface: u32, available: usize },
    #[error("pcapng section exceeds the configured interface limit of {limit}")]
    InterfaceLimit { limit: usize },
    #[error("pcapng stream exceeds the configured retained-interface limit of {limit}")]
    TotalInterfaceLimit { limit: usize },
    #[error("pcapng stream exceeded {limit} metadata blocks before the next packet")]
    MetadataBlockLimit { limit: usize },
    #[error("pcapng stream exceeded {limit} metadata bytes before the next packet")]
    MetadataByteLimit { limit: usize },
    #[error("frame link type {actual} does not match interface {interface} link type {expected}")]
    InterfaceLinkTypeMismatch {
        interface: u32,
        expected: u32,
        actual: u32,
    },
    #[error("more than one pcapng interface uses link type {link_type}; select one explicitly")]
    AmbiguousInterface { link_type: u32 },
    #[error("{field} metadata cannot be represented in {format}")]
    MetadataNotRepresentable { format: Format, field: &'static str },
    #[error("this operation requires {expected}, but the writer is configured for {actual}")]
    WrongWriterFormat { expected: Format, actual: Format },
    #[error("capture stream frame count {actual} exceeds the configured limit of {limit}")]
    FrameLimitExceeded { actual: u64, limit: u64 },
    #[error("capture stream payload bytes {actual} exceed the configured limit of {limit}")]
    StreamByteLimitExceeded { actual: u64, limit: u64 },
    #[error("capture timestamp resolution {base}^{exponent} cannot be represented")]
    InvalidTimestampResolution { base: u8, exponent: u8 },
}

impl Classified for Error {
    fn classification(&self) -> Classification {
        match self {
            Self::Io(_) => Classification::new(
                "io.capture_file",
                Kind::Io,
                Some(
                    "inspect the capture input/output stream and retry from a known record boundary",
                ),
            ),
            Self::InvalidTimestampResolution { .. } => Classification::new(
                "cli.capture_option",
                Kind::Cli,
                Some("use a supported finite capture timestamp or replay timing option"),
            ),
            Self::SizeLimitExceeded { .. }
            | Self::InterfaceLimit { .. }
            | Self::TotalInterfaceLimit { .. }
            | Self::MetadataBlockLimit { .. }
            | Self::MetadataByteLimit { .. }
            | Self::FrameLimitExceeded { .. }
            | Self::StreamByteLimitExceeded { .. } => Classification::new(
                "policy.capture_stream_limit",
                Kind::Policy,
                Some(
                    "reduce the capture stream or deliberately raise its finite frame/byte budget",
                ),
            ),
            _ => Classification::new(
                "packet.capture_file",
                Kind::Packet,
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
pub(super) enum TimestampPrecision {
    Microseconds,
    Nanoseconds,
}
