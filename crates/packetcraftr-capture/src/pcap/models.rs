// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::{fmt, io};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::LinkType;
use packetcraftr_error::{Classification, Classified, Kind};

/// Default maximum size of an offline packet or a PCAPNG block (16 MiB).
pub const DEFAULT_SIZE_LIMIT: usize = 16 * 1024 * 1024;
/// Default maximum number of interface descriptions retained per PCAPNG section.
pub const DEFAULT_INTERFACE_LIMIT: usize = 4_096;
/// Default maximum interface descriptions retained across all PCAPNG sections.
pub const DEFAULT_TOTAL_INTERFACE_LIMIT: usize = 65_536;
/// Default maximum metadata blocks consumed before one packet is returned.
pub const DEFAULT_METADATA_BLOCK_LIMIT: usize = 4_096;
/// Default maximum non-frame metadata records retained from a PCAPNG stream.
pub const DEFAULT_METADATA_RECORD_LIMIT: usize = 4_096;
/// Maximum bytes retained from any one comment or resolved name.
pub const MAX_METADATA_TEXT_BYTES: usize = 4 * 1024;
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
    /// Maximum comments, resolved names, and statistics records retained.
    ///
    /// Records past this bound are counted in [`CaptureMetadata::dropped`]
    /// rather than failing the stream, so a capture that carries more
    /// annotation than a caller wants to hold is still readable.
    pub max_metadata_records: usize,
}

impl Default for ReaderOptions {
    fn default() -> Self {
        Self {
            max_size: DEFAULT_SIZE_LIMIT,
            max_interfaces_per_section: DEFAULT_INTERFACE_LIMIT,
            max_total_interfaces: DEFAULT_TOTAL_INTERFACE_LIMIT,
            max_metadata_blocks_per_frame: DEFAULT_METADATA_BLOCK_LIMIT,
            max_metadata_records: DEFAULT_METADATA_RECORD_LIMIT,
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

/// Where a retained PCAPNG comment came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommentScope {
    /// A section header comment, describing the capture as a whole.
    Section,
    /// An interface description comment.
    Interface { interface: u32 },
    /// A packet comment, attached to the frame at this stream position.
    Frame { sequence: u64 },
}

/// One `opt_comment` retained from a PCAPNG stream.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Comment {
    pub scope: CommentScope,
    /// Comment text, truncated to [`MAX_METADATA_TEXT_BYTES`] on a UTF-8
    /// boundary. `truncated` records whether anything was cut.
    pub text: String,
    pub truncated: bool,
}

/// One address-to-name record from a PCAPNG name-resolution block.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NameRecord {
    pub address: std::net::IpAddr,
    pub names: Vec<String>,
}

/// Counters from one PCAPNG interface-statistics block.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterfaceStatistics {
    pub interface: u32,
    /// Frames the capture source reported receiving, when it reported any.
    pub received: Option<u64>,
    /// Frames the capture source reported dropping, when it reported any.
    pub dropped: Option<u64>,
    /// Frames the operating-system filter accepted, when reported.
    pub filter_accepted: Option<u64>,
}

/// Non-frame metadata retained from a PCAPNG stream.
///
/// Retention is bounded by [`ReaderOptions::max_metadata_records`]; anything
/// past that bound is counted rather than stored, so this can never grow with
/// untrusted input.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureMetadata {
    pub comments: Vec<Comment>,
    pub name_records: Vec<NameRecord>,
    pub interface_statistics: Vec<InterfaceStatistics>,
    /// Records seen but not retained because the bound was reached.
    pub dropped: u64,
}

impl CaptureMetadata {
    pub(super) fn retained_records(&self) -> usize {
        let resolved_names = self
            .name_records
            .iter()
            .map(|record| record.names.len().max(1))
            .sum::<usize>();
        self.comments
            .len()
            .saturating_add(resolved_names)
            .saturating_add(self.interface_statistics.len())
    }

    /// Whether anything at all was retained or observed.
    pub fn is_empty(&self) -> bool {
        self.comments.is_empty()
            && self.name_records.is_empty()
            && self.interface_statistics.is_empty()
            && self.dropped == 0
    }

    /// Total records observed, including any the bound excluded.
    pub fn observed(&self) -> u64 {
        self.dropped.saturating_add(self.retained_records() as u64)
    }
}

/// Metadata a transcode could not carry into the target format.
///
/// A copy that loses annotation says so; nothing is dropped silently.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetadataLoss {
    pub comments: u64,
    pub name_records: u64,
    pub interface_statistics: u64,
    /// Records the source declared that the reader could not retain, because
    /// [`ReaderOptions::max_metadata_records`] was reached. Their kind is not
    /// known, so they are counted here rather than in one of the categories
    /// above; leaving them out would understate the loss.
    pub unretained: u64,
}

impl MetadataLoss {
    pub fn is_empty(self) -> bool {
        self.total() == 0
    }

    pub fn total(self) -> u64 {
        self.comments
            .saturating_add(self.name_records)
            .saturating_add(self.interface_statistics)
            .saturating_add(self.unretained)
    }
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
    /// Source metadata the target format could not represent.
    pub dropped_metadata: MetadataLoss,
}

/// An error while reading or writing an offline capture.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
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
    #[error("captured frame contains {actual} bytes, exceeding the u32 capture-record limit")]
    CapturedLengthTooLarge { actual: usize },
    #[error("frame captured length says {declared} bytes but contains {actual}")]
    CapturedLengthMismatch { declared: u32, actual: usize },
    #[error("frame original length {original} is smaller than captured length {captured}")]
    OriginalLengthTooSmall { captured: u32, original: u32 },
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
            Self::FrameLimitExceeded { .. } | Self::StreamByteLimitExceeded { .. } => {
                Classification::new(
                    "policy.capture_stream_limit",
                    Kind::Policy,
                    Some(
                        "reduce the capture stream or deliberately raise its finite frame/byte budget",
                    ),
                )
            }
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
