// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::fmt;

use bytes::Bytes;
use serde::{Deserialize, Serialize};

pub use crate::frame::DEFAULT_SIZE_LIMIT;
use crate::frame::LinkType;

use super::error::Error;

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

impl Limits {
    /// Admits one more frame, returning the new frame and captured-byte
    /// totals, or the ceiling it would have crossed.
    ///
    /// Every path that streams frames under an aggregate budget — the rewrite
    /// copy, the analysis loop, and the CLI's per-frame reader — charges
    /// through here.
    pub fn advance(
        self,
        frames: u64,
        captured_bytes: u64,
        frame_bytes: u32,
    ) -> Result<(u64, u64), Error> {
        let frames = frames.checked_add(1).ok_or(Error::FrameLimitExceeded {
            actual: u64::MAX,
            limit: self.max_frames,
        })?;
        if frames > self.max_frames {
            return Err(Error::FrameLimitExceeded {
                actual: frames,
                limit: self.max_frames,
            });
        }

        let captured_bytes = captured_bytes.checked_add(u64::from(frame_bytes)).ok_or(
            Error::StreamByteLimitExceeded {
                actual: u64::MAX,
                limit: self.max_bytes,
            },
        )?;
        if captured_bytes > self.max_bytes {
            return Err(Error::StreamByteLimitExceeded {
                actual: captured_bytes,
                limit: self.max_bytes,
            });
        }

        Ok((frames, captured_bytes))
    }
}

/// Resource ceilings applied while streaming an offline capture.
///
/// Limits are enforced where their corresponding input is encountered. A zero
/// value therefore disables that class of input rather than being rejected
/// uniformly during construction.
///
/// ```rust
/// use std::io::Cursor;
/// use packetcraftr_core::analysis::pcap::{Reader, ReaderOptions, Writer};
/// use packetcraftr_core::frame::LinkType;
///
/// let bytes = Writer::pcap(Vec::new(), LinkType::ETHERNET)?.into_inner();
/// let options = ReaderOptions {
///     max_size: 64 * 1024,
///     ..ReaderOptions::default()
/// };
/// let _reader = Reader::with_options(Cursor::new(bytes), options)?;
/// # Ok::<(), packetcraftr_core::analysis::pcap::Error>(())
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
/// ```rust
/// use packetcraftr_core::analysis::pcap::{Endianness, PcapOptions, Writer};
/// use packetcraftr_core::frame::LinkType;
///
/// let options = PcapOptions {
///     endianness: Endianness::Big,
///     snap_len: 65_535,
///     max_size: 65_535,
///     ..PcapOptions::default()
/// };
/// let _writer = Writer::pcap_with_options(Vec::new(), LinkType::ETHERNET, options)?;
/// # Ok::<(), packetcraftr_core::analysis::pcap::Error>(())
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
    /// Aggregate frame and captured-payload ceilings for the whole stream.
    /// Fixed at construction, so a writer's budget cannot be retuned once it
    /// has begun producing output.
    pub stream_limits: Limits,
}

impl Default for PcapOptions {
    fn default() -> Self {
        Self {
            endianness: Endianness::Little,
            timestamp_resolution: TimestampResolution::Decimal(9),
            snap_len: DEFAULT_SIZE_LIMIT,
            max_size: DEFAULT_SIZE_LIMIT,
            stream_limits: Limits::default(),
        }
    }
}

/// PCAPNG section configuration.
///
/// ```rust
/// use packetcraftr_core::analysis::pcap::{PcapNgOptions, Writer};
/// use packetcraftr_core::frame::LinkType;
///
/// let options = PcapNgOptions {
///     max_interfaces: 8,
///     ..PcapNgOptions::default()
/// };
/// let mut writer = Writer::pcapng_with_options(Vec::new(), options)?;
/// writer.add_interface(LinkType::ETHERNET)?;
/// # Ok::<(), packetcraftr_core::analysis::pcap::Error>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PcapNgOptions {
    /// Byte order used for the section and its blocks.
    pub endianness: Endianness,
    /// Maximum block and captured packet size, in bytes.
    pub max_size: usize,
    /// Maximum number of interface descriptions in the section.
    pub max_interfaces: usize,
    /// Aggregate frame and captured-payload ceilings for the whole stream.
    /// Fixed at construction, so a writer's budget cannot be retuned once it
    /// has begun producing output.
    pub stream_limits: Limits,
}

impl Default for PcapNgOptions {
    fn default() -> Self {
        Self {
            endianness: Endianness::Little,
            max_size: DEFAULT_SIZE_LIMIT,
            max_interfaces: DEFAULT_INTERFACE_LIMIT,
            stream_limits: Limits::default(),
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
/// The index in [`crate::analysis::pcap::Reader::interfaces`] is the global interface
/// ID used by [`crate::frame::Frame::interface`]. Source-local
/// section and interface identifiers remain available on [`CaptureRecord`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Interface {
    pub link_type: LinkType,
    pub snap_len: u32,
    pub timestamp_resolution: TimestampResolution,
    pub timestamp_offset: i64,
}

/// One option carried by a PCAPNG section, interface, or packet block.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PcapNgOption {
    pub code: u16,
    pub value: Bytes,
}

/// Parsed classic-PCAP global-header fields that affect packet interpretation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PcapHeader {
    pub endianness: Endianness,
    pub timestamp_resolution: TimestampResolution,
    pub snap_len: u32,
    /// Complete 32-bit network word, including standardized high-bit FCS metadata.
    pub network: u32,
    #[serde(skip)]
    pub(super) raw: Bytes,
}

/// Parsed PCAPNG section-header fields.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Section {
    pub index: u64,
    pub endianness: Endianness,
    pub major: u16,
    pub minor: u16,
    pub length: Option<u64>,
    pub options: Vec<PcapNgOption>,
    #[serde(skip)]
    pub(super) raw: Bytes,
}

/// Header consumed when a streaming reader is opened.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CaptureHeader {
    Pcap(PcapHeader),
    PcapNg(Section),
}

impl CaptureHeader {
    pub fn format(&self) -> Format {
        match self {
            Self::Pcap(_) => Format::Pcap,
            Self::PcapNg(_) => Format::PcapNg,
        }
    }

    pub(super) fn raw(&self) -> &[u8] {
        match self {
            Self::Pcap(header) => &header.raw,
            Self::PcapNg(section) => &section.raw,
        }
    }
}

/// Packet-block representation retained by one [`CaptureRecord`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PacketBlockKind {
    Classic,
    Enhanced,
    Simple,
    Obsolete,
}

/// Metadata-block representation retained by one [`CaptureRecord`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MetadataBlockKind {
    Section(Section),
    InterfaceDescription {
        section: u64,
        local_id: u32,
        global_id: u32,
        interface: Interface,
        options: Vec<PcapNgOption>,
    },
    NameResolution {
        section: u64,
    },
    InterfaceStatistics {
        section: u64,
        interface_id: u32,
    },
    Custom {
        section: u64,
        block_type: u32,
    },
    Unknown {
        section: u64,
        block_type: u32,
    },
}

/// Kind and source location of one capture record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordKind {
    Packet {
        block: PacketBlockKind,
        section: Option<u64>,
        interface_id: Option<u32>,
        options: Vec<PcapNgOption>,
    },
    Metadata(MetadataBlockKind),
}

/// One bounded source record, including its validated raw representation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CaptureRecord {
    pub kind: RecordKind,
    pub frame: Option<crate::frame::Frame>,
    pub(super) format: Format,
    pub(super) raw: Bytes,
}

impl CaptureRecord {
    pub fn format(&self) -> Format {
        self.format
    }

    pub fn raw_bytes(&self) -> &[u8] {
        &self.raw
    }
}

/// Result of a bounded streaming capture rewrite.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RewriteReport {
    pub format: Format,
    pub frames: u64,
    pub captured_bytes: u64,
    pub interfaces: usize,
    pub metadata_records: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum TimestampPrecision {
    Microseconds,
    Nanoseconds,
}
