// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use bytes::Bytes;
use serde::{Deserialize, Serialize};

use crate::frame::{DEFAULT_SIZE_LIMIT, LinkType};

use super::error::Error;

pub const DEFAULT_INTERFACE_LIMIT: usize = 4_096;
pub const DEFAULT_TOTAL_INTERFACE_LIMIT: usize = 65_536;
pub const DEFAULT_METADATA_BLOCK_LIMIT: usize = 4_096;
pub const DEFAULT_METADATA_BYTE_LIMIT: usize = 64 * 1024 * 1024;
pub const DEFAULT_STREAM_FRAMES: u64 = 10_000;
pub const DEFAULT_STREAM_BYTES: u64 = 256 * 1024 * 1024;

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
    pub fn validate(&self) -> Result<(), Error> {
        for (field, value) in [
            ("max_frames", self.max_frames),
            ("max_bytes", self.max_bytes),
        ] {
            if value == 0 {
                return Err(Error::InvalidLimit { field, value });
            }
        }
        Ok(())
    }
}

/// A charge that would exceed either ceiling fails and leaves the budget
/// unchanged.
///
/// ```rust
/// use packetcraftr_core::capture_file::{Budget, Error, Limits};
///
/// let mut budget = Budget::new(Limits { max_frames: 1, max_bytes: 64 })?;
/// budget.charge(60)?;
/// assert!(matches!(budget.charge(1), Err(Error::FrameLimitExceeded { .. })));
/// assert_eq!((budget.frames(), budget.captured_bytes()), (1, 60));
/// # Ok::<(), Error>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Budget {
    limits: Limits,
    frames: u64,
    captured_bytes: u64,
}

impl Budget {
    pub fn new(limits: Limits) -> Result<Self, Error> {
        limits.validate()?;
        Ok(Self {
            limits,
            frames: 0,
            captured_bytes: 0,
        })
    }

    #[must_use]
    pub fn limits(&self) -> Limits {
        self.limits
    }

    #[must_use]
    pub fn frames(&self) -> u64 {
        self.frames
    }

    #[must_use]
    pub fn captured_bytes(&self) -> u64 {
        self.captured_bytes
    }

    #[cfg(test)]
    pub(super) fn charged(limits: Limits, frames: u64, captured_bytes: u64) -> Self {
        Self {
            limits,
            frames,
            captured_bytes,
        }
    }

    pub fn charge(&mut self, frame_bytes: u32) -> Result<(), Error> {
        *self = self.after(frame_bytes)?;
        Ok(())
    }

    pub fn after(&self, frame_bytes: u32) -> Result<Self, Error> {
        let frames = self
            .frames
            .checked_add(1)
            .ok_or(Error::FrameLimitExceeded {
                actual: u64::MAX,
                limit: self.limits.max_frames,
            })?;
        if frames > self.limits.max_frames {
            return Err(Error::FrameLimitExceeded {
                actual: frames,
                limit: self.limits.max_frames,
            });
        }

        let captured_bytes = self
            .captured_bytes
            .checked_add(u64::from(frame_bytes))
            .ok_or(Error::StreamByteLimitExceeded {
                actual: u64::MAX,
                limit: self.limits.max_bytes,
            })?;
        if captured_bytes > self.limits.max_bytes {
            return Err(Error::StreamByteLimitExceeded {
                actual: captured_bytes,
                limit: self.limits.max_bytes,
            });
        }

        Ok(Self {
            frames,
            captured_bytes,
            ..*self
        })
    }
}

/// A zero value disables that class of input rather than being rejected.
///
/// ```rust
/// use std::io::Cursor;
/// use packetcraftr_core::capture_file::{Reader, ReaderLimits, Writer};
/// use packetcraftr_core::frame::LinkType;
///
/// let bytes = Writer::pcap(Vec::new(), LinkType::ETHERNET)?.into_inner();
/// let options = ReaderLimits {
///     max_size: 64 * 1024,
///     ..ReaderLimits::default()
/// };
/// let _reader = Reader::with_limits(Cursor::new(bytes), options)?;
/// # Ok::<(), packetcraftr_core::capture_file::Error>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReaderLimits {
    pub max_size: usize,
    pub max_interfaces_per_section: usize,
    pub max_total_interfaces: usize,
    pub max_metadata_blocks_per_frame: usize,
    pub max_metadata_bytes_per_frame: usize,
}

impl Default for ReaderLimits {
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

/// ```rust
/// use packetcraftr_core::capture_file::{Endianness, PcapOptions, Writer};
/// use packetcraftr_core::frame::LinkType;
///
/// let options = PcapOptions {
///     endianness: Endianness::Big,
///     snap_len: 65_535,
///     max_size: 65_535,
///     ..PcapOptions::default()
/// };
/// let _writer = Writer::pcap_with_options(Vec::new(), LinkType::ETHERNET, options)?;
/// # Ok::<(), packetcraftr_core::capture_file::Error>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PcapOptions {
    pub endianness: Endianness,
    pub timestamp_resolution: TimestampResolution,
    pub snap_len: usize,
    pub max_size: usize,
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

/// ```rust
/// use packetcraftr_core::capture_file::{PcapNgOptions, Writer};
/// use packetcraftr_core::frame::LinkType;
///
/// let options = PcapNgOptions {
///     max_interfaces: 8,
///     ..PcapNgOptions::default()
/// };
/// let mut writer = Writer::pcapng_with_options(Vec::new(), options)?;
/// writer.add_interface(LinkType::ETHERNET)?;
/// # Ok::<(), packetcraftr_core::capture_file::Error>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PcapNgOptions {
    pub endianness: Endianness,
    pub max_size: usize,
    pub max_interfaces: usize,
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Format {
    Pcap,
    PcapNg,
}

impl Format {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pcap => "pcap",
            Self::PcapNg => "pcapng",
        }
    }
}

display_via_as_str!(Format);

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Endianness {
    #[default]
    Little,
    Big,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TimestampResolution {
    Decimal(u8),
    Binary(u8),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Interface {
    pub link_type: LinkType,
    pub snap_len: u32,
    pub timestamp_resolution: TimestampResolution,
    pub timestamp_offset: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PcapNgOption {
    pub code: u16,
    pub value: Bytes,
}

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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PacketBlockKind {
    Classic,
    Enhanced,
    Simple,
    Obsolete,
}

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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SelectionReport {
    pub format: Format,
    pub frames_read: u64,
    pub frames_selected: u64,
    pub captured_bytes_read: u64,
    pub captured_bytes_selected: u64,
    pub interfaces: usize,
    pub metadata_records: u64,
}

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
