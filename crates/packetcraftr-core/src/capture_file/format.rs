// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Capture formats and their writer options.

use serde::{Deserialize, Serialize};

use crate::frame::DEFAULT_MAX_SIZE;

use super::limits::{DEFAULT_MAX_INTERFACES_PER_SECTION, Limits};
use super::wire::WRITER_TIMESTAMP_RESOLUTION;

/// Classic PCAP file configuration.
///
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
    /// Byte order used for the global header and every packet record.
    pub endianness: Endianness,
    /// Timestamp precision. Classic PCAP supports decimal microseconds or nanoseconds.
    pub timestamp_resolution: TimestampResolution,
    /// Snapshot length written to the global header, in bytes.
    pub snap_len: usize,
    /// Maximum captured packet size accepted by the writer, in bytes.
    pub max_size: usize,
    /// Aggregate frame and captured-payload ceilings for the whole stream.
    /// Fixed at construction, so a writer's limits cannot be retuned once it
    /// has begun producing output.
    pub stream_limits: Limits,
}

impl Default for PcapOptions {
    fn default() -> Self {
        Self {
            endianness: Endianness::Little,
            timestamp_resolution: WRITER_TIMESTAMP_RESOLUTION,
            snap_len: DEFAULT_MAX_SIZE,
            max_size: DEFAULT_MAX_SIZE,
            stream_limits: Limits::default(),
        }
    }
}

/// PCAPNG section configuration.
///
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
    /// Byte order used for the section and its blocks.
    pub endianness: Endianness,
    /// Maximum block and captured packet size, in bytes.
    pub max_size: usize,
    pub max_interfaces: usize,
    /// Aggregate frame and captured-payload ceilings for the whole stream.
    /// Fixed at construction, so a writer's limits cannot be retuned once it
    /// has begun producing output.
    pub stream_limits: Limits,
}

impl Default for PcapNgOptions {
    fn default() -> Self {
        Self {
            endianness: Endianness::Little,
            max_size: DEFAULT_MAX_SIZE,
            max_interfaces: DEFAULT_MAX_INTERFACES_PER_SECTION,
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
    /// The stable lowercase display name: `pcap` or `pcapng`.
    ///
    /// Consumers publish this spelling verbatim, so it must not change. The
    /// serde form of [`Format::PcapNg`] is `pcap_ng`, a separate spelling that
    /// makes no output commitment.
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

/// Timestamp tick resolution declared by classic PCAP or one PCAPNG interface.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TimestampResolution {
    Decimal(u8),
    Binary(u8),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum TimestampPrecision {
    Microseconds,
    Nanoseconds,
}
