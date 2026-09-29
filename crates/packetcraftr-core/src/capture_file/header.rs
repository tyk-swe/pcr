// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Capture headers and interface descriptions read when a capture opens.

use bytes::Bytes;
use serde::{Deserialize, Serialize};

use crate::frame::LinkType;

use super::format::{Endianness, Format, TimestampResolution};
use super::wire::PCAPNG_OPTION_IF_FCSLEN;

/// Metadata associated with one capture interface.
///
/// The index in [`crate::capture_file::Reader::interfaces`] is the global interface
/// ID used by [`crate::frame::Frame::interface`]. Source-local
/// section and interface identifiers remain available on
/// [`CaptureRecord`](crate::capture_file::CaptureRecord).
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

impl PcapNgOption {
    /// An `if_fcslen` of zero bits declares no FCS; any other value, including a malformed one,
    /// is treated as declaring one.
    pub(super) fn declares_fcs(&self) -> bool {
        self.code == PCAPNG_OPTION_IF_FCSLEN && self.value.as_ref() != [0]
    }
}

/// libpcap's `LT_FCS_LENGTH_PRESENT` flag and `LT_FCS_LENGTH` field, in 16-bit words, above the
/// LINKTYPE; the length is ignored unless the flag is set.
const PCAP_FCS_LENGTH_PRESENT: u32 = 0x0400_0000;
const PCAP_FCS_LENGTH: u32 = 0xf000_0000;

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

impl PcapHeader {
    pub(super) fn declares_fcs(&self) -> bool {
        self.network & PCAP_FCS_LENGTH_PRESENT != 0 && self.network & PCAP_FCS_LENGTH != 0
    }
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
