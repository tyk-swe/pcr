// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Capture headers and interface descriptions read when a capture opens.

use bytes::Bytes;
use serde::{Deserialize, Serialize};

use crate::frame::LinkType;

use super::format::{Endianness, Format, TimestampResolution};

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
