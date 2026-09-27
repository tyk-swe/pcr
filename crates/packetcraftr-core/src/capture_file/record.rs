// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded capture records and the kind metadata each retains.

use bytes::Bytes;
use serde::{Deserialize, Serialize};

use super::format::Format;
use super::header::{Interface, PcapNgOption, Section};

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
