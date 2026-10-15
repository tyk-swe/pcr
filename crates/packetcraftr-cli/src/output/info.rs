// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Published `files info` metadata: what one capture is, without its packets.

use serde::Serialize;

use packetcraftr_core::capture_file::{
    Endianness as LibraryEndianness, Format as LibraryFormat, TimestampResolution as LibraryTicks,
    compression, inspect as library,
};

use super::contract::Error;
use super::frame::Timestamp;

published_enum! {
    pub enum Compression from compression::Format {
        None => "none",
        Gzip => "gzip",
        Zstd => "zstd",
    }
}

published_enum! {
    pub enum Endianness from LibraryEndianness {
        Little => "little",
        Big => "big",
    }
}

published_enum! {
    pub enum Format from LibraryFormat {
        Pcap => "pcap",
        PcapNg => "pcapng",
    }
}

/// PCAPNG section-header version; null for classic PCAP.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct PcapNgVersion {
    pub major: u16,
    pub minor: u16,
}

/// One interface's global identity joined with its declaring metadata.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Interface {
    pub global_id: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub section: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_id: Option<u32>,
    pub link_type: u32,
    pub snap_len: u32,
    pub timestamp_resolution: TimestampResolution,
    pub timestamp_offset: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// The tick resolution one interface's timestamps count in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TimestampResolution {
    /// Ticks are powers of ten: 6 is microseconds, 9 is nanoseconds.
    Decimal(u8),
    /// Ticks are powers of two.
    Binary(u8),
}

impl From<LibraryTicks> for TimestampResolution {
    fn from(value: LibraryTicks) -> Self {
        match value {
            LibraryTicks::Decimal(value) => Self::Decimal(value),
            LibraryTicks::Binary(value) => Self::Binary(value),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct PacketBlocks {
    pub classic: u64,
    pub enhanced: u64,
    pub simple: u64,
    pub obsolete: u64,
}

/// One unknown-block type and how many blocks carried it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct UnknownBlock {
    pub block_type: u32,
    pub count: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Report {
    pub format: Format,
    pub compression: Compression,
    pub endianness: Endianness,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pcapng_version: Option<PcapNgVersion>,
    pub sections: u64,
    pub frames: u64,
    pub captured_bytes: u64,
    pub original_bytes: u64,
    pub truncated_frames: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_timestamp: Option<Timestamp>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_timestamp: Option<Timestamp>,
    pub interfaces: Vec<Interface>,
    pub packet_blocks: PacketBlocks,
    pub name_resolution_blocks: u64,
    pub interface_statistics_blocks: u64,
    pub custom_blocks: u64,
    pub unknown_blocks: Vec<UnknownBlock>,
    pub unknown_block_types_omitted: u64,
    pub declares_fcs: bool,
}

impl TryFrom<(library::InfoReport, Compression)> for Report {
    type Error = Error;

    fn try_from((report, compression): (library::InfoReport, Compression)) -> Result<Self, Error> {
        Ok(Self {
            format: report.format.into(),
            compression,
            endianness: report.endianness.into(),
            pcapng_version: report
                .pcapng_version
                .map(|(major, minor)| PcapNgVersion { major, minor }),
            sections: report.sections,
            frames: report.frames,
            captured_bytes: report.captured_bytes,
            original_bytes: report.original_bytes,
            truncated_frames: report.truncated_frames,
            first_timestamp: report
                .first_timestamp
                .map(Timestamp::try_from)
                .transpose()?,
            last_timestamp: report.last_timestamp.map(Timestamp::try_from).transpose()?,
            interfaces: report
                .interfaces
                .into_iter()
                .map(|interface| Interface {
                    global_id: interface.global_id,
                    section: interface.section,
                    local_id: interface.local_id,
                    link_type: interface.link_type.0,
                    snap_len: interface.snap_len,
                    timestamp_resolution: interface.timestamp_resolution.into(),
                    timestamp_offset: interface.timestamp_offset,
                    name: interface.name,
                    description: interface.description,
                })
                .collect(),
            packet_blocks: PacketBlocks {
                classic: report.packets.classic,
                enhanced: report.packets.enhanced,
                simple: report.packets.simple,
                obsolete: report.packets.obsolete,
            },
            name_resolution_blocks: report.name_resolution_blocks,
            interface_statistics_blocks: report.interface_statistics_blocks,
            custom_blocks: report.custom_blocks,
            unknown_blocks: report
                .unknown_blocks
                .into_iter()
                .map(|(block_type, count)| UnknownBlock { block_type, count })
                .collect(),
            unknown_block_types_omitted: report.unknown_block_types_omitted,
            declares_fcs: report.declares_fcs,
        })
    }
}
