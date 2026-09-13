// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Portable, streaming PCAP and PCAPNG support.
//!
//! Format I/O uses [`std::io`], with optional gzip/Zstd adapters. Native
//! libpcap/Npcap is not required for capture-file access.
//!
//! [`rewrite`] is the fidelity-preserving path: it validates and copies every
//! bounded source record without changing formats. [`Writer`] creates a new
//! capture from frames and therefore is not a source-structure rewrite API.

mod classic;
pub mod compression;
mod error;
mod map;
mod merge;
pub use map::{MapError, MapReport, map_frames};
mod model;
mod pcapng;
mod reader;
mod rewrite;
mod wire;
mod writer;

pub use error::{Error, SelectionError};
pub use merge::{MergeError, MergeLimits, MergeReport, MergeSource, MergedInterface, merge};
pub use model::{
    CaptureHeader, CaptureRecord, DEFAULT_INTERFACE_LIMIT, DEFAULT_METADATA_BLOCK_LIMIT,
    DEFAULT_METADATA_BYTE_LIMIT, DEFAULT_STREAM_BYTES, DEFAULT_STREAM_FRAMES,
    DEFAULT_TOTAL_INTERFACE_LIMIT, Endianness, Format, Interface, Limits, MetadataBlockKind,
    PacketBlockKind, PcapHeader, PcapNgOption, PcapNgOptions, PcapOptions, ReaderOptions,
    RecordKind, RewriteReport, Section, SelectionReport, TimestampResolution,
};
pub use reader::Reader;
pub use rewrite::{rewrite, select};
pub use writer::Writer;
