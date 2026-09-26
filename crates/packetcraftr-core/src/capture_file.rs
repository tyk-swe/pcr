// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Capture files: portable streaming PCAP/PCAPNG I/O with optional gzip/Zstd
//! support; no native libpcap/Npcap dependency. [`rewrite`](fn@rewrite)
//! preserves validated source records and format; [`Writer`] creates new
//! captures from frames.

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
