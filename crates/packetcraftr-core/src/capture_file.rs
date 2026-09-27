// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Capture files: portable streaming PCAP/PCAPNG I/O with optional gzip/Zstd
//! support; no native libpcap/Npcap dependency. [`rewrite`](fn@rewrite)
//! preserves validated source records and format; [`Writer`] creates new
//! captures from frames.
//!
//! This module also owns link-type knowledge: the known
//! [`LinkType`](crate::frame::LinkType) numbers and the single mapping
//! between a link type and its built-in root protocol
//! ([`LinkType::BUILTIN_ROOTS`](crate::frame::LinkType::BUILTIN_ROOTS),
//! [`root_protocol`](crate::frame::LinkType::root_protocol),
//! [`for_root_protocol`](crate::frame::LinkType::for_root_protocol)).

mod classic;
pub mod compression;
mod error;
mod link_type;
mod map;
mod merge;
pub use map::{MapReport, map_frames};
mod model;
mod pcapng;
mod reader;
mod rewrite;
mod wire;
mod writer;

pub use error::Error;
pub use merge::{MAX_MERGE_SOURCES, MergeLimits, MergeReport, MergeSource, MergedInterface, merge};
pub use model::{
    Budget, CaptureHeader, CaptureRecord, DEFAULT_MAX_INTERFACES_PER_SECTION,
    DEFAULT_MAX_METADATA_BLOCKS_PER_FRAME, DEFAULT_MAX_METADATA_BYTES_PER_FRAME,
    DEFAULT_MAX_STREAM_BYTES, DEFAULT_MAX_STREAM_FRAMES, DEFAULT_MAX_TOTAL_INTERFACES, Endianness,
    Format, Interface, Limits, MetadataBlockKind, PacketBlockKind, PcapHeader, PcapNgOption,
    PcapNgOptions, PcapOptions, ReaderLimits, RecordKind, RewriteReport, Section, SelectionReport,
    TimestampResolution,
};
pub use reader::Reader;
pub use rewrite::{rewrite, select};
pub use writer::Writer;
