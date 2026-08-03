// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#![forbid(unsafe_code)]

//! Runtime-neutral capture records and streaming offline capture I/O.

mod pcap;

pub use packetcraftr_core::frame::{Direction, Frame, FrameError, LinkType};
pub use pcap::{
    DEFAULT_INTERFACE_LIMIT, DEFAULT_METADATA_BLOCK_LIMIT, DEFAULT_METADATA_BYTE_LIMIT,
    DEFAULT_SIZE_LIMIT, DEFAULT_STREAM_BYTES, DEFAULT_STREAM_FRAMES, DEFAULT_TOTAL_INTERFACE_LIMIT,
    Endianness, Error, Format, Interface, Limits, PcapNgOptions, PcapOptions, Reader,
    ReaderOptions, TimestampResolution, TranscodeReport, Writer, transcode,
};
