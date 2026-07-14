// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Pure-Rust, streaming PCAP and PCAPNG support.
//!
//! The implementation deliberately depends only on [`std::io`].  Native
//! libpcap/Npcap is a live-I/O concern and is not required for reading or
//! writing capture files.

mod classic;
mod models;
mod pcapng;
mod reader;
mod transcode;
mod wire;
mod writer;

pub use models::{
    DEFAULT_INTERFACE_LIMIT, DEFAULT_METADATA_BLOCK_LIMIT, DEFAULT_SIZE_LIMIT,
    DEFAULT_STREAM_BYTES, DEFAULT_STREAM_FRAMES, DEFAULT_TOTAL_INTERFACE_LIMIT, Endianness, Error,
    Format, Interface, Limits, TimestampResolution, TranscodeReport,
};
pub use reader::Reader;
pub use transcode::transcode;
pub use writer::Writer;

#[cfg(test)]
mod tests;
