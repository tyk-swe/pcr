// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::path::PathBuf;

use packetcraftr_core::analysis::StreamRef;

use crate::command_options::{
    CompressionArgs, DecodeArgs, Destination, OfflineLimitsArgs, Selector, stream_selector,
};

pub(crate) const AFTER_LONG_HELP: &str = r"Export selects whole conversations (--stream), IP datagrams by a physical frame they contain (--datagram-frame), or frames a --filter matches, and writes the selected physical frames together with every frame they depend on, such as the other fragments of a reassembled datagram. The destination keeps the source capture format and metadata and is published only after every frame was written.

Examples:
  packetcraftr export capture.pcapng --write conversation.pcapng --stream tcp:4
  packetcraftr export capture.pcap --write datagram.pcap --datagram-frame 12
  packetcraftr export capture.pcapng --write dns.pcapng --filter 'dns'";

#[derive(Debug, clap::Args)]
pub(crate) struct Args {
    /// Source PCAP/PCAPNG; - reads redirected stdin. Compression is detected.
    pub(crate) path: PathBuf,
    /// New destination, preserving the source capture format and metadata.
    #[arg(long)]
    pub(crate) write: PathBuf,
    /// Whole conversations, as tcp:INDEX or udp:INDEX. Repeat to select several.
    #[arg(long = "stream", value_name = "TRANSPORT:INDEX", value_parser = stream_selector)]
    pub(crate) streams: Vec<Selector<StreamRef>>,
    /// Include complete or incomplete IP datagrams containing this physical frame.
    #[arg(long = "datagram-frame")]
    pub(crate) datagram_frames: Vec<u64>,
    /// Match physical or reconstructed fields, including attached IP dependencies.
    #[arg(long)]
    pub(crate) filter: Option<String>,
    /// Maximum physical frames selected for export; at most 1,000,000.
    #[arg(long, default_value_t = 100_000)]
    pub(crate) max_selected_frames: usize,
    #[command(flatten)]
    pub(crate) compression: CompressionArgs<SavedCapture>,
    #[command(flatten)]
    pub(crate) decode: DecodeArgs,
    #[command(flatten)]
    pub(crate) limits: OfflineLimitsArgs,
}

/// The saved export, in its source capture format.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct SavedCapture;

impl Destination for SavedCapture {
    const HELP: &'static str = "Compression of the saved capture file";
}
