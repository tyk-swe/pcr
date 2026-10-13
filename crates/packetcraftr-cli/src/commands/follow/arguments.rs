// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::path::PathBuf;

use clap::ValueEnum;

use crate::command_options::{DecodeArgs, OfflineLimitsArgs};

pub(crate) const AFTER_LONG_HELP: &str = r"Offline conversation payload extraction using capture-global `tcp:INDEX` or
`udp:INDEX` numbering (first sender is `client`). Raw output requires a single
direction. `--write DIR` atomically stages `TRANSPORT-INDEX-client.bin` and
`TRANSPORT-INDEX-server.bin` in an existing directory without overwriting files.

Examples:
  packetcraftr follow capture.pcapng --stream tcp:0
  packetcraftr follow capture.pcapng --stream tcp:0 --direction client --output raw > client.bin
  mkdir -p ./directions && packetcraftr follow capture.pcapng --stream tcp:0 --write ./directions
  packetcraftr --output json follow capture.pcapng --stream udp:2
  packetcraftr --output ndjson follow capture.pcapng --stream tcp:7";

/// How a followed conversation's chunks are narrowed by sender.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub(crate) enum Direction {
    /// Both directions, interleaved in delivery order.
    Both,
    /// Only bytes the client — the conversation's first captured sender — sent.
    Client,
    /// Only bytes the server sent.
    Server,
}

#[derive(Debug, clap::Args)]
pub(crate) struct Args {
    /// Classic PCAP or PCAPNG input path; - reads redirected stdin.
    pub(crate) path: PathBuf,
    /// Conversation to follow, as `tcp:INDEX` or `udp:INDEX`, using the
    /// same indices stats reports and stream filters match.
    #[arg(long, value_name = "TRANSPORT:INDEX", value_parser = crate::command_options::stream_selector)]
    pub(crate) stream: crate::command_options::Selector<packetcraftr_core::analysis::StreamRef>,
    /// Which sender's bytes to emit.
    #[arg(long, value_enum, default_value_t = Direction::Both)]
    pub(crate) direction: Direction,
    /// Save each selected direction's payload into an existing writable DIR as
    /// `TRANSPORT-INDEX-client.bin` and `TRANSPORT-INDEX-server.bin`, staged
    /// and published atomically without overwriting existing files. An empty
    /// direction produces an empty file.
    #[arg(long, value_name = "DIR")]
    pub(crate) write: Option<PathBuf>,
    /// Total payload bytes allowed across all direction files `--write` saves.
    #[arg(long, default_value_t = 64*1024*1024)]
    pub(crate) max_application_output_bytes: usize,
    #[command(flatten)]
    pub(crate) limits: OfflineLimitsArgs,
    #[command(flatten)]
    pub(crate) decode: DecodeArgs,
}
