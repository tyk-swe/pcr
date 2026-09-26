// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::path::PathBuf;

use clap::ValueEnum;

use crate::command_options::{DecodeArgs, OfflineLimitsArgs};

pub(crate) const AFTER_LONG_HELP: &str = r"Following is computed offline over dissected frames; no live capture or transmission is involved.

The conversation index comes from the same first-seen numbering stats reports and stream filters match, so 'follow --stream tcp:7' extracts the conversation 'tcp.stream == 7' selects. The client is the endpoint that sent the conversation's first captured frame. TCP payload is reassembled in stream order per direction; UDP emits one chunk per datagram. Completed IP-fragmented datagrams join their transport conversation on the fragment that completes them. Raw output needs a single direction, since interleaved raw bytes would be indistinguishable.

--write DIR saves each selected direction's payload as TRANSPORT-INDEX-client.bin
and TRANSPORT-INDEX-server.bin inside DIR. Files are staged in DIR and published
atomically; existing files are never overwritten, a direction with no payload
publishes as an empty file, and --direction narrows which files are written.
Both files share the single --max-application-output-bytes budget. Publishing is
not a multi-file transaction: on failure, staged bytes are discarded and files
this invocation already published are rolled back where possible. Cleanup failures
report the paths that could not be removed.

Examples:
  packetcraftr follow capture.pcapng --stream tcp:0
  packetcraftr follow capture.pcapng --stream tcp:0 --direction client --output raw > client.bin
  packetcraftr follow capture.pcapng --stream tcp:0 --write ./directions
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
    pub(crate) stream: packetcraftr_core::analysis::StreamRef,
    /// Which sender's bytes to emit.
    #[arg(long, value_enum, default_value_t = Direction::Both)]
    pub(crate) direction: Direction,
    /// Save each selected direction's payload into DIR as
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
