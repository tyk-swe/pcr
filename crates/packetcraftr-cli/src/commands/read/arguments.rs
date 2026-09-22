// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::path::PathBuf;

use crate::command_options::{DecodeArgs, EpochBoundsArgs, OfflineCaptureLimitsArgs};

pub(crate) const AFTER_LONG_HELP: &str = r#"Examples:
  packetcraftr read capture.pcapng --max-frames 100
  packetcraftr --output ndjson read capture.pcap
  packetcraftr --output ndjson read - < capture.pcapng
  packetcraftr read capture.pcapng --filter 'tcp.flags.syn == 1 && !tcp.flags.ack' --dissect
  packetcraftr read capture.pcapng --tls-port 4433 --filter 'tls.sni contains "example"' --dissect
  packetcraftr --output pcapng read capture.pcapng > validated-copy.pcapng
  packetcraftr --output pcapng read capture.pcapng --filter 'udp.port == 53' > dns.pcapng
  packetcraftr --output pcapng read - --normalize --filter 'udp' < capture.pcap > selected.pcapng
  packetcraftr read capture.pcapng --start-epoch 1700000000.5 --stop-epoch 1700000060

--start-epoch/--stop-epoch keep only frames whose capture timestamp falls
inside the inclusive bounds, compared at full precision without rounding.
Either side may be omitted. Reversed bounds are rejected. Frames without
timestamps are never kept while bounds are set. Bounds compose with --filter
and skipped frames still count toward --max-frames/--max-bytes.

Capture output requires the input format unless --normalize is used. Without --filter, every record is copied
verbatim. With --filter, selected packet records and all metadata are retained;
PCAPNG section lengths become unknown. Interface statistics describe the source.
Limits count all input packets. Errors can leave partial output. Related packets
and fragments are not automatically included. An empty selection is valid.

--normalize with --output pcapng writes matching physical frames into one new
section, remapping selected interfaces. It preserves bytes, lengths, link types,
directions and interface timestamp metadata. Comments, unknown blocks/options and
original section structure are discarded. Timestamps must be exactly representable
as nanosecond capture time and at their interface resolution; unrepresentable times
and selected frames without timestamps fail. No matches produce a valid section
with no interfaces or packets. Frame/payload limits count all input. --max-frame-bytes
also bounds output blocks. --max-interfaces limits descriptions per input section
and selected interfaces in the normalized output. The separate capture-wide input
ceiling is 65,536 descriptions, including interfaces with no selected frames.

NDJSON emits frame events followed by one complete event. Text prefixes each frame,
and NDJSON source_frame identifies it, with the one-based capture position used by
frame.number. Filtering does not renumber that source position; NDJSON envelope
sequence remains the zero-based emitted-record position."#;

#[derive(Debug, clap::Args)]
pub(crate) struct Args {
    /// Select a registered field; repeat to preserve the requested column order.
    #[arg(long = "field", value_name = "PATH", conflicts_with_all = ["normalize", "dissect"])]
    pub(crate) fields: Vec<String>,
    /// Maximum encoded projection data bytes across all rows (excluding envelopes).
    #[arg(long, default_value_t = 16 * 1024 * 1024)]
    pub(crate) max_projection_bytes: usize,

    /// Compress binary capture output; independent of the input's detected format.
    #[arg(long, value_enum, default_value_t = crate::command_options::Compression::None)]
    pub(crate) compression: crate::command_options::Compression,

    /// Classic PCAP or PCAPNG input path; - reads redirected stdin.
    pub(crate) path: PathBuf,
    #[command(flatten)]
    pub(crate) limits: OfflineCaptureLimitsArgs,
    #[command(flatten)]
    pub(crate) epoch: EpochBoundsArgs,
    /// Keep only frames matching a display filter.
    #[arg(long, value_name = "EXPR")]
    pub(crate) filter: Option<String>,
    /// Export a new PCAPNG from physical frames, discarding source-only metadata.
    #[arg(long)]
    pub(crate) normalize: bool,
    /// Include each frame's dissected layer stack in the output.
    #[arg(long)]
    pub(crate) dissect: bool,
    #[command(flatten)]
    pub(crate) decode: DecodeArgs,
}
