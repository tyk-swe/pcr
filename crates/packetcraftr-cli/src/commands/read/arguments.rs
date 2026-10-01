// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::path::PathBuf;

use crate::command_options::{
    CaptureStdout, CompressionArgs, DecodeArgs, EpochBoundsArgs, FrameSelectionArgs,
    OfflineCaptureLimitsArgs, TreeArgs,
};

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
  packetcraftr read capture.pcapng --frames 1-100,250,300- --every 5
  packetcraftr --output pcap read capture.pcapng --normalize > single-interface.pcap
  packetcraftr read capture.pcapng --filter 'dns' --dissect --tree

--start-epoch/--stop-epoch keep only frames whose capture timestamp falls
inside the inclusive bounds, compared at full precision without rounding.
Either side may be omitted. Reversed bounds are rejected. Frames without
timestamps are never kept while bounds are set. Bounds compose with --filter
and skipped frames still count toward --max-frames/--max-bytes.

--frames keeps the listed one-based source positions (N, N-M inclusive, or open-ended N-,
comma-separated, at most 256 items; overlaps merge) and --every N keeps positions 1, N+1,
2N+1, and so on. Together they intersect on the source position, and they compose with
--filter and the epoch bounds. They apply without decoding to stream, --field, --normalize,
and capture output, where selected records are copied verbatim. Skipped frames still count
toward --max-frames/--max-bytes, and frame.number keeps the source position.

Capture output requires the input format unless --normalize is used. Without --filter, every record is copied
verbatim. With --filter, selected packet records and all metadata are retained;
PCAPNG section lengths become unknown. Interface statistics describe the source.
Limits count all input packets. Errors can leave partial output. Related packets
and fragments are not automatically included. An empty selection is valid.

--normalize with --output pcap writes the same selection as classic PCAP. Classic PCAP holds
one link type and no interface or direction metadata, so the selected frames must share one
interface, carry no inbound/outbound direction, have timestamps, and fit the source snapshot
length. The file uses nanosecond resolution when the source interface does and microsecond
resolution when it does; other source resolutions fail, as does a timestamp the chosen
resolution cannot represent exactly. Selecting no frame fails because classic PCAP has no
header without a link type. A conflict found after earlier frames may leave partial output.
Plain --output pcap without --normalize still requires PCAP input.

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

--tree, with --dissect and text output, prints each frame's header line, then every layer
and its fields as an indented tree in place of the DNS summary lines. See `dissect --help`
for the tree format; its lines count against --max-tree-bytes across all frames.

NDJSON emits frame events followed by one complete event. Text prefixes each frame,
and NDJSON source_frame identifies it, with the one-based capture position used by
frame.number. Filtering does not renumber that source position; NDJSON envelope
sequence remains the zero-based emitted-record position."#;

#[derive(Debug, clap::Args)]
pub(crate) struct Args {
    /// Select a registered field; repeat to preserve the requested column order.
    #[arg(long = "field", value_name = "PATH", conflicts_with_all = ["normalize", "dissect", "tree"])]
    pub(crate) fields: Vec<String>,
    /// Maximum encoded projection data bytes across all rows (excluding envelopes).
    #[arg(long, default_value_t = 16 * 1024 * 1024)]
    pub(crate) max_projection_bytes: usize,

    #[command(flatten)]
    pub(crate) compression: CompressionArgs<CaptureStdout>,

    /// Classic PCAP or PCAPNG input path; - reads redirected stdin.
    pub(crate) path: PathBuf,
    #[command(flatten)]
    pub(crate) limits: OfflineCaptureLimitsArgs,
    #[command(flatten)]
    pub(crate) epoch: EpochBoundsArgs,
    #[command(flatten)]
    pub(crate) selection: FrameSelectionArgs,
    /// Keep only frames matching a display filter.
    #[arg(long, value_name = "EXPR")]
    pub(crate) filter: Option<String>,
    /// Export a new PCAPNG or single-interface PCAP from physical frames, discarding source-only metadata.
    #[arg(long)]
    pub(crate) normalize: bool,
    /// Include each frame's dissected layer stack in the output.
    #[arg(long)]
    pub(crate) dissect: bool,
    #[command(flatten)]
    pub(crate) tree: TreeArgs,
    #[command(flatten)]
    pub(crate) decode: DecodeArgs,
}
