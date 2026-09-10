// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::path::PathBuf;

use crate::command_options::{DecodeArgs, OfflineCaptureLimitsArgs};

pub(crate) const AFTER_LONG_HELP: &str = r#"Examples:
  packetcraftr read capture.pcapng --max-frames 100
  packetcraftr --output ndjson read capture.pcap
  packetcraftr --output ndjson read - < capture.pcapng
  packetcraftr read capture.pcapng --filter 'tcp.flags.syn == 1 && !tcp.flags.ack' --dissect
  packetcraftr read capture.pcapng --tls-port 4433 --filter 'tls.sni contains "example"' --dissect
  packetcraftr --output pcapng read capture.pcapng > validated-copy.pcapng
  packetcraftr --output pcapng read capture.pcapng --filter 'udp.port == 53' > dns.pcapng
  packetcraftr --output pcapng read - --normalize --filter 'udp' < capture.pcap > selected.pcapng

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
    /// Classic PCAP or PCAPNG input path; - reads redirected stdin.
    pub(crate) path: PathBuf,
    #[command(flatten)]
    pub(crate) limits: OfflineCaptureLimitsArgs,
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
