// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::path::PathBuf;

use crate::command_options::{OfflineCaptureLimitsArgs, TlsPortArgs};

pub(crate) const AFTER_LONG_HELP: &str = r#"Examples:
  packetcraftr read capture.pcapng --max-frames 100
  packetcraftr --output ndjson read capture.pcap
  packetcraftr --output ndjson read - < capture.pcapng
  packetcraftr read capture.pcapng --filter 'tcp.flags.syn == 1 && !tcp.flags.ack' --dissect
  packetcraftr read capture.pcapng --tls-port 4433 --filter 'tls.sni contains "example"' --dissect
  packetcraftr --output pcapng read capture.pcapng > validated-copy.pcapng
  packetcraftr --output pcapng read - --normalize --filter 'udp' < capture.pcap > selected.pcapng

Capture output preserves source records by default, requires the same format,
and cannot filter. --normalize with --output pcapng instead writes matching physical
frames into one new section, remapping selected interfaces. It preserves bytes,
lengths, link types, directions and interface timestamp metadata. Comments, unknown
blocks/options and original section structure are discarded. Timestamps pass through
nanosecond capture time, losing subnanosecond detail. Selected frames without a
timestamp or with a time not exactly representable at their interface resolution fail.
No matches produce a valid section with no interfaces or packets.
Frame/payload limits count all input; block and interface limits also bound output.

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
    /// Keep matching frames; capture output requires --normalize --output pcapng.
    #[arg(long, value_name = "EXPR")]
    pub(crate) filter: Option<String>,
    /// Export a new PCAPNG from physical frames, discarding source-only metadata.
    #[arg(long)]
    pub(crate) normalize: bool,
    /// Include each frame's dissected layer stack in the output.
    #[arg(long)]
    pub(crate) dissect: bool,
    #[command(flatten)]
    pub(crate) tls_ports: TlsPortArgs,
}
