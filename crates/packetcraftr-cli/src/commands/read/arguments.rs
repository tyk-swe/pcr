// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::path::PathBuf;

use crate::command_options::{OfflineCaptureLimitsArgs, TlsPortArgs};

pub(crate) const AFTER_LONG_HELP: &str = r#"Examples:
  packetcraftr read capture.pcapng --max-frames 100
  packetcraftr --output ndjson read capture.pcap
  packetcraftr read capture.pcapng --filter 'tcp.flags.syn == 1 && !tcp.flags.ack' --dissect
  packetcraftr read capture.pcapng --tls-port 4433 --filter 'tls.sni contains "example"' --dissect
  packetcraftr --output pcapng read capture.pcapng > validated-copy.pcapng
  packetcraftr --output pcapng read capture.pcapng --filter 'udp.port == 53' > dns.pcapng

Capture output requires the input format. Without --filter, every record is copied
verbatim. With --filter, selected packet records and all metadata are retained;
PCAPNG section lengths become unknown. Interface statistics describe the source.
Limits count all input packets. Errors can leave partial output. Related packets
and fragments are not automatically included. An empty selection is valid.

NDJSON emits frame events followed by one complete event. Text prefixes each frame,
and NDJSON source_frame identifies it, with the one-based capture position used by
frame.number. Filtering does not renumber that source position; NDJSON envelope
sequence remains the zero-based emitted-record position."#;

#[derive(Debug, clap::Args)]
pub(crate) struct Args {
    /// Classic PCAP or PCAPNG input path.
    pub(crate) path: PathBuf,
    #[command(flatten)]
    pub(crate) limits: OfflineCaptureLimitsArgs,
    /// Keep only frames matching a display filter.
    #[arg(long, value_name = "EXPR")]
    pub(crate) filter: Option<String>,
    /// Include each frame's dissected layer stack in the output.
    #[arg(long)]
    pub(crate) dissect: bool,
    #[command(flatten)]
    pub(crate) tls_ports: TlsPortArgs,
}
