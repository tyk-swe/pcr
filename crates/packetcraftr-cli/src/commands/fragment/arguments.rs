// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::command_options::{CaptureStdout, CompressionArgs, PacketBudgetArgs, RecipeArgs};

pub(crate) const AFTER_LONG_HELP: &str = r#"Fragmentation is explicit and offline: the recipe is built strictly, then split at --mtu, which excludes the link header. IPv6 requires --identification; IPv4 uses the header's own unless --identification replaces it.

Text and hex print one fragment per line, NDJSON streams each fragment before one complete event, and PCAP or PCAPNG write the fragments to stdout as a capture stream.

Examples:
  packetcraftr fragment --mtu 576 --packet 'ipv4(dst=192.0.2.1)/udp(dport=9)/raw(text=hello)'
  packetcraftr --output pcapng fragment --mtu 1280 --identification 7 --packet 'ipv6(dst=2001:db8::1)/udp(dport=9)/raw(hex="00")' > fragments.pcapng"#;

#[derive(Debug, clap::Args)]
pub(crate) struct Args {
    #[command(flatten)]
    pub(crate) compression: CompressionArgs<CaptureStdout>,

    #[command(flatten)]
    pub(crate) recipe: RecipeArgs,
    /// IP MTU, excluding the link header. Fragmentation is always explicit.
    #[arg(long)]
    pub(crate) mtu: usize,
    /// Fragment identification; required when splitting IPv6.
    #[arg(long)]
    pub(crate) identification: Option<u32>,
    /// Maximum fragments produced from the datagram; at most 8192.
    #[arg(long, default_value_t = 1024)]
    pub(crate) max_fragments: usize,
    /// Maximum bytes across all produced fragment frames.
    #[arg(long, default_value_t = 256 * 1024 * 1024)]
    pub(crate) max_output_bytes: usize,
    #[command(flatten)]
    pub(crate) budget: PacketBudgetArgs,
}
