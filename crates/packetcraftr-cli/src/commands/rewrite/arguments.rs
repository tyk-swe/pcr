// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::IpAddr;
use std::path::PathBuf;

use packetcraftr_core::transform::{FieldAssignment, VlanRewrite};

use super::rules;
use crate::command_options::{
    CompressionArgs, DecodeArgs, MaxDurationArgs, OfflineCaptureLimitsArgs, RunTime, SavedPcapNg,
};

pub(crate) const AFTER_LONG_HELP: &str = r"Header edits (--source-mac, --destination-ip, --vlan, and the rest) and field assignments (--set) apply to every frame --filter matches, or to every frame; a --rules-file holds ordered rules instead. Header edits recompute lengths and transport checksums; field assignments repair covering checksums unless --checksum-mode preserve keeps checksum bytes exactly. The destination is published only when every frame rewrote cleanly; --dry-run reports the field changes without writing it.

Examples:
  packetcraftr rewrite capture.pcapng --write rewritten.pcapng --destination-ip 192.0.2.10
  packetcraftr rewrite capture.pcapng --write out.pcapng --set ipv4.ttl=64 --filter 'udp'
  packetcraftr rewrite capture.pcapng --write out.pcapng --rules-file rules.json
  packetcraftr rewrite capture.pcapng --write out.pcapng --set dns.id=7 --dry-run";

#[derive(Debug, clap::Args)]
pub(crate) struct Args {
    /// Source capture; - reads redirected stdin. gzip and Zstd are detected.
    pub(crate) path: PathBuf,
    /// New PCAPNG destination, published only when all frames are valid.
    /// With --dry-run the destination is only named, never created.
    #[arg(long)]
    pub(crate) write: PathBuf,
    /// Match original frame fields; unmatched frames are retained unchanged.
    #[arg(long)]
    pub(crate) filter: Option<String>,
    /// Ordered JSON rules under packetcraftr.rewrite/v1 (header patches) or
    /// /v2 (field assignments); at most 1 MiB and 64 rules.
    #[arg(long)]
    pub(crate) rules_file: Option<PathBuf>,
    /// Assign one fixed-width field in place, <protocol>[#occurrence].<field>=
    /// <value>; repeatable. Supports ipv4.ttl, ipv6.hop_limit, tcp.sequence,
    /// tcp.acknowledgment, tcp/udp ports, and dns.id. Header edits apply first
    /// when combined with them; conflicts with --rules-file.
    #[arg(long = "set", value_name = "FIELD=VALUE", value_parser = rules::assignment)]
    // clap prints this doc comment verbatim as --help text, so it is not rustdoc markup.
    #[allow(rustdoc::invalid_html_tags)]
    pub(crate) sets: Vec<FieldAssignment>,
    /// Checksum behavior for field assignments: repair recomputes covering
    /// checksums; preserve keeps checksum bytes exactly.
    #[arg(long, value_enum)]
    pub(crate) checksum_mode: Option<rules::ChecksumArg>,
    /// Report the field-edit changes --set or v2 rules would make, without
    /// creating or replacing the destination. Requires assignments only.
    #[arg(long)]
    pub(crate) dry_run: bool,
    /// Replace the outer Ethernet source MAC address.
    #[arg(long, value_parser = rules::mac)]
    pub(crate) source_mac: Option<[u8; 6]>,
    /// Replace the outer Ethernet destination MAC address.
    #[arg(long, value_parser = rules::mac)]
    pub(crate) destination_mac: Option<[u8; 6]>,
    /// Replace the IP source address.
    #[arg(long)]
    pub(crate) source_ip: Option<IpAddr>,
    /// Replace the IP destination address.
    #[arg(long)]
    pub(crate) destination_ip: Option<IpAddr>,
    /// Replace the TCP or UDP source port.
    #[arg(long)]
    pub(crate) source_port: Option<u16>,
    /// Replace the TCP or UDP destination port.
    #[arg(long)]
    pub(crate) destination_port: Option<u16>,
    /// Replace the outer VLAN stack; repeat VID or TPID:VID[:PRIORITY[:DEI]].
    #[arg(long = "vlan", value_parser = rules::vlan, conflicts_with = "strip_vlans")]
    // clap prints this doc comment verbatim as --help text, so it is not rustdoc markup.
    #[allow(rustdoc::broken_intra_doc_links)]
    pub(crate) vlans: Vec<VlanRewrite>,
    /// Remove the outer VLAN stack.
    #[arg(long)]
    pub(crate) strip_vlans: bool,
    #[command(flatten)]
    pub(crate) compression: CompressionArgs<SavedPcapNg>,
    #[command(flatten)]
    pub(crate) duration: MaxDurationArgs<RewriteRunTime>,
    #[command(flatten)]
    pub(crate) decode: DecodeArgs,
    #[command(flatten)]
    pub(crate) limits: OfflineCaptureLimitsArgs,
}

/// The whole rewrite.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct RewriteRunTime;

impl RunTime for RewriteRunTime {
    const HELP: &'static str = "Maximum rewrite run time in milliseconds";
}
