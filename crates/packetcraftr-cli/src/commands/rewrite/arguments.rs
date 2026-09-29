// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::path::PathBuf;

use packetcraftr_core::{
    error::Kind,
    transform::{ChecksumMode, FieldAssignment},
};

use crate::command_options::{
    CompressionArgs, DecodeArgs, MaxDurationArgs, OfflineCaptureLimitsArgs, RunTime, SavedPcapNg,
};
use crate::errors::CliError;

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
    #[arg(long = "set", value_name = "FIELD=VALUE", value_parser = assignment)]
    #[allow(rustdoc::invalid_html_tags)]
    pub(crate) sets: Vec<FieldAssignment>,
    /// Checksum behavior for field assignments: repair recomputes covering
    /// checksums; preserve keeps checksum bytes exactly.
    #[arg(long, value_enum)]
    pub(crate) checksum_mode: Option<ChecksumArg>,
    /// Report the field-edit changes --set or v2 rules would make, without
    /// creating or replacing the destination. Requires assignments only.
    #[arg(long)]
    pub(crate) dry_run: bool,
    /// Remap source prefixes preserving host bits; repeat OLD/PREFIX=NEW/PREFIX.
    #[arg(
        long = "source-cidr-map",
        value_name = "OLD=NEW",
        conflicts_with = "rules_file"
    )]
    pub(crate) source_cidr_maps: Vec<packetcraftr_core::transform::CidrMap>,
    /// Remap destination prefixes preserving host bits; repeat OLD/PREFIX=NEW/PREFIX.
    #[arg(
        long = "destination-cidr-map",
        value_name = "OLD=NEW",
        conflicts_with = "rules_file"
    )]
    pub(crate) destination_cidr_maps: Vec<packetcraftr_core::transform::CidrMap>,
    #[command(flatten)]
    pub(crate) headers: crate::command_options::HeaderRewriteArgs,
    #[command(flatten)]
    pub(crate) compression: CompressionArgs<SavedPcapNg>,
    #[command(flatten)]
    pub(crate) duration: MaxDurationArgs<RewriteRunTime>,
    #[command(flatten)]
    pub(crate) decode: DecodeArgs,
    #[command(flatten)]
    pub(crate) limits: OfflineCaptureLimitsArgs,
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct RewriteRunTime;

impl RunTime for RewriteRunTime {
    const HELP: &'static str = "Maximum rewrite run time in milliseconds";
    const PARSED: std::ops::RangeInclusive<u64> =
        1..=crate::command_options::MAX_DURATION_MILLISECONDS;
}

/// How field edits treat the checksums covering changed bytes.
#[derive(Clone, Copy, Debug, clap::ValueEnum)]
pub(crate) enum ChecksumArg {
    /// Recompute every supported checksum covering a changed field.
    Repair,
    /// Retain checksum bytes exactly, for deliberately malformed fixtures.
    Preserve,
}

impl From<ChecksumArg> for ChecksumMode {
    fn from(mode: ChecksumArg) -> Self {
        match mode {
            ChecksumArg::Repair => Self::Repair,
            ChecksumArg::Preserve => Self::Preserve,
        }
    }
}

fn assignment(value: &str) -> Result<FieldAssignment, CliError> {
    value
        .parse()
        .map_err(|error| CliError::caused(Kind::Usage, &error))
}
