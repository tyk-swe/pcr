// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::IpAddr;
use std::path::PathBuf;

use packetcraftr_core::{
    error::Kind,
    packet::MacAddress,
    transform::{ChecksumMode, FieldAssignment, HeaderRewrite, IpMapping, MacMapping, VlanRewrite},
};

use crate::command_options::{
    CompressionArgs, DecodeArgs, MaxDurationArgs, OfflineCaptureLimitsArgs, RunTime, SavedPcapNg,
};
use crate::errors::CliError;

pub(crate) const AFTER_LONG_HELP: &str = r"Header edits (--source-mac, --destination-ip, --vlan, and the rest) and field assignments (--set) apply to every frame --filter matches, or to every frame; a --rules-file holds ordered rules instead. --map-ip and --map-mac remap addresses many-to-many instead of setting one fixed address: each frame's outer source and destination are looked up independently, equal-length CIDR prefixes keep the host bits, and unmatched addresses and frames pass through. Header edits recompute lengths and transport checksums; field assignments repair covering checksums unless --checksum-mode preserve keeps checksum bytes exactly. The destination is published only when every frame rewrote cleanly; --dry-run reports the field changes without writing it.

Examples:
  packetcraftr rewrite capture.pcapng --write rewritten.pcapng --destination-ip 192.0.2.10
  packetcraftr rewrite capture.pcapng --write out.pcapng --set ipv4.ttl=64 --filter 'udp'
  packetcraftr rewrite capture.pcapng --write out.pcapng --rules-file rules.json
  packetcraftr rewrite capture.pcapng --write out.pcapng --map-ip 192.0.2.0/24=198.51.100.0/24
  packetcraftr rewrite capture.pcapng --write out.pcapng --map-mac 02:00:00:00:00:01=02:00:00:00:00:02
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
    /// <value>; repeatable. Supports ipv4.ttl, ipv4.identification,
    /// ipv4.dscp_ecn, ipv6.hop_limit, tcp.sequence, tcp.acknowledgment,
    /// tcp.window, tcp/udp ports, icmp and icmpv6 identifier and sequence,
    /// dns.id, dhcpv4.transaction_id, and vxlan.vni and geneve.vni. Header
    /// edits apply first when combined with them; conflicts with --rules-file.
    #[arg(long = "set", value_name = "FIELD=VALUE", value_parser = assignment)]
    #[allow(rustdoc::invalid_html_tags)]
    pub(crate) sets: Vec<FieldAssignment>,
    /// Remap IP addresses, OLD=NEW; repeatable. Each side is an address or an
    /// equal-length CIDR prefix whose host bits carry over, so
    /// 192.0.2.0/24=198.51.100.0/24 turns 192.0.2.7 into 198.51.100.7. Source
    /// and destination match independently; sources must not overlap and the
    /// table holds at most 4096 entries with --map-mac. Conflicts with
    /// --rules-file and the fixed address flags.
    #[arg(
        long = "map-ip",
        value_name = "OLD=NEW",
        value_parser = ip_mapping,
        conflicts_with_all = ["rules_file", "source_mac", "destination_mac", "source_ip", "destination_ip"]
    )]
    pub(crate) map_ips: Vec<IpMapping>,
    /// Remap Ethernet source and destination addresses, OLD=NEW; repeatable.
    /// Conflicts with --rules-file and the fixed address flags.
    #[arg(
        long = "map-mac",
        value_name = "OLD=NEW",
        value_parser = mac_mapping,
        conflicts_with_all = ["rules_file", "source_mac", "destination_mac", "source_ip", "destination_ip"]
    )]
    pub(crate) map_macs: Vec<MacMapping>,
    /// Checksum behavior for field assignments: repair recomputes covering
    /// checksums; preserve keeps checksum bytes exactly.
    #[arg(long, value_enum)]
    pub(crate) checksum_mode: Option<ChecksumArg>,
    /// Report the field-edit changes --set or v2 rules would make, without
    /// creating or replacing the destination. Requires assignments only.
    #[arg(long)]
    pub(crate) dry_run: bool,
    /// Replace the outer Ethernet source MAC address.
    #[arg(long, value_parser = mac)]
    pub(crate) source_mac: Option<[u8; 6]>,
    /// Replace the outer Ethernet destination MAC address.
    #[arg(long, value_parser = mac)]
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
    #[arg(long = "vlan", value_parser = vlan, conflicts_with = "strip_vlans")]
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

fn ip_mapping(value: &str) -> Result<IpMapping, CliError> {
    value
        .parse()
        .map_err(|error| CliError::caused(Kind::Usage, &error))
}

fn mac_mapping(value: &str) -> Result<MacMapping, CliError> {
    value
        .parse()
        .map_err(|error| CliError::caused(Kind::Usage, &error))
}

fn mac(value: &str) -> Result<[u8; 6], CliError> {
    value
        .parse::<MacAddress>()
        .map(|address| address.0)
        .map_err(|error| CliError::caused(Kind::Usage, &error))
}

fn vlan(value: &str) -> Result<VlanRewrite, CliError> {
    fn number(value: &str) -> Result<u16, CliError> {
        match value.strip_prefix("0x") {
            Some(digits) if digits.bytes().all(|digit| digit.is_ascii_hexdigit()) => {
                u16::from_str_radix(digits, 16).ok()
            }
            Some(_) => None,
            None => value.parse().ok(),
        }
        .ok_or_else(|| CliError::new(Kind::Usage, "invalid VLAN number"))
    }
    let parts: Vec<_> = value.split(':').collect();
    let tag = match parts.as_slice() {
        [id] => VlanRewrite {
            ether_type: 0x8100,
            identifier: number(id)?,
            priority: 0,
            drop_eligible: false,
        },
        [kind, id, rest @ ..] if rest.len() <= 2 => {
            let priority = rest.first().map(|s| number(s)).transpose()?.unwrap_or(0);
            let dei = rest.get(1).map(|s| number(s)).transpose()?.unwrap_or(0);
            if priority > 7 || dei > 1 {
                return Err(CliError::new(
                    Kind::Usage,
                    "VLAN priority must be 0..=7 and DEI 0 or 1",
                ));
            }
            VlanRewrite {
                ether_type: number(kind)?,
                identifier: number(id)?,
                priority: priority as u8,
                drop_eligible: dei == 1,
            }
        }
        _ => {
            return Err(CliError::new(
                Kind::Usage,
                "use VID or TPID:VID[:PRIORITY[:DEI]]",
            ));
        }
    };
    HeaderRewrite {
        vlans: Some(vec![tag]),
        ..Default::default()
    }
    .validate()
    .map_err(CliError::classified)?;
    Ok(tag)
}
