// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::IpAddr;
use std::str::FromStr;

use clap::{Args, ValueEnum};
use packetcraftr::{live as workflow, packet};

use crate::command_options::{
    CaptureLimitArgs, CliAddressFamily, CliLinkMode, HostnameTrafficPolicyArgs,
};

pub(crate) const AFTER_LONG_HELP: &str = r#"Examples:
  packetcraftr scan 192.0.2.10 --transport tcp --ports 22,80,443
  packetcraftr scan 192.0.2.10 --transport udp --ports 53,8000-8100
  packetcraftr --output ndjson scan 198.51.100.10 --transport icmp

Port syntax:
  --ports accepts comma-separated u16 ports and inclusive ranges of the form
  START-END, where START and END are both u16 ports and START <= END. Repeated
  ports and overlapping ranges keep their first-seen order and deduplicate.
  Expansion is bounded by --max-ports and stops as soon as another distinct
  port would exceed that limit."#;

/// One CLI `--ports` token: either a single u16 port or an inclusive
/// `START-END` range. This is a CLI-only concern; expansion into the
/// `Vec<u16>` carried by `workflow::scan::Request` happens in
/// `commands::scan::conversion`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CliScanPortSpec {
    Single(u16),
    RangeInclusive { start: u16, end: u16 },
}

impl FromStr for CliScanPortSpec {
    type Err = String;

    fn from_str(token: &str) -> Result<Self, Self::Err> {
        let Some((start_part, end_part)) = token.split_once('-') else {
            return Ok(Self::Single(parse_port(token)?));
        };
        if start_part.is_empty() || end_part.is_empty() {
            return Err(format!(
                "invalid port spec `{token}`: inclusive ranges need the form START-END with both \
                 endpoints present"
            ));
        }
        let start = parse_port(start_part)?;
        let end = parse_port(end_part)?;
        if end < start {
            return Err(format!(
                "invalid port spec `{token}`: range end {end} precedes start {start}"
            ));
        }
        Ok(Self::RangeInclusive { start, end })
    }
}

fn parse_port(token: &str) -> Result<u16, String> {
    token
        .parse::<u16>()
        .map_err(|_| format!("invalid port spec `{token}`: expected a u16 port or START-END range"))
}

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
pub(crate) enum CliScanTransport {
    #[default]
    Tcp,
    Udp,
    Icmp,
}

impl From<CliScanTransport> for workflow::scan::Transport {
    fn from(value: CliScanTransport) -> Self {
        match value {
            CliScanTransport::Tcp => Self::Tcp,
            CliScanTransport::Udp => Self::Udp,
            CliScanTransport::Icmp => Self::Icmp,
        }
    }
}

#[derive(Debug, Args)]
pub(crate) struct ScanArgs {
    /// Explicit IP address or hostname to scan.
    #[arg(value_name = "ADDRESS_OR_HOSTNAME")]
    pub(crate) target: String,
    /// TCP SYN, UDP, or ICMP echo probes.
    #[arg(long, value_enum, default_value_t = CliScanTransport::Tcp)]
    pub(crate) transport: CliScanTransport,
    /// Select all authorized addresses or only one IP family.
    #[arg(long, value_enum, default_value_t = CliAddressFamily::Any)]
    pub(crate) family: CliAddressFamily,
    /// Comma-separated TCP/UDP destination ports or inclusive START-END ranges;
    /// omitted for ICMP.
    #[arg(long, value_delimiter = ',', num_args = 1..)]
    pub(crate) ports: Vec<CliScanPortSpec>,
    /// Number of bounded attempts per selected endpoint.
    #[arg(long, default_value_t = 1)]
    pub(crate) attempts: u32,
    /// Response window for each capture-ready batch.
    #[arg(long, default_value_t = 1_000)]
    pub(crate) timeout_ms: u64,
    /// Optional average probe-rate ceiling; batches remain deliberate bursts.
    #[arg(long)]
    pub(crate) rate: Option<u32>,
    /// Maximum probes sent by one shared-capture exchange batch.
    #[arg(long, default_value_t = workflow::scan::DEFAULT_SCAN_BATCH_SIZE)]
    pub(crate) batch_size: usize,
    /// Maximum distinct destination ports accepted by the request.
    #[arg(long, default_value_t = workflow::scan::DEFAULT_MAX_SCAN_PORTS)]
    pub(crate) max_ports: usize,
    /// Maximum generated probes after target resolution and attempts.
    #[arg(long, default_value_t = packet::template::DEFAULT_MAX_TEMPLATE_PACKETS)]
    pub(crate) max_probes: usize,
    /// Maximum worst-case timeout plus intentional rate delay in milliseconds.
    #[arg(long, default_value_t = 3_600_000)]
    pub(crate) max_duration_ms: u64,
    /// Maximum undecodable exact frames retained across the scan.
    #[arg(long, default_value_t = workflow::scan::DEFAULT_MAX_UNDECODED_SCAN_FRAMES)]
    pub(crate) max_undecoded: usize,
    /// Interface name or numeric index used as an exact route constraint.
    #[arg(long, value_name = "NAME_OR_INDEX")]
    pub(crate) interface: Option<String>,
    /// Interface-owned source preference used only for route selection.
    #[arg(long)]
    pub(crate) source: Option<IpAddr>,
    /// Automatic, Layer 2, or raw Layer 3 transmission intent.
    #[arg(long, value_enum, default_value_t = CliLinkMode::Auto)]
    pub(crate) link_mode: CliLinkMode,
    #[command(flatten)]
    pub(crate) limits: CaptureLimitArgs,
    #[command(flatten)]
    pub(crate) policy: HostnameTrafficPolicyArgs,
}
