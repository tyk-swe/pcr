// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::str::FromStr;

use clap::ValueEnum;
use packetcraftr::core;

use crate::command_options::{
    AddressFamily, CaptureLimitsArgs, HostnameTrafficPolicyArgs, RouteSelectionArgs,
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

/// One CLI `--ports` token: a u16 port or inclusive `START-END` range.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PortSpec {
    Single(u16),
    RangeInclusive { start: u16, end: u16 },
}

impl FromStr for PortSpec {
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
pub(crate) enum Transport {
    #[default]
    Tcp,
    Udp,
    Icmp,
}

impl From<Transport> for packetcraftr::scan::Transport {
    fn from(value: Transport) -> Self {
        match value {
            Transport::Tcp => Self::Tcp,
            Transport::Udp => Self::Udp,
            Transport::Icmp => Self::Icmp,
        }
    }
}

#[derive(Debug, clap::Args)]
pub(crate) struct Args {
    /// Explicit IP address or hostname to scan.
    #[arg(value_name = "ADDRESS_OR_HOSTNAME")]
    pub(crate) target: String,
    /// TCP SYN, UDP, or ICMP echo probes.
    #[arg(long, value_enum, default_value_t = Transport::Tcp)]
    pub(crate) transport: Transport,
    /// Select all authorized addresses or only one IP family.
    #[arg(long, value_enum, default_value_t = AddressFamily::Any)]
    pub(crate) family: AddressFamily,
    /// Comma-separated TCP/UDP destination ports or inclusive START-END ranges;
    /// omitted for ICMP.
    #[arg(long, value_delimiter = ',', num_args = 1..)]
    pub(crate) ports: Vec<PortSpec>,
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
    #[arg(long, default_value_t = packetcraftr::scan::DEFAULT_SCAN_BATCH_SIZE)]
    pub(crate) batch_size: usize,
    /// Maximum distinct destination ports accepted by the request.
    #[arg(long, default_value_t = packetcraftr::scan::DEFAULT_MAX_SCAN_PORTS)]
    pub(crate) max_ports: usize,
    /// Maximum generated probes after target resolution and attempts.
    #[arg(long, default_value_t = core::template::DEFAULT_MAX_TEMPLATE_PACKETS)]
    pub(crate) max_probes: usize,
    /// Maximum worst-case timeout plus intentional rate delay in milliseconds.
    #[arg(long, default_value_t = 3_600_000)]
    pub(crate) max_duration_ms: u64,
    /// Maximum undecodable exact frames retained across the scan.
    #[arg(long, default_value_t = packetcraftr::scan::DEFAULT_MAX_UNDECODED_SCAN_FRAMES)]
    pub(crate) max_undecoded: usize,
    #[command(flatten)]
    pub(crate) route: RouteSelectionArgs,
    #[command(flatten)]
    pub(crate) limits: CaptureLimitsArgs,
    #[command(flatten)]
    pub(crate) policy: HostnameTrafficPolicyArgs,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn port_specs_parse_single_ports_and_inclusive_ranges() {
        let cases = [
            ("0", PortSpec::Single(0)),
            ("65535", PortSpec::Single(u16::MAX)),
            ("80-82", PortSpec::RangeInclusive { start: 80, end: 82 }),
            (
                "443-443",
                PortSpec::RangeInclusive {
                    start: 443,
                    end: 443,
                },
            ),
        ];

        for (input, expected) in cases {
            assert_eq!(input.parse::<PortSpec>(), Ok(expected), "{input}");
        }
    }

    #[test]
    fn port_specs_reject_missing_reversed_and_non_u16_endpoints() {
        for input in ["", "65536", "-80", "80-", "82-80", "1-2-3", " 80"] {
            assert!(
                input.parse::<PortSpec>().is_err(),
                "{input:?} must not parse",
            );
        }
    }
}
