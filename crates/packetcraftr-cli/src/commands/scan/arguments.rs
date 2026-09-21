// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::str::FromStr;

use clap::ValueEnum;
use packetcraftr_core as core;

use crate::command_options::{
    AddressFamily, CaptureLimitsArgs, HostnamePolicyArgs, RouteSelectionArgs,
};

pub(crate) const AFTER_LONG_HELP: &str = r"Examples:
  packetcraftr scan 192.0.2.10 --transport tcp --ports 22,80,443
  packetcraftr scan 192.0.2.10 --transport udp --ports 53,8000-8100
  packetcraftr scan 192.0.2.10 --ports 1-1024 --max-in-flight 32
  packetcraftr scan 192.0.2.10 --transport udp --ports 53,9000 \
    --udp-profiles examples/documents/udp-profiles.json --max-in-flight 8
  packetcraftr --output ndjson scan 198.51.100.10 --transport icmp

Port syntax:
  --ports accepts comma-separated u16 ports and inclusive ranges of the form
  START-END, where START and END are both u16 ports and START <= END. Repeated
  ports and overlapping ranges keep their first-seen order and deduplicate.
  Expansion is bounded by --max-ports and stops as soon as another distinct
  port would exceed that limit.

The default window is one probe. --rate bounds probe starts across the operation;
larger windows overlap response waits. Planned duration conservatively includes
timeout waves and pacing delays; it is not an achieved-throughput guarantee.

Multiple targets accept IP addresses, hostnames, and bounded CIDRs. --exclude
removes numeric addresses/CIDRs; --max-targets bounds the distinct selection.
--connect uses ordinary TCP sockets, requires no raw-packet privileges, and caps
overlapping connections at 16. It reports socket outcomes and rejects packet
route overrides. Hostname lookup requires the existing policy opt-in.

--max-in-flight bounds overlapping raw-packet response windows (1..=1024).
The complete plan is authorized before active discovery; capture is shared per
interface and ready before sends. One pacing schedule, operation deadline and
evidence budget apply across every window. --max-prepared-bytes bounds charged
plans and active packet descriptions. Executors lacking window support reject it.
NDJSON publishes probe_sent receipts before final probe events. Failures retain
confirmed pending transmissions in error.scan.

--udp-profiles reads a bounded packetcraftr.udp-profiles/v1 document. Profiles
select a typed DNS query or explicit hexadecimal bytes per port, with DNS identity
checks or bounded offset/mask checks. Unmapped ports use --udp-payload-* or the
empty default payload. A profile's application status is separate from endpoint
reachability: open does not imply confirmed. DNS responses must match ID, opcode,
and questions. Configured byte checks only confirm those checks, not identity.
A nonmatching UDP reply remains evidence while a rolling window waits for a valid
application reply or its deadline. Profiles do not perform hidden resolution.
";

/// One CLI `--ports` token, parsed into the library's own port selection.
///
/// Only the token syntax and its clap-facing messages live here; expansion,
/// de-duplication, and the `max_ports` ceiling belong to
/// [`packetcraftr::scan::select_ports`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PortSpec(pub(crate) packetcraftr::scan::PortSpec);

impl FromStr for PortSpec {
    type Err = String;

    fn from_str(token: &str) -> Result<Self, Self::Err> {
        let Some((start_part, end_part)) = token.split_once('-') else {
            return Ok(Self(packetcraftr::scan::PortSpec::Single(parse_port(
                token,
            )?)));
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
        Ok(Self(packetcraftr::scan::PortSpec::RangeInclusive {
            start,
            end,
        }))
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

impl From<Transport> for packetcraftr::probe::Transport {
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
    /// Use ordinary TCP connections without raw packet privileges.
    #[arg(long = "connect")]
    pub(crate) connect: bool,
    /// Maximum overlapping probe windows; ordinary TCP is capped at 16.
    #[arg(long, default_value_t = 1)]
    pub(crate) max_in_flight: usize,

    /// Explicit IP addresses, hostnames, or bounded CIDRs, in selection order.
    #[arg(value_name = "TARGET", required=true, num_args=1..)]
    pub(crate) targets: Vec<String>,
    /// Numeric IP or CIDR to exclude; repeat as needed.
    #[arg(long = "exclude", value_name = "IP_OR_CIDR")]
    pub(crate) exclusions: Vec<packetcraftr::target::Network>,
    /// Maximum distinct selected addresses across all targets.
    #[arg(long, default_value_t = 1024)]
    pub(crate) max_targets: usize,
    /// TCP SYN, UDP, or ICMP echo probes.
    #[arg(long, value_enum, default_value_t = Transport::Tcp)]
    pub(crate) transport: Transport,
    /// Exact UDP probe payload in hex, with optional whitespace, colon, or dash separators.
    #[arg(long, value_name = "HEX", conflicts_with = "udp_payload_file")]
    pub(crate) udp_payload_hex: Option<String>,
    /// File containing exact UDP probe payload bytes (maximum 65507 bytes).
    #[arg(long, value_name = "PATH", conflicts_with = "udp_payload_hex")]
    pub(crate) udp_payload_file: Option<std::path::PathBuf>,
    /// Select all authorized addresses or only one IP family.
    #[arg(long, value_enum, default_value_t = AddressFamily::Any)]
    pub(crate) family: AddressFamily,
    /// Comma-separated TCP/UDP destination ports or inclusive START-END ranges;
    /// omitted for ICMP.
    #[arg(long, value_delimiter = ',', num_args = 1..)]
    pub(crate) ports: Vec<PortSpec>,
    /// Number of bounded attempts per selected endpoint.
    #[arg(long, default_value_t = packetcraftr::scan::DEFAULT_ATTEMPTS)]
    pub(crate) attempts: u32,
    /// Response window for each capture-ready probe.
    #[arg(long, default_value_t = 1_000)]
    pub(crate) timeout_ms: u64,
    /// Operation-wide probe-start rate ceiling, not achieved throughput.
    #[arg(long)]
    pub(crate) rate: Option<u32>,
    /// Maximum distinct destination ports accepted by the request.
    #[arg(long, default_value_t = packetcraftr::scan::DEFAULT_MAX_PORTS)]
    pub(crate) max_ports: usize,
    /// Maximum generated probes after target resolution and attempts.
    #[arg(long, default_value_t = core::template::DEFAULT_MAX_TEMPLATE_PACKETS)]
    pub(crate) max_probes: usize,
    /// Maximum worst-case timeout plus intentional rate delay in milliseconds.
    #[arg(long, default_value_t = 3_600_000)]
    pub(crate) max_duration_ms: u64,
    /// Maximum undecodable exact frames retained across the scan.
    #[arg(long, default_value_t = packetcraftr::scan::DEFAULT_MAX_UNDECODED_FRAMES)]
    pub(crate) max_undecoded: usize,
    /// Bounded per-port payload and response-check assignments (UDP profiles v1).
    #[arg(long)]
    pub(crate) udp_profiles: Option<std::path::PathBuf>,
    /// Maximum charged plans and in-flight packet descriptions.
    #[arg(long,default_value_t=64*1024*1024)]
    pub(crate) max_prepared_bytes: usize,
    #[command(flatten)]
    pub(crate) route: RouteSelectionArgs,
    #[command(flatten)]
    pub(crate) limits: CaptureLimitsArgs,
    #[command(flatten)]
    pub(crate) policy: HostnamePolicyArgs,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn port_specs_parse_single_ports_and_inclusive_ranges() {
        use packetcraftr::scan::PortSpec as Spec;

        let cases = [
            ("0", PortSpec(Spec::Single(0))),
            ("65535", PortSpec(Spec::Single(u16::MAX))),
            (
                "80-82",
                PortSpec(Spec::RangeInclusive { start: 80, end: 82 }),
            ),
            (
                "443-443",
                PortSpec(Spec::RangeInclusive {
                    start: 443,
                    end: 443,
                }),
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
