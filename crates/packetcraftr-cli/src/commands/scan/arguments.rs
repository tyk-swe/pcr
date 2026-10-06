// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::str::FromStr;

use clap::ValueEnum;
use packetcraftr_core as core;

use crate::command_options::{
    AddressFamily, CaptureLimitsArgs, HostnamePolicyArgs, MaxDurationArgs, RouteSelectionArgs,
    TimeoutArgs,
};

pub(crate) const AFTER_LONG_HELP: &str = r"Examples:
  packetcraftr scan 192.0.2.10 --transport tcp --ports 22,80,443
  packetcraftr scan 192.0.2.10 --transport udp --ports 53,8000-8100
  packetcraftr scan 192.0.2.10 --ports 1-1024 --max-in-flight 32
  packetcraftr scan 192.0.2.10 --transport udp --ports 53,9000 \
    --udp-profiles examples/documents/udp-profiles.json --max-in-flight 8
  packetcraftr --output ndjson scan 198.51.100.10 --transport icmp
  packetcraftr scan 192.0.2.10 --transport tcp,udp --ports @name-services,udp:ntp
  packetcraftr scan 192.0.2.10 --ports @all --exclude-ports telnet,8000-8100
  packetcraftr scan 192.0.2.10 --transport udp --ports @infrastructure \
    --curated-udp-payloads

Port syntax:
  --ports and --exclude-ports accept comma-separated terms: a u16 port, an
  inclusive START-END range with START <= END, a catalog name such as `https`,
  or a catalog preset such as `@web`. A `tcp:` or `udp:` prefix limits a term to
  one transport; otherwise it applies to every --transport. A name resolves to
  its catalog port on each transport that lists it. Endpoints keep their
  first-seen order and deduplicate; TCP and UDP on one port stay distinct.
  Exclusions are removed after expansion and before any probe is planned, so
  no stage probes an excluded endpoint, then --max-ports bounds the remainder.
  No transport has a default selection: a scan names its ports. Catalog names
  are conventional assignments (hints), not service identification; results
  name the catalog version. The bundled presets are web, mail, name-services,
  infrastructure, legacy-services, and all.

The default window is one probe. --rate bounds probe starts across the operation;
larger windows overlap response waits. Planned duration conservatively includes
timeout waves and pacing delays; it is not an achieved-throughput guarantee.

Multiple targets accept IP addresses, hostnames, scoped fe80::/10%zone
targets, and bounded CIDRs. --targets-file/- and --exclude-file/- read
line-oriented manifests (one declaration per line, # comments); at most one
stdin consumer is admitted across include/exclude/payload/profile inputs.
--exclude removes numeric addresses/CIDRs; --max-targets bounds the distinct
selection. --list publishes the exact selected target plan with origins and
resolved scopes without transmitting, capturing, or connecting; hostname
resolution still requires its policy opt-in and is reported as performed.
--connect uses ordinary TCP sockets, requires no raw-packet privileges, and caps
overlapping connections at 16. It reports socket outcomes and rejects packet
route overrides. Hostname lookup requires the existing policy opt-in.
--method selects raw packets (the default), tcp-connect (the same as
--connect), or auto. An explicit method is never replaced: raw fails with a
capability error when this build cannot capture and transmit. auto chooses raw
when the build can, and otherwise tcp-connect when every endpoint is TCP and no
packet route override is set; results publish the method and why auto chose it.

Each port endpoint reports an inferred state (open, closed, filtered,
open_or_filtered, or unknown) with the rule that produced it and the attempts
that support, conflict with, or did not answer it, beside every attempt
outcome. A silent UDP port is open_or_filtered. Socket deadlines and local
errors are operational failures, never port states. Late, duplicate, and
ambiguous replies are retained as unattributed evidence, bounded by
--max-undecoded and the evidence budget.

--max-in-flight bounds overlapping raw-packet response windows (1..=1024).
The complete plan is authorized before active discovery; capture is shared per
interface and ready before sends. One pacing schedule, operation deadline and
evidence budget apply across every window. --max-prepared-bytes bounds charged
plans and active packet descriptions.
With a window above one, NDJSON publishes probe_sent receipts before final probe
events and failures retain confirmed pending transmissions in error.scan; a
window of one publishes final probe events only.

--udp-profiles reads a bounded packetcraftr.udp-profiles/v1 document. Profiles
select a typed DNS query or explicit hexadecimal bytes per port, with DNS identity
checks or bounded offset/mask checks. Unmapped ports use --udp-payload-* or the
empty default payload. A profile's application status is separate from endpoint
reachability: open does not imply confirmed. DNS responses must match ID, opcode,
and questions. Configured byte checks only confirm those checks, not identity.
A nonmatching UDP reply remains evidence while a rolling window waits for a valid
application reply or its deadline. Profiles do not perform hidden resolution.
--curated-udp-payloads adds the bundled, versioned payload profiles (named
curated/...) for the selected UDP ports they cover; an operator profile for the
same port wins, and results list applied and overridden ports.
";

/// One `--ports` or `--exclude-ports` term.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PortTerm(pub(crate) packetcraftr::scan::Term);

impl FromStr for PortTerm {
    type Err = String;

    fn from_str(token: &str) -> Result<Self, Self::Err> {
        let (transport, selector) = match token.split_once(':') {
            Some(("tcp", selector)) => (Some(packetcraftr::probe::Transport::Tcp), selector),
            Some(("udp", selector)) => (Some(packetcraftr::probe::Transport::Udp), selector),
            Some((prefix, _)) => {
                return Err(format!(
                    "invalid port term `{token}`: transport prefix `{prefix}` is not tcp or udp"
                ));
            }
            None => (None, token),
        };
        let selector = if let Some(preset) = selector.strip_prefix('@') {
            packetcraftr::scan::Selector::Preset(catalog_name(token, preset)?)
        } else if selector.starts_with(|c: char| c.is_ascii_digit() || c == '-') {
            packetcraftr::scan::Selector::Ports(selector.parse::<PortSpec>()?.0)
        } else {
            packetcraftr::scan::Selector::Name(catalog_name(token, selector)?)
        };
        Ok(Self(packetcraftr::scan::Term {
            transport,
            selector,
        }))
    }
}

fn catalog_name(token: &str, name: &str) -> Result<String, String> {
    let valid = name.len() <= packetcraftr_core::document::port_catalog::MAX_NAME_BYTES
        && name.starts_with(|c: char| c.is_ascii_lowercase())
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
    if valid {
        Ok(name.to_owned())
    } else {
        Err(format!(
            "invalid port term `{token}`: expected a u16 port, START-END range, catalog name, \
             or @preset"
        ))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PortSpec(packetcraftr::scan::PortSpec);

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

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ValueEnum)]
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

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ValueEnum)]
pub(crate) enum Method {
    #[default]
    Raw,
    TcpConnect,
    Auto,
}

impl From<Method> for packetcraftr::scan::method::Requested {
    fn from(value: Method) -> Self {
        match value {
            Method::Raw => Self::Raw,
            Method::TcpConnect => Self::Connect,
            Method::Auto => Self::Automatic,
        }
    }
}

#[derive(Debug, clap::Args)]
pub(crate) struct Args {
    /// Use ordinary TCP connections without raw packet privileges; the same as
    /// `--method tcp-connect`.
    #[arg(long = "connect", conflicts_with = "method")]
    pub(crate) connect: bool,
    /// Raw packets, ordinary TCP connections, or automatic selection from
    /// this build's capabilities; an explicit method is never replaced.
    #[arg(long, value_enum, default_value_t = Method::Raw)]
    pub(crate) method: Method,
    /// Maximum overlapping probe windows; ordinary TCP is capped at 16.
    #[arg(long, default_value_t = 1)]
    pub(crate) max_in_flight: usize,

    /// Publish the selected target plan and its origins without sending probes.
    #[arg(long)]
    pub(crate) list: bool,
    /// Explicit IP addresses, hostnames, scoped fe80::/10%zone addresses, or
    /// bounded CIDRs, in selection order.
    #[arg(value_name = "TARGET", num_args = 0..)]
    pub(crate) targets: Vec<String>,
    /// Target manifest with one declaration per line, or - for stdin; repeat as needed.
    #[arg(long, value_name = "PATH")]
    pub(crate) targets_file: Vec<std::path::PathBuf>,
    /// Numeric IP or CIDR manifest, or - for stdin; repeat as needed.
    #[arg(long, value_name = "PATH")]
    pub(crate) exclude_file: Vec<std::path::PathBuf>,
    /// Combined byte budget across all manifests (maximum and default 1 MiB).
    #[arg(long, value_name = "BYTES")]
    pub(crate) max_manifest_bytes: Option<usize>,
    /// Combined physical-line budget across all manifests (maximum and default 4096).
    #[arg(long, value_name = "LINES")]
    pub(crate) max_manifest_lines: Option<usize>,
    /// Numeric IP or CIDR to exclude; repeat as needed.
    #[arg(long = "exclude", value_name = "IP_OR_CIDR")]
    pub(crate) exclusions: Vec<packetcraftr::target::Network>,
    /// Maximum distinct selected addresses across all targets.
    #[arg(long, default_value_t = packetcraftr::scan::Limits::default().max_targets)]
    pub(crate) max_targets: usize,
    /// TCP SYN, UDP, or ICMP echo probes; TCP and UDP combine in one plan
    /// (`tcp,udp`), while ICMP echo stands alone.
    #[arg(long, value_enum, value_delimiter = ',', num_args = 1.., default_value = "tcp")]
    pub(crate) transport: Vec<Transport>,
    /// Exact UDP probe payload in hex, with optional whitespace, colon, or dash separators.
    #[arg(long, value_name = "HEX", conflicts_with = "udp_payload_file")]
    pub(crate) udp_payload_hex: Option<String>,
    /// File containing exact UDP probe payload bytes (maximum 65507 bytes).
    #[arg(long, value_name = "PATH", conflicts_with = "udp_payload_hex")]
    pub(crate) udp_payload_file: Option<std::path::PathBuf>,
    /// Select all authorized addresses or only one IP family.
    #[arg(long, value_enum, default_value_t = AddressFamily::Any)]
    pub(crate) family: AddressFamily,
    /// Comma-separated ports, START-END ranges, catalog names, or @presets,
    /// optionally prefixed `tcp:` or `udp:`; omitted for ICMP.
    #[arg(long, value_name = "TERMS", value_delimiter = ',', num_args = 1..)]
    pub(crate) ports: Vec<PortTerm>,
    /// Terms removed from the expanded selection before planning.
    #[arg(long, value_name = "TERMS", value_delimiter = ',', num_args = 1..)]
    pub(crate) exclude_ports: Vec<PortTerm>,
    /// Number of bounded attempts per selected endpoint.
    #[arg(long, default_value_t = packetcraftr::scan::DEFAULT_ATTEMPTS)]
    pub(crate) attempts: u32,
    #[command(flatten)]
    pub(crate) timeout: TimeoutArgs,
    /// Operation-wide probe-start rate ceiling, not achieved throughput.
    #[arg(long)]
    pub(crate) rate: Option<u32>,
    /// Maximum distinct destination ports accepted by the request.
    #[arg(long, default_value_t = packetcraftr::scan::DEFAULT_MAX_PORTS)]
    pub(crate) max_ports: usize,
    /// Maximum generated probes after target resolution and attempts.
    #[arg(long, default_value_t = core::template::DEFAULT_MAX_TEMPLATE_PACKETS)]
    pub(crate) max_probes: usize,
    #[command(flatten)]
    pub(crate) duration: MaxDurationArgs,
    /// Maximum undecodable exact frames retained across the scan.
    #[arg(long, default_value_t = packetcraftr::scan::DEFAULT_MAX_UNDECODED_FRAMES)]
    pub(crate) max_undecoded: usize,
    /// Bounded per-port payload and response-check assignments (UDP profiles v1).
    #[arg(long)]
    pub(crate) udp_profiles: Option<std::path::PathBuf>,
    /// Probe covered UDP ports with the bundled, versioned curated payloads;
    /// operator profiles win for their ports.
    #[arg(long)]
    pub(crate) curated_udp_payloads: bool,
    /// Maximum charged plans and in-flight packet descriptions.
    #[arg(long, default_value_t = packetcraftr::scan::Limits::default().max_prepared_bytes)]
    pub(crate) max_prepared_bytes: usize,
    #[command(flatten)]
    pub(crate) route: RouteSelectionArgs,
    #[command(flatten)]
    pub(crate) limits: CaptureLimitsArgs,
    #[command(flatten)]
    pub(crate) policy: HostnamePolicyArgs,
}
