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
  packetcraftr network scan 192.0.2.10 --transport tcp --ports 22,80,443
  packetcraftr network scan 192.0.2.10 --transport udp --ports 53,8000-8100
  packetcraftr network scan 192.0.2.10 --transport sctp --ports 80,9899
  packetcraftr network scan 192.0.2.10 --transport sctp --sctp-scan cookie-echo --ports 80
  packetcraftr network scan 192.0.2.10 --transport ip --ip-protocols 1,6,17,47,132
  packetcraftr network scan 192.0.2.10 --ports 1-1024 --max-in-flight 32
  packetcraftr network scan 192.0.2.10 --tcp-scan ack --ports 22,80,443
  packetcraftr network scan 192.0.2.10 --tcp-scan custom --tcp-flags 0x029 --ports 80
  packetcraftr network scan 192.0.2.10 --transport udp --ports 53,9000 \
    --udp-profiles examples/documents/udp-profiles.json --max-in-flight 8
  packetcraftr --output ndjson network scan 198.51.100.10 --transport icmp
  packetcraftr network scan 192.0.2.10 --transport tcp,udp,sctp --ports @name-services,udp:ntp,sctp:9899
  packetcraftr network scan 192.0.2.10 --ports @all --exclude-ports ssh,8000-8100
  packetcraftr network scan 192.0.2.10 --transport udp --ports @infrastructure --curated-udp-payloads
  packetcraftr network scan 192.0.2.0/28 --discovery only --discovery-probes icmp,neighbor
  packetcraftr network scan 192.0.2.0/28 --discovery before --discovery-probes icmp,tcp,tcp-ack,sctp \
    --discovery-ports 22,443 --ports @web --reverse-dns 192.0.2.53

Ports, IP protocols, and methods:
  --ports and --exclude-ports accept u16 ports, START-END ranges, catalog names,
  and @presets (@web, @mail, @name-services, @infrastructure, @legacy-services,
  @all), optionally prefixed tcp:, udp:, or sctp:. --transport ip selects
  standalone IP-protocol inventory via --ip-protocols and --exclude-ip-protocols
  (0..=255 or START-END ranges). Exclusions apply before budgets.
  --method selects raw (default), tcp-connect (--connect), or auto; explicit
  methods never fall back. --tcp-scan selects syn (default), ack, window, fin,
  null, xmas, maimon, or observation-only custom (--tcp-flags 0..=0x1ff) for raw
  TCP scan endpoints; --sctp-scan selects init (default) or cookie-echo for raw
  SCTP scan endpoints. Each endpoint publishes an inferred state and supporting,
  conflicting, unanswered, or failed attempt sequences beside attempt outcomes.

Targets, discovery, scheduling, and follow-ups:
  Targets accept IPs, hostnames (with --allow-hostname-resolution), scoped
  fe80::/10%zone addresses, CIDRs, and --targets-file/--exclude-file manifests.
  --list publishes the target/port/IP-protocol plan without sending probes.
  --discovery before|only|skip runs icmp, icmp-timestamp, icmp-netmask, neighbor
  (ARP/NDP), tcp, tcp-ack, udp, sctp, or ip probes sharing the scan's budgets.
  --adaptive enables per-host RTT timeouts, AIMD windows, backoff retries, and
  host deadlines. --traceroute (raw only) traces scanned hosts before
  --reverse-dns PTR lookups under remaining budgets.";

/// One `--ports` or `--exclude-ports` term.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PortTerm(pub(crate) packetcraftr::scan::Term);

impl FromStr for PortTerm {
    type Err = String;

    fn from_str(token: &str) -> Result<Self, Self::Err> {
        let (transport, selector) = match token.split_once(':') {
            Some(("tcp", selector)) => (Some(packetcraftr::probe::Transport::Tcp), selector),
            Some(("udp", selector)) => (Some(packetcraftr::probe::Transport::Udp), selector),
            Some(("sctp", selector)) => (Some(packetcraftr::probe::Transport::Sctp), selector),
            Some((prefix, _)) => {
                return Err(format!(
                    "invalid port term `{token}`: transport prefix `{prefix}` is not tcp or udp (or sctp)"
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

/// One `--ip-protocols`, `--exclude-ip-protocols`, or `--discovery-ip-protocols` term.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct IpProtocolTerm(pub(crate) packetcraftr::scan::IpProtocolSpec);

impl FromStr for IpProtocolTerm {
    type Err = String;

    fn from_str(token: &str) -> Result<Self, Self::Err> {
        let Some((start_part, end_part)) = token.split_once('-') else {
            return Ok(Self(packetcraftr::scan::IpProtocolSpec::Single(
                parse_ip_protocol(token)?,
            )));
        };
        if start_part.is_empty() || end_part.is_empty() {
            return Err(format!(
                "invalid IP protocol spec `{token}`: inclusive ranges need the form START-END with both endpoints present"
            ));
        }
        let start = parse_ip_protocol(start_part)?;
        let end = parse_ip_protocol(end_part)?;
        if end < start {
            return Err(format!(
                "invalid IP protocol spec `{token}`: range end {end} precedes start {start}"
            ));
        }
        Ok(Self(packetcraftr::scan::IpProtocolSpec::RangeInclusive {
            start,
            end,
        }))
    }
}

fn parse_ip_protocol(token: &str) -> Result<u8, String> {
    token.parse::<u8>().map_err(|_| {
        format!(
            "invalid IP protocol spec `{token}`: expected a u8 protocol number (0..=255) or START-END range"
        )
    })
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ValueEnum)]
pub(crate) enum Transport {
    #[default]
    Tcp,
    Udp,
    Sctp,
    Icmp,
    Ip,
}

impl From<Transport> for packetcraftr::probe::Transport {
    fn from(value: Transport) -> Self {
        match value {
            Transport::Tcp => Self::Tcp,
            Transport::Udp => Self::Udp,
            Transport::Sctp => Self::Sctp,
            Transport::Icmp => Self::Icmp,
            Transport::Ip => Self::Ip,
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

/// The TCP segment each raw scan probe sends to a TCP scan endpoint.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ValueEnum)]
pub(crate) enum TcpScan {
    #[default]
    Syn,
    Ack,
    Window,
    Fin,
    Null,
    Xmas,
    Maimon,
    Custom,
}

const MAX_TCP_FLAGS: u16 = 0x1ff;

/// Decimal or `0x` hexadecimal TCP flag bits within the nine defined bits.
fn parse_tcp_flags(token: &str) -> Result<u16, String> {
    let parsed = match token
        .strip_prefix("0x")
        .or_else(|| token.strip_prefix("0X"))
    {
        Some(hex) => u16::from_str_radix(hex, 16),
        None => token.parse::<u16>(),
    };
    match parsed {
        Ok(flags) if flags <= MAX_TCP_FLAGS => Ok(flags),
        _ => Err(format!(
            "invalid TCP flags `{token}`: expected a decimal or 0x hexadecimal value within 0..={MAX_TCP_FLAGS:#x}"
        )),
    }
}

impl TcpScan {
    /// The library mode; custom needs `--tcp-flags` and nothing else accepts it.
    pub(crate) fn resolve(
        self,
        flags: Option<u16>,
    ) -> Result<packetcraftr::scan::TcpScan, crate::errors::CliError> {
        use packetcraftr::scan::TcpScan as Mode;
        let usage = |message: &str| {
            crate::errors::CliError::new(packetcraftr_core::error::Kind::Usage, message)
        };
        match (self, flags) {
            (Self::Custom, Some(flags)) => Ok(Mode::Custom { flags }),
            (Self::Custom, None) => Err(usage("--tcp-scan custom requires --tcp-flags")),
            (_, Some(_)) => Err(usage("--tcp-flags requires --tcp-scan custom")),
            (Self::Syn, None) => Ok(Mode::Syn),
            (Self::Ack, None) => Ok(Mode::Ack),
            (Self::Window, None) => Ok(Mode::Window),
            (Self::Fin, None) => Ok(Mode::Fin),
            (Self::Null, None) => Ok(Mode::Null),
            (Self::Xmas, None) => Ok(Mode::Xmas),
            (Self::Maimon, None) => Ok(Mode::Maimon),
        }
    }
}

/// The SCTP chunk each raw scan probe sends to an SCTP scan endpoint.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ValueEnum)]
pub(crate) enum SctpScan {
    #[default]
    Init,
    CookieEcho,
}

impl From<SctpScan> for packetcraftr::scan::SctpScan {
    fn from(value: SctpScan) -> Self {
        match value {
            SctpScan::Init => Self::Init,
            SctpScan::CookieEcho => Self::CookieEcho,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub(crate) enum Discovery {
    /// Discover hosts, then scan the ones that answered.
    Before,
    /// Discover hosts and probe no port.
    Only,
    /// Scan every host and record that discovery was deliberately skipped.
    Skip,
}

impl From<Discovery> for packetcraftr::scan::discovery::Mode {
    fn from(value: Discovery) -> Self {
        match value {
            Discovery::Before => Self::Before,
            Discovery::Only => Self::Only,
            Discovery::Skip => Self::Skipped,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub(crate) enum DiscoveryProbe {
    /// ICMP or ICMPv6 echo.
    Icmp,
    /// IPv4 ICMP timestamp request (type 13).
    IcmpTimestamp,
    /// IPv4 ICMP address mask request (type 17).
    IcmpNetmask,
    /// ARP or NDP for an on-link target; a routed target reports its next hop.
    Neighbor,
    /// TCP SYN, or a connection with `--connect`, to each discovery port.
    Tcp,
    /// Raw TCP ACK to each discovery port.
    TcpAck,
    /// UDP to each discovery port.
    Udp,
    /// SCTP INIT to each discovery port.
    Sctp,
    /// Empty-payload IP-protocol probe to each `--discovery-ip-protocols` number.
    Ip,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub(crate) enum UnresponsiveHosts {
    Skip,
    Scan,
}

impl From<UnresponsiveHosts> for packetcraftr::scan::discovery::Unresponsive {
    fn from(value: UnresponsiveHosts) -> Self {
        match value {
            UnresponsiveHosts::Skip => Self::Skip,
            UnresponsiveHosts::Scan => Self::Scan,
        }
    }
}

/// Opt-in adaptive scheduling; its timing and window bounds apply only with
/// `--adaptive` and never silently alter the fixed order.
#[derive(Clone, Copy, Debug, clap::Args)]
pub(crate) struct AdaptiveArgs {
    /// Schedule probes adaptively per scoped host: bounded waves sized by an
    /// AIMD window, per-host response timeouts, bounded exponential retries,
    /// and per-host deadlines inside the operation deadline.
    #[arg(long)]
    pub(crate) adaptive: bool,
    /// Floor on the adaptive response timeout in milliseconds (default 10).
    #[arg(long, requires = "adaptive", value_name = "MS")]
    pub(crate) min_timeout_ms: Option<u64>,
    /// Ceiling on the adaptive response timeout in milliseconds
    /// (defaults to --timeout-ms).
    #[arg(long, requires = "adaptive", value_name = "MS")]
    pub(crate) max_timeout_ms: Option<u64>,
    /// Floor on the adaptive admission window (default 1).
    #[arg(long, requires = "adaptive", value_name = "COUNT")]
    pub(crate) min_window: Option<usize>,
    /// Opening adaptive admission window (defaults to min(4, max-in-flight)).
    #[arg(long, requires = "adaptive", value_name = "COUNT")]
    pub(crate) initial_window: Option<usize>,
    /// Per-scoped-host deadline in milliseconds (defaults to --max-duration-ms).
    #[arg(long, requires = "adaptive", value_name = "MS")]
    pub(crate) host_timeout_ms: Option<u64>,
    /// Base delay before a silent endpoint's next attempt in milliseconds
    /// (default 100).
    #[arg(long, requires = "adaptive", value_name = "MS")]
    pub(crate) retry_backoff_ms: Option<u64>,
    /// Ceiling on the retry delay in milliseconds (default 1000).
    #[arg(long, requires = "adaptive", value_name = "MS")]
    pub(crate) max_backoff_ms: Option<u64>,
}

impl AdaptiveArgs {
    /// The effective configuration, or `None` for fixed scheduling.
    pub(crate) fn into_adaptive(
        self,
        timeout: std::time::Duration,
        max_duration: std::time::Duration,
        max_in_flight: usize,
    ) -> Option<packetcraftr::scan::Adaptive> {
        self.adaptive.then_some(packetcraftr::scan::Adaptive {
            min_timeout: self
                .min_timeout_ms
                .map(std::time::Duration::from_millis)
                .unwrap_or(std::time::Duration::from_millis(10)),
            max_timeout: self
                .max_timeout_ms
                .map(std::time::Duration::from_millis)
                .unwrap_or(timeout),
            min_window: self.min_window.unwrap_or(1),
            initial_window: self
                .initial_window
                .unwrap_or_else(|| 4usize.min(max_in_flight)),
            host_timeout: self
                .host_timeout_ms
                .map(std::time::Duration::from_millis)
                .unwrap_or(max_duration),
            retry_backoff: self
                .retry_backoff_ms
                .map(std::time::Duration::from_millis)
                .unwrap_or(std::time::Duration::from_millis(100)),
            max_backoff: self
                .max_backoff_ms
                .map(std::time::Duration::from_millis)
                .unwrap_or(std::time::Duration::from_secs(1)),
        })
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
    /// Maximum overlapping probe windows; ordinary TCP accepts an operation
    /// bound above the shared 16-worker pool, which queues with backpressure.
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
    /// TCP, UDP, SCTP, ICMP echo, or IP-protocol probes; TCP, UDP, and SCTP
    /// combine in one plan (`tcp,udp,sctp`), while ICMP echo and IP-protocol
    /// inventory stand alone.
    #[arg(
        long,
        value_enum,
        value_delimiter = ',',
        num_args = 1,
        default_value = "tcp"
    )]
    pub(crate) transport: Vec<Transport>,
    /// TCP segment sent to each raw TCP scan endpoint: syn (default), ack,
    /// window, fin, null, xmas, maimon, or custom with --tcp-flags. Diagnostic
    /// modes are stack-dependent inferences; discovery stays SYN unless
    /// tcp-ack is explicitly selected.
    #[arg(long, value_enum, default_value_t = TcpScan::Syn)]
    pub(crate) tcp_scan: TcpScan,
    /// TCP flag bits for --tcp-scan custom, decimal or 0x hexadecimal within
    /// 0..=0x1ff; custom probes are observation-only and infer no port state.
    #[arg(long, value_name = "FLAGS", value_parser = parse_tcp_flags)]
    pub(crate) tcp_flags: Option<u16>,
    /// SCTP chunk sent to each raw SCTP scan endpoint: init (default) or
    /// cookie-echo. Discovery SCTP probes always send INIT.
    #[arg(long, value_enum, default_value_t = SctpScan::Init)]
    pub(crate) sctp_scan: SctpScan,
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
    /// optionally prefixed `tcp:`, `udp:`, or `sctp:`; omitted for ICMP and IP.
    #[arg(long, value_name = "TERMS", value_delimiter = ',', num_args = 1..)]
    pub(crate) ports: Vec<PortTerm>,
    /// Terms removed from the expanded port selection before planning.
    #[arg(long, value_name = "TERMS", value_delimiter = ',', num_args = 1..)]
    pub(crate) exclude_ports: Vec<PortTerm>,
    /// Comma-separated IP protocol numbers (0..=255) or START-END ranges for
    /// `--transport ip`.
    #[arg(long, value_name = "TERMS", value_delimiter = ',', num_args = 1..)]
    pub(crate) ip_protocols: Vec<IpProtocolTerm>,
    /// IP protocol numbers or START-END ranges removed before planning.
    #[arg(long, value_name = "TERMS", value_delimiter = ',', num_args = 1..)]
    pub(crate) exclude_ip_protocols: Vec<IpProtocolTerm>,
    /// Discover hosts `before` the scan or `only`, or `skip` discovery and
    /// say so; without it, hosts are scanned and labeled not discovered.
    #[arg(long, value_enum)]
    pub(crate) discovery: Option<Discovery>,
    /// Discovery probes: icmp, icmp-timestamp, icmp-netmask, neighbor, tcp,
    /// tcp-ack, udp, sctp, and ip (default icmp).
    #[arg(
        long,
        value_enum,
        value_delimiter = ',',
        num_args = 1,
        requires = "discovery"
    )]
    pub(crate) discovery_probes: Vec<DiscoveryProbe>,
    /// Port terms for tcp, tcp-ack, udp, and sctp discovery probes, in --ports
    /// syntax; --exclude-ports applies to them too.
    #[arg(
        long,
        value_name = "TERMS",
        value_delimiter = ',',
        num_args = 1..,
        requires = "discovery"
    )]
    pub(crate) discovery_ports: Vec<PortTerm>,
    /// IP protocol numbers or START-END ranges for `ip` discovery probes;
    /// --exclude-ip-protocols applies to them too.
    #[arg(
        long,
        value_name = "TERMS",
        value_delimiter = ',',
        num_args = 1..,
        requires = "discovery"
    )]
    pub(crate) discovery_ip_protocols: Vec<IpProtocolTerm>,
    /// Whether `--discovery before` skips (default) or scans hosts that did
    /// not answer.
    #[arg(long, value_enum, requires = "discovery")]
    pub(crate) unresponsive_hosts: Option<UnresponsiveHosts>,
    /// Look up PTR names through this DNS server for hosts that answered
    /// discovery, or for every host when discovery did not run.
    #[arg(long, value_name = "SERVER")]
    pub(crate) reverse_dns: Option<String>,
    /// DNS server port for --reverse-dns.
    #[arg(
        long,
        value_name = "PORT",
        default_value_t = packetcraftr::dns::DEFAULT_SERVER_PORT,
        requires = "reverse_dns"
    )]
    pub(crate) reverse_dns_port: u16,
    /// Number of bounded attempts per selected endpoint.
    #[arg(long, default_value_t = packetcraftr::scan::DEFAULT_ATTEMPTS)]
    pub(crate) attempts: u32,
    #[command(flatten)]
    pub(crate) adaptive: AdaptiveArgs,
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
    /// After the scan, trace every scanned host.
    #[arg(long)]
    pub(crate) traceroute: bool,
    /// Probe for hosts the scan saw no responsive TCP or ICMP echo probe
    /// from; without it those hosts are not traced.
    #[arg(long, value_enum, requires = "traceroute")]
    pub(crate) traceroute_strategy:
        Option<crate::commands::network::traceroute::arguments::Strategy>,
    /// Non-zero UDP base port or fixed TCP port for --traceroute-strategy.
    #[arg(long, value_parser = clap::value_parser!(u16).range(1..), requires = "traceroute")]
    pub(crate) traceroute_port: Option<u16>,
    /// First non-zero IPv4 TTL or IPv6 hop limit traced.
    #[arg(
        long,
        default_value_t = packetcraftr::traceroute::DEFAULT_FIRST_HOP,
        value_parser = clap::value_parser!(u8).range(1..),
        requires = "traceroute"
    )]
    pub(crate) traceroute_first_hop: u8,
    /// Last IPv4 TTL or IPv6 hop limit traced.
    #[arg(long, default_value_t = packetcraftr::traceroute::DEFAULT_MAX_HOPS, requires = "traceroute")]
    pub(crate) traceroute_max_hops: u8,
    /// Number of attempts retained for every traced hop.
    #[arg(long, default_value_t = packetcraftr::traceroute::DEFAULT_PROBES_PER_HOP, requires = "traceroute")]
    pub(crate) traceroute_attempts: u32,
    /// Maximum trace-stage transmissions: every host and hop's probes plus the
    /// neighbor requests link-layer traces may resolve (one per probe).
    #[arg(long, default_value_t = core::template::DEFAULT_MAX_TEMPLATE_PACKETS, requires = "traceroute")]
    pub(crate) traceroute_max_probes: usize,
    /// Let a host reuse hops an earlier host's trace observed within this
    /// operation, for hops younger than this many milliseconds.
    #[arg(
        long,
        value_name = "MS",
        value_parser = clap::value_parser!(u64).range(1..=crate::command_options::MAX_MILLISECONDS),
        requires = "traceroute"
    )]
    pub(crate) traceroute_reuse_max_age_ms: Option<u64>,
    #[command(flatten)]
    pub(crate) route: RouteSelectionArgs,
    #[command(flatten)]
    pub(crate) limits: CaptureLimitsArgs,
    #[command(flatten)]
    pub(crate) policy: HostnamePolicyArgs,
}
