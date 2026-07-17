// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

// Clap argument and command models.

use std::net::IpAddr;
use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};
use packetcraftr::{capture, client, net, output, packet, workflow};

#[derive(Debug, Parser)]
#[command(
    name = "packetcraftr",
    bin_name = "packetcraftr",
    version,
    about = "Reflective packet construction, dissection, capture, and network tools",
    long_about = "PacketcraftR builds and dissects arbitrary packet stacks with exact bytes, bounded parsing, passive route planning, and policy-gated live workflows. Native features, dependencies, and privileges determine which live paths are available."
)]
pub(super) struct Cli {
    #[arg(long, global = true, value_enum, default_value_t = CliOutputFormat::Text)]
    pub(super) output: CliOutputFormat,
    #[command(subcommand)]
    pub(super) command: Command,
}

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
pub(super) enum CliOutputFormat {
    #[default]
    Text,
    Json,
    Ndjson,
    Hex,
    Raw,
    Pcap,
    Pcapng,
}

impl std::fmt::Display for CliOutputFormat {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(output::contract::Format::from(*self).as_str())
    }
}

impl From<CliOutputFormat> for output::contract::Format {
    fn from(value: CliOutputFormat) -> Self {
        match value {
            CliOutputFormat::Text => Self::Text,
            CliOutputFormat::Json => Self::Json,
            CliOutputFormat::Ndjson => Self::Ndjson,
            CliOutputFormat::Hex => Self::Hex,
            CliOutputFormat::Raw => Self::Raw,
            CliOutputFormat::Pcap => Self::Pcap,
            CliOutputFormat::Pcapng => Self::Pcapng,
        }
    }
}

#[derive(Debug, Subcommand)]
pub(super) enum Command {
    /// Build exact packet bytes from an expression or document.
    Build(BuildArgs),
    /// Decode a frame with bounded, registry-driven dissection.
    Dissect(DissectArgs),
    /// Stream frames from a classic PCAP or PCAPNG file.
    Read(ReadArgs),
    /// Enumerate local interfaces.
    Interfaces,
    /// Passively select route, source, MTU, and link mode.
    Plan(RouteArgs),
    /// Transmit a packet under traffic policy.
    Send(SendArgs),
    /// Capture-ready request/response exchange.
    Exchange(ExchangeArgs),
    /// Stream live captured frames.
    Capture(CaptureArgs),
    /// Replay a PCAP/PCAPNG stream.
    Replay(ReplayArgs),
    /// Run a structured network scan.
    Scan(ScanArgs),
    /// Run bounded, policy-gated traceroute probes.
    #[command(
        long_about = "Run bounded, policy-gated traceroute probes. UDP starts at --port and increments the destination port for every probe; TCP keeps --port fixed. Each hop sends its attempts as one burst and shares one --timeout-ms response window. Traceroute supports text, JSON, and NDJSON output. Public destinations and hostname resolution require their respective explicit policy options."
    )]
    Traceroute(TracerouteArgs),
    /// Run a structured DNS operation.
    Dns(DnsArgs),
    /// Run bounded field-aware packet fuzzing.
    Fuzz(FuzzArgs),
    /// Enumerate passive interface-bound route decisions.
    Routes,
}

#[derive(Debug, Args)]
pub(super) struct RecipeArgs {
    /// One-off layer expression.
    #[arg(long, conflicts_with = "packet_file")]
    pub(super) packet: Option<String>,
    /// Versioned JSON/YAML packet document.
    #[arg(long, value_name = "PATH", conflicts_with = "packet")]
    pub(super) packet_file: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub(super) struct BuildArgs {
    #[command(flatten)]
    pub(super) recipe: RecipeArgs,
    #[arg(long, value_enum, default_value_t = CliBuildMode::Strict)]
    pub(super) mode: CliBuildMode,
}

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
pub(super) enum CliBuildMode {
    #[default]
    Strict,
    Permissive,
}

#[derive(Debug, Args)]
pub(super) struct DissectArgs {
    /// Whole-frame hexadecimal bytes.
    #[arg(long, conflicts_with = "file")]
    pub(super) hex: Option<String>,
    /// File containing raw frame bytes.
    #[arg(long, value_name = "PATH", conflicts_with = "hex")]
    pub(super) file: Option<PathBuf>,
    /// Open numeric DLT/link type (defaults to Ethernet/DLT 1).
    #[arg(long, default_value_t = 1)]
    pub(super) link_type: u32,
}

#[derive(Debug, Args)]
pub(super) struct ReadArgs {
    pub(super) path: PathBuf,
    /// Maximum frames read or copied from the capture stream.
    #[arg(long, default_value_t = capture::DEFAULT_STREAM_FRAMES)]
    pub(super) max_frames: u64,
    /// Maximum aggregate captured payload bytes read or copied.
    #[arg(long, default_value_t = capture::DEFAULT_STREAM_BYTES)]
    pub(super) max_bytes: u64,
    /// Maximum bytes accepted from any one captured frame or PCAPNG block.
    #[arg(long, default_value_t = capture::DEFAULT_SIZE_LIMIT)]
    pub(super) max_frame_bytes: usize,
    /// Maximum PCAPNG interfaces accepted from the input.
    #[arg(long, default_value_t = capture::DEFAULT_INTERFACE_LIMIT)]
    pub(super) max_interfaces: usize,
}

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
pub(super) enum CliReplayTiming {
    #[default]
    Original,
    Immediate,
}

#[derive(Debug, Args)]
pub(super) struct ReplayArgs {
    /// Classic PCAP or PCAPNG input path.
    pub(super) path: PathBuf,
    /// Exact interface name or numeric index used for every transmission.
    #[arg(long, value_name = "NAME_OR_INDEX")]
    pub(super) interface: String,
    /// Automatic, Layer 2, or raw Layer 3 replay intent.
    #[arg(long, value_enum, default_value_t = CliLinkMode::Auto)]
    pub(super) link_mode: CliLinkMode,
    /// Preserve captured intervals or send immediately.
    #[arg(long, value_enum, default_value_t = CliReplayTiming::Original)]
    pub(super) timing: CliReplayTiming,
    /// Positive multiplier for captured replay speed (2 means twice as fast).
    #[arg(long, conflicts_with = "rate")]
    pub(super) speed: Option<f64>,
    /// Positive fixed frame rate, overriding captured intervals.
    #[arg(long, conflicts_with = "speed")]
    pub(super) rate: Option<f64>,
    /// Maximum cumulative intentional replay delay in milliseconds.
    #[arg(long, default_value_t = 3_600_000)]
    pub(super) max_duration_ms: u64,
    /// Maximum bytes accepted from any one captured frame or PCAPNG block.
    #[arg(long, default_value_t = capture::DEFAULT_SIZE_LIMIT)]
    pub(super) max_frame_bytes: usize,
    /// Maximum PCAPNG interfaces accepted from the input.
    #[arg(long, default_value_t = capture::DEFAULT_INTERFACE_LIMIT)]
    pub(super) max_interfaces: usize,
    /// Per-operation opt-in required when dissection preserves malformed bytes.
    #[arg(long)]
    pub(super) allow_malformed_live: bool,
    #[command(flatten)]
    pub(super) policy: ReplayPolicyArgs,
}

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
pub(super) enum CliFuzzStrategy {
    #[default]
    Boundary,
    Random,
    BitFlip,
    Malformed,
}

impl From<CliFuzzStrategy> for workflow::fuzz::Strategy {
    fn from(value: CliFuzzStrategy) -> Self {
        match value {
            CliFuzzStrategy::Boundary => Self::Boundary,
            CliFuzzStrategy::Random => Self::Random,
            CliFuzzStrategy::BitFlip => Self::BitFlip,
            CliFuzzStrategy::Malformed => Self::Malformed,
        }
    }
}

#[derive(Debug, Args)]
pub(super) struct FuzzArgs {
    #[command(flatten)]
    pub(super) recipe: RecipeArgs,
    /// Stable operation seed used to derive each case independently.
    #[arg(long, default_value_t = 0)]
    pub(super) seed: u64,
    /// Absolute first case index; combine with --cases 1 to reproduce a case.
    #[arg(long, default_value_t = 0)]
    pub(super) first_case: u64,
    /// Number of ordered cases to generate.
    #[arg(long, default_value_t = workflow::fuzz::DEFAULT_FUZZ_CASES)]
    pub(super) cases: usize,
    /// Comma-separated field-aware mutation strategies.
    #[arg(
        long = "strategy",
        value_enum,
        value_delimiter = ',',
        default_value = "boundary,random,bit-flip,malformed"
    )]
    pub(super) strategies: Vec<CliFuzzStrategy>,
    /// Restrict mutation to repeated LAYER.FIELD targets; defaults to all fields.
    #[arg(long = "field", value_delimiter = ',')]
    pub(super) fields: Vec<String>,
    /// Strict or permissive packet construction for generated cases.
    #[arg(long, value_enum, default_value_t = CliBuildMode::Strict)]
    pub(super) mode: CliBuildMode,
    /// Explicitly enable route, capture, and transmission; offline is the default.
    #[arg(long)]
    pub(super) live: bool,
    /// Independent per-operation opt-in for permissive/malformed live cases.
    #[arg(long)]
    pub(super) allow_malformed_live: bool,
    /// Optional route destination when the packet has no fixed destination.
    #[arg(long)]
    pub(super) destination: Option<IpAddr>,
    /// Response window for each capture-ready live case.
    #[arg(long, default_value_t = 1_000)]
    pub(super) timeout_ms: u64,
    /// Optional average live-case rate ceiling.
    #[arg(long)]
    pub(super) rate: Option<u32>,
    /// Maximum cases accepted by this operation.
    #[arg(long, default_value_t = workflow::fuzz::DEFAULT_MAX_FUZZ_CASES)]
    pub(super) max_cases: usize,
    /// Maximum aggregate retained case data and live wire bytes.
    #[arg(long, default_value_t = net::capture::Limits::default().max_bytes)]
    pub(super) max_total_bytes: usize,
    /// Maximum bytes allocated for one generated field value.
    #[arg(long, default_value_t = workflow::fuzz::DEFAULT_MAX_FUZZ_FIELD_BYTES)]
    pub(super) max_field_bytes: usize,
    /// Maximum list elements generated by one mutation.
    #[arg(long, default_value_t = workflow::fuzz::DEFAULT_MAX_FUZZ_LIST_ITEMS)]
    pub(super) max_list_items: usize,
    /// Maximum deterministic shrink candidates returned per case.
    #[arg(long, default_value_t = workflow::fuzz::DEFAULT_MAX_FUZZ_SHRINK_STEPS)]
    pub(super) max_shrink_steps: usize,
    /// Maximum worst-case timeout plus intentional rate delay in milliseconds.
    #[arg(long, default_value_t = 3_600_000)]
    pub(super) max_duration_ms: u64,
    /// Interface name or numeric index used as an exact live route constraint.
    #[arg(long, value_name = "NAME_OR_INDEX")]
    pub(super) interface: Option<String>,
    /// Interface-owned source preference used only for live route selection.
    #[arg(long)]
    pub(super) source: Option<IpAddr>,
    /// Automatic, Layer 2, or raw Layer 3 live transmission intent.
    #[arg(long, value_enum, default_value_t = CliLinkMode::Auto)]
    pub(super) link_mode: CliLinkMode,
    #[command(flatten)]
    pub(super) limits: CaptureLimitArgs,
    #[command(flatten)]
    pub(super) policy: TrafficPolicyArgs,
}

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
pub(super) enum CliScanTransport {
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

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
pub(super) enum CliAddressFamily {
    #[default]
    Any,
    Ipv4,
    Ipv6,
}

impl From<CliAddressFamily> for workflow::AddressFamily {
    fn from(value: CliAddressFamily) -> Self {
        match value {
            CliAddressFamily::Any => Self::Any,
            CliAddressFamily::Ipv4 => Self::Ipv4,
            CliAddressFamily::Ipv6 => Self::Ipv6,
        }
    }
}

#[derive(Debug, Args)]
pub(super) struct ScanArgs {
    /// Explicit IP address or hostname to scan.
    #[arg(value_name = "ADDRESS_OR_HOSTNAME")]
    pub(super) target: String,
    /// TCP SYN, UDP, or ICMP echo probes.
    #[arg(long, value_enum, default_value_t = CliScanTransport::Tcp)]
    pub(super) transport: CliScanTransport,
    /// Select all authorized addresses or only one IP family.
    #[arg(long, value_enum, default_value_t = CliAddressFamily::Any)]
    pub(super) family: CliAddressFamily,
    /// Comma-separated TCP/UDP destination ports; omitted for ICMP.
    #[arg(long, value_delimiter = ',', num_args = 1..)]
    pub(super) ports: Vec<u16>,
    /// Number of bounded attempts per selected endpoint.
    #[arg(long, default_value_t = 1)]
    pub(super) attempts: u32,
    /// Response window for each capture-ready batch.
    #[arg(long, default_value_t = 1_000)]
    pub(super) timeout_ms: u64,
    /// Optional average probe-rate ceiling; batches remain deliberate bursts.
    #[arg(long)]
    pub(super) rate: Option<u32>,
    /// Maximum probes sent by one shared-capture exchange batch.
    #[arg(long, default_value_t = workflow::scan::DEFAULT_SCAN_BATCH_SIZE)]
    pub(super) batch_size: usize,
    /// Maximum distinct destination ports accepted by the request.
    #[arg(long, default_value_t = workflow::scan::DEFAULT_MAX_SCAN_PORTS)]
    pub(super) max_ports: usize,
    /// Maximum generated probes after target resolution and attempts.
    #[arg(long, default_value_t = packet::template::DEFAULT_MAX_TEMPLATE_PACKETS)]
    pub(super) max_probes: usize,
    /// Maximum worst-case timeout plus intentional rate delay in milliseconds.
    #[arg(long, default_value_t = 3_600_000)]
    pub(super) max_duration_ms: u64,
    /// Maximum undecodable exact frames retained across the scan.
    #[arg(long, default_value_t = workflow::scan::DEFAULT_MAX_UNDECODED_SCAN_FRAMES)]
    pub(super) max_undecoded: usize,
    /// Interface name or numeric index used as an exact route constraint.
    #[arg(long, value_name = "NAME_OR_INDEX")]
    pub(super) interface: Option<String>,
    /// Interface-owned source preference used only for route selection.
    #[arg(long)]
    pub(super) source: Option<IpAddr>,
    /// Automatic, Layer 2, or raw Layer 3 transmission intent.
    #[arg(long, value_enum, default_value_t = CliLinkMode::Auto)]
    pub(super) link_mode: CliLinkMode,
    #[command(flatten)]
    pub(super) limits: CaptureLimitArgs,
    #[command(flatten)]
    pub(super) policy: TrafficPolicyArgs,
}

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
pub(super) enum CliDnsQueryType {
    #[default]
    A,
    Aaaa,
    Cname,
    Mx,
    Ns,
    Ptr,
    Soa,
    Srv,
    Txt,
    Any,
}

impl From<CliDnsQueryType> for workflow::dns::QueryType {
    fn from(value: CliDnsQueryType) -> Self {
        match value {
            CliDnsQueryType::A => Self::A,
            CliDnsQueryType::Aaaa => Self::Aaaa,
            CliDnsQueryType::Cname => Self::Cname,
            CliDnsQueryType::Mx => Self::Mx,
            CliDnsQueryType::Ns => Self::Ns,
            CliDnsQueryType::Ptr => Self::Ptr,
            CliDnsQueryType::Soa => Self::Soa,
            CliDnsQueryType::Srv => Self::Srv,
            CliDnsQueryType::Txt => Self::Txt,
            CliDnsQueryType::Any => Self::Any,
        }
    }
}

#[derive(Debug, Args)]
pub(super) struct DnsArgs {
    /// Explicit DNS server IP address or hostname.
    #[arg(value_name = "SERVER")]
    pub(super) server: String,
    /// Bounded ASCII DNS owner name to query.
    #[arg(value_name = "NAME")]
    pub(super) name: String,
    /// DNS question type.
    #[arg(long = "type", value_enum, default_value_t = CliDnsQueryType::A)]
    pub(super) query_type: CliDnsQueryType,
    /// Select the first authorized server address or one IP family.
    #[arg(long, value_enum, default_value_t = CliAddressFamily::Any)]
    pub(super) family: CliAddressFamily,
    /// DNS server UDP port.
    #[arg(long, default_value_t = workflow::dns::DEFAULT_DNS_SERVER_PORT)]
    pub(super) port: u16,
    /// Explicit 16-bit transaction ID; a process-local value is generated when omitted.
    #[arg(long)]
    pub(super) transaction_id: Option<u16>,
    /// First UDP source port; an ephemeral-range value is generated when omitted.
    #[arg(long)]
    pub(super) source_port: Option<u16>,
    /// Disable the recursion-desired query flag.
    #[arg(long)]
    pub(super) no_recursion: bool,
    /// Number of independently re-resolved and re-authorized attempts.
    #[arg(long, default_value_t = workflow::dns::DEFAULT_DNS_ATTEMPTS)]
    pub(super) attempts: u32,
    /// Response window for each capture-ready query.
    #[arg(long, default_value_t = 1_000)]
    pub(super) timeout_ms: u64,
    /// Optional average query-rate ceiling.
    #[arg(long)]
    pub(super) rate: Option<u32>,
    /// Maximum worst-case timeout plus intentional retry delay in milliseconds.
    #[arg(long, default_value_t = 3_600_000)]
    pub(super) max_duration_ms: u64,
    /// Maximum complete DNS message bytes decoded.
    #[arg(long, default_value_t = workflow::dns::MAX_DNS_MESSAGE_BYTES)]
    pub(super) max_message_bytes: usize,
    /// Maximum total answer, authority, and additional records decoded.
    #[arg(long, default_value_t = workflow::dns::DEFAULT_MAX_DNS_RECORDS)]
    pub(super) max_records: usize,
    /// Maximum compression-pointer traversals for any decoded DNS name.
    #[arg(long, default_value_t = workflow::dns::DEFAULT_MAX_DNS_NAME_POINTERS)]
    pub(super) max_name_pointers: usize,
    /// Maximum TXT character strings in one record.
    #[arg(long, default_value_t = workflow::dns::DEFAULT_MAX_DNS_TXT_STRINGS)]
    pub(super) max_txt_strings: usize,
    /// Maximum aggregate TXT data bytes in one record.
    #[arg(long, default_value_t = workflow::dns::DEFAULT_MAX_DNS_TXT_BYTES)]
    pub(super) max_txt_bytes: usize,
    /// Maximum rejected-record metadata entries retained.
    #[arg(long, default_value_t = workflow::dns::DEFAULT_MAX_REJECTED_DNS_RECORDS)]
    pub(super) max_rejected_records: usize,
    /// Maximum undecodable exact frames retained across attempts.
    #[arg(long, default_value_t = workflow::dns::DEFAULT_MAX_UNDECODED_DNS_FRAMES)]
    pub(super) max_undecoded: usize,
    /// Interface name or numeric index used as an exact route constraint.
    #[arg(long, value_name = "NAME_OR_INDEX")]
    pub(super) interface: Option<String>,
    /// Interface-owned source preference used only for route selection.
    #[arg(long)]
    pub(super) source: Option<IpAddr>,
    /// Automatic, Layer 2, or raw Layer 3 transmission intent.
    #[arg(long, value_enum, default_value_t = CliLinkMode::Auto)]
    pub(super) link_mode: CliLinkMode,
    #[command(flatten)]
    pub(super) limits: CaptureLimitArgs,
    #[command(flatten)]
    pub(super) policy: TrafficPolicyArgs,
}

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
pub(super) enum CliTracerouteStrategy {
    #[default]
    Udp,
    Icmp,
    Tcp,
}

impl From<CliTracerouteStrategy> for workflow::traceroute::Strategy {
    fn from(value: CliTracerouteStrategy) -> Self {
        match value {
            CliTracerouteStrategy::Udp => Self::Udp,
            CliTracerouteStrategy::Icmp => Self::Icmp,
            CliTracerouteStrategy::Tcp => Self::Tcp,
        }
    }
}

#[derive(Debug, Args)]
pub(super) struct TracerouteArgs {
    /// Explicit IP address or hostname to trace.
    #[arg(value_name = "ADDRESS_OR_HOSTNAME")]
    pub(super) target: String,
    /// UDP, ICMP echo, or TCP SYN probes.
    #[arg(long, value_enum, default_value_t = CliTracerouteStrategy::Udp)]
    pub(super) strategy: CliTracerouteStrategy,
    /// Select the first authorized address or only one IP family.
    #[arg(long, value_enum, default_value_t = CliAddressFamily::Any)]
    pub(super) family: CliAddressFamily,
    /// Non-zero UDP base port (incremented per probe) or fixed TCP destination port.
    #[arg(long)]
    pub(super) port: Option<u16>,
    /// First non-zero IPv4 TTL or IPv6 hop limit.
    #[arg(long, default_value_t = workflow::traceroute::DEFAULT_TRACEROUTE_FIRST_HOP)]
    pub(super) first_hop: u8,
    /// Last IPv4 TTL or IPv6 hop limit attempted.
    #[arg(long, default_value_t = workflow::traceroute::DEFAULT_TRACEROUTE_MAX_HOPS)]
    pub(super) max_hops: u8,
    /// Number of attempts retained for every hop.
    #[arg(long, default_value_t = workflow::traceroute::DEFAULT_TRACEROUTE_PROBES_PER_HOP)]
    pub(super) attempts: u32,
    /// Shared response window for every capture-ready hop batch.
    #[arg(long, default_value_t = 1_000)]
    pub(super) timeout_ms: u64,
    /// Optional average probe-rate ceiling; each hop remains one deliberate burst.
    #[arg(long)]
    pub(super) rate: Option<u32>,
    /// Maximum generated probes across all hops.
    #[arg(long, default_value_t = packet::template::DEFAULT_MAX_TEMPLATE_PACKETS)]
    pub(super) max_probes: usize,
    /// Maximum worst-case timeout plus intentional rate delay in milliseconds.
    #[arg(long, default_value_t = 3_600_000)]
    pub(super) max_duration_ms: u64,
    /// Maximum hop-scoped undecodable exact frames retained.
    #[arg(long, default_value_t = workflow::traceroute::DEFAULT_MAX_UNDECODED_TRACEROUTE_FRAMES)]
    pub(super) max_undecoded: usize,
    /// Interface name or numeric index used as an exact route constraint.
    #[arg(long, value_name = "NAME_OR_INDEX")]
    pub(super) interface: Option<String>,
    /// Interface-owned source preference used only for route selection.
    #[arg(long)]
    pub(super) source: Option<IpAddr>,
    /// Automatic, Layer 2, or raw Layer 3 transmission intent.
    #[arg(long, value_enum, default_value_t = CliLinkMode::Auto)]
    pub(super) link_mode: CliLinkMode,
    #[command(flatten)]
    pub(super) limits: CaptureLimitArgs,
    #[command(flatten)]
    pub(super) policy: TrafficPolicyArgs,
}

#[derive(Debug, Args)]
pub(super) struct RouteArgs {
    #[command(flatten)]
    pub(super) recipe: RecipeArgs,
    /// Explicit address or hostname when the packet has no fixed destination.
    #[arg(long, value_name = "ADDRESS_OR_HOSTNAME")]
    pub(super) destination: Option<String>,
    /// Interface name or numeric index used as an exact route constraint.
    #[arg(long, value_name = "NAME_OR_INDEX")]
    pub(super) interface: Option<String>,
    /// Interface-owned source preference used only for route selection.
    #[arg(long)]
    pub(super) source: Option<IpAddr>,
    /// Automatic, Layer 2, or raw Layer 3 transmission intent.
    #[arg(long, value_enum, default_value_t = CliLinkMode::Auto)]
    pub(super) link_mode: CliLinkMode,
    #[command(flatten)]
    pub(super) policy: TrafficPolicyArgs,
}

#[derive(Debug, Args)]
pub(super) struct SendArgs {
    #[command(flatten)]
    pub(super) route: RouteArgs,
    /// Strict or permissive packet construction.
    #[arg(long, value_enum, default_value_t = CliBuildMode::Strict)]
    pub(super) mode: CliBuildMode,
    /// Per-operation opt-in required for a permissively built live frame.
    #[arg(long)]
    pub(super) allow_permissive_live: bool,
}

#[derive(Debug, Args)]
pub(super) struct CaptureArgs {
    #[command(flatten)]
    pub(super) route: RouteArgs,
    /// Overall capture window in milliseconds.
    #[arg(long, default_value_t = 3_000)]
    pub(super) timeout_ms: u64,
    #[command(flatten)]
    pub(super) limits: CaptureLimitArgs,
}

#[derive(Debug, Args)]
pub(super) struct ExchangeArgs {
    #[command(flatten)]
    pub(super) send: SendArgs,
    /// Overall response window in milliseconds.
    #[arg(long, default_value_t = 3_000)]
    pub(super) timeout_ms: u64,
    /// Maximum matched responses retained across the exchange.
    #[arg(long, default_value_t = client::exchange::DEFAULT_MAX_UNSOLICITED_FRAMES)]
    pub(super) max_responses: usize,
    /// Maximum unsolicited decoded frames retained across the exchange.
    #[arg(long, default_value_t = client::exchange::DEFAULT_MAX_UNSOLICITED_FRAMES)]
    pub(super) max_unsolicited: usize,
    #[command(flatten)]
    pub(super) limits: CaptureLimitArgs,
}

#[derive(Clone, Debug, Args)]
pub(super) struct TrafficPolicyArgs {
    /// Deliberately authorize globally routable destinations.
    #[arg(long)]
    allow_public_destinations: bool,
    /// Deliberately authorize hostname resolution before route lookup.
    #[arg(long)]
    allow_hostname_resolution: bool,
    /// Policy-level opt-in for permissively built live packets.
    #[arg(long)]
    allow_permissive_packets: bool,
    /// Maximum packets authorized for one operation.
    #[arg(long, default_value_t = 10_000)]
    max_packets: u64,
    /// Maximum wire bytes authorized for one operation.
    #[arg(long, default_value_t = net::capture::Limits::default().max_bytes as u64)]
    max_bytes: u64,
    /// Maximum distinct addresses accepted from one hostname resolution.
    #[arg(long, default_value_t = client::policy::DEFAULT_MAX_RESOLVED_ADDRESSES)]
    max_resolved_addresses: usize,
}

#[derive(Clone, Debug, Args)]
pub(super) struct ReplayPolicyArgs {
    /// Deliberately authorize globally routable destinations.
    #[arg(long)]
    allow_public_destinations: bool,
    /// Policy-level opt-in for malformed/permissive live bytes.
    #[arg(long)]
    allow_permissive_packets: bool,
    /// Maximum packets authorized for one operation.
    #[arg(long, default_value_t = capture::DEFAULT_STREAM_FRAMES)]
    pub(super) max_packets: u64,
    /// Maximum wire bytes authorized for one operation.
    #[arg(long, default_value_t = capture::DEFAULT_STREAM_BYTES)]
    pub(super) max_bytes: u64,
}

#[derive(Clone, Debug, Args)]
pub(super) struct CaptureLimitArgs {
    /// Aggregate backend capture-queue frame bound.
    #[arg(long, default_value_t = net::capture::Limits::default().max_frames)]
    max_queue_frames: usize,
    /// Aggregate retained/queued capture byte bound.
    #[arg(long, default_value_t = net::capture::Limits::default().max_bytes)]
    max_captured_bytes: usize,
    /// Maximum bytes retained from any one captured frame.
    #[arg(long, default_value_t = capture::DEFAULT_SIZE_LIMIT)]
    snap_length: usize,
    /// Backend queue behavior when a configured bound is reached.
    #[arg(long, value_enum, default_value_t = CliCaptureOverflowPolicy::Fail)]
    overflow_policy: CliCaptureOverflowPolicy,
}

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
pub(super) enum CliCaptureOverflowPolicy {
    #[default]
    Fail,
    DropNewest,
    DropOldest,
}

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
pub(super) enum CliLinkMode {
    #[default]
    Auto,
    Layer2,
    Layer3,
}

impl From<CliLinkMode> for net::link::Mode {
    fn from(value: CliLinkMode) -> Self {
        match value {
            CliLinkMode::Auto => Self::Auto,
            CliLinkMode::Layer2 => Self::Layer2,
            CliLinkMode::Layer3 => Self::Layer3,
        }
    }
}

impl From<CliCaptureOverflowPolicy> for net::capture::OverflowPolicy {
    fn from(value: CliCaptureOverflowPolicy) -> Self {
        match value {
            CliCaptureOverflowPolicy::Fail => Self::Fail,
            CliCaptureOverflowPolicy::DropNewest => Self::DropNewest,
            CliCaptureOverflowPolicy::DropOldest => Self::DropOldest,
        }
    }
}

impl TrafficPolicyArgs {
    pub(super) fn into_policy(self) -> client::policy::Policy {
        client::policy::Policy {
            allow_public_destinations: self.allow_public_destinations,
            allow_hostname_resolution: self.allow_hostname_resolution,
            allow_permissive_packets: self.allow_permissive_packets,
            max_packets_per_operation: self.max_packets,
            max_bytes_per_operation: self.max_bytes,
            max_resolved_addresses: self.max_resolved_addresses,
        }
    }
}

impl ReplayPolicyArgs {
    pub(super) fn into_policy(self) -> client::policy::Policy {
        client::policy::Policy {
            allow_public_destinations: self.allow_public_destinations,
            allow_permissive_packets: self.allow_permissive_packets,
            max_packets_per_operation: self.max_packets,
            max_bytes_per_operation: self.max_bytes,
            ..client::policy::Policy::default()
        }
    }
}

impl CaptureLimitArgs {
    pub(super) fn into_limits(self) -> net::capture::Limits {
        net::capture::Limits {
            max_frames: self.max_queue_frames,
            max_bytes: self.max_captured_bytes,
            snap_length: self.snap_length,
            overflow_policy: self.overflow_policy.into(),
        }
    }
}
