// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

// Clap argument and command models.

#[derive(Debug, Parser)]
#[command(
    name = "packetcraftr",
    bin_name = "packetcraftr",
    version,
    about = "Reflective packet construction, dissection, capture, and network tools",
    long_about = "PacketcraftR builds and dissects arbitrary packet stacks with exact bytes, bounded parsing, passive route planning, and policy-gated live workflows. Native features, dependencies, and privileges determine which live paths are available."
)]
struct Cli {
    #[arg(long, global = true, value_enum, default_value_t = CliOutputFormat::Text)]
    output: CliOutputFormat,
    #[command(subcommand)]
    command: Command,
}

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
enum CliOutputFormat {
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
        formatter.write_str(OutputFormat::from(*self).as_str())
    }
}

impl From<CliOutputFormat> for OutputFormat {
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
enum Command {
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
    /// Run structured traceroute probes.
    Traceroute(TracerouteArgs),
    /// Run a structured DNS operation.
    Dns(DnsArgs),
    /// Run bounded field-aware packet fuzzing.
    Fuzz(FuzzArgs),
    /// Enumerate passive interface-bound route decisions.
    Routes,
}

#[derive(Debug, Args)]
struct RecipeArgs {
    /// One-off layer expression.
    #[arg(long, conflicts_with = "packet_file")]
    packet: Option<String>,
    /// Versioned JSON/YAML packet document.
    #[arg(long, value_name = "PATH", conflicts_with = "packet")]
    packet_file: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct BuildArgs {
    #[command(flatten)]
    recipe: RecipeArgs,
    #[arg(long, value_enum, default_value_t = CliBuildMode::Strict)]
    mode: CliBuildMode,
}

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
enum CliBuildMode {
    #[default]
    Strict,
    Permissive,
}

#[derive(Debug, Args)]
struct DissectArgs {
    /// Whole-frame hexadecimal bytes.
    #[arg(long, conflicts_with = "file")]
    hex: Option<String>,
    /// File containing raw frame bytes.
    #[arg(long, value_name = "PATH", conflicts_with = "hex")]
    file: Option<PathBuf>,
    /// Open numeric DLT/link type (defaults to Ethernet/DLT 1).
    #[arg(long, default_value_t = 1)]
    link_type: u32,
}

#[derive(Debug, Args)]
struct ReadArgs {
    path: PathBuf,
    /// Maximum frames read or copied from the capture stream.
    #[arg(long, default_value_t = crate::capture::DEFAULT_STREAM_FRAMES)]
    max_frames: u64,
    /// Maximum aggregate captured payload bytes read or copied.
    #[arg(long, default_value_t = crate::capture::DEFAULT_STREAM_BYTES)]
    max_bytes: u64,
    /// Maximum bytes accepted from any one captured frame or PCAPNG block.
    #[arg(long, default_value_t = crate::capture::DEFAULT_SIZE_LIMIT)]
    max_frame_bytes: usize,
    /// Maximum PCAPNG interfaces accepted from the input.
    #[arg(long, default_value_t = crate::capture::DEFAULT_INTERFACE_LIMIT)]
    max_interfaces: usize,
}

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
enum CliReplayTiming {
    #[default]
    Original,
    Immediate,
}

#[derive(Debug, Args)]
struct ReplayArgs {
    /// Classic PCAP or PCAPNG input path.
    path: PathBuf,
    /// Exact interface name or numeric index used for every transmission.
    #[arg(long, value_name = "NAME_OR_INDEX")]
    interface: String,
    /// Automatic, Layer 2, or raw Layer 3 replay intent.
    #[arg(long, value_enum, default_value_t = CliLinkMode::Auto)]
    link_mode: CliLinkMode,
    /// Preserve captured intervals or send immediately.
    #[arg(long, value_enum, default_value_t = CliReplayTiming::Original)]
    timing: CliReplayTiming,
    /// Positive multiplier for captured replay speed (2 means twice as fast).
    #[arg(long, conflicts_with = "rate")]
    speed: Option<f64>,
    /// Positive fixed frame rate, overriding captured intervals.
    #[arg(long, conflicts_with = "speed")]
    rate: Option<f64>,
    /// Maximum cumulative intentional replay delay in milliseconds.
    #[arg(long, default_value_t = 3_600_000)]
    max_duration_ms: u64,
    /// Maximum bytes accepted from any one captured frame or PCAPNG block.
    #[arg(long, default_value_t = crate::capture::DEFAULT_SIZE_LIMIT)]
    max_frame_bytes: usize,
    /// Maximum PCAPNG interfaces accepted from the input.
    #[arg(long, default_value_t = crate::capture::DEFAULT_INTERFACE_LIMIT)]
    max_interfaces: usize,
    /// Per-operation opt-in required when dissection preserves malformed bytes.
    #[arg(long)]
    allow_malformed_live: bool,
    #[command(flatten)]
    policy: ReplayPolicyArgs,
}

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
enum CliFuzzStrategy {
    #[default]
    Boundary,
    Random,
    BitFlip,
    Malformed,
}

impl From<CliFuzzStrategy> for FuzzStrategy {
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
struct FuzzArgs {
    #[command(flatten)]
    recipe: RecipeArgs,
    /// Stable operation seed used to derive each case independently.
    #[arg(long, default_value_t = 0)]
    seed: u64,
    /// Absolute first case index; combine with --cases 1 to reproduce a case.
    #[arg(long, default_value_t = 0)]
    first_case: u64,
    /// Number of ordered cases to generate.
    #[arg(long, default_value_t = crate::workflow_api::DEFAULT_FUZZ_CASES)]
    cases: usize,
    /// Comma-separated field-aware mutation strategies.
    #[arg(
        long = "strategy",
        value_enum,
        value_delimiter = ',',
        default_value = "boundary,random,bit-flip,malformed"
    )]
    strategies: Vec<CliFuzzStrategy>,
    /// Restrict mutation to repeated LAYER.FIELD targets; defaults to all fields.
    #[arg(long = "field", value_delimiter = ',')]
    fields: Vec<String>,
    /// Strict or permissive packet construction for generated cases.
    #[arg(long, value_enum, default_value_t = CliBuildMode::Strict)]
    mode: CliBuildMode,
    /// Explicitly enable route, capture, and transmission; offline is the default.
    #[arg(long)]
    live: bool,
    /// Independent per-operation opt-in for permissive/malformed live cases.
    #[arg(long)]
    allow_malformed_live: bool,
    /// Optional route destination when the packet has no fixed destination.
    #[arg(long)]
    destination: Option<IpAddr>,
    /// Response window for each capture-ready live case.
    #[arg(long, default_value_t = 1_000)]
    timeout_ms: u64,
    /// Optional average live-case rate ceiling.
    #[arg(long)]
    rate: Option<u32>,
    /// Maximum cases accepted by this operation.
    #[arg(long, default_value_t = crate::workflow_api::DEFAULT_MAX_FUZZ_CASES)]
    max_cases: usize,
    /// Maximum aggregate retained case data and live wire bytes.
    #[arg(long, default_value_t = crate::net::DEFAULT_CAPTURE_QUEUE_BYTES)]
    max_total_bytes: usize,
    /// Maximum bytes allocated for one generated field value.
    #[arg(long, default_value_t = crate::workflow_api::DEFAULT_MAX_FUZZ_FIELD_BYTES)]
    max_field_bytes: usize,
    /// Maximum list elements generated by one mutation.
    #[arg(long, default_value_t = crate::workflow_api::DEFAULT_MAX_FUZZ_LIST_ITEMS)]
    max_list_items: usize,
    /// Maximum deterministic shrink candidates returned per case.
    #[arg(long, default_value_t = crate::workflow_api::DEFAULT_MAX_FUZZ_SHRINK_STEPS)]
    max_shrink_steps: usize,
    /// Maximum worst-case timeout plus intentional rate delay in milliseconds.
    #[arg(long, default_value_t = 3_600_000)]
    max_duration_ms: u64,
    /// Interface name or numeric index used as an exact live route constraint.
    #[arg(long, value_name = "NAME_OR_INDEX")]
    interface: Option<String>,
    /// Interface-owned source preference used only for live route selection.
    #[arg(long)]
    source: Option<IpAddr>,
    /// Automatic, Layer 2, or raw Layer 3 live transmission intent.
    #[arg(long, value_enum, default_value_t = CliLinkMode::Auto)]
    link_mode: CliLinkMode,
    #[command(flatten)]
    limits: CaptureLimitArgs,
    #[command(flatten)]
    policy: TrafficPolicyArgs,
}

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
enum CliScanTransport {
    #[default]
    Tcp,
    Udp,
    Icmp,
}

impl From<CliScanTransport> for ScanTransport {
    fn from(value: CliScanTransport) -> Self {
        match value {
            CliScanTransport::Tcp => Self::Tcp,
            CliScanTransport::Udp => Self::Udp,
            CliScanTransport::Icmp => Self::Icmp,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
enum CliScanAddressFamily {
    #[default]
    Any,
    Ipv4,
    Ipv6,
}

impl From<CliScanAddressFamily> for ScanAddressFamily {
    fn from(value: CliScanAddressFamily) -> Self {
        match value {
            CliScanAddressFamily::Any => Self::Any,
            CliScanAddressFamily::Ipv4 => Self::Ipv4,
            CliScanAddressFamily::Ipv6 => Self::Ipv6,
        }
    }
}

#[derive(Debug, Args)]
struct ScanArgs {
    /// Explicit IP address or hostname to scan.
    #[arg(value_name = "ADDRESS_OR_HOSTNAME")]
    target: String,
    /// TCP SYN, UDP, or ICMP echo probes.
    #[arg(long, value_enum, default_value_t = CliScanTransport::Tcp)]
    transport: CliScanTransport,
    /// Select all authorized addresses or only one IP family.
    #[arg(long, value_enum, default_value_t = CliScanAddressFamily::Any)]
    family: CliScanAddressFamily,
    /// Comma-separated TCP/UDP destination ports; omitted for ICMP.
    #[arg(long, value_delimiter = ',', num_args = 1..)]
    ports: Vec<u16>,
    /// Number of bounded attempts per selected endpoint.
    #[arg(long, default_value_t = 1)]
    attempts: u32,
    /// Response window for each capture-ready batch.
    #[arg(long, default_value_t = 1_000)]
    timeout_ms: u64,
    /// Optional average probe-rate ceiling; batches remain deliberate bursts.
    #[arg(long)]
    rate: Option<u32>,
    /// Maximum probes sent by one shared-capture exchange batch.
    #[arg(long, default_value_t = crate::workflow_api::DEFAULT_SCAN_BATCH_SIZE)]
    batch_size: usize,
    /// Maximum distinct destination ports accepted by the request.
    #[arg(long, default_value_t = crate::workflow_api::DEFAULT_MAX_SCAN_PORTS)]
    max_ports: usize,
    /// Maximum generated probes after target resolution and attempts.
    #[arg(long, default_value_t = crate::packet::internal::DEFAULT_MAX_TEMPLATE_PACKETS)]
    max_probes: usize,
    /// Maximum worst-case timeout plus intentional rate delay in milliseconds.
    #[arg(long, default_value_t = 3_600_000)]
    max_duration_ms: u64,
    /// Maximum undecodable exact frames retained across the scan.
    #[arg(long, default_value_t = crate::workflow_api::DEFAULT_MAX_UNDECODED_SCAN_FRAMES)]
    max_undecoded: usize,
    /// Interface name or numeric index used as an exact route constraint.
    #[arg(long, value_name = "NAME_OR_INDEX")]
    interface: Option<String>,
    /// Interface-owned source preference used only for route selection.
    #[arg(long)]
    source: Option<IpAddr>,
    /// Automatic, Layer 2, or raw Layer 3 transmission intent.
    #[arg(long, value_enum, default_value_t = CliLinkMode::Auto)]
    link_mode: CliLinkMode,
    #[command(flatten)]
    limits: CaptureLimitArgs,
    #[command(flatten)]
    policy: TrafficPolicyArgs,
}

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
enum CliDnsAddressFamily {
    #[default]
    Any,
    Ipv4,
    Ipv6,
}

impl From<CliDnsAddressFamily> for DnsAddressFamily {
    fn from(value: CliDnsAddressFamily) -> Self {
        match value {
            CliDnsAddressFamily::Any => Self::Any,
            CliDnsAddressFamily::Ipv4 => Self::Ipv4,
            CliDnsAddressFamily::Ipv6 => Self::Ipv6,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
enum CliDnsQueryType {
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

impl From<CliDnsQueryType> for DnsQueryType {
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
struct DnsArgs {
    /// Explicit DNS server IP address or hostname.
    #[arg(value_name = "SERVER")]
    server: String,
    /// Bounded ASCII DNS owner name to query.
    #[arg(value_name = "NAME")]
    name: String,
    /// DNS question type.
    #[arg(long = "type", value_enum, default_value_t = CliDnsQueryType::A)]
    query_type: CliDnsQueryType,
    /// Select the first authorized server address or one IP family.
    #[arg(long, value_enum, default_value_t = CliDnsAddressFamily::Any)]
    family: CliDnsAddressFamily,
    /// DNS server UDP port.
    #[arg(long, default_value_t = crate::workflow_api::DEFAULT_DNS_SERVER_PORT)]
    port: u16,
    /// Explicit 16-bit transaction ID; a process-local value is generated when omitted.
    #[arg(long)]
    transaction_id: Option<u16>,
    /// First UDP source port; an ephemeral-range value is generated when omitted.
    #[arg(long)]
    source_port: Option<u16>,
    /// Disable the recursion-desired query flag.
    #[arg(long)]
    no_recursion: bool,
    /// Number of independently re-resolved and re-authorized attempts.
    #[arg(long, default_value_t = crate::workflow_api::DEFAULT_DNS_ATTEMPTS)]
    attempts: u32,
    /// Response window for each capture-ready query.
    #[arg(long, default_value_t = 1_000)]
    timeout_ms: u64,
    /// Optional average query-rate ceiling.
    #[arg(long)]
    rate: Option<u32>,
    /// Maximum worst-case timeout plus intentional retry delay in milliseconds.
    #[arg(long, default_value_t = 3_600_000)]
    max_duration_ms: u64,
    /// Maximum complete DNS message bytes decoded.
    #[arg(long, default_value_t = crate::workflow_api::MAX_DNS_MESSAGE_BYTES)]
    max_message_bytes: usize,
    /// Maximum total answer, authority, and additional records decoded.
    #[arg(long, default_value_t = crate::workflow_api::DEFAULT_MAX_DNS_RECORDS)]
    max_records: usize,
    /// Maximum compression-pointer traversals for any decoded DNS name.
    #[arg(long, default_value_t = crate::workflow_api::DEFAULT_MAX_DNS_NAME_POINTERS)]
    max_name_pointers: usize,
    /// Maximum TXT character strings in one record.
    #[arg(long, default_value_t = crate::workflow_api::DEFAULT_MAX_DNS_TXT_STRINGS)]
    max_txt_strings: usize,
    /// Maximum aggregate TXT data bytes in one record.
    #[arg(long, default_value_t = crate::workflow_api::DEFAULT_MAX_DNS_TXT_BYTES)]
    max_txt_bytes: usize,
    /// Maximum rejected-record metadata entries retained.
    #[arg(long, default_value_t = crate::workflow_api::DEFAULT_MAX_REJECTED_DNS_RECORDS)]
    max_rejected_records: usize,
    /// Maximum undecodable exact frames retained across attempts.
    #[arg(long, default_value_t = crate::workflow_api::DEFAULT_MAX_UNDECODED_DNS_FRAMES)]
    max_undecoded: usize,
    /// Interface name or numeric index used as an exact route constraint.
    #[arg(long, value_name = "NAME_OR_INDEX")]
    interface: Option<String>,
    /// Interface-owned source preference used only for route selection.
    #[arg(long)]
    source: Option<IpAddr>,
    /// Automatic, Layer 2, or raw Layer 3 transmission intent.
    #[arg(long, value_enum, default_value_t = CliLinkMode::Auto)]
    link_mode: CliLinkMode,
    #[command(flatten)]
    limits: CaptureLimitArgs,
    #[command(flatten)]
    policy: TrafficPolicyArgs,
}

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
enum CliTracerouteStrategy {
    #[default]
    Udp,
    Icmp,
    Tcp,
}

impl From<CliTracerouteStrategy> for TracerouteStrategy {
    fn from(value: CliTracerouteStrategy) -> Self {
        match value {
            CliTracerouteStrategy::Udp => Self::Udp,
            CliTracerouteStrategy::Icmp => Self::Icmp,
            CliTracerouteStrategy::Tcp => Self::Tcp,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
enum CliTracerouteAddressFamily {
    #[default]
    Any,
    Ipv4,
    Ipv6,
}

impl From<CliTracerouteAddressFamily> for TracerouteAddressFamily {
    fn from(value: CliTracerouteAddressFamily) -> Self {
        match value {
            CliTracerouteAddressFamily::Any => Self::Any,
            CliTracerouteAddressFamily::Ipv4 => Self::Ipv4,
            CliTracerouteAddressFamily::Ipv6 => Self::Ipv6,
        }
    }
}

#[derive(Debug, Args)]
struct TracerouteArgs {
    /// Explicit IP address or hostname to trace.
    #[arg(value_name = "ADDRESS_OR_HOSTNAME")]
    target: String,
    /// UDP, ICMP echo, or TCP SYN probes.
    #[arg(long, value_enum, default_value_t = CliTracerouteStrategy::Udp)]
    strategy: CliTracerouteStrategy,
    /// Select the first authorized address or only one IP family.
    #[arg(long, value_enum, default_value_t = CliTracerouteAddressFamily::Any)]
    family: CliTracerouteAddressFamily,
    /// UDP base destination port or fixed TCP destination port.
    #[arg(long)]
    port: Option<u16>,
    /// First non-zero IPv4 TTL or IPv6 hop limit.
    #[arg(long, default_value_t = crate::workflow_api::DEFAULT_TRACEROUTE_FIRST_HOP)]
    first_hop: u8,
    /// Last IPv4 TTL or IPv6 hop limit attempted.
    #[arg(long, default_value_t = crate::workflow_api::DEFAULT_TRACEROUTE_MAX_HOPS)]
    max_hops: u8,
    /// Number of attempts retained for every hop.
    #[arg(long, default_value_t = crate::workflow_api::DEFAULT_TRACEROUTE_PROBES_PER_HOP)]
    attempts: u32,
    /// Response window for each capture-ready hop batch.
    #[arg(long, default_value_t = 1_000)]
    timeout_ms: u64,
    /// Optional average probe-rate ceiling; each hop remains one deliberate burst.
    #[arg(long)]
    rate: Option<u32>,
    /// Maximum generated probes across all hops.
    #[arg(long, default_value_t = crate::packet::internal::DEFAULT_MAX_TEMPLATE_PACKETS)]
    max_probes: usize,
    /// Maximum worst-case timeout plus intentional rate delay in milliseconds.
    #[arg(long, default_value_t = 3_600_000)]
    max_duration_ms: u64,
    /// Maximum hop-scoped undecodable exact frames retained.
    #[arg(long, default_value_t = crate::workflow_api::DEFAULT_MAX_UNDECODED_TRACEROUTE_FRAMES)]
    max_undecoded: usize,
    /// Interface name or numeric index used as an exact route constraint.
    #[arg(long, value_name = "NAME_OR_INDEX")]
    interface: Option<String>,
    /// Interface-owned source preference used only for route selection.
    #[arg(long)]
    source: Option<IpAddr>,
    /// Automatic, Layer 2, or raw Layer 3 transmission intent.
    #[arg(long, value_enum, default_value_t = CliLinkMode::Auto)]
    link_mode: CliLinkMode,
    #[command(flatten)]
    limits: CaptureLimitArgs,
    #[command(flatten)]
    policy: TrafficPolicyArgs,
}

#[derive(Debug, Args)]
struct RouteArgs {
    #[command(flatten)]
    recipe: RecipeArgs,
    /// Explicit address or hostname when the packet has no fixed destination.
    #[arg(long, value_name = "ADDRESS_OR_HOSTNAME")]
    destination: Option<String>,
    /// Interface name or numeric index used as an exact route constraint.
    #[arg(long, value_name = "NAME_OR_INDEX")]
    interface: Option<String>,
    /// Interface-owned source preference used only for route selection.
    #[arg(long)]
    source: Option<IpAddr>,
    /// Automatic, Layer 2, or raw Layer 3 transmission intent.
    #[arg(long, value_enum, default_value_t = CliLinkMode::Auto)]
    link_mode: CliLinkMode,
    #[command(flatten)]
    policy: TrafficPolicyArgs,
}

#[derive(Debug, Args)]
struct SendArgs {
    #[command(flatten)]
    route: RouteArgs,
    /// Strict or permissive packet construction.
    #[arg(long, value_enum, default_value_t = CliBuildMode::Strict)]
    mode: CliBuildMode,
    /// Per-operation opt-in required for a permissively built live frame.
    #[arg(long)]
    allow_permissive_live: bool,
}

#[derive(Debug, Args)]
struct CaptureArgs {
    #[command(flatten)]
    route: RouteArgs,
    /// Overall capture window in milliseconds.
    #[arg(long, default_value_t = 3_000)]
    timeout_ms: u64,
    #[command(flatten)]
    limits: CaptureLimitArgs,
}

#[derive(Debug, Args)]
struct ExchangeArgs {
    #[command(flatten)]
    send: SendArgs,
    /// Overall response window in milliseconds.
    #[arg(long, default_value_t = 3_000)]
    timeout_ms: u64,
    /// Maximum matched responses retained across the exchange.
    #[arg(long, default_value_t = crate::client::exchange::DEFAULT_MAX_UNSOLICITED_FRAMES)]
    max_responses: usize,
    /// Maximum unsolicited decoded frames retained across the exchange.
    #[arg(long, default_value_t = crate::client::exchange::DEFAULT_MAX_UNSOLICITED_FRAMES)]
    max_unsolicited: usize,
    #[command(flatten)]
    limits: CaptureLimitArgs,
}

#[derive(Clone, Debug, Args)]
struct TrafficPolicyArgs {
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
    #[arg(long, default_value_t = crate::net::DEFAULT_CAPTURE_QUEUE_BYTES as u64)]
    max_bytes: u64,
    /// Maximum distinct addresses accepted from one hostname resolution.
    #[arg(long, default_value_t = crate::client::target::DEFAULT_MAX_RESOLVED_ADDRESSES)]
    max_resolved_addresses: usize,
}

#[derive(Clone, Debug, Args)]
struct ReplayPolicyArgs {
    /// Deliberately authorize globally routable destinations.
    #[arg(long)]
    allow_public_destinations: bool,
    /// Policy-level opt-in for malformed/permissive live bytes.
    #[arg(long)]
    allow_permissive_packets: bool,
    /// Maximum packets authorized for one operation.
    #[arg(long, default_value_t = crate::capture::DEFAULT_STREAM_FRAMES)]
    max_packets: u64,
    /// Maximum wire bytes authorized for one operation.
    #[arg(long, default_value_t = crate::capture::DEFAULT_STREAM_BYTES)]
    max_bytes: u64,
}

#[derive(Clone, Debug, Args)]
struct CaptureLimitArgs {
    /// Aggregate backend capture-queue frame bound.
    #[arg(long, default_value_t = crate::net::DEFAULT_CAPTURE_QUEUE_FRAMES)]
    max_queue_frames: usize,
    /// Aggregate retained/queued capture byte bound.
    #[arg(long, default_value_t = crate::net::DEFAULT_CAPTURE_QUEUE_BYTES)]
    max_captured_bytes: usize,
    /// Maximum bytes retained from any one captured frame.
    #[arg(long, default_value_t = crate::capture::DEFAULT_SIZE_LIMIT)]
    snap_length: usize,
    /// Backend queue behavior when a configured bound is reached.
    #[arg(long, value_enum, default_value_t = CliCaptureOverflowPolicy::Fail)]
    overflow_policy: CliCaptureOverflowPolicy,
}

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
enum CliCaptureOverflowPolicy {
    #[default]
    Fail,
    DropNewest,
    DropOldest,
}

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
enum CliLinkMode {
    #[default]
    Auto,
    Layer2,
    Layer3,
}

impl From<CliLinkMode> for LinkMode {
    fn from(value: CliLinkMode) -> Self {
        match value {
            CliLinkMode::Auto => Self::Auto,
            CliLinkMode::Layer2 => Self::Layer2,
            CliLinkMode::Layer3 => Self::Layer3,
        }
    }
}

impl From<CliCaptureOverflowPolicy> for CaptureOverflowPolicy {
    fn from(value: CliCaptureOverflowPolicy) -> Self {
        match value {
            CliCaptureOverflowPolicy::Fail => Self::Fail,
            CliCaptureOverflowPolicy::DropNewest => Self::DropNewest,
            CliCaptureOverflowPolicy::DropOldest => Self::DropOldest,
        }
    }
}

impl TrafficPolicyArgs {
    fn into_policy(self) -> TrafficPolicy {
        TrafficPolicy {
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
    fn into_policy(self) -> TrafficPolicy {
        TrafficPolicy {
            allow_public_destinations: self.allow_public_destinations,
            allow_permissive_packets: self.allow_permissive_packets,
            max_packets_per_operation: self.max_packets,
            max_bytes_per_operation: self.max_bytes,
            ..TrafficPolicy::default()
        }
    }
}

impl CaptureLimitArgs {
    fn into_limits(self) -> CaptureQueueLimits {
        CaptureQueueLimits {
            max_frames: self.max_queue_frames,
            max_bytes: self.max_captured_bytes,
            snap_length: self.snap_length,
            overflow_policy: self.overflow_policy.into(),
        }
    }
}
