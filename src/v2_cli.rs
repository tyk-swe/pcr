// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#![forbid(unsafe_code)]

use std::collections::hash_map::RandomState;
use std::fs::File;
use std::hash::{BuildHasher, Hasher};
use std::io::{self, IsTerminal, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use clap::{Args, Parser, Subcommand, ValueEnum};
use serde::Serialize;

use crate::client::{
    Client, ClientDnsExecutor, ClientFuzzExecutor, ClientScanExecutor, ClientTracerouteExecutor,
    ExchangeOptions, LiveTarget, SendOptions, SystemHostnameResolver, TrafficPolicy,
    TrafficPolicyDnsAuthorizer, TrafficPolicyError, TrafficPolicyFuzzAuthorizer,
    TrafficPolicyScanAuthorizer, TrafficPolicyTracerouteAuthorizer,
};
use crate::core::{
    parse_packet_expression, BuildContext, BuildMode, BuildOptions, Builder, DecodeOptions,
    Dissector, DocumentFormat, ExpressionOptions, Packet, PacketDocument, PacketTemplate,
    DEFAULT_MAX_DOCUMENT_BYTES, DEFAULT_MAX_DOCUMENT_NESTING, DEFAULT_MAX_LAYERS,
};
use crate::error::{ClassifiedError, ErrorClassification, FailureKind};
use crate::io::{
    transcode_capture, CaptureFileFormat, CaptureOverflowPolicy, CaptureProvider,
    CaptureQueueLimits, CaptureReader, CaptureSession, CaptureStreamLimits, CaptureWriter,
    CapturedFrame, DestinationScope, DispatchPacketIo, InterfaceId, InterfaceInfo,
    InterfaceProvider, LinkCapability, LinkMode, LinkType, LiveIoError, MaterializedRoute,
    PacketIo, PlannedRoute, ReplayTiming, RouteDecision, RouteProvider, RouteSelectionReason,
    SystemCaptureProvider, SystemInterfaceProvider, SystemLayer2Io, SystemLayer3Io,
    SystemNeighborResolver, SystemRouteProvider, TransmissionFrame,
};
use crate::output::{
    AggregateErrorOutput, AggregateOutput, BuildCommandResult, CaptureFrameCommandResult,
    CommandName, DissectCommandResult, DnsAttemptStatus, DnsCommandResult, DnsOutcome,
    DnsRecordOutput, DnsSection, DnsStreamCommandResult, ExchangeCommandResult,
    ExchangeStreamCommandResult, FrameOutput, FuzzCaseOutcome, FuzzCommandResult, FuzzMode,
    FuzzStreamCommandResult, InterfacesCommandResult, OutputContractError, OutputError,
    OutputFormat, PlanCommandResult, ReadFrameCommandResult, ReplayCommandResult,
    ReplayFrameCommandResult, RoutesCommandResult, ScanCommandResult, ScanStreamCommandResult,
    SendCommandResult, StreamErrorRecord, StreamRecord, TraceCompletionReason, TraceProbeStatus,
    TraceResponseKind, TracerouteCommandResult, TracerouteStreamCommandResult,
};
use crate::tools::{
    dns, fuzz, fuzz_live, replay_capture, scan, traceroute, DnsAddressFamily, DnsError,
    DnsExchange, DnsExchangeExecution, DnsExecutionError, DnsExecutor, DnsLimits, DnsQueryType,
    DnsRequest, FuzzCaseExecution, FuzzError, FuzzExecutionCase, FuzzExecutionError, FuzzExecutor,
    FuzzLimits, FuzzLiveOptions, FuzzRequest, FuzzStrategy, FuzzTarget, ReplayAuthorizationError,
    ReplayAuthorizer, ReplayError, ReplayLimits, ReplayOptions, ReplayTransmission,
    ReplayTransmitter, ScanAddressFamily, ScanBatch, ScanBatchExecution, ScanError,
    ScanExecutionError, ScanExecutor, ScanLimits, ScanRequest, ScanTarget, ScanTransport,
    SystemDnsClock, SystemFuzzClock, SystemReplayClock, SystemScanClock, SystemTracerouteClock,
    TracerouteAddressFamily, TracerouteBatch, TracerouteBatchExecution, TracerouteError,
    TracerouteExecutionError, TracerouteExecutor, TracerouteLimits, TracerouteRequest,
    TracerouteStrategy,
};

#[derive(Debug, Parser)]
#[command(
    name = "packetcraftr",
    version,
    about = "Reflective packet construction, dissection, capture, and network tools",
    long_about = "PacketcraftR v0.2 beta candidate: arbitrary packet stacks, strict/permissive exact building, bounded dissection, passive route planning, and policy-gated live workflows under frozen CLI, exit-code, packet-document, and output contracts. Native features, dependencies, and privileges determine which live paths are available."
)]
struct Cli {
    #[arg(long, global = true, value_enum, default_value_t = OutputFormat::Text)]
    output: OutputFormat,
    #[command(subcommand)]
    command: Command,
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
    #[arg(long, default_value_t = crate::io::DEFAULT_CAPTURE_STREAM_FRAMES)]
    max_frames: u64,
    /// Maximum aggregate captured payload bytes read or copied.
    #[arg(long, default_value_t = crate::io::DEFAULT_CAPTURE_STREAM_BYTES)]
    max_bytes: u64,
    /// Maximum bytes accepted from any one captured frame or PCAPNG block.
    #[arg(long, default_value_t = crate::io::DEFAULT_CAPTURE_SIZE_LIMIT)]
    max_frame_bytes: usize,
    /// Maximum PCAPNG interfaces accepted from the input.
    #[arg(long, default_value_t = crate::io::DEFAULT_PCAPNG_INTERFACE_LIMIT)]
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
    #[arg(long, default_value_t = crate::io::DEFAULT_CAPTURE_SIZE_LIMIT)]
    max_frame_bytes: usize,
    /// Maximum PCAPNG interfaces accepted from the input.
    #[arg(long, default_value_t = crate::io::DEFAULT_PCAPNG_INTERFACE_LIMIT)]
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
    #[arg(long, default_value_t = crate::tools::DEFAULT_FUZZ_CASES)]
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
    #[arg(long, default_value_t = crate::tools::DEFAULT_MAX_FUZZ_CASES)]
    max_cases: usize,
    /// Maximum aggregate retained case data and live wire bytes.
    #[arg(long, default_value_t = crate::io::DEFAULT_CAPTURE_QUEUE_BYTES)]
    max_total_bytes: usize,
    /// Maximum bytes allocated for one generated field value.
    #[arg(long, default_value_t = crate::tools::DEFAULT_MAX_FUZZ_FIELD_BYTES)]
    max_field_bytes: usize,
    /// Maximum list elements generated by one mutation.
    #[arg(long, default_value_t = crate::tools::DEFAULT_MAX_FUZZ_LIST_ITEMS)]
    max_list_items: usize,
    /// Maximum deterministic shrink candidates returned per case.
    #[arg(long, default_value_t = crate::tools::DEFAULT_MAX_FUZZ_SHRINK_STEPS)]
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
    #[arg(long, default_value_t = crate::tools::DEFAULT_SCAN_BATCH_SIZE)]
    batch_size: usize,
    /// Maximum distinct destination ports accepted by the request.
    #[arg(long, default_value_t = crate::tools::DEFAULT_MAX_SCAN_PORTS)]
    max_ports: usize,
    /// Maximum generated probes after target resolution and attempts.
    #[arg(long, default_value_t = crate::core::DEFAULT_MAX_TEMPLATE_PACKETS)]
    max_probes: usize,
    /// Maximum worst-case timeout plus intentional rate delay in milliseconds.
    #[arg(long, default_value_t = 3_600_000)]
    max_duration_ms: u64,
    /// Maximum undecodable exact frames retained across the scan.
    #[arg(long, default_value_t = crate::tools::DEFAULT_MAX_UNDECODED_SCAN_FRAMES)]
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
    #[arg(long, default_value_t = crate::tools::DEFAULT_DNS_SERVER_PORT)]
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
    #[arg(long, default_value_t = crate::tools::DEFAULT_DNS_ATTEMPTS)]
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
    #[arg(long, default_value_t = crate::tools::MAX_DNS_MESSAGE_BYTES)]
    max_message_bytes: usize,
    /// Maximum total answer, authority, and additional records decoded.
    #[arg(long, default_value_t = crate::tools::DEFAULT_MAX_DNS_RECORDS)]
    max_records: usize,
    /// Maximum compression-pointer traversals for any decoded DNS name.
    #[arg(long, default_value_t = crate::tools::DEFAULT_MAX_DNS_NAME_POINTERS)]
    max_name_pointers: usize,
    /// Maximum TXT character strings in one record.
    #[arg(long, default_value_t = crate::tools::DEFAULT_MAX_DNS_TXT_STRINGS)]
    max_txt_strings: usize,
    /// Maximum aggregate TXT data bytes in one record.
    #[arg(long, default_value_t = crate::tools::DEFAULT_MAX_DNS_TXT_BYTES)]
    max_txt_bytes: usize,
    /// Maximum rejected-record metadata entries retained.
    #[arg(long, default_value_t = crate::tools::DEFAULT_MAX_REJECTED_DNS_RECORDS)]
    max_rejected_records: usize,
    /// Maximum undecodable exact frames retained across attempts.
    #[arg(long, default_value_t = crate::tools::DEFAULT_MAX_UNDECODED_DNS_FRAMES)]
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
    #[arg(long, default_value_t = crate::tools::DEFAULT_TRACEROUTE_FIRST_HOP)]
    first_hop: u8,
    /// Last IPv4 TTL or IPv6 hop limit attempted.
    #[arg(long, default_value_t = crate::tools::DEFAULT_TRACEROUTE_MAX_HOPS)]
    max_hops: u8,
    /// Number of attempts retained for every hop.
    #[arg(long, default_value_t = crate::tools::DEFAULT_TRACEROUTE_PROBES_PER_HOP)]
    attempts: u32,
    /// Response window for each capture-ready hop batch.
    #[arg(long, default_value_t = 1_000)]
    timeout_ms: u64,
    /// Optional average probe-rate ceiling; each hop remains one deliberate burst.
    #[arg(long)]
    rate: Option<u32>,
    /// Maximum generated probes across all hops.
    #[arg(long, default_value_t = crate::core::DEFAULT_MAX_TEMPLATE_PACKETS)]
    max_probes: usize,
    /// Maximum worst-case timeout plus intentional rate delay in milliseconds.
    #[arg(long, default_value_t = 3_600_000)]
    max_duration_ms: u64,
    /// Maximum hop-scoped undecodable exact frames retained.
    #[arg(long, default_value_t = crate::tools::DEFAULT_MAX_UNDECODED_TRACEROUTE_FRAMES)]
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
    #[arg(long, default_value_t = crate::client::DEFAULT_MAX_UNSOLICITED_FRAMES)]
    max_responses: usize,
    /// Maximum unsolicited decoded frames retained across the exchange.
    #[arg(long, default_value_t = crate::client::DEFAULT_MAX_UNSOLICITED_FRAMES)]
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
    #[arg(long, default_value_t = crate::io::DEFAULT_CAPTURE_QUEUE_BYTES as u64)]
    max_bytes: u64,
    /// Maximum distinct addresses accepted from one hostname resolution.
    #[arg(long, default_value_t = crate::client::DEFAULT_MAX_RESOLVED_ADDRESSES)]
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
    #[arg(long, default_value_t = crate::io::DEFAULT_CAPTURE_STREAM_FRAMES)]
    max_packets: u64,
    /// Maximum wire bytes authorized for one operation.
    #[arg(long, default_value_t = crate::io::DEFAULT_CAPTURE_STREAM_BYTES)]
    max_bytes: u64,
}

#[derive(Clone, Debug, Args)]
struct CaptureLimitArgs {
    /// Aggregate backend capture-queue frame bound.
    #[arg(long, default_value_t = crate::io::DEFAULT_CAPTURE_QUEUE_FRAMES)]
    max_queue_frames: usize,
    /// Aggregate retained/queued capture byte bound.
    #[arg(long, default_value_t = crate::io::DEFAULT_CAPTURE_QUEUE_BYTES)]
    max_captured_bytes: usize,
    /// Maximum bytes retained from any one captured frame.
    #[arg(long, default_value_t = crate::io::DEFAULT_CAPTURE_SIZE_LIMIT)]
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

#[derive(Clone, Copy, Debug)]
struct CombinedIo<P, C> {
    packets: P,
    capture: C,
}

impl<P, C> CombinedIo<P, C> {
    fn new(packets: P, capture: C) -> Self {
        Self { packets, capture }
    }
}

impl<P: PacketIo, C: Send + Sync> PacketIo for CombinedIo<P, C> {
    fn send(
        &self,
        frame: crate::io::TransmissionFrame<'_>,
    ) -> Result<crate::io::IoSendReport, LiveIoError> {
        self.packets.send(frame)
    }
}

impl<P: Send + Sync, C: CaptureProvider> CaptureProvider for CombinedIo<P, C> {
    type Capture = C::Capture;

    fn arm_capture(
        &self,
        route: &crate::io::PlannedRoute,
        limits: CaptureQueueLimits,
    ) -> Result<Self::Capture, LiveIoError> {
        self.capture.arm_capture(route, limits)
    }
}

struct PreparedRouteRequest {
    packet: Packet,
    destination: Option<IpAddr>,
    options: crate::io::PlanOptions,
    policy: TrafficPolicy,
}

pub(crate) fn run_entrypoint() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => {
            let code = if error.use_stderr() { 2 } else { 0 };
            if code != 0 {
                if let Some(output) = machine_format_from_env() {
                    let message = error.to_string();
                    let error = CliError::new(code, message);
                    let emitted = match output {
                        OutputFormat::Json => emit_json(&AggregateErrorOutput::error(
                            command_from_env(),
                            error.output_error(),
                        )),
                        OutputFormat::Ndjson => emit_json_compact(&StreamErrorRecord::error(
                            command_from_env(),
                            0,
                            error.output_error(),
                        )),
                        _ => unreachable!("machine_format_from_env returns structured formats"),
                    };
                    return match emitted {
                        Ok(()) => exit_code(code),
                        Err(write_error) => {
                            let _ = emit_stderr_error(&write_error.message);
                            exit_code(write_error.code)
                        }
                    };
                }
            }
            return if code == 0 {
                if error.print().is_ok() {
                    ExitCode::SUCCESS
                } else {
                    exit_code(5)
                }
            } else {
                match emit_stderr_message(&error.to_string()) {
                    Ok(()) => exit_code(code),
                    Err(_) => exit_code(5),
                }
            };
        }
    };
    let output = cli.output;
    let command = cli.command.name();
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let emitted = match output {
                OutputFormat::Json => emit_json(&AggregateErrorOutput::error(
                    Some(command),
                    error.output_error(),
                )),
                OutputFormat::Ndjson => emit_json_compact(&StreamErrorRecord::error(
                    Some(command),
                    error.sequence.unwrap_or(0),
                    error.output_error(),
                )),
                _ => emit_stderr_error(&error.message),
            };
            if let Err(write_error) = emitted {
                if matches!(output, OutputFormat::Json | OutputFormat::Ndjson) {
                    let _ = emit_stderr_error(&write_error.message);
                };
                return exit_code(write_error.code);
            }
            exit_code(error.code)
        }
    }
}

impl Command {
    fn name(&self) -> CommandName {
        match self {
            Self::Build(_) => CommandName::Build,
            Self::Dissect(_) => CommandName::Dissect,
            Self::Read(_) => CommandName::Read,
            Self::Interfaces => CommandName::Interfaces,
            Self::Plan(_) => CommandName::Plan,
            Self::Send(_) => CommandName::Send,
            Self::Exchange(_) => CommandName::Exchange,
            Self::Capture(_) => CommandName::Capture,
            Self::Replay(_) => CommandName::Replay,
            Self::Scan(_) => CommandName::Scan,
            Self::Traceroute(_) => CommandName::Traceroute,
            Self::Dns(_) => CommandName::Dns,
            Self::Fuzz(_) => CommandName::Fuzz,
            Self::Routes => CommandName::Routes,
        }
    }
}

fn run(cli: Cli) -> Result<(), CliError> {
    cli.command
        .name()
        .require_format(cli.output)
        .map_err(CliError::classified)?;
    match cli.command {
        Command::Build(arguments) => run_build(arguments, cli.output),
        Command::Dissect(arguments) => run_dissect(arguments, cli.output),
        Command::Read(arguments) => run_read(arguments, cli.output),
        Command::Interfaces => run_interfaces(cli.output),
        Command::Plan(arguments) => run_plan(arguments, cli.output),
        Command::Send(arguments) => run_send(arguments, cli.output),
        Command::Capture(arguments) => run_capture(arguments, cli.output),
        Command::Exchange(arguments) => run_exchange(arguments, cli.output),
        Command::Replay(arguments) => run_replay(arguments, cli.output),
        Command::Scan(arguments) => run_scan(arguments, cli.output),
        Command::Traceroute(arguments) => run_traceroute(arguments, cli.output),
        Command::Dns(arguments) => run_dns(arguments, cli.output),
        Command::Fuzz(arguments) => run_fuzz(arguments, cli.output),
        Command::Routes => run_routes(cli.output),
    }
}

type SystemPackets = DispatchPacketIo<SystemLayer2Io, SystemLayer3Io>;
type SystemLiveIo = CombinedIo<SystemPackets, SystemCaptureProvider>;
type SystemClient = Client<SystemRouteProvider, SystemNeighborResolver, SystemLiveIo>;

fn default_registry_arc() -> Result<Arc<crate::core::ProtocolRegistry>, CliError> {
    crate::protocols::default_registry()
        .map(Arc::new)
        .map_err(|source| {
            CliError::new(70, format!("built-in registry invariant failed: {source}"))
        })
}

fn system_client(
    registry: Arc<crate::core::ProtocolRegistry>,
    policy: TrafficPolicy,
) -> SystemClient {
    Client::new(
        registry,
        SystemRouteProvider,
        SystemNeighborResolver::default(),
        CombinedIo::new(
            DispatchPacketIo::new(SystemLayer2Io, SystemLayer3Io),
            SystemCaptureProvider,
        ),
        policy,
    )
}

fn prepare_route_request(
    arguments: RouteArgs,
    registry: &crate::core::ProtocolRegistry,
) -> Result<PreparedRouteRequest, CliError> {
    let RouteArgs {
        recipe,
        destination,
        interface,
        source,
        link_mode,
        policy,
    } = arguments;
    let packet = read_recipe(recipe, registry)?;
    let policy = policy.into_policy();
    policy.validate().map_err(CliError::classified)?;
    // This check intentionally precedes interface discovery and route lookup.
    policy
        .authorize_packet_destinations(&packet)
        .map_err(CliError::classified)?;
    let destination = resolve_live_destination(destination, &packet, &policy)?;
    let interface = resolve_interface(interface, &SystemInterfaceProvider)?;
    Ok(PreparedRouteRequest {
        packet,
        destination,
        options: crate::io::PlanOptions {
            link_mode: link_mode.into(),
            interface,
            preferred_source: source,
        },
        policy,
    })
}

fn resolve_live_destination(
    value: Option<String>,
    packet: &Packet,
    policy: &TrafficPolicy,
) -> Result<Option<IpAddr>, CliError> {
    let Some(value) = value else {
        return Ok(None);
    };
    let target = value.parse::<LiveTarget>().map_err(CliError::classified)?;
    let resolved = policy
        .resolve_target(&target, &SystemHostnameResolver)
        .map_err(CliError::classified)?;
    let family = packet
        .iter()
        .find_map(|layer| match layer.protocol_id().as_str() {
            "ipv4" => Some(true),
            "ipv6" => Some(false),
            _ => None,
        });
    match family {
        Some(ipv4) => resolved.address_for_family(ipv4).map(Some).ok_or_else(|| {
            CliError::classified(
                crate::client::TargetResolutionError::AddressFamilyUnavailable {
                    family: if ipv4 { "IPv4" } else { "IPv6" },
                },
            )
        }),
        None => Ok(Some(resolved.selected_address())),
    }
}

fn resolve_interface<I: InterfaceProvider>(
    selector: Option<String>,
    provider: &I,
) -> Result<Option<InterfaceId>, CliError> {
    let Some(selector) = selector else {
        return Ok(None);
    };
    let interfaces = provider.interfaces().map_err(CliError::classified)?;
    let requested_index = selector.parse::<u32>().ok();
    interfaces
        .into_iter()
        .find(|interface| {
            requested_index.map_or_else(
                || interface.id.name == selector,
                |index| interface.id.index == index,
            )
        })
        .map(|interface| Some(interface.id))
        .ok_or_else(|| {
            CliError::classified(LiveIoError::Device {
                interface: selector,
                message: "no interface matches the requested name or index".to_owned(),
            })
        })
}

fn run_plan(arguments: RouteArgs, output: OutputFormat) -> Result<(), CliError> {
    let registry = default_registry_arc()?;
    let request = prepare_route_request(arguments, &registry)?;
    let client = system_client(Arc::clone(&registry), request.policy);
    let route = client
        .plan(&request.packet, request.destination, &request.options)
        .map_err(CliError::classified)?;
    let result = PlanCommandResult { route };
    match output {
        OutputFormat::Text => render_planned_route(&result.route),
        OutputFormat::Json => emit_json(&AggregateOutput::success(
            CommandName::Plan,
            result,
            Vec::new(),
        )),
        _ => Err(CliError::classified(
            OutputContractError::UnsupportedFormat {
                command: CommandName::Plan,
                format: output,
            },
        )),
    }
}

fn render_planned_route(route: &crate::io::PlannedRoute) -> Result<(), CliError> {
    write_stdout_line(format_args!(
        "interface={} index={} mode={:?} mtu={} link_type={}",
        route.route.interface.name,
        route.route.interface.index,
        route.mode,
        route.route.mtu,
        route.route.link_type.0
    ))?;
    write_stdout_line(format_args!(
        "lookup_destination={} final_destination={} source={} next_hop={} destination_mac={}",
        optional_display(route.lookup_destination),
        optional_display(route.final_destination),
        optional_display(route.packet_source),
        optional_display(route.route.next_hop),
        route
            .destination_mac
            .map(|value| value.to_string())
            .unwrap_or_else(|| "unresolved".to_owned())
    ))
}

fn optional_display<T: std::fmt::Display>(value: Option<T>) -> String {
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|| "none".to_owned())
}

fn run_routes(output: OutputFormat) -> Result<(), CliError> {
    let interfaces = SystemInterfaceProvider
        .interfaces()
        .map_err(CliError::classified)?;
    let provider = SystemRouteProvider;
    let mut routes = Vec::new();
    for interface in interfaces
        .into_iter()
        .filter(|interface| interface.flags.up)
    {
        let route = provider.lookup_interface(&interface.id).map_err(|source| {
            CliError::from_classification(
                provider.classify_error(&source),
                source.to_string(),
                Vec::new(),
            )
        })?;
        if let Some(route) = route {
            routes.push(route);
        }
    }
    routes.sort_by_key(|route| (route.interface.index, route.interface.name.clone()));
    routes.dedup_by(|left, right| left.interface == right.interface);
    let result = RoutesCommandResult { routes };
    match output {
        OutputFormat::Text => {
            for route in result.routes {
                write_stdout_line(format_args!(
                    "{} (index {}): source={} mtu={} capability={:?} link_type={}",
                    route.interface.name,
                    route.interface.index,
                    optional_display(route.selected_address.or(route.preferred_source)),
                    route.mtu,
                    route.capability,
                    route.link_type.0
                ))?;
            }
            Ok(())
        }
        OutputFormat::Json => emit_json(&AggregateOutput::success(
            CommandName::Routes,
            result,
            Vec::new(),
        )),
        _ => Err(CliError::classified(
            OutputContractError::UnsupportedFormat {
                command: CommandName::Routes,
                format: output,
            },
        )),
    }
}

fn run_send(arguments: SendArgs, output: OutputFormat) -> Result<(), CliError> {
    let SendArgs {
        route,
        mode,
        allow_permissive_live,
    } = arguments;
    let registry = default_registry_arc()?;
    let request = prepare_route_request(route, &registry)?;
    let client = system_client(Arc::clone(&registry), request.policy);
    let report = client
        .send(
            request.packet,
            SendOptions {
                destination: request.destination,
                plan: request.options,
                build: BuildOptions {
                    mode: cli_build_mode(mode),
                    ..BuildOptions::default()
                },
                allow_permissive_live,
            },
        )
        .map_err(CliError::classified)?;
    let (result, diagnostics, stats) =
        SendCommandResult::try_from_report(report).map_err(CliError::classified)?;
    match output {
        OutputFormat::Text => {
            write_stdout_line(format_args!(
                "sent {} bytes via {} (index {}, {:?})",
                result.frame.length,
                result.route.plan.route.interface.name,
                result.route.plan.route.interface.index,
                result.route.plan.mode
            ))?;
            for diagnostic in diagnostics {
                write_stdout_line(format_args!(
                    "{:?} {}: {}",
                    diagnostic.severity, diagnostic.code, diagnostic.message
                ))?;
            }
            Ok(())
        }
        OutputFormat::Json => emit_json(
            &AggregateOutput::success(CommandName::Send, result, diagnostics).with_stats(stats),
        ),
        OutputFormat::Hex => write_stdout_line(format_args!("{}", result.frame.bytes_hex)),
        OutputFormat::Raw => write_raw(result.frame.bytes()),
        OutputFormat::Pcap | OutputFormat::Pcapng => {
            let frame = CapturedFrame::new(
                SystemTime::now(),
                result.route.plan.route.link_type,
                result.frame.bytes().to_vec(),
            )
            .map_err(|source| CliError::new(3, source.to_string()))?;
            write_capture_file(output, [frame])
        }
        _ => Err(CliError::classified(
            OutputContractError::UnsupportedFormat {
                command: CommandName::Send,
                format: output,
            },
        )),
    }
}

fn cli_build_mode(mode: CliBuildMode) -> BuildMode {
    match mode {
        CliBuildMode::Strict => BuildMode::Strict,
        CliBuildMode::Permissive => BuildMode::Permissive,
    }
}

#[derive(Debug)]
struct CaptureOutcome {
    diagnostics: Vec<crate::core::Diagnostic>,
    stats: crate::client::OperationStats,
}

#[derive(Clone, Copy, Debug)]
struct CaptureBudget {
    max_frames: u64,
    max_bytes: u64,
}

impl From<&TrafficPolicy> for CaptureBudget {
    fn from(policy: &TrafficPolicy) -> Self {
        Self {
            max_frames: policy.max_packets_per_operation,
            max_bytes: policy.max_bytes_per_operation,
        }
    }
}

fn run_capture(arguments: CaptureArgs, output: OutputFormat) -> Result<(), CliError> {
    let CaptureArgs {
        route,
        timeout_ms,
        limits,
    } = arguments;
    let timeout = Duration::from_millis(timeout_ms);
    validate_capture_window(timeout)?;
    let limits = limits
        .into_limits()
        .validate()
        .map_err(CliError::classified)?;
    let registry = default_registry_arc()?;
    let request = prepare_route_request(route, &registry)?;
    let budget = CaptureBudget::from(&request.policy);
    let client = system_client(Arc::clone(&registry), request.policy);
    let route = client
        .plan(&request.packet, request.destination, &request.options)
        .map_err(CliError::classified)?;

    match output {
        OutputFormat::Text => {
            let capture = SystemCaptureProvider
                .arm_capture(&route, limits)
                .map_err(CliError::classified)?;
            let outcome = drive_capture(capture, timeout, limits, budget, |frame, sequence| {
                let frame = FrameOutput::try_from_frame(frame).map_err(CliError::classified)?;
                write_stdout_line(format_args!(
                    "{sequence}: dlt={} caplen={} wirelen={} {}",
                    frame.link_type,
                    frame.captured_length,
                    frame.original_length,
                    spaced_hex(frame.bytes())
                ))
            })?;
            write_stdout_line(format_args!(
                "captured {} frame(s), {} byte(s)",
                outcome.stats.packets_completed, outcome.stats.bytes
            ))?;
            render_diagnostics_text(&outcome.diagnostics)
        }
        OutputFormat::Hex => {
            let capture = SystemCaptureProvider
                .arm_capture(&route, limits)
                .map_err(CliError::classified)?;
            let outcome = drive_capture(capture, timeout, limits, budget, |frame, _| {
                let frame = FrameOutput::try_from_frame(frame).map_err(CliError::classified)?;
                write_stdout_line(format_args!("{}", frame.bytes_hex))
            })?;
            render_diagnostics_stderr(&outcome.diagnostics)
        }
        OutputFormat::Ndjson => {
            let capture = SystemCaptureProvider
                .arm_capture(&route, limits)
                .map_err(CliError::classified)?;
            let outcome = drive_capture(capture, timeout, limits, budget, |frame, sequence| {
                let frame = FrameOutput::try_from_frame(frame).map_err(CliError::classified)?;
                emit_json_compact(&StreamRecord::success(
                    CommandName::Capture,
                    sequence,
                    CaptureFrameCommandResult::Frame { frame },
                    Vec::new(),
                ))
                .map_err(|error| error.at_sequence(sequence))
            })?;
            let sequence = outcome.stats.packets_completed;
            emit_json_compact(
                &StreamRecord::success(
                    CommandName::Capture,
                    sequence,
                    CaptureFrameCommandResult::Complete { frames: sequence },
                    outcome.diagnostics,
                )
                .with_stats(outcome.stats),
            )
            .map_err(|error| error.at_sequence(sequence))
        }
        OutputFormat::Pcap | OutputFormat::Pcapng => {
            let format = capture_file_format(output)?;
            let mut capture = SystemCaptureProvider
                .arm_capture(&route, limits)
                .map_err(CliError::classified)?;
            let stdout = io::stdout();
            let mut writer = match CaptureWriter::with_limit(
                stdout.lock(),
                format,
                route.route.link_type,
                limits.snap_length,
            ) {
                Ok(writer) => writer,
                Err(source) => {
                    let error =
                        CliError::new(5, format!("initialize capture output failed: {source}"));
                    return Err(shutdown_after_error(&mut capture, error));
                }
            };
            if let Err(source) = writer.set_stream_limits(CaptureStreamLimits {
                max_frames: budget.max_frames,
                max_bytes: budget.max_bytes,
            }) {
                let error = CliError::classified(source);
                return Err(shutdown_after_error(&mut capture, error));
            }
            let outcome = drive_capture(capture, timeout, limits, budget, |frame, _| {
                writer
                    .write_frame(&capture_file_frame(frame, format))
                    .map_err(|source| {
                        CliError::new(5, format!("write capture output failed: {source}"))
                    })
            })?;
            let mut stdout = writer.into_inner();
            stdout
                .flush()
                .map_err(|source| CliError::new(5, format!("write stdout failed: {source}")))?;
            render_diagnostics_stderr(&outcome.diagnostics)
        }
        _ => Err(CliError::classified(
            OutputContractError::UnsupportedFormat {
                command: CommandName::Capture,
                format: output,
            },
        )),
    }
}

fn validate_capture_window(timeout: Duration) -> Result<(), CliError> {
    if timeout > crate::io::MAX_CAPTURE_TIMEOUT || Instant::now().checked_add(timeout).is_none() {
        return Err(CliError::classified(LiveIoError::InvalidCaptureTimeout {
            timeout,
            maximum: crate::io::MAX_CAPTURE_TIMEOUT,
        }));
    }
    Ok(())
}

fn drive_capture<C, F>(
    mut capture: C,
    timeout: Duration,
    limits: CaptureQueueLimits,
    budget: CaptureBudget,
    mut emit: F,
) -> Result<CaptureOutcome, CliError>
where
    C: CaptureSession,
    F: FnMut(CapturedFrame, u64) -> Result<(), CliError>,
{
    let started = Instant::now();
    if let Err(source) = capture.wait_ready() {
        let error = CliError::classified(source).at_sequence(0);
        return Err(shutdown_after_error(&mut capture, error));
    }
    let deadline = Instant::now()
        .checked_add(timeout)
        .expect("validated capture timeout must fit the monotonic clock");
    let mut frames = 0_u64;
    let mut bytes = 0_u64;
    while frames < budget.max_frames {
        let now = Instant::now();
        let Some(remaining) = deadline.checked_duration_since(now) else {
            break;
        };
        if remaining.is_zero() {
            break;
        }
        let frame = match capture.next_frame(remaining) {
            Ok(Some(frame)) => frame,
            Ok(None) => break,
            Err(source) => {
                let error = CliError::classified(source).at_sequence(frames);
                return Err(shutdown_after_error(&mut capture, error));
            }
        };
        let next_bytes = bytes.checked_add(frame.bytes.len() as u64).ok_or_else(|| {
            shutdown_after_error(
                &mut capture,
                CliError::new(70, "capture output byte accounting overflowed").at_sequence(frames),
            )
        })?;
        if next_bytes > budget.max_bytes {
            let error = CliError::classified(TrafficPolicyError::ByteLimit {
                actual: next_bytes,
                limit: budget.max_bytes,
            })
            .at_sequence(frames);
            return Err(shutdown_after_error(&mut capture, error));
        }
        bytes = next_bytes;
        if let Err(error) = emit(frame, frames) {
            return Err(shutdown_after_error(
                &mut capture,
                error.at_sequence_if_absent(frames),
            ));
        }
        frames = frames.checked_add(1).ok_or_else(|| {
            shutdown_after_error(
                &mut capture,
                CliError::classified(OutputContractError::SequenceOverflow).at_sequence(frames),
            )
        })?;
    }
    capture
        .shutdown()
        .map_err(CliError::classified)
        .map_err(|error| error.at_sequence(frames))?;
    let statistics = capture
        .statistics()
        .validate()
        .map_err(CliError::classified)
        .map_err(|error| error.at_sequence(frames))?;
    let mut diagnostics = Vec::new();
    if statistics.has_loss() {
        if limits.overflow_policy == CaptureOverflowPolicy::Fail {
            return Err(CliError::classified(
                statistics
                    .evidence_loss_error()
                    .expect("lossy capture statistics must produce a typed error"),
            )
            .at_sequence(frames));
        }
        diagnostics.push(crate::core::Diagnostic::warning(
            "capture.evidence_incomplete",
            format!(
                "capture backend reported {} overflow event(s), {} receiver drop(s), {} total dropped frame(s), and {} dropped byte(s) under {:?}",
                statistics.overflow_events,
                statistics.receiver_dropped_frames,
                statistics.dropped_frames,
                statistics.dropped_bytes,
                limits.overflow_policy
            ),
        ));
    }
    Ok(CaptureOutcome {
        diagnostics,
        stats: crate::client::OperationStats {
            packets_attempted: frames,
            packets_completed: frames,
            bytes,
            elapsed: started.elapsed(),
            capture: statistics,
        },
    })
}

fn shutdown_after_error<C: CaptureSession>(capture: &mut C, error: CliError) -> CliError {
    match capture.shutdown() {
        Ok(()) => error,
        Err(cleanup) => error.with_cleanup(cleanup),
    }
}

fn render_diagnostics_text(diagnostics: &[crate::core::Diagnostic]) -> Result<(), CliError> {
    for diagnostic in diagnostics {
        write_stdout_line(format_args!(
            "{:?} {}: {}",
            diagnostic.severity, diagnostic.code, diagnostic.message
        ))?;
    }
    Ok(())
}

fn render_diagnostics_stderr(diagnostics: &[crate::core::Diagnostic]) -> Result<(), CliError> {
    for diagnostic in diagnostics {
        emit_stderr_message(&format!(
            "{:?} {}: {}",
            diagnostic.severity, diagnostic.code, diagnostic.message
        ))?;
    }
    Ok(())
}

fn run_exchange(arguments: ExchangeArgs, output: OutputFormat) -> Result<(), CliError> {
    let ExchangeArgs {
        send,
        timeout_ms,
        max_responses,
        max_unsolicited,
        limits,
    } = arguments;
    let SendArgs {
        route,
        mode,
        allow_permissive_live,
    } = send;
    let limits = limits.into_limits();
    let mut options = ExchangeOptions {
        timeout: Duration::from_millis(timeout_ms),
        max_template_packets: 1,
        max_responses,
        max_unsolicited,
        max_capture_queue_frames: limits.max_frames,
        max_captured_bytes: limits.max_bytes,
        capture_overflow_policy: limits.overflow_policy,
        ..ExchangeOptions::default()
    };
    options.decode.max_packet_size = limits.snap_length;
    // Validate before packet parsing can trigger hostname/interface work.
    options.validate().map_err(CliError::classified)?;

    let registry = default_registry_arc()?;
    let request = prepare_route_request(route, &registry)?;
    options.send = SendOptions {
        destination: request.destination,
        plan: request.options,
        build: BuildOptions {
            mode: cli_build_mode(mode),
            ..BuildOptions::default()
        },
        allow_permissive_live,
    };
    let client = system_client(Arc::clone(&registry), request.policy);
    let result = client
        .exchange(&PacketTemplate::new(request.packet), options)
        .map_err(CliError::classified)?;

    if matches!(output, OutputFormat::Pcap | OutputFormat::Pcapng) {
        let frames = result
            .sent_evidence
            .iter()
            .cloned()
            .chain(
                result
                    .responses
                    .iter()
                    .map(|response| response.response.frame.clone()),
            )
            .chain(result.unsolicited.iter().map(|packet| packet.frame.clone()))
            .chain(result.undecoded.iter().cloned())
            .collect::<Vec<_>>();
        let mut frames = frames;
        frames.sort_by_key(|frame| frame.timestamp);
        return write_capture_file(output, frames);
    }

    let (result, diagnostics, stats) =
        ExchangeCommandResult::try_from_exchange(result).map_err(CliError::classified)?;
    match output {
        OutputFormat::Text => {
            write_stdout_line(format_args!(
                "sent={} responses={} unanswered={} unsolicited={} undecoded={} bytes={}",
                result.sent.len(),
                result.responses.len(),
                result.unanswered.len(),
                result.unsolicited.len(),
                result.undecoded.len(),
                stats.bytes
            ))?;
            render_diagnostics_text(&diagnostics)
        }
        OutputFormat::Json => emit_json(
            &AggregateOutput::success(CommandName::Exchange, result, diagnostics).with_stats(stats),
        ),
        OutputFormat::Ndjson => render_exchange_stream(result, diagnostics, stats),
        _ => Err(CliError::classified(
            OutputContractError::UnsupportedFormat {
                command: CommandName::Exchange,
                format: output,
            },
        )),
    }
}

fn render_exchange_stream(
    result: ExchangeCommandResult,
    diagnostics: Vec<crate::core::Diagnostic>,
    stats: crate::client::OperationStats,
) -> Result<(), CliError> {
    let ExchangeCommandResult {
        sent,
        responses,
        unanswered,
        unsolicited,
        undecoded,
    } = result;
    let mut sequence = 0_u64;
    for (request_index, frame) in sent.into_iter().enumerate() {
        emit_exchange_record(
            &mut sequence,
            ExchangeStreamCommandResult::Sent {
                request_index: request_index as u64,
                frame,
            },
        )?;
    }
    for response in responses {
        emit_exchange_record(
            &mut sequence,
            ExchangeStreamCommandResult::Response {
                request_index: response.request_index,
                response: response.response,
                latency: response.latency,
            },
        )?;
    }
    for request_index in &unanswered {
        emit_exchange_record(
            &mut sequence,
            ExchangeStreamCommandResult::Unanswered {
                request_index: *request_index,
            },
        )?;
    }
    for frame in unsolicited {
        emit_exchange_record(
            &mut sequence,
            ExchangeStreamCommandResult::Unsolicited { frame },
        )?;
    }
    for frame in undecoded {
        emit_exchange_record(
            &mut sequence,
            ExchangeStreamCommandResult::Undecoded { frame },
        )?;
    }
    emit_json_compact(
        &StreamRecord::success(
            CommandName::Exchange,
            sequence,
            ExchangeStreamCommandResult::Complete { unanswered },
            diagnostics,
        )
        .with_stats(stats),
    )
    .map_err(|error| error.at_sequence(sequence))
}

fn emit_exchange_record(
    sequence: &mut u64,
    result: ExchangeStreamCommandResult,
) -> Result<(), CliError> {
    emit_json_compact(&StreamRecord::success(
        CommandName::Exchange,
        *sequence,
        result,
        Vec::new(),
    ))
    .map_err(|error| error.at_sequence(*sequence))?;
    *sequence = sequence.checked_add(1).ok_or_else(|| {
        CliError::classified(OutputContractError::SequenceOverflow).at_sequence(*sequence)
    })?;
    Ok(())
}

fn run_scan(arguments: ScanArgs, output: OutputFormat) -> Result<(), CliError> {
    let ScanArgs {
        target,
        transport,
        family,
        ports,
        attempts,
        timeout_ms,
        rate,
        batch_size,
        max_ports,
        max_probes,
        max_duration_ms,
        max_undecoded,
        interface,
        source,
        link_mode,
        limits,
        policy,
    } = arguments;
    let target = match target.parse::<LiveTarget>().map_err(CliError::classified)? {
        LiveTarget::Address(address) => ScanTarget::Address(address),
        LiveTarget::Hostname(hostname) => ScanTarget::Hostname(hostname.to_string()),
    };
    let queue_limits = limits.into_limits();
    let scan_limits = ScanLimits {
        max_ports,
        max_probes,
        batch_size,
        max_duration: Duration::from_millis(max_duration_ms),
        max_evidence_frames: queue_limits.max_frames,
        max_evidence_bytes: queue_limits.max_bytes,
        max_undecoded,
    };
    scan_limits.validate().map_err(scan_cli_error)?;
    let policy = policy.into_policy();
    policy.validate().map_err(CliError::classified)?;
    validate_live_interface_selector("scan", interface.as_deref())?;
    let request = ScanRequest {
        target,
        transport: transport.into(),
        address_family: family.into(),
        ports,
        attempts,
        timeout: Duration::from_millis(timeout_ms),
        probes_per_second: rate,
        limits: scan_limits,
    };
    let registry = default_registry_arc()?;
    let mut exchange = ExchangeOptions {
        send: SendOptions {
            destination: None,
            plan: crate::io::PlanOptions {
                link_mode: link_mode.into(),
                interface: None,
                preferred_source: source,
            },
            build: BuildOptions::default(),
            allow_permissive_live: false,
        },
        timeout: request.timeout,
        max_template_packets: batch_size,
        max_unsolicited: queue_limits.max_frames,
        max_responses: queue_limits.max_frames,
        max_capture_queue_frames: queue_limits.max_frames,
        max_captured_bytes: queue_limits.max_bytes,
        capture_overflow_policy: queue_limits.overflow_policy,
        decode: DecodeOptions::default(),
    };
    exchange.decode.max_packet_size = queue_limits.snap_length;
    exchange.validate().map_err(CliError::classified)?;

    let mut executor = CliScanExecutor {
        registry: Arc::clone(&registry),
        policy: policy.clone(),
        exchange,
        interface,
        interface_resolved: false,
    };
    let resolver = SystemHostnameResolver;
    let mut authorizer = TrafficPolicyScanAuthorizer::new(&policy, &resolver);
    let mut clock = SystemScanClock;
    let result = scan(
        &request,
        &mut authorizer,
        &registry,
        &mut executor,
        &mut clock,
    )
    .map_err(scan_cli_error)?;
    let (result, diagnostics, stats) =
        ScanCommandResult::try_from_scan(result).map_err(CliError::classified)?;

    match output {
        OutputFormat::Text => render_scan_text(result, diagnostics, stats),
        OutputFormat::Json => emit_json(
            &AggregateOutput::success(CommandName::Scan, result, diagnostics).with_stats(stats),
        ),
        OutputFormat::Ndjson => render_scan_stream(result, diagnostics, stats),
        _ => Err(CliError::classified(
            OutputContractError::UnsupportedFormat {
                command: CommandName::Scan,
                format: output,
            },
        )),
    }
}

fn validate_live_interface_selector(command: &str, selector: Option<&str>) -> Result<(), CliError> {
    let Some(selector) = selector else {
        return Ok(());
    };
    if selector.is_empty() {
        return Err(CliError::new(
            2,
            format!("{command} interface cannot be empty"),
        ));
    }
    let numeric = selector.bytes().all(|byte| byte.is_ascii_digit());
    let index = selector.parse::<u32>().unwrap_or(0);
    if numeric && index == 0 {
        return Err(CliError::new(
            2,
            format!("{command} interface index must be non-zero"),
        ));
    }
    Ok(())
}

struct CliScanExecutor {
    registry: Arc<crate::core::ProtocolRegistry>,
    policy: TrafficPolicy,
    exchange: ExchangeOptions,
    interface: Option<String>,
    interface_resolved: bool,
}

impl ScanExecutor for CliScanExecutor {
    fn execute(&mut self, batch: &ScanBatch) -> Result<ScanBatchExecution, ScanExecutionError> {
        if !self.interface_resolved {
            self.exchange.send.plan.interface =
                resolve_interface(self.interface.take(), &SystemInterfaceProvider)
                    .map_err(scan_execution_error_from_cli)?;
            self.interface_resolved = true;
        }
        let client = system_client(Arc::clone(&self.registry), self.policy.clone());
        ClientScanExecutor::new(&client, self.exchange.clone()).execute(batch)
    }
}

fn scan_execution_error_from_cli(error: CliError) -> ScanExecutionError {
    ScanExecutionError::new(error.message, error.classification, error.causes)
}

fn scan_cli_error(error: ScanError) -> CliError {
    let sequence = error.sequence();
    let mut error = CliError::classified(error);
    if let Some(sequence) = sequence {
        error = error.at_sequence(sequence);
    }
    error
}

fn render_scan_text(
    result: ScanCommandResult,
    diagnostics: Vec<crate::core::Diagnostic>,
    stats: crate::client::OperationStats,
) -> Result<(), CliError> {
    write_stdout_line(format_args!(
        "target={} resolved={}",
        result.target,
        result
            .resolved_addresses
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",")
    ))?;
    for port in &result.ports {
        let destination = port
            .evidence
            .first()
            .map(|evidence| evidence.destination)
            .ok_or_else(|| CliError::new(70, "scan endpoint has no attempt evidence"))?;
        let endpoint = if port.transport == "icmp" {
            "icmp".to_owned()
        } else {
            format!("{}/{}", port.transport, port.port)
        };
        write_stdout_line(format_args!(
            "{} {} classification={}",
            destination,
            endpoint,
            scan_classification_name(port.classification)
        ))?;
        for evidence in &port.evidence {
            write_stdout_line(format_args!(
                "  attempt={} status={} classification={} sent={} received={} responder={} latency={} reason={}",
                evidence.attempt,
                scan_probe_status_name(evidence.status),
                scan_classification_name(evidence.classification),
                output_timestamp_text(evidence.sent_at),
                evidence
                    .received_at
                    .map(output_timestamp_text)
                    .unwrap_or_else(|| "none".to_owned()),
                evidence
                    .responder
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "none".to_owned()),
                evidence
                    .latency
                    .map(|value| format!("{value:?}"))
                    .unwrap_or_else(|| "none".to_owned()),
                evidence.reason,
            ))?;
            if let Some(frame) = &evidence.frame {
                write_stdout_line(format_args!(
                    "    frame dlt={} caplen={} wirelen={} {}",
                    frame.link_type,
                    frame.captured_length,
                    frame.original_length,
                    spaced_hex(frame.bytes())
                ))?;
            }
        }
    }
    for frame in &result.undecoded {
        write_stdout_line(format_args!(
            "undecoded dlt={} caplen={} wirelen={} {}",
            frame.link_type,
            frame.captured_length,
            frame.original_length,
            spaced_hex(frame.bytes())
        ))?;
    }
    write_stdout_line(format_args!(
        "scanned {} endpoint(s) with {} completed probe(s), {} byte(s)",
        result.ports.len(),
        stats.packets_completed,
        stats.bytes
    ))?;
    render_diagnostics_text(&diagnostics)
}

fn output_timestamp_text(timestamp: crate::output::OutputTimestamp) -> String {
    format!("{}.{:09}", timestamp.unix_seconds, timestamp.nanoseconds)
}

fn scan_classification_name(value: crate::output::ScanClassification) -> &'static str {
    match value {
        crate::output::ScanClassification::Open => "open",
        crate::output::ScanClassification::Closed => "closed",
        crate::output::ScanClassification::Filtered => "filtered",
        crate::output::ScanClassification::Unreachable => "unreachable",
        crate::output::ScanClassification::Unknown => "unknown",
        crate::output::ScanClassification::Timeout => "timeout",
    }
}

fn scan_probe_status_name(value: crate::output::ScanProbeStatus) -> &'static str {
    match value {
        crate::output::ScanProbeStatus::Response => "response",
        crate::output::ScanProbeStatus::Timeout => "timeout",
    }
}

fn render_scan_stream(
    result: ScanCommandResult,
    diagnostics: Vec<crate::core::Diagnostic>,
    stats: crate::client::OperationStats,
) -> Result<(), CliError> {
    let ScanCommandResult {
        target,
        resolved_addresses,
        ports,
        undecoded,
    } = result;
    let mut sequence = 0_u64;
    for port in ports {
        let resolved_address = port
            .evidence
            .first()
            .map(|evidence| evidence.destination)
            .ok_or_else(|| {
                CliError::new(70, "scan endpoint has no attempt evidence").at_sequence(sequence)
            })?;
        emit_scan_record(
            &mut sequence,
            ScanStreamCommandResult::Port {
                target: target.clone(),
                resolved_address,
                port,
            },
        )?;
    }
    for frame in undecoded {
        emit_scan_record(&mut sequence, ScanStreamCommandResult::Undecoded { frame })?;
    }
    emit_json_compact(
        &StreamRecord::success(
            CommandName::Scan,
            sequence,
            ScanStreamCommandResult::Complete {
                target,
                resolved_addresses,
            },
            diagnostics,
        )
        .with_stats(stats),
    )
    .map_err(|error| error.at_sequence(sequence))
}

fn emit_scan_record(sequence: &mut u64, result: ScanStreamCommandResult) -> Result<(), CliError> {
    emit_json_compact(&StreamRecord::success(
        CommandName::Scan,
        *sequence,
        result,
        Vec::new(),
    ))
    .map_err(|error| error.at_sequence(*sequence))?;
    *sequence = sequence.checked_add(1).ok_or_else(|| {
        CliError::classified(OutputContractError::SequenceOverflow).at_sequence(*sequence)
    })?;
    Ok(())
}

fn run_dns(arguments: DnsArgs, output: OutputFormat) -> Result<(), CliError> {
    let DnsArgs {
        server,
        name,
        query_type,
        family,
        port,
        transaction_id,
        source_port,
        no_recursion,
        attempts,
        timeout_ms,
        rate,
        max_duration_ms,
        max_message_bytes,
        max_records,
        max_name_pointers,
        max_txt_strings,
        max_txt_bytes,
        max_rejected_records,
        max_undecoded,
        interface,
        source,
        link_mode,
        limits,
        policy,
    } = arguments;
    let server = match server.parse::<LiveTarget>().map_err(CliError::classified)? {
        LiveTarget::Address(address) => ScanTarget::Address(address),
        LiveTarget::Hostname(hostname) => ScanTarget::Hostname(hostname.to_string()),
    };
    let queue_limits = limits.into_limits();
    let request = DnsRequest {
        server,
        address_family: family.into(),
        server_port: port,
        source_port: source_port.unwrap_or_else(generated_dns_source_port),
        query_name: name,
        query_type: query_type.into(),
        transaction_id: transaction_id.unwrap_or_else(generated_dns_transaction_id),
        recursion_desired: !no_recursion,
        attempts,
        timeout: Duration::from_millis(timeout_ms),
        queries_per_second: rate,
        limits: DnsLimits {
            max_message_bytes,
            max_records,
            max_name_pointers,
            max_txt_strings,
            max_txt_bytes,
            max_rejected_records,
            max_evidence_frames: queue_limits.max_frames,
            max_evidence_bytes: queue_limits.max_bytes,
            max_undecoded,
            max_duration: Duration::from_millis(max_duration_ms),
        },
    };
    request.validate().map_err(dns_cli_error)?;
    let policy = policy.into_policy();
    policy.validate().map_err(CliError::classified)?;
    validate_live_interface_selector("dns", interface.as_deref())?;

    let registry = default_registry_arc()?;
    let mut exchange = ExchangeOptions {
        send: SendOptions {
            destination: None,
            plan: crate::io::PlanOptions {
                link_mode: link_mode.into(),
                interface: None,
                preferred_source: source,
            },
            build: BuildOptions::default(),
            allow_permissive_live: false,
        },
        timeout: request.timeout,
        max_template_packets: 1,
        max_unsolicited: queue_limits.max_frames,
        max_responses: queue_limits.max_frames,
        max_capture_queue_frames: queue_limits.max_frames,
        max_captured_bytes: queue_limits.max_bytes,
        capture_overflow_policy: queue_limits.overflow_policy,
        decode: DecodeOptions::default(),
    };
    exchange.decode.max_packet_size = queue_limits.snap_length;
    exchange.validate().map_err(CliError::classified)?;

    let mut executor = CliDnsExecutor {
        registry: Arc::clone(&registry),
        policy: policy.clone(),
        exchange,
        interface,
        interface_resolved: false,
    };
    let resolver = SystemHostnameResolver;
    let mut authorizer = TrafficPolicyDnsAuthorizer::new(&policy, &resolver);
    let mut clock = SystemDnsClock;
    let result = dns(
        &request,
        &mut authorizer,
        &registry,
        &mut executor,
        &mut clock,
    )
    .map_err(dns_cli_error)?;
    let (result, diagnostics, stats) =
        DnsCommandResult::try_from_dns(result).map_err(CliError::classified)?;
    match output {
        OutputFormat::Text => render_dns_text(result, diagnostics, stats),
        OutputFormat::Json => emit_json(
            &AggregateOutput::success(CommandName::Dns, result, diagnostics).with_stats(stats),
        ),
        OutputFormat::Ndjson => render_dns_stream(result, diagnostics, stats),
        _ => Err(CliError::classified(
            OutputContractError::UnsupportedFormat {
                command: CommandName::Dns,
                format: output,
            },
        )),
    }
}

fn generated_dns_transaction_id() -> u16 {
    generated_dns_entropy() as u16
}

fn generated_dns_source_port() -> u16 {
    const WIDTH: u64 = u16::MAX as u64 - crate::tools::DNS_EPHEMERAL_SOURCE_PORT_BASE as u64 + 1;
    crate::tools::DNS_EPHEMERAL_SOURCE_PORT_BASE + (generated_dns_entropy() % WIDTH) as u16
}

fn generated_dns_entropy() -> u64 {
    let time = SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let mut hasher = RandomState::new().build_hasher();
    hasher.write_u128(time);
    hasher.write_u32(std::process::id());
    hasher.finish()
}

struct CliDnsExecutor {
    registry: Arc<crate::core::ProtocolRegistry>,
    policy: TrafficPolicy,
    exchange: ExchangeOptions,
    interface: Option<String>,
    interface_resolved: bool,
}

impl DnsExecutor for CliDnsExecutor {
    fn execute(
        &mut self,
        exchange: &DnsExchange,
    ) -> Result<DnsExchangeExecution, DnsExecutionError> {
        if !self.interface_resolved {
            self.exchange.send.plan.interface =
                resolve_interface(self.interface.take(), &SystemInterfaceProvider)
                    .map_err(dns_execution_error_from_cli)?;
            self.interface_resolved = true;
        }
        let client = system_client(Arc::clone(&self.registry), self.policy.clone());
        ClientDnsExecutor::new(&client, self.exchange.clone()).execute(exchange)
    }
}

fn dns_execution_error_from_cli(error: CliError) -> DnsExecutionError {
    DnsExecutionError::new(error.message, error.classification, error.causes)
}

fn dns_cli_error(error: DnsError) -> CliError {
    let sequence = error.sequence();
    let mut error = CliError::classified(error);
    if let Some(sequence) = sequence {
        error = error.at_sequence(sequence);
    }
    error
}

fn render_dns_text(
    result: DnsCommandResult,
    diagnostics: Vec<crate::core::Diagnostic>,
    stats: crate::client::OperationStats,
) -> Result<(), CliError> {
    write_stdout_line(format_args!(
        "server={}:{} resolved={} query={} type={} id={} transport={} outcome={}",
        result.server,
        result.server_port,
        result
            .resolved_addresses
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(","),
        result.query_name,
        result.query_type,
        result.transaction_id,
        result.transport,
        dns_outcome_name(result.outcome),
    ))?;
    for attempt in &result.attempts {
        write_stdout_line(format_args!(
            "attempt={} server={} source_port={} status={} sent={} received={} latency={} rcode={} reason={}",
            attempt.attempt,
            attempt.server_address,
            attempt.source_port,
            dns_attempt_status_name(attempt.status),
            output_timestamp_text(attempt.sent_at),
            attempt
                .received_at
                .map(output_timestamp_text)
                .unwrap_or_else(|| "none".to_owned()),
            attempt
                .latency
                .map(|value| format!("{value:?}"))
                .unwrap_or_else(|| "none".to_owned()),
            attempt
                .response_code
                .map(|value| value.to_string())
                .unwrap_or_else(|| "none".to_owned()),
            attempt.reason,
        ))?;
        if let Some(frame) = &attempt.frame {
            write_stdout_line(format_args!(
                "  frame dlt={} caplen={} wirelen={} {}",
                frame.link_type,
                frame.captured_length,
                frame.original_length,
                spaced_hex(frame.bytes())
            ))?;
        }
    }
    for (section, records) in [
        (DnsSection::Answer, &result.answers),
        (DnsSection::Authority, &result.authorities),
        (DnsSection::Additional, &result.additionals),
    ] {
        for record in records {
            render_dns_record_text(section, record)?;
        }
    }
    for record in &result.rejected_records {
        write_stdout_line(format_args!(
            "rejected section={} index={} owner={} type_code={} reason={}",
            dns_section_name(record.section),
            record.index,
            record.owner,
            record.type_code,
            record.reason,
        ))?;
    }
    for evidence in &result.undecoded {
        write_stdout_line(format_args!(
            "undecoded attempt={} dlt={} caplen={} wirelen={} {}",
            evidence.attempt,
            evidence.frame.link_type,
            evidence.frame.captured_length,
            evidence.frame.original_length,
            spaced_hex(evidence.frame.bytes())
        ))?;
    }
    write_stdout_line(format_args!(
        "dns response_code={} response_name={} authoritative={} truncated={} accepted={} rejected={} queries={} bytes={}",
        result
            .response_code
            .map(|value| value.to_string())
            .unwrap_or_else(|| "none".to_owned()),
        result.response_code_name.as_deref().unwrap_or("none"),
        result
            .authoritative
            .map(|value| value.to_string())
            .unwrap_or_else(|| "none".to_owned()),
        result
            .truncated
            .map(|value| value.to_string())
            .unwrap_or_else(|| "none".to_owned()),
        result.answers.len() + result.authorities.len() + result.additionals.len(),
        result.rejected_record_count,
        stats.packets_completed,
        stats.bytes,
    ))?;
    render_diagnostics_text(&diagnostics)
}

fn render_dns_record_text(section: DnsSection, record: &DnsRecordOutput) -> Result<(), CliError> {
    let data = serde_json::to_string(&record.data)
        .map_err(|error| CliError::new(4, format!("DNS output serialization failed: {error}")))?;
    write_stdout_line(format_args!(
        "record section={} owner={} class={} ttl={} data={}",
        dns_section_name(section),
        record.owner,
        record.class,
        record.ttl,
        data,
    ))
}

fn render_dns_stream(
    result: DnsCommandResult,
    diagnostics: Vec<crate::core::Diagnostic>,
    stats: crate::client::OperationStats,
) -> Result<(), CliError> {
    let DnsCommandResult {
        server,
        server_port,
        resolved_addresses,
        query_name,
        query_type,
        transaction_id,
        transport,
        outcome,
        response_code,
        response_code_name,
        authoritative,
        truncated,
        recursion_desired,
        recursion_available,
        authenticated_data,
        checking_disabled,
        answers,
        authorities,
        additionals,
        rejected_records,
        rejected_record_count,
        attempts,
        undecoded,
    } = result;
    let mut sequence = 0_u64;
    for evidence in attempts {
        emit_dns_record(
            &mut sequence,
            DnsStreamCommandResult::Attempt {
                server: server.clone(),
                server_port,
                query_name: query_name.clone(),
                query_type: query_type.clone(),
                evidence,
            },
        )?;
    }
    for (section, records) in [
        (DnsSection::Answer, answers),
        (DnsSection::Authority, authorities),
        (DnsSection::Additional, additionals),
    ] {
        for record in records {
            emit_dns_record(
                &mut sequence,
                DnsStreamCommandResult::Record {
                    server: server.clone(),
                    server_port,
                    query_name: query_name.clone(),
                    query_type: query_type.clone(),
                    section,
                    record,
                },
            )?;
        }
    }
    for record in rejected_records {
        emit_dns_record(
            &mut sequence,
            DnsStreamCommandResult::Rejected {
                server: server.clone(),
                server_port,
                query_name: query_name.clone(),
                query_type: query_type.clone(),
                record,
            },
        )?;
    }
    for evidence in undecoded {
        emit_dns_record(
            &mut sequence,
            DnsStreamCommandResult::Undecoded { evidence },
        )?;
    }
    emit_json_compact(
        &StreamRecord::success(
            CommandName::Dns,
            sequence,
            DnsStreamCommandResult::Complete {
                server,
                server_port,
                resolved_addresses,
                query_name,
                query_type,
                transaction_id,
                transport,
                outcome,
                response_code,
                response_code_name,
                authoritative,
                truncated,
                recursion_desired,
                recursion_available,
                authenticated_data,
                checking_disabled,
                rejected_record_count,
            },
            diagnostics,
        )
        .with_stats(stats),
    )
    .map_err(|error| error.at_sequence(sequence))
}

fn emit_dns_record(sequence: &mut u64, result: DnsStreamCommandResult) -> Result<(), CliError> {
    emit_json_compact(&StreamRecord::success(
        CommandName::Dns,
        *sequence,
        result,
        Vec::new(),
    ))
    .map_err(|error| error.at_sequence(*sequence))?;
    *sequence = sequence.checked_add(1).ok_or_else(|| {
        CliError::classified(OutputContractError::SequenceOverflow).at_sequence(*sequence)
    })?;
    Ok(())
}

fn dns_attempt_status_name(value: DnsAttemptStatus) -> &'static str {
    match value {
        DnsAttemptStatus::Response => "response",
        DnsAttemptStatus::Truncated => "truncated",
        DnsAttemptStatus::Timeout => "timeout",
        DnsAttemptStatus::Unrelated => "unrelated",
        DnsAttemptStatus::DecodeFailure => "decode_failure",
        DnsAttemptStatus::NetworkFailure => "network_failure",
    }
}

fn dns_outcome_name(value: DnsOutcome) -> &'static str {
    match value {
        DnsOutcome::Response => "response",
        DnsOutcome::Truncated => "truncated",
        DnsOutcome::Timeout => "timeout",
        DnsOutcome::Unrelated => "unrelated",
        DnsOutcome::DecodeFailure => "decode_failure",
        DnsOutcome::NetworkFailure => "network_failure",
    }
}

fn dns_section_name(value: DnsSection) -> &'static str {
    match value {
        DnsSection::Answer => "answer",
        DnsSection::Authority => "authority",
        DnsSection::Additional => "additional",
    }
}

fn run_fuzz(arguments: FuzzArgs, output: OutputFormat) -> Result<(), CliError> {
    let FuzzArgs {
        recipe,
        seed,
        first_case,
        cases,
        strategies,
        fields,
        mode,
        live,
        allow_malformed_live,
        destination,
        timeout_ms,
        rate,
        max_cases,
        max_total_bytes,
        max_field_bytes,
        max_list_items,
        max_shrink_steps,
        max_duration_ms,
        interface,
        source,
        link_mode,
        limits,
        policy,
    } = arguments;
    let registry = default_registry_arc()?;
    let packet = read_recipe(recipe, &registry)?;
    let targets = fields
        .into_iter()
        .map(|field| {
            field
                .parse::<FuzzTarget>()
                .map_err(|source| CliError::new(2, source.to_string()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let queue_limits = limits.into_limits();
    let build_mode = match mode {
        CliBuildMode::Strict => BuildMode::Strict,
        CliBuildMode::Permissive => BuildMode::Permissive,
    };
    let request = FuzzRequest {
        seed,
        first_case,
        cases,
        strategies: strategies.into_iter().map(Into::into).collect(),
        targets,
        build: BuildOptions {
            mode: build_mode,
            max_packet_size: queue_limits.snap_length,
            ..BuildOptions::default()
        },
        limits: FuzzLimits {
            max_cases,
            max_packet_bytes: queue_limits.snap_length,
            max_total_bytes,
            max_field_bytes,
            max_list_items,
            max_shrink_steps,
            max_evidence_frames: queue_limits.max_frames,
            max_evidence_bytes: queue_limits.max_bytes,
            max_duration: Duration::from_millis(max_duration_ms),
        },
    };
    request.validate().map_err(fuzz_cli_error)?;

    let result = if live {
        let policy = policy.into_policy();
        policy.validate().map_err(CliError::classified)?;
        validate_live_interface_selector("fuzz", interface.as_deref())?;
        let mut exchange = ExchangeOptions {
            send: SendOptions {
                destination,
                plan: crate::io::PlanOptions {
                    link_mode: link_mode.into(),
                    interface: None,
                    preferred_source: source,
                },
                build: request.build.clone(),
                allow_permissive_live: allow_malformed_live,
            },
            timeout: Duration::from_millis(timeout_ms),
            max_template_packets: 1,
            max_unsolicited: queue_limits.max_frames,
            max_responses: queue_limits.max_frames,
            max_capture_queue_frames: queue_limits.max_frames,
            max_captured_bytes: queue_limits.max_bytes,
            capture_overflow_policy: queue_limits.overflow_policy,
            decode: DecodeOptions::default(),
        };
        exchange.decode.max_packet_size = queue_limits.snap_length;
        exchange.validate().map_err(CliError::classified)?;
        let mut executor = CliFuzzExecutor {
            registry: Arc::clone(&registry),
            policy: policy.clone(),
            exchange,
            interface,
            interface_resolved: false,
        };
        let mut authorizer = TrafficPolicyFuzzAuthorizer::new(&policy);
        let mut clock = SystemFuzzClock;
        fuzz_live(
            &request,
            FuzzLiveOptions {
                timeout: Duration::from_millis(timeout_ms),
                cases_per_second: rate,
                destination,
                allow_malformed_live,
            },
            packet,
            registry,
            &mut authorizer,
            &mut executor,
            &mut clock,
        )
        .map_err(fuzz_cli_error)?
    } else {
        // This branch intentionally never validates or resolves the live
        // interface and never constructs a native client.
        fuzz(&request, packet, registry).map_err(fuzz_cli_error)?
    };
    let (result, diagnostics, stats) =
        FuzzCommandResult::try_from_fuzz(result).map_err(CliError::classified)?;
    match output {
        OutputFormat::Text => render_fuzz_text(result, diagnostics, stats),
        OutputFormat::Json => emit_json(
            &AggregateOutput::success(CommandName::Fuzz, result, diagnostics).with_stats(stats),
        ),
        OutputFormat::Ndjson => render_fuzz_stream(result, diagnostics, stats),
        _ => Err(CliError::classified(
            OutputContractError::UnsupportedFormat {
                command: CommandName::Fuzz,
                format: output,
            },
        )),
    }
}

struct CliFuzzExecutor {
    registry: Arc<crate::core::ProtocolRegistry>,
    policy: TrafficPolicy,
    exchange: ExchangeOptions,
    interface: Option<String>,
    interface_resolved: bool,
}

impl FuzzExecutor for CliFuzzExecutor {
    fn execute(
        &mut self,
        case: &FuzzExecutionCase,
        timeout: Duration,
    ) -> Result<FuzzCaseExecution, FuzzExecutionError> {
        if !self.interface_resolved {
            self.exchange.send.plan.interface =
                resolve_interface(self.interface.take(), &SystemInterfaceProvider)
                    .map_err(fuzz_execution_error_from_cli)?;
            self.interface_resolved = true;
        }
        let client = system_client(Arc::clone(&self.registry), self.policy.clone());
        ClientFuzzExecutor::new(&client, self.exchange.clone()).execute(case, timeout)
    }
}

fn fuzz_execution_error_from_cli(error: CliError) -> FuzzExecutionError {
    FuzzExecutionError::new(error.message, error.classification, error.causes)
}

fn fuzz_cli_error(error: FuzzError) -> CliError {
    let sequence = error.sequence();
    let mut error = CliError::classified(error);
    if let Some(sequence) = sequence {
        error = error.at_sequence(sequence);
    }
    error
}

fn render_fuzz_text(
    result: FuzzCommandResult,
    diagnostics: Vec<crate::core::Diagnostic>,
    stats: crate::client::OperationStats,
) -> Result<(), CliError> {
    write_stdout_line(format_args!(
        "mode={} seed={} first_case={} generated={} built={} rejected={}",
        fuzz_mode_name(result.mode),
        result.seed,
        result.first_case,
        result.cases_generated,
        result.cases_built,
        result.cases_rejected,
    ))?;
    for case in &result.cases {
        write_stdout_line(format_args!(
            "case={} seed={} strategy={} target={}.{} outcome={} length={} reproduce=--seed {} --first-case {} --cases 1",
            case.index,
            case.seed,
            case.mutation.strategy,
            case.mutation.layer,
            case.mutation.field,
            fuzz_outcome_name(case.outcome),
            case.frame.as_ref().map(|frame| frame.length).unwrap_or(0),
            case.reproduction.operation_seed,
            case.reproduction.case_index,
        ))?;
        let original = serde_json::to_string(&case.mutation.original).map_err(|source| {
            CliError::new(70, format!("serialize fuzz mutation failed: {source}"))
        })?;
        let value = serde_json::to_string(&case.mutation.value).map_err(|source| {
            CliError::new(70, format!("serialize fuzz mutation failed: {source}"))
        })?;
        write_stdout_line(format_args!("  original={original} value={value}"))?;
        if let Some(frame) = &case.frame {
            write_stdout_line(format_args!("  frame {}", spaced_hex(frame.bytes())))?;
        }
        if let Some(error) = &case.error {
            write_stdout_line(format_args!(
                "  error kind={} code={} message={}",
                error.kind.as_str(),
                error.code,
                error.message,
            ))?;
        }
        if let Some(sent) = &case.sent {
            write_stdout_line(format_args!(
                "  sent dlt={} caplen={} wirelen={} {}",
                sent.link_type,
                sent.captured_length,
                sent.original_length,
                spaced_hex(sent.bytes())
            ))?;
        }
        for (kind, frames) in [
            ("response", &case.responses),
            ("unmatched", &case.unmatched),
            ("undecoded", &case.undecoded),
        ] {
            for frame in frames {
                write_stdout_line(format_args!(
                    "  {kind} dlt={} caplen={} wirelen={} {}",
                    frame.link_type,
                    frame.captured_length,
                    frame.original_length,
                    spaced_hex(frame.bytes())
                ))?;
            }
        }
        render_diagnostics_text(&case.diagnostics)?;
    }
    write_stdout_line(format_args!(
        "fuzz completed {} case(s), {} packet operation(s), {} byte(s)",
        result.cases_generated, stats.packets_completed, stats.bytes
    ))?;
    render_diagnostics_text(&diagnostics)
}

fn render_fuzz_stream(
    result: FuzzCommandResult,
    diagnostics: Vec<crate::core::Diagnostic>,
    stats: crate::client::OperationStats,
) -> Result<(), CliError> {
    let FuzzCommandResult {
        seed,
        first_case,
        mode,
        cases_generated,
        cases_built,
        cases_rejected,
        cases,
    } = result;
    let mut sequence = 0_u64;
    for case in cases {
        emit_fuzz_record(
            &mut sequence,
            FuzzStreamCommandResult::Case {
                operation_seed: seed,
                case: Box::new(case),
            },
        )?;
    }
    emit_json_compact(
        &StreamRecord::success(
            CommandName::Fuzz,
            sequence,
            FuzzStreamCommandResult::Complete {
                operation_seed: seed,
                first_case,
                mode,
                cases_generated,
                cases_built,
                cases_rejected,
            },
            diagnostics,
        )
        .with_stats(stats),
    )
    .map_err(|error| error.at_sequence(sequence))
}

fn emit_fuzz_record(sequence: &mut u64, result: FuzzStreamCommandResult) -> Result<(), CliError> {
    emit_json_compact(&StreamRecord::success(
        CommandName::Fuzz,
        *sequence,
        result,
        Vec::new(),
    ))
    .map_err(|error| error.at_sequence(*sequence))?;
    *sequence = sequence.checked_add(1).ok_or_else(|| {
        CliError::classified(OutputContractError::SequenceOverflow).at_sequence(*sequence)
    })?;
    Ok(())
}

fn fuzz_mode_name(value: FuzzMode) -> &'static str {
    match value {
        FuzzMode::Offline => "offline",
        FuzzMode::Live => "live",
    }
}

fn fuzz_outcome_name(value: FuzzCaseOutcome) -> &'static str {
    match value {
        FuzzCaseOutcome::Built => "built",
        FuzzCaseOutcome::Rejected => "rejected",
        FuzzCaseOutcome::Sent => "sent",
        FuzzCaseOutcome::Response => "response",
        FuzzCaseOutcome::Timeout => "timeout",
        FuzzCaseOutcome::Error => "error",
    }
}

fn run_traceroute(arguments: TracerouteArgs, output: OutputFormat) -> Result<(), CliError> {
    let TracerouteArgs {
        target,
        strategy,
        family,
        port,
        first_hop,
        max_hops,
        attempts,
        timeout_ms,
        rate,
        max_probes,
        max_duration_ms,
        max_undecoded,
        interface,
        source,
        link_mode,
        limits,
        policy,
    } = arguments;
    let target = match target.parse::<LiveTarget>().map_err(CliError::classified)? {
        LiveTarget::Address(address) => ScanTarget::Address(address),
        LiveTarget::Hostname(hostname) => ScanTarget::Hostname(hostname.to_string()),
    };
    let strategy: TracerouteStrategy = strategy.into();
    let destination_port = match strategy {
        TracerouteStrategy::Udp => Some(port.unwrap_or(crate::tools::DEFAULT_TRACEROUTE_UDP_PORT)),
        TracerouteStrategy::Tcp => Some(port.unwrap_or(crate::tools::DEFAULT_TRACEROUTE_TCP_PORT)),
        TracerouteStrategy::Icmp => port,
    };
    let queue_limits = limits.into_limits();
    let trace_limits = TracerouteLimits {
        max_probes,
        max_duration: Duration::from_millis(max_duration_ms),
        max_evidence_frames: queue_limits.max_frames,
        max_evidence_bytes: queue_limits.max_bytes,
        max_undecoded,
    };
    let request = TracerouteRequest {
        target,
        strategy,
        address_family: family.into(),
        destination_port,
        first_hop,
        max_hops,
        probes_per_hop: attempts,
        timeout: Duration::from_millis(timeout_ms),
        probes_per_second: rate,
        limits: trace_limits,
    };
    request.validate().map_err(traceroute_cli_error)?;
    let policy = policy.into_policy();
    policy.validate().map_err(CliError::classified)?;
    validate_live_interface_selector("traceroute", interface.as_deref())?;

    let registry = default_registry_arc()?;
    let mut exchange = ExchangeOptions {
        send: SendOptions {
            destination: None,
            plan: crate::io::PlanOptions {
                link_mode: link_mode.into(),
                interface: None,
                preferred_source: source,
            },
            build: BuildOptions::default(),
            allow_permissive_live: false,
        },
        timeout: request.timeout,
        max_template_packets: attempts as usize,
        max_unsolicited: queue_limits.max_frames,
        max_responses: queue_limits.max_frames,
        max_capture_queue_frames: queue_limits.max_frames,
        max_captured_bytes: queue_limits.max_bytes,
        capture_overflow_policy: queue_limits.overflow_policy,
        decode: DecodeOptions::default(),
    };
    exchange.decode.max_packet_size = queue_limits.snap_length;
    exchange.validate().map_err(CliError::classified)?;

    let mut executor = CliTracerouteExecutor {
        registry: Arc::clone(&registry),
        policy: policy.clone(),
        exchange,
        interface,
        interface_resolved: false,
    };
    let resolver = SystemHostnameResolver;
    let mut authorizer = TrafficPolicyTracerouteAuthorizer::new(&policy, &resolver);
    let mut clock = SystemTracerouteClock;
    let result = traceroute(
        &request,
        &mut authorizer,
        &registry,
        &mut executor,
        &mut clock,
    )
    .map_err(traceroute_cli_error)?;
    let (result, diagnostics, stats) =
        TracerouteCommandResult::try_from_traceroute(result).map_err(CliError::classified)?;

    match output {
        OutputFormat::Text => render_traceroute_text(result, diagnostics, stats),
        OutputFormat::Json => emit_json(
            &AggregateOutput::success(CommandName::Traceroute, result, diagnostics)
                .with_stats(stats),
        ),
        OutputFormat::Ndjson => render_traceroute_stream(result, diagnostics, stats),
        _ => Err(CliError::classified(
            OutputContractError::UnsupportedFormat {
                command: CommandName::Traceroute,
                format: output,
            },
        )),
    }
}

struct CliTracerouteExecutor {
    registry: Arc<crate::core::ProtocolRegistry>,
    policy: TrafficPolicy,
    exchange: ExchangeOptions,
    interface: Option<String>,
    interface_resolved: bool,
}

impl TracerouteExecutor for CliTracerouteExecutor {
    fn execute(
        &mut self,
        batch: &TracerouteBatch,
    ) -> Result<TracerouteBatchExecution, TracerouteExecutionError> {
        if !self.interface_resolved {
            self.exchange.send.plan.interface =
                resolve_interface(self.interface.take(), &SystemInterfaceProvider)
                    .map_err(traceroute_execution_error_from_cli)?;
            self.interface_resolved = true;
        }
        let client = system_client(Arc::clone(&self.registry), self.policy.clone());
        ClientTracerouteExecutor::new(&client, self.exchange.clone()).execute(batch)
    }
}

fn traceroute_execution_error_from_cli(error: CliError) -> TracerouteExecutionError {
    TracerouteExecutionError::new(error.message, error.classification, error.causes)
}

fn traceroute_cli_error(error: TracerouteError) -> CliError {
    let sequence = error.sequence();
    let mut error = CliError::classified(error);
    if let Some(sequence) = sequence {
        error = error.at_sequence(sequence);
    }
    error
}

fn render_traceroute_text(
    result: TracerouteCommandResult,
    diagnostics: Vec<crate::core::Diagnostic>,
    stats: crate::client::OperationStats,
) -> Result<(), CliError> {
    write_stdout_line(format_args!(
        "target={} resolved={} destination={} strategy={} port={}",
        result.target,
        result
            .resolved_addresses
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(","),
        result.destination,
        result.strategy,
        result
            .destination_port
            .map(|value| value.to_string())
            .unwrap_or_else(|| "none".to_owned()),
    ))?;
    for hop in &result.hops {
        write_stdout_line(format_args!("hop={}", hop.hop_limit))?;
        for probe in &hop.probes {
            write_stdout_line(format_args!(
                "  sequence={} attempt={} status={} response={} sent={} received={} responder={} latency={} port={} reason={}",
                probe.sequence,
                probe.attempt,
                trace_probe_status_name(probe.status),
                probe
                    .response_kind
                    .map(trace_response_kind_name)
                    .unwrap_or("none"),
                output_timestamp_text(probe.sent_at),
                probe
                    .received_at
                    .map(output_timestamp_text)
                    .unwrap_or_else(|| "none".to_owned()),
                probe
                    .responder
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "none".to_owned()),
                probe
                    .latency
                    .map(|value| format!("{value:?}"))
                    .unwrap_or_else(|| "none".to_owned()),
                probe
                    .destination_port
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "none".to_owned()),
                probe.reason,
            ))?;
            if let Some(frame) = &probe.frame {
                write_stdout_line(format_args!(
                    "    frame dlt={} caplen={} wirelen={} {}",
                    frame.link_type,
                    frame.captured_length,
                    frame.original_length,
                    spaced_hex(frame.bytes())
                ))?;
            }
        }
    }
    for evidence in &result.undecoded {
        write_stdout_line(format_args!(
            "undecoded hop={} dlt={} caplen={} wirelen={} {}",
            evidence.hop_limit,
            evidence.frame.link_type,
            evidence.frame.captured_length,
            evidence.frame.original_length,
            spaced_hex(evidence.frame.bytes())
        ))?;
    }
    write_stdout_line(format_args!(
        "trace completion={} hops={} probes={} bytes={}",
        trace_completion_name(result.completion),
        result.hops.len(),
        stats.packets_completed,
        stats.bytes
    ))?;
    render_diagnostics_text(&diagnostics)
}

fn trace_probe_status_name(value: TraceProbeStatus) -> &'static str {
    match value {
        TraceProbeStatus::Response => "response",
        TraceProbeStatus::Timeout => "timeout",
    }
}

fn trace_response_kind_name(value: TraceResponseKind) -> &'static str {
    match value {
        TraceResponseKind::Intermediate => "intermediate",
        TraceResponseKind::DestinationReached => "destination_reached",
        TraceResponseKind::Unreachable => "unreachable",
    }
}

fn trace_completion_name(value: TraceCompletionReason) -> &'static str {
    match value {
        TraceCompletionReason::DestinationReached => "destination_reached",
        TraceCompletionReason::Unreachable => "unreachable",
        TraceCompletionReason::MaximumHops => "maximum_hops",
        TraceCompletionReason::Timeout => "timeout",
    }
}

fn render_traceroute_stream(
    result: TracerouteCommandResult,
    diagnostics: Vec<crate::core::Diagnostic>,
    stats: crate::client::OperationStats,
) -> Result<(), CliError> {
    let TracerouteCommandResult {
        target,
        resolved_addresses,
        destination,
        strategy,
        destination_port,
        hops,
        undecoded,
        completion,
    } = result;
    let mut sequence = 0_u64;
    for hop in hops {
        emit_traceroute_record(
            &mut sequence,
            TracerouteStreamCommandResult::Hop {
                target: target.clone(),
                destination,
                hop,
            },
        )?;
    }
    for evidence in undecoded {
        emit_traceroute_record(
            &mut sequence,
            TracerouteStreamCommandResult::Undecoded {
                hop_limit: evidence.hop_limit,
                frame: evidence.frame,
            },
        )?;
    }
    emit_json_compact(
        &StreamRecord::success(
            CommandName::Traceroute,
            sequence,
            TracerouteStreamCommandResult::Complete {
                target,
                resolved_addresses,
                destination,
                strategy,
                destination_port,
                completion,
            },
            diagnostics,
        )
        .with_stats(stats),
    )
    .map_err(|error| error.at_sequence(sequence))
}

fn emit_traceroute_record(
    sequence: &mut u64,
    result: TracerouteStreamCommandResult,
) -> Result<(), CliError> {
    emit_json_compact(&StreamRecord::success(
        CommandName::Traceroute,
        *sequence,
        result,
        Vec::new(),
    ))
    .map_err(|error| error.at_sequence(*sequence))?;
    *sequence = sequence.checked_add(1).ok_or_else(|| {
        CliError::classified(OutputContractError::SequenceOverflow).at_sequence(*sequence)
    })?;
    Ok(())
}

fn capture_file_format(output: OutputFormat) -> Result<CaptureFileFormat, CliError> {
    match output {
        OutputFormat::Pcap => Ok(CaptureFileFormat::Pcap),
        OutputFormat::Pcapng => Ok(CaptureFileFormat::PcapNg),
        _ => Err(CliError::new(
            70,
            "capture-file renderer received a non-capture format",
        )),
    }
}

fn capture_file_frame(mut frame: CapturedFrame, format: CaptureFileFormat) -> CapturedFrame {
    match format {
        CaptureFileFormat::Pcap => frame.interface = None,
        CaptureFileFormat::PcapNg => frame.interface = Some(0),
    }
    frame
}

fn write_capture_file(
    output: OutputFormat,
    frames: impl IntoIterator<Item = CapturedFrame>,
) -> Result<(), CliError> {
    write_raw(&encode_capture_file(output, frames)?)
}

fn encode_capture_file(
    output: OutputFormat,
    frames: impl IntoIterator<Item = CapturedFrame>,
) -> Result<Vec<u8>, CliError> {
    let format = capture_file_format(output)?;
    let mut frames = frames.into_iter();
    let first = frames.next().ok_or_else(|| {
        CliError::new(
            2,
            "capture-file output requires at least one captured or transmitted frame",
        )
    })?;
    if format == CaptureFileFormat::Pcap {
        let mut writer =
            CaptureWriter::new(Vec::new(), format, first.link_type).map_err(|source| {
                CliError::new(5, format!("initialize capture output failed: {source}"))
            })?;
        writer
            .write_frame(&capture_file_frame(first, format))
            .map_err(|source| CliError::new(5, format!("write capture output failed: {source}")))?;
        for frame in frames {
            writer
                .write_frame(&capture_file_frame(frame, format))
                .map_err(|source| {
                    CliError::new(5, format!("write capture output failed: {source}"))
                })?;
        }
        return Ok(writer.into_inner());
    }

    let mut writer = CaptureWriter::pcapng(Vec::new()).map_err(|source| {
        CliError::new(5, format!("initialize capture output failed: {source}"))
    })?;
    let mut interfaces = Vec::<(LinkType, u32)>::new();
    for mut frame in std::iter::once(first).chain(frames) {
        let interface = match interfaces
            .iter()
            .find(|(link_type, _)| *link_type == frame.link_type)
        {
            Some((_, interface)) => *interface,
            None => {
                let interface = writer.add_interface(frame.link_type).map_err(|source| {
                    CliError::new(5, format!("initialize capture interface failed: {source}"))
                })?;
                interfaces.push((frame.link_type, interface));
                interface
            }
        };
        frame.interface = Some(interface);
        writer
            .write_frame(&frame)
            .map_err(|source| CliError::new(5, format!("write capture output failed: {source}")))?;
    }
    Ok(writer.into_inner())
}

fn run_build(arguments: BuildArgs, output: OutputFormat) -> Result<(), CliError> {
    let registry = Arc::new(crate::protocols::default_registry().map_err(|source| {
        CliError::new(70, format!("built-in registry invariant failed: {source}"))
    })?);
    let packet = read_recipe(arguments.recipe, &registry)?;
    let built = Builder::new(registry)
        .build(
            packet,
            BuildContext::default(),
            BuildOptions {
                mode: match arguments.mode {
                    CliBuildMode::Strict => BuildMode::Strict,
                    CliBuildMode::Permissive => BuildMode::Permissive,
                },
                ..BuildOptions::default()
            },
        )
        .map_err(|source| CliError::new(3, source.to_string()))?;
    let (result, diagnostics) = BuildCommandResult::from_built(built);
    match output {
        OutputFormat::Text => {
            write_stdout_line(format_args!("built {} bytes", result.length))?;
            write_stdout_line(format_args!("{}", spaced_hex(result.bytes())))?;
            for diagnostic in &diagnostics {
                write_stdout_line(format_args!(
                    "{:?} {}: {}",
                    diagnostic.severity, diagnostic.code, diagnostic.message
                ))?;
            }
            Ok(())
        }
        OutputFormat::Hex => write_stdout_line(format_args!("{}", result.bytes_hex)),
        OutputFormat::Raw => write_raw(result.bytes()),
        OutputFormat::Json => emit_json(&AggregateOutput::success(
            CommandName::Build,
            result,
            diagnostics,
        )),
        _ => Err(CliError::classified(
            OutputContractError::UnsupportedFormat {
                command: CommandName::Build,
                format: output,
            },
        )),
    }
}

fn run_dissect(arguments: DissectArgs, output: OutputFormat) -> Result<(), CliError> {
    let bytes = match (arguments.hex, arguments.file) {
        (Some(value), None) => crate::core::decode_hex(&value)
            .map_err(|source| CliError::new(2, source.to_string()))?
            .to_vec(),
        (None, Some(path)) => read_bounded_file(&path, DEFAULT_MAX_DOCUMENT_BYTES)?,
        (None, None) => read_stdin_bounded(DEFAULT_MAX_DOCUMENT_BYTES)?,
        (Some(_), Some(_)) => unreachable!("clap enforces conflicts"),
    };
    let registry = Arc::new(crate::protocols::default_registry().map_err(|source| {
        CliError::new(70, format!("built-in registry invariant failed: {source}"))
    })?);
    let decoded = Dissector::new(registry)
        .decode(
            CapturedFrame::new(SystemTime::now(), LinkType(arguments.link_type), bytes)
                .map_err(|source| CliError::new(3, source.to_string()))?,
            DecodeOptions::default(),
        )
        .map_err(|source| CliError::new(3, source.to_string()))?;
    let (result, diagnostics) = DissectCommandResult::from_decoded(decoded);
    match output {
        OutputFormat::Text => {
            write_stdout_line(format_args!(
                "decoded {} bytes into {} layer(s)",
                result.length,
                result.packet.layers.len()
            ))?;
            for (index, layer) in result.packet.layers.iter().enumerate() {
                write_stdout_line(format_args!("{index}: {}", layer.protocol))?;
            }
            for diagnostic in &diagnostics {
                write_stdout_line(format_args!(
                    "{:?} {}: {}",
                    diagnostic.severity, diagnostic.code, diagnostic.message
                ))?;
            }
            Ok(())
        }
        OutputFormat::Hex => write_stdout_line(format_args!("{}", result.bytes_hex)),
        OutputFormat::Raw => write_raw(result.bytes()),
        OutputFormat::Json => emit_json(&AggregateOutput::success(
            CommandName::Dissect,
            result,
            diagnostics,
        )),
        _ => Err(CliError::classified(
            OutputContractError::UnsupportedFormat {
                command: CommandName::Dissect,
                format: output,
            },
        )),
    }
}

fn run_read(arguments: ReadArgs, output: OutputFormat) -> Result<(), CliError> {
    let ReadArgs {
        path,
        max_frames,
        max_bytes,
        max_frame_bytes,
        max_interfaces,
    } = arguments;
    validate_capture_stream_limits(max_frames, max_bytes, max_frame_bytes, max_interfaces)?;
    let file = File::open(&path)
        .map_err(|source| CliError::new(5, format!("open {} failed: {source}", path.display())))?;
    let mut reader = CaptureReader::with_limits(file, max_frame_bytes, max_interfaces)
        .map_err(CliError::classified)?;
    let stream_limits = CaptureStreamLimits {
        max_frames,
        max_bytes,
    };
    if matches!(output, OutputFormat::Pcap | OutputFormat::Pcapng) {
        let format = capture_file_format(output)?;
        let stdout = io::stdout();
        let (_output, _report) =
            transcode_capture(&mut reader, stdout.lock(), format, stream_limits)
                .map_err(CliError::classified)?;
        return Ok(());
    }

    let mut sequence = 0_u64;
    let mut captured_bytes = 0_u64;
    loop {
        let Some(frame) = reader
            .next_frame()
            .map_err(|source| CliError::classified(source).at_sequence(sequence))?
        else {
            return Ok(());
        };
        let next_sequence = sequence.checked_add(1).ok_or_else(|| {
            CliError::classified(OutputContractError::SequenceOverflow).at_sequence(sequence)
        })?;
        if next_sequence > max_frames {
            return Err(
                CliError::classified(crate::io::CaptureError::FrameLimitExceeded {
                    actual: next_sequence,
                    limit: max_frames,
                })
                .at_sequence(sequence),
            );
        }
        let next_bytes = captured_bytes
            .checked_add(u64::from(frame.captured_length))
            .ok_or_else(|| {
                CliError::classified(crate::io::CaptureError::StreamByteLimitExceeded {
                    actual: u64::MAX,
                    limit: max_bytes,
                })
                .at_sequence(sequence)
            })?;
        if next_bytes > max_bytes {
            return Err(
                CliError::classified(crate::io::CaptureError::StreamByteLimitExceeded {
                    actual: next_bytes,
                    limit: max_bytes,
                })
                .at_sequence(sequence),
            );
        }
        let result = ReadFrameCommandResult::try_from_frame(frame)
            .map_err(|source| CliError::classified(source).at_sequence(sequence))?;
        match output {
            OutputFormat::Text => write_stdout_line(format_args!(
                "{sequence}: dlt={} caplen={} wirelen={} {}",
                result.frame.link_type,
                result.frame.captured_length,
                result.frame.original_length,
                spaced_hex(result.frame.bytes())
            ))?,
            OutputFormat::Hex => write_stdout_line(format_args!("{}", result.frame.bytes_hex))?,
            OutputFormat::Ndjson => emit_json_compact(&StreamRecord::success(
                CommandName::Read,
                sequence,
                result,
                Vec::new(),
            ))
            .map_err(|error| error.at_sequence(sequence))?,
            _ => {
                return Err(CliError::classified(
                    OutputContractError::UnsupportedFormat {
                        command: CommandName::Read,
                        format: output,
                    },
                ))
            }
        }
        sequence = next_sequence;
        captured_bytes = next_bytes;
    }
}

fn validate_capture_stream_limits(
    max_frames: u64,
    max_bytes: u64,
    max_frame_bytes: usize,
    max_interfaces: usize,
) -> Result<(), CliError> {
    if max_frames == 0 || max_bytes == 0 || max_frame_bytes == 0 || max_interfaces == 0 {
        return Err(CliError::from_classification(
            ErrorClassification::new(
                "cli.capture_limit",
                FailureKind::Cli,
                Some("use finite non-zero capture frame, byte, packet, and interface limits"),
            ),
            "capture stream limits must be non-zero",
            Vec::new(),
        ));
    }
    if max_frame_bytes as u64 > max_bytes {
        return Err(CliError::from_classification(
            ErrorClassification::new(
                "cli.capture_limit",
                FailureKind::Cli,
                Some("set max-frame-bytes no higher than the aggregate max-bytes budget"),
            ),
            format!("max-frame-bytes {max_frame_bytes} exceeds max-bytes {max_bytes}"),
            Vec::new(),
        ));
    }
    Ok(())
}

struct CliReplayAuthorizer {
    policy: TrafficPolicy,
    registry: Arc<crate::core::ProtocolRegistry>,
    allow_malformed_live: bool,
}

impl ReplayAuthorizer for CliReplayAuthorizer {
    fn authorize(
        &mut self,
        frame: &CapturedFrame,
        _mode: LinkMode,
    ) -> Result<(), ReplayAuthorizationError> {
        if frame.captured_length != frame.original_length {
            return Err(ReplayAuthorizationError::new(
                format!(
                    "captured frame contains {} of {} original wire bytes",
                    frame.captured_length, frame.original_length
                ),
                ErrorClassification::new(
                    "packet.replay_truncated",
                    FailureKind::Packet,
                    Some("replay only complete captured frames whose captured and original lengths match"),
                ),
                Vec::new(),
            ));
        }
        let (wire_destinations, unsupported_routing) = replay_wire_policy(frame);
        for destination in wire_destinations {
            self.policy
                .authorize_destination(destination)
                .map_err(|source| {
                    ReplayAuthorizationError::new(
                        source.to_string(),
                        source.classification(),
                        source.causes(),
                    )
                })?;
        }
        if unsupported_routing {
            return Err(ReplayAuthorizationError::new(
                "captured IPv6 packet uses an unsupported routing header",
                ErrorClassification::new(
                    "capability.replay_routing_header",
                    FailureKind::Capability,
                    Some("replay only typed RFC 8754 Segment Routing Headers; unsupported routing types cannot be policy-authorized safely"),
                ),
                Vec::new(),
            ));
        }
        let decoded = Dissector::new(Arc::clone(&self.registry))
            .decode(frame.clone(), DecodeOptions::default())
            .map_err(|source| {
                ReplayAuthorizationError::new(
                    source.to_string(),
                    ErrorClassification::new(
                        "packet.decode",
                        FailureKind::Packet,
                        Some("repair the frame or link type before authorizing live replay"),
                    ),
                    Vec::new(),
                )
            })?;
        let rebuilt = Builder::new(Arc::clone(&self.registry))
            .build(
                decoded.packet.clone(),
                BuildContext::default(),
                BuildOptions {
                    mode: BuildMode::Permissive,
                    ..BuildOptions::default()
                },
            )
            .map_err(|source| {
                ReplayAuthorizationError::new(
                    format!("captured frame cannot be rebuilt exactly: {source}"),
                    ErrorClassification::new(
                        "packet.replay_rebuild",
                        FailureKind::Packet,
                        Some("repair the capture so its decoded layers rebuild the exact submitted bytes"),
                    ),
                    Vec::new(),
                )
            })?;
        if rebuilt.bytes != frame.bytes {
            return Err(ReplayAuthorizationError::new(
                "captured frame did not reproduce the exact source bytes",
                ErrorClassification::new(
                    "internal.replay_rebuild",
                    FailureKind::Internal,
                    Some("do not replay bytes whose codec round trip changed the authoritative capture"),
                ),
                Vec::new(),
            ));
        }
        if rebuilt.requires_live_opt_in && !self.allow_malformed_live {
            return Err(ReplayAuthorizationError::new(
                "permissive or malformed captured bytes require --allow-malformed-live",
                ErrorClassification::new(
                    "policy.permissive_live_opt_in",
                    FailureKind::Policy,
                    Some("set the per-operation malformed-live opt-in in addition to policy approval"),
                ),
                Vec::new(),
            ));
        }
        if rebuilt.requires_live_opt_in && !self.policy.allow_permissive_packets {
            let source = TrafficPolicyError::PermissivePacket;
            return Err(ReplayAuthorizationError::new(
                source.to_string(),
                source.classification(),
                source.causes(),
            ));
        }
        self.policy
            .authorize_packet_destinations(&decoded.packet)
            .map_err(|source| {
                ReplayAuthorizationError::new(
                    source.to_string(),
                    source.classification(),
                    source.causes(),
                )
            })
    }
}

struct SystemReplayTransmitter {
    resolved: Option<InterfaceInfo>,
    packets: SystemPackets,
    routes: SystemRouteProvider,
}

impl SystemReplayTransmitter {
    fn new() -> Self {
        Self {
            resolved: None,
            packets: DispatchPacketIo::new(SystemLayer2Io, SystemLayer3Io),
            routes: SystemRouteProvider,
        }
    }

    fn resolve(
        &mut self,
        requested: &InterfaceId,
        mode: LinkMode,
        frame: &CapturedFrame,
    ) -> Result<InterfaceId, LiveIoError> {
        if self.resolved.is_none() {
            let interfaces = SystemInterfaceProvider.interfaces()?;
            let selected = interfaces
                .into_iter()
                .find(|interface| {
                    if requested.index != 0 {
                        interface.id.index == requested.index
                    } else {
                        interface.id.name == requested.name
                    }
                })
                .ok_or_else(|| LiveIoError::Device {
                    interface: requested.name.clone(),
                    message: "no interface matches the requested name or index".to_owned(),
                })?;
            if !selected.flags.up {
                return Err(LiveIoError::Device {
                    interface: selected.id.name,
                    message: "selected interface is not up".to_owned(),
                });
            }
            self.resolved = Some(selected);
        }
        let selected = self.resolved.as_ref().expect("resolved above");
        let supported = match mode {
            LinkMode::Layer2 => matches!(
                selected.capability,
                LinkCapability::Layer2 | LinkCapability::Layer2And3
            ),
            LinkMode::Layer3 => matches!(
                selected.capability,
                LinkCapability::Layer3 | LinkCapability::Layer2And3
            ),
            LinkMode::Auto => false,
        };
        if !supported {
            return Err(LiveIoError::Unsupported {
                message: format!(
                    "interface {} does not support requested {mode:?} replay",
                    selected.id.name
                ),
            });
        }
        if mode == LinkMode::Layer2 && selected.link_type != frame.link_type {
            return Err(LiveIoError::Device {
                interface: selected.id.name.clone(),
                message: format!(
                    "interface link type {} differs from captured link type {}",
                    selected.link_type.0, frame.link_type.0
                ),
            });
        }
        Ok(selected.id.clone())
    }

    fn materialized_route(
        &self,
        interface: &InterfaceInfo,
        mode: LinkMode,
        frame: &CapturedFrame,
    ) -> Result<MaterializedRoute, LiveIoError> {
        let plan = match mode {
            LinkMode::Layer2 => PlannedRoute {
                route: RouteDecision {
                    interface: interface.id.clone(),
                    source_mac: interface.mac_address,
                    selected_address: interface.addresses.first().map(|value| value.address),
                    preferred_source: None,
                    next_hop: None,
                    selection_reason: RouteSelectionReason::InterfaceOnly,
                    destination_scope: DestinationScope::Link,
                    mtu: interface.mtu.unwrap_or(u32::MAX),
                    capability: interface.capability,
                    link_type: interface.link_type,
                },
                mode,
                lookup_destination: None,
                final_destination: None,
                visited_destinations: Vec::new(),
                packet_source: None,
                neighbor_source: None,
                neighbor_target: None,
                destination_mac: None,
                source_mac: interface.mac_address,
                neighbor_vlan_tags: Vec::new(),
                synthesized_ethernet: false,
            },
            LinkMode::Layer3 => {
                let (source, destination) = replay_ip_endpoints(&frame.bytes)?;
                let route = self
                    .routes
                    .lookup_with_preferences(destination, Some(&interface.id), None)
                    .map_err(|source| map_replay_route_error(&self.routes, source))?;
                if route.interface != interface.id {
                    return Err(LiveIoError::Device {
                        interface: interface.id.name.clone(),
                        message: format!(
                            "route selected {} (index {})",
                            route.interface.name, route.interface.index
                        ),
                    });
                }
                if !matches!(
                    route.capability,
                    LinkCapability::Layer3 | LinkCapability::Layer2And3
                ) {
                    return Err(LiveIoError::Unsupported {
                        message: format!(
                            "route through {} does not support raw Layer 3 transmission",
                            route.interface.name
                        ),
                    });
                }
                let source_mac = route.source_mac;
                PlannedRoute {
                    route,
                    mode,
                    lookup_destination: Some(destination),
                    final_destination: Some(destination),
                    visited_destinations: vec![destination],
                    packet_source: Some(source),
                    neighbor_source: None,
                    neighbor_target: None,
                    destination_mac: None,
                    source_mac,
                    neighbor_vlan_tags: Vec::new(),
                    synthesized_ethernet: false,
                }
            }
            LinkMode::Auto => return Err(LiveIoError::UnresolvedLinkMode),
        };
        Ok(MaterializedRoute {
            plan,
            neighbor_resolution: None,
        })
    }
}

impl ReplayTransmitter for SystemReplayTransmitter {
    fn validate_interface(
        &mut self,
        interface: &InterfaceId,
        mode: LinkMode,
        frame: &CapturedFrame,
    ) -> Result<InterfaceId, LiveIoError> {
        self.resolve(interface, mode, frame)
    }

    fn transmit(
        &mut self,
        interface: &InterfaceId,
        mode: LinkMode,
        frame: &CapturedFrame,
    ) -> Result<ReplayTransmission, LiveIoError> {
        let selected = self
            .resolved
            .as_ref()
            .filter(|selected| selected.id == *interface)
            .cloned()
            .ok_or_else(|| LiveIoError::Device {
                interface: interface.name.clone(),
                message: "interface was not validated before replay transmission".to_owned(),
            })?;
        let route = self.materialized_route(&selected, mode, frame)?;
        let report = self
            .packets
            .send(TransmissionFrame::try_new(&frame.bytes, &route)?)?;
        Ok(ReplayTransmission {
            interface: selected.id,
            report,
        })
    }
}

fn map_replay_route_error(
    provider: &SystemRouteProvider,
    source: crate::io::NativeRouteError,
) -> LiveIoError {
    let classification = provider.classify_error(&source);
    match classification.kind {
        FailureKind::Capability => LiveIoError::Unsupported {
            message: source.to_string(),
        },
        _ => LiveIoError::Send {
            message: format!("replay route selection failed: {source}"),
        },
    }
}

fn replay_ip_endpoints(bytes: &[u8]) -> Result<(IpAddr, IpAddr), LiveIoError> {
    let invalid = |message: String| LiveIoError::InvalidTransmissionFrame { message };
    let Some(version) = bytes.first().map(|byte| byte >> 4) else {
        return Err(invalid("replay frame is empty".to_owned()));
    };
    match version {
        4 if bytes.len() >= 20 => {
            let source = Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15]);
            let destination = Ipv4Addr::new(bytes[16], bytes[17], bytes[18], bytes[19]);
            Ok((IpAddr::V4(source), IpAddr::V4(destination)))
        }
        6 if bytes.len() >= 40 => {
            let mut source = [0_u8; 16];
            let mut destination = [0_u8; 16];
            source.copy_from_slice(&bytes[8..24]);
            destination.copy_from_slice(&bytes[24..40]);
            Ok((
                IpAddr::V6(Ipv6Addr::from(source)),
                IpAddr::V6(Ipv6Addr::from(destination)),
            ))
        }
        4 => Err(invalid(
            "replay frame has a truncated IPv4 header".to_owned(),
        )),
        6 => Err(invalid(
            "replay frame has a truncated IPv6 header".to_owned(),
        )),
        value => Err(invalid(format!(
            "replay frame has unsupported IP version {value}"
        ))),
    }
}

fn replay_wire_policy(frame: &CapturedFrame) -> (Vec<IpAddr>, bool) {
    let bytes = frame.bytes.as_ref();
    let (network_offset, protocol) = match frame.link_type.0 {
        12 | 101 => (0, bytes.first().map(|byte| byte >> 4).unwrap_or(0)),
        228 => (0, 4),
        229 => (0, 6),
        1 if bytes.len() >= 14 => {
            let mut offset = 14_usize;
            let mut ether_type = u16::from_be_bytes([bytes[12], bytes[13]]);
            for _ in 0..DEFAULT_MAX_LAYERS {
                if !matches!(ether_type, 0x8100 | 0x88a8) || bytes.len() < offset + 4 {
                    break;
                }
                ether_type = u16::from_be_bytes([bytes[offset + 2], bytes[offset + 3]]);
                offset += 4;
            }
            let protocol = match ether_type {
                0x0800 => 4,
                0x86dd => 6,
                _ => 0,
            };
            (offset, protocol)
        }
        _ => (0, 0),
    };
    let mut destinations = Vec::new();
    let unsupported_routing = match protocol {
        4 => {
            collect_ipv4_wire_destinations(bytes, network_offset, &mut destinations);
            false
        }
        6 => collect_ipv6_wire_destinations(bytes, network_offset, &mut destinations),
        _ => false,
    };
    (destinations, unsupported_routing)
}

#[cfg(test)]
fn replay_wire_destinations(frame: &CapturedFrame) -> Vec<IpAddr> {
    replay_wire_policy(frame).0
}

fn collect_ipv4_wire_destinations(bytes: &[u8], offset: usize, output: &mut Vec<IpAddr>) {
    let Some(header) = bytes.get(offset..offset.saturating_add(20)) else {
        return;
    };
    output.push(IpAddr::V4(Ipv4Addr::new(
        header[16], header[17], header[18], header[19],
    )));
    let header_length = usize::from(header[0] & 0x0f).saturating_mul(4);
    if !(20..=60).contains(&header_length) {
        return;
    }
    let Some(header) = bytes.get(offset..offset.saturating_add(header_length)) else {
        return;
    };
    let mut cursor = 20_usize;
    while cursor < header.len() {
        match header[cursor] {
            0 => break,
            1 => cursor += 1,
            option => {
                let Some(length) = header.get(cursor + 1).copied().map(usize::from) else {
                    break;
                };
                if length < 2 || cursor.saturating_add(length) > header.len() {
                    break;
                }
                if matches!(option, 131 | 137) && length >= 7 {
                    for address in header[cursor + 3..cursor + length].chunks_exact(4) {
                        output.push(IpAddr::V4(Ipv4Addr::new(
                            address[0], address[1], address[2], address[3],
                        )));
                    }
                }
                cursor += length;
            }
        }
    }
}

fn collect_ipv6_wire_destinations(bytes: &[u8], offset: usize, output: &mut Vec<IpAddr>) -> bool {
    let Some(header) = bytes.get(offset..offset.saturating_add(40)) else {
        return false;
    };
    let mut destination = [0_u8; 16];
    destination.copy_from_slice(&header[24..40]);
    output.push(IpAddr::V6(Ipv6Addr::from(destination)));
    let mut next_header = header[6];
    let mut cursor = offset.saturating_add(40);
    let mut unsupported_routing = false;
    for _ in 0..DEFAULT_MAX_LAYERS {
        match next_header {
            0 | 43 | 60 => {
                let Some(extension) = bytes.get(cursor..cursor.saturating_add(8)) else {
                    unsupported_routing |= next_header == 43;
                    break;
                };
                let length = (usize::from(extension[1]) + 1).saturating_mul(8);
                let Some(extension) = bytes.get(cursor..cursor.saturating_add(length)) else {
                    unsupported_routing |= next_header == 43;
                    break;
                };
                if next_header == 43 && extension[2] == 4 {
                    let segment_count = usize::from(extension[4]).saturating_add(1);
                    let available = extension.len().saturating_sub(8) / 16;
                    for segment in extension[8..]
                        .chunks_exact(16)
                        .take(segment_count.min(available))
                    {
                        let mut address = [0_u8; 16];
                        address.copy_from_slice(segment);
                        output.push(IpAddr::V6(Ipv6Addr::from(address)));
                    }
                } else if next_header == 43 {
                    unsupported_routing = true;
                }
                next_header = extension[0];
                cursor = cursor.saturating_add(length);
            }
            44 => {
                let Some(fragment) = bytes.get(cursor..cursor.saturating_add(8)) else {
                    break;
                };
                next_header = fragment[0];
                cursor = cursor.saturating_add(8);
            }
            51 => {
                let Some(authentication) = bytes.get(cursor..cursor.saturating_add(2)) else {
                    break;
                };
                let length = (usize::from(authentication[1]) + 2).saturating_mul(4);
                if bytes.get(cursor..cursor.saturating_add(length)).is_none() {
                    break;
                }
                next_header = authentication[0];
                cursor = cursor.saturating_add(length);
            }
            _ => break,
        }
    }
    unsupported_routing
}

fn replay_timing(arguments: &ReplayArgs) -> Result<ReplayTiming, CliError> {
    let timing = if let Some(rate) = arguments.rate {
        if matches!(arguments.timing, CliReplayTiming::Immediate) {
            return Err(CliError::new(
                2,
                "--rate cannot be combined with --timing immediate",
            ));
        }
        ReplayTiming::FixedRate(rate)
    } else if let Some(speed) = arguments.speed {
        if matches!(arguments.timing, CliReplayTiming::Immediate) {
            return Err(CliError::new(
                2,
                "--speed cannot be combined with --timing immediate",
            ));
        }
        ReplayTiming::Scaled(1.0 / speed)
    } else {
        match arguments.timing {
            CliReplayTiming::Original => ReplayTiming::Original,
            CliReplayTiming::Immediate => ReplayTiming::Immediate,
        }
    };
    timing.validate().map_err(CliError::classified)
}

fn requested_replay_interface(selector: &str) -> Result<InterfaceId, CliError> {
    if selector.is_empty() {
        return Err(CliError::new(2, "replay interface cannot be empty"));
    }
    let index = selector.parse::<u32>().unwrap_or(0);
    if selector.bytes().all(|byte| byte.is_ascii_digit()) && index == 0 {
        return Err(CliError::new(2, "replay interface index must be non-zero"));
    }
    Ok(InterfaceId {
        name: selector.to_owned(),
        index,
    })
}

fn run_replay(arguments: ReplayArgs, output: OutputFormat) -> Result<(), CliError> {
    validate_capture_stream_limits(
        arguments.policy.max_packets,
        arguments.policy.max_bytes,
        arguments.max_frame_bytes,
        arguments.max_interfaces,
    )?;
    let timing = replay_timing(&arguments)?;
    let requested_interface = requested_replay_interface(&arguments.interface)?;
    let policy = arguments.policy.clone().into_policy();
    policy.validate().map_err(CliError::classified)?;
    let limits = ReplayLimits {
        max_frames: policy.max_packets_per_operation,
        max_bytes: policy.max_bytes_per_operation,
        max_frame_bytes: arguments.max_frame_bytes,
        max_duration: Duration::from_millis(arguments.max_duration_ms),
    }
    .validate()
    .map_err(CliError::classified)?;
    let file = File::open(&arguments.path).map_err(|source| {
        CliError::new(
            5,
            format!("open {} failed: {source}", arguments.path.display()),
        )
    })?;
    let mut reader =
        CaptureReader::with_limits(file, arguments.max_frame_bytes, arguments.max_interfaces)
            .map_err(CliError::classified)?;
    let registry = default_registry_arc()?;
    let mut authorizer = CliReplayAuthorizer {
        policy,
        registry,
        allow_malformed_live: arguments.allow_malformed_live,
    };
    let options = ReplayOptions {
        interface: requested_interface.clone(),
        link_mode: arguments.link_mode.into(),
        timing,
        limits,
    };
    let mut transmitter = SystemReplayTransmitter::new();
    let mut clock = SystemReplayClock;
    let started = Instant::now();

    match output {
        OutputFormat::Text => {
            let summary = replay_capture(
                &mut reader,
                &options,
                &mut authorizer,
                &mut transmitter,
                &mut clock,
                |evidence| {
                    let sequence = evidence.source_sequence;
                    let result = ReplayFrameCommandResult::try_from_evidence(evidence)
                        .map_err(|source| ReplayError::output(sequence, source.to_string()))?;
                    write_stdout_line(format_args!(
                        "{}: sent {} bytes via {} (index {}, {:?}) dlt={} {}",
                        result.source_sequence,
                        result.bytes_sent,
                        result.interface.name,
                        result.interface.index,
                        result.link_mode,
                        result.frame.link_type,
                        spaced_hex(result.frame.bytes())
                    ))
                    .map_err(|source| ReplayError::output(result.source_sequence, source.message))
                },
            )
            .map_err(replay_cli_error)?;
            write_stdout_line(format_args!(
                "replayed {} frame(s), {} byte(s), scheduled delay {:?}",
                summary.frames_completed, summary.bytes_completed, summary.scheduled_duration
            ))
        }
        OutputFormat::Json => {
            let mut frames = Vec::new();
            let summary = replay_capture(
                &mut reader,
                &options,
                &mut authorizer,
                &mut transmitter,
                &mut clock,
                |evidence| {
                    let sequence = evidence.source_sequence;
                    let result = ReplayFrameCommandResult::try_from_evidence(evidence)
                        .map_err(|source| ReplayError::output(sequence, source.to_string()))?;
                    frames.push(result);
                    Ok(())
                },
            )
            .map_err(replay_cli_error)?;
            let stats = replay_stats(&summary, started.elapsed());
            let result = ReplayCommandResult::from_summary(
                summary,
                requested_interface,
                options.link_mode,
                frames,
            );
            emit_json(
                &AggregateOutput::success(CommandName::Replay, result, Vec::new())
                    .with_stats(stats),
            )
        }
        OutputFormat::Ndjson => {
            let summary = replay_capture(
                &mut reader,
                &options,
                &mut authorizer,
                &mut transmitter,
                &mut clock,
                |evidence| {
                    let sequence = evidence.source_sequence;
                    let result = ReplayFrameCommandResult::try_from_evidence(evidence)
                        .map_err(|source| ReplayError::output(sequence, source.to_string()))?;
                    emit_json_compact(&StreamRecord::success(
                        CommandName::Replay,
                        sequence,
                        result,
                        Vec::new(),
                    ))
                    .map_err(|source| ReplayError::output(sequence, source.message))
                },
            )
            .map_err(replay_cli_error)?;
            let sequence = summary.frames_completed;
            let stats = replay_stats(&summary, started.elapsed());
            let result = ReplayCommandResult::from_summary(
                summary,
                requested_interface,
                options.link_mode,
                Vec::new(),
            );
            emit_json_compact(
                &StreamRecord::success(CommandName::Replay, sequence, result, Vec::new())
                    .with_stats(stats),
            )
            .map_err(|error| error.at_sequence(sequence))
        }
        OutputFormat::Pcap | OutputFormat::Pcapng => {
            let format = capture_file_format(output)?;
            let stdout = io::stdout();
            let mut writer = replay_capture_writer(
                &reader,
                stdout.lock(),
                format,
                limits,
                arguments.max_interfaces,
            )?;
            let mut interfaces = Vec::<(Option<u32>, u32)>::new();
            replay_capture(
                &mut reader,
                &options,
                &mut authorizer,
                &mut transmitter,
                &mut clock,
                |evidence| {
                    write_replay_capture_evidence(&mut writer, format, &mut interfaces, evidence)
                },
            )
            .map_err(replay_cli_error)?;
            writer.flush().map_err(CliError::classified)
        }
        _ => Err(CliError::classified(
            OutputContractError::UnsupportedFormat {
                command: CommandName::Replay,
                format: output,
            },
        )),
    }
}

fn replay_capture_writer<W: Write>(
    reader: &CaptureReader<File>,
    output: W,
    format: CaptureFileFormat,
    limits: ReplayLimits,
    max_interfaces: usize,
) -> Result<CaptureWriter<W>, CliError> {
    let mut writer = match format {
        CaptureFileFormat::Pcap => {
            if reader.format() != CaptureFileFormat::Pcap {
                return Err(CliError::classified(
                    crate::io::CaptureError::MetadataNotRepresentable {
                        format,
                        field: "pcapng replay evidence",
                    },
                ));
            }
            let interface = reader.interfaces()[0];
            CaptureWriter::pcap_with_metadata(
                output,
                interface.link_type,
                reader.endianness(),
                interface.timestamp_resolution,
                interface.snap_len as usize,
                limits.max_frame_bytes,
            )
        }
        CaptureFileFormat::PcapNg => CaptureWriter::pcapng_with_resource_limits(
            output,
            reader.endianness(),
            limits.max_frame_bytes,
            max_interfaces,
        ),
    }
    .map_err(CliError::classified)?;
    writer
        .set_stream_limits(CaptureStreamLimits {
            max_frames: limits.max_frames,
            max_bytes: limits.max_bytes,
        })
        .map_err(CliError::classified)?;
    Ok(writer)
}

fn write_replay_capture_evidence<W: Write>(
    writer: &mut CaptureWriter<W>,
    format: CaptureFileFormat,
    interfaces: &mut Vec<(Option<u32>, u32)>,
    evidence: crate::tools::ReplayFrameEvidence,
) -> Result<(), ReplayError> {
    let sequence = evidence.source_sequence;
    let mut frame = evidence.frame;
    frame.interface = match format {
        CaptureFileFormat::Pcap => None,
        CaptureFileFormat::PcapNg => {
            let interface = match interfaces
                .iter()
                .find(|(source, _)| *source == evidence.source_interface_id)
            {
                Some((_, interface)) => *interface,
                None => {
                    let interface = writer
                        .add_interface_description(evidence.capture_interface)
                        .map_err(|source| ReplayError::output(sequence, source.to_string()))?;
                    interfaces.push((evidence.source_interface_id, interface));
                    interface
                }
            };
            Some(interface)
        }
    };
    writer
        .write_frame(&frame)
        .map_err(|source| ReplayError::output(sequence, source.to_string()))
}

fn replay_stats(
    summary: &crate::tools::ReplaySummary,
    elapsed: Duration,
) -> crate::client::OperationStats {
    crate::client::OperationStats {
        packets_attempted: summary.frames_attempted,
        packets_completed: summary.frames_completed,
        bytes: summary.bytes_completed,
        elapsed,
        capture: crate::io::CaptureStatistics::default(),
    }
}

fn replay_cli_error(error: ReplayError) -> CliError {
    let sequence = error.sequence();
    let mut error = CliError::classified(error);
    if let Some(sequence) = sequence {
        error = error.at_sequence(sequence);
    }
    error
}

fn run_interfaces(output: OutputFormat) -> Result<(), CliError> {
    let interfaces = crate::io::InterfaceProvider::interfaces(&crate::io::SystemInterfaceProvider)
        .map_err(CliError::classified)?;
    let result = InterfacesCommandResult::new(interfaces);
    match output {
        OutputFormat::Text => {
            for interface in result.interfaces {
                write_stdout_line(format_args!(
                    "{} (index {}): {}",
                    interface.name,
                    interface.index,
                    interface.addresses.join(", ")
                ))?;
            }
            Ok(())
        }
        OutputFormat::Json => emit_json(&AggregateOutput::success(
            CommandName::Interfaces,
            result,
            Vec::new(),
        )),
        _ => Err(CliError::classified(
            OutputContractError::UnsupportedFormat {
                command: CommandName::Interfaces,
                format: output,
            },
        )),
    }
}

fn read_recipe(
    arguments: RecipeArgs,
    registry: &crate::core::ProtocolRegistry,
) -> Result<Packet, CliError> {
    let stdin = read_nonterminal_stdin_bounded(DEFAULT_MAX_DOCUMENT_BYTES)?;
    let RecipeArgs {
        packet,
        packet_file,
    } = arguments;
    let source_count = usize::from(packet.is_some())
        + usize::from(packet_file.is_some())
        + usize::from(stdin.is_some());
    if source_count != 1 {
        return Err(CliError::new(
            2,
            "exactly one of --packet, --packet-file, or non-empty stdin is required",
        ));
    }

    let (input, path) = match (packet, packet_file, stdin) {
        (Some(expression), None, None) => return parse_expression(&expression, registry),
        (None, Some(path), None) => {
            let bytes = read_bounded_file(&path, DEFAULT_MAX_DOCUMENT_BYTES)?;
            let input = String::from_utf8(bytes).map_err(|source| {
                CliError::new(2, format!("packet document is not UTF-8: {source}"))
            })?;
            (input, Some(path))
        }
        (None, None, Some(bytes)) => {
            let input = String::from_utf8(bytes).map_err(|source| {
                CliError::new(2, format!("stdin recipe is not UTF-8: {source}"))
            })?;
            (input, None)
        }
        _ => unreachable!("source count was validated"),
    };
    let trimmed = input.trim_start();
    let format = path
        .as_deref()
        .and_then(document_format_from_path)
        .or_else(|| trimmed.starts_with('{').then_some(DocumentFormat::Json))
        .or_else(|| {
            (trimmed.starts_with("schema:") || trimmed.starts_with("---"))
                .then_some(DocumentFormat::Yaml)
        });
    if let Some(format) = format {
        return PacketDocument::parse_with_resource_limits(
            &input,
            format,
            DEFAULT_MAX_DOCUMENT_BYTES,
            DEFAULT_MAX_LAYERS,
            DEFAULT_MAX_DOCUMENT_NESTING,
        )
        .and_then(|document| document.to_packet(registry, DEFAULT_MAX_LAYERS))
        .map_err(|source| CliError::new(2, source.to_string()));
    }
    parse_expression(&input, registry)
}

fn parse_expression(
    input: &str,
    registry: &crate::core::ProtocolRegistry,
) -> Result<Packet, CliError> {
    parse_packet_expression(input, registry, ExpressionOptions::default())
        .map_err(|source| CliError::new(2, source.to_string()))
}

fn document_format_from_path(path: &Path) -> Option<DocumentFormat> {
    match path.extension()?.to_str()?.to_ascii_lowercase().as_str() {
        "json" => Some(DocumentFormat::Json),
        "yaml" | "yml" => Some(DocumentFormat::Yaml),
        _ => None,
    }
}

fn read_bounded_file(path: &Path, maximum: usize) -> Result<Vec<u8>, CliError> {
    let file = File::open(path)
        .map_err(|source| CliError::new(2, format!("open {} failed: {source}", path.display())))?;
    read_bounded(file, maximum)
}

fn read_stdin_bounded(maximum: usize) -> Result<Vec<u8>, CliError> {
    read_bounded(io::stdin().lock(), maximum)
}

fn read_nonterminal_stdin_bounded(maximum: usize) -> Result<Option<Vec<u8>>, CliError> {
    let stdin = io::stdin();
    if stdin.is_terminal() {
        return Ok(None);
    }
    let bytes = read_bounded_allow_empty(stdin.lock(), maximum)?;
    Ok((!bytes.is_empty()).then_some(bytes))
}

fn read_bounded(reader: impl Read, maximum: usize) -> Result<Vec<u8>, CliError> {
    let bytes = read_bounded_allow_empty(reader, maximum)?;
    if bytes.is_empty() {
        return Err(CliError::new(
            2,
            "one of --packet, --packet-file, or non-empty stdin is required",
        ));
    }
    Ok(bytes)
}

fn read_bounded_allow_empty(reader: impl Read, maximum: usize) -> Result<Vec<u8>, CliError> {
    let mut bytes = Vec::new();
    reader
        .take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| CliError::new(2, format!("read packet input failed: {source}")))?;
    if bytes.len() > maximum {
        return Err(CliError::new(
            2,
            format!("packet input exceeds {maximum} byte limit"),
        ));
    }
    Ok(bytes)
}

fn spaced_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len().saturating_mul(3));
    for (index, byte) in bytes.iter().enumerate() {
        use std::fmt::Write as _;
        if index != 0 {
            output.push(' ');
        }
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn emit_json(value: &impl Serialize) -> Result<(), CliError> {
    let rendered = serde_json::to_string_pretty(value)
        .map_err(|source| CliError::new(70, format!("serialize output failed: {source}")))?;
    write_machine_line(&rendered)
}

fn emit_json_compact(value: &impl Serialize) -> Result<(), CliError> {
    let rendered = serde_json::to_string(value)
        .map_err(|source| CliError::new(70, format!("serialize output failed: {source}")))?;
    write_machine_line(&rendered)
}

fn write_stdout_line(arguments: std::fmt::Arguments<'_>) -> Result<(), CliError> {
    let rendered = terminal_safe(&arguments.to_string());
    write_machine_line(&rendered)
}

fn write_machine_line(rendered: &str) -> Result<(), CliError> {
    let mut stdout = io::stdout().lock();
    stdout
        .write_all(rendered.as_bytes())
        .and_then(|()| stdout.write_all(b"\n"))
        .and_then(|()| stdout.flush())
        .map_err(|source| CliError::new(5, format!("write stdout failed: {source}")))
}

fn emit_stderr_error(message: &str) -> Result<(), CliError> {
    let mut stderr = io::stderr().lock();
    writeln!(stderr, "error: {}", terminal_safe(message))
        .and_then(|()| stderr.flush())
        .map_err(|source| CliError::new(5, format!("write stderr failed: {source}")))
}

fn emit_stderr_message(message: &str) -> Result<(), CliError> {
    let mut stderr = io::stderr().lock();
    writeln!(stderr, "{}", terminal_safe(message))
        .and_then(|()| stderr.flush())
        .map_err(|source| CliError::new(5, format!("write stderr failed: {source}")))
}

fn terminal_safe(value: &str) -> String {
    let mut safe = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '\n' => safe.push_str("\\n"),
            '\r' => safe.push_str("\\r"),
            '\t' => safe.push_str("\\t"),
            character
                if character.is_control()
                    || matches!(
                        character,
                        '\u{061c}'
                            | '\u{200b}'..='\u{200f}'
                            | '\u{202a}'..='\u{202e}'
                            | '\u{2060}'..='\u{206f}'
                            | '\u{feff}'
                    ) =>
            {
                use std::fmt::Write as _;
                let _ = write!(safe, "\\u{{{:x}}}", character as u32);
            }
            character => safe.push(character),
        }
    }
    safe
}

fn write_raw(bytes: &[u8]) -> Result<(), CliError> {
    let mut stdout = io::stdout().lock();
    stdout
        .write_all(bytes)
        .and_then(|()| stdout.flush())
        .map_err(|source| CliError::new(5, format!("write stdout failed: {source}")))
}

#[derive(Debug)]
struct CliError {
    code: u8,
    message: String,
    classification: ErrorClassification,
    causes: Vec<String>,
    sequence: Option<u64>,
}

impl CliError {
    fn new(code: u8, message: impl Into<String>) -> Self {
        let kind = match code {
            2 => FailureKind::Cli,
            3 => FailureKind::Packet,
            4 => FailureKind::Capability,
            5 => FailureKind::Io,
            6 => FailureKind::Policy,
            _ => FailureKind::Internal,
        };
        Self {
            code,
            message: message.into(),
            classification: ErrorClassification::new(
                match kind {
                    FailureKind::Cli => "cli.error",
                    FailureKind::Packet => "packet.error",
                    FailureKind::Capability => "capability.unavailable",
                    FailureKind::Io => "io.runtime",
                    FailureKind::Policy => "policy.denied",
                    FailureKind::Internal => "internal.error",
                },
                kind,
                None,
            ),
            causes: Vec::new(),
            sequence: None,
        }
    }

    fn classified(error: impl ClassifiedError + std::fmt::Display) -> Self {
        let classification = error.classification();
        let causes = error.causes();
        Self::from_classification(classification, error.to_string(), causes)
    }

    fn from_classification(
        classification: ErrorClassification,
        message: impl Into<String>,
        causes: Vec<String>,
    ) -> Self {
        Self {
            code: classification.exit_code(),
            message: message.into(),
            classification,
            causes,
            sequence: None,
        }
    }

    fn at_sequence(mut self, sequence: u64) -> Self {
        self.sequence = Some(sequence);
        self
    }

    fn at_sequence_if_absent(mut self, sequence: u64) -> Self {
        self.sequence.get_or_insert(sequence);
        self
    }

    fn with_cleanup(mut self, cleanup: LiveIoError) -> Self {
        let operation = self.message.clone();
        self.message = format!("{operation}; capture shutdown also failed: {cleanup}");
        if self.causes.is_empty() {
            self.causes.push(operation);
        }
        self.causes.push(cleanup.to_string());
        self
    }

    fn output_error(&self) -> OutputError {
        OutputError::new(
            self.classification,
            self.message.clone(),
            self.causes.clone(),
        )
    }
}

fn machine_format_from_env() -> Option<OutputFormat> {
    let arguments = std::env::args().collect::<Vec<_>>();
    arguments.iter().enumerate().find_map(|(index, argument)| {
        let value = if argument == "--output" {
            arguments.get(index + 1).map(String::as_str)
        } else {
            argument.strip_prefix("--output=")
        }?;
        match value {
            "json" => Some(OutputFormat::Json),
            "ndjson" => Some(OutputFormat::Ndjson),
            _ => None,
        }
    })
}

fn command_from_env() -> Option<CommandName> {
    const COMMANDS: &[(&str, CommandName)] = &[
        ("build", CommandName::Build),
        ("dissect", CommandName::Dissect),
        ("plan", CommandName::Plan),
        ("send", CommandName::Send),
        ("exchange", CommandName::Exchange),
        ("capture", CommandName::Capture),
        ("read", CommandName::Read),
        ("replay", CommandName::Replay),
        ("scan", CommandName::Scan),
        ("traceroute", CommandName::Traceroute),
        ("dns", CommandName::Dns),
        ("fuzz", CommandName::Fuzz),
        ("interfaces", CommandName::Interfaces),
        ("routes", CommandName::Routes),
    ];
    std::env::args().find_map(|argument| {
        COMMANDS
            .iter()
            .find_map(|(name, command)| (*name == argument).then_some(*command))
    })
}

fn exit_code(code: u8) -> ExitCode {
    ExitCode::from(code)
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use super::*;

    struct ScriptedCapture {
        ready: Option<Result<(), LiveIoError>>,
        frames: VecDeque<Result<Option<CapturedFrame>, LiveIoError>>,
        shutdown: Option<Result<(), LiveIoError>>,
        statistics: crate::io::CaptureStatistics,
    }

    impl CaptureSession for ScriptedCapture {
        fn wait_ready(&mut self) -> Result<(), LiveIoError> {
            self.ready.take().unwrap_or(Ok(()))
        }

        fn next_frame(&mut self, _timeout: Duration) -> Result<Option<CapturedFrame>, LiveIoError> {
            self.frames.pop_front().unwrap_or(Ok(None))
        }

        fn shutdown(&mut self) -> Result<(), LiveIoError> {
            self.shutdown.take().unwrap_or(Ok(()))
        }

        fn statistics(&self) -> crate::io::CaptureStatistics {
            self.statistics
        }
    }

    fn test_capture_budget() -> CaptureBudget {
        CaptureBudget {
            max_frames: 10,
            max_bytes: 1024,
        }
    }

    #[test]
    fn packet_sources_are_mutually_exclusive() {
        let result = Cli::try_parse_from([
            "packetcraftr",
            "build",
            "--packet",
            "raw()",
            "--packet-file",
            "packet.json",
        ]);
        assert!(result.is_err());
    }

    #[test]
    fn scan_cli_parses_typed_transport_ports_and_finite_limits() {
        let cli = Cli::try_parse_from([
            "packetcraftr",
            "scan",
            "192.168.56.10",
            "--transport",
            "udp",
            "--ports",
            "53,161",
            "--attempts",
            "2",
            "--batch-size",
            "2",
            "--rate",
            "10",
        ])
        .unwrap();
        let Command::Scan(arguments) = cli.command else {
            panic!("expected scan command");
        };
        assert!(matches!(arguments.transport, CliScanTransport::Udp));
        assert_eq!(arguments.ports, [53, 161]);
        assert_eq!(arguments.attempts, 2);
        assert_eq!(arguments.batch_size, 2);
        assert_eq!(arguments.rate, Some(10));
    }

    #[test]
    fn scan_request_validation_fails_before_route_or_live_io() {
        let cli = Cli::try_parse_from([
            "packetcraftr",
            "scan",
            "192.168.56.10",
            "--transport",
            "icmp",
            "--ports",
            "80",
        ])
        .unwrap();
        let error = run(cli).unwrap_err();
        assert_eq!(error.classification.code, "cli.scan_limit");
        assert!(error.message.contains("ICMP scans are portless"));
    }

    #[test]
    fn dns_cli_parses_query_policy_route_and_finite_bounds() {
        let cli = Cli::try_parse_from([
            "packetcraftr",
            "dns",
            "10.0.0.53",
            "_service._tcp.example.test",
            "--type",
            "srv",
            "--family",
            "ipv4",
            "--port",
            "5353",
            "--transaction-id",
            "7",
            "--source-port",
            "50000",
            "--attempts",
            "3",
            "--rate",
            "10",
            "--interface",
            "test0",
            "--source",
            "10.0.0.2",
            "--link-mode",
            "layer3",
        ])
        .unwrap();
        let Command::Dns(arguments) = cli.command else {
            panic!("expected DNS command");
        };
        assert!(matches!(arguments.query_type, CliDnsQueryType::Srv));
        assert!(matches!(arguments.family, CliDnsAddressFamily::Ipv4));
        assert_eq!(arguments.port, 5353);
        assert_eq!(arguments.transaction_id, Some(7));
        assert_eq!(arguments.source_port, Some(50_000));
        assert_eq!(arguments.attempts, 3);
        assert_eq!(arguments.rate, Some(10));
        assert_eq!(arguments.interface.as_deref(), Some("test0"));
        assert_eq!(arguments.source, Some("10.0.0.2".parse().unwrap()));
        assert!(matches!(arguments.link_mode, CliLinkMode::Layer3));
    }

    #[test]
    fn dns_request_validation_fails_before_route_or_live_io() {
        let cli =
            Cli::try_parse_from(["packetcraftr", "dns", "10.0.0.53", "bad name.example"]).unwrap();
        let error = run(cli).unwrap_err();
        assert_eq!(error.classification.code, "packet.dns_query");
        assert!(error.message.contains("invalid"));
    }

    #[test]
    fn traceroute_cli_parses_strategy_family_hops_attempts_and_rate() {
        let cli = Cli::try_parse_from([
            "packetcraftr",
            "traceroute",
            "192.168.56.10",
            "--strategy",
            "tcp",
            "--family",
            "ipv4",
            "--port",
            "443",
            "--first-hop",
            "2",
            "--max-hops",
            "12",
            "--attempts",
            "4",
            "--rate",
            "20",
        ])
        .unwrap();
        let Command::Traceroute(arguments) = cli.command else {
            panic!("expected traceroute command");
        };
        assert!(matches!(arguments.strategy, CliTracerouteStrategy::Tcp));
        assert!(matches!(arguments.family, CliTracerouteAddressFamily::Ipv4));
        assert_eq!(arguments.port, Some(443));
        assert_eq!(arguments.first_hop, 2);
        assert_eq!(arguments.max_hops, 12);
        assert_eq!(arguments.attempts, 4);
        assert_eq!(arguments.rate, Some(20));
    }

    #[test]
    fn traceroute_request_validation_fails_before_route_or_live_io() {
        let cli = Cli::try_parse_from([
            "packetcraftr",
            "traceroute",
            "192.168.56.10",
            "--strategy",
            "icmp",
            "--port",
            "80",
        ])
        .unwrap();
        let error = run(cli).unwrap_err();
        assert_eq!(error.classification.code, "cli.traceroute_limit");
        assert!(error.message.contains("ICMP traceroute is portless"));
    }

    #[test]
    fn whole_frame_hex_is_not_truncated() {
        let bytes = (0u8..=255).collect::<Vec<_>>();
        assert_eq!(
            crate::output::WireFrameOutput::new(bytes).bytes_hex.len(),
            512
        );
    }

    #[test]
    fn terminal_text_escapes_controls_and_directional_overrides() {
        let safe = terminal_safe("line\n\u{1b}[31m\u{202e}tail");
        assert_eq!(safe, "line\\n\\u{1b}[31m\\u{202e}tail");
        assert!(!safe.chars().any(char::is_control));
    }

    #[test]
    fn per_item_tool_errors_retain_their_input_sequence() {
        let scan = scan_cli_error(ScanError::InvalidEvidence {
            sequence: 7,
            message: "invalid scan evidence".to_owned(),
        });
        assert_eq!(scan.sequence, Some(7));

        let traceroute = traceroute_cli_error(TracerouteError::InvalidEvidence {
            sequence: 8,
            message: "invalid traceroute evidence".to_owned(),
        });
        assert_eq!(traceroute.sequence, Some(8));

        let dns = dns_cli_error(DnsError::InvalidEvidence {
            attempt: 3,
            message: "invalid DNS evidence".to_owned(),
        });
        assert_eq!(dns.sequence, Some(2));

        let fuzz = fuzz_cli_error(FuzzError::InvalidEvidence {
            case_index: 9,
            message: "invalid fuzz evidence".to_owned(),
        });
        assert_eq!(fuzz.sequence, Some(9));

        let replay = replay_cli_error(ReplayError::output(10, "replay output failed"));
        assert_eq!(replay.sequence, Some(10));
    }

    #[test]
    fn classified_live_errors_use_the_frozen_cli_exit_contract() {
        let capability = CliError::classified(crate::io::LiveIoError::Privilege {
            message: "permission denied".to_owned(),
        });
        assert_eq!(capability.code, 4);
        assert_eq!(capability.classification.code, "capability.privilege");

        let runtime = CliError::classified(crate::io::LiveIoError::PartialSend {
            expected: 10,
            actual: 9,
        });
        assert_eq!(runtime.code, 5);
        assert_eq!(runtime.classification.code, "io.partial_send");

        let dual = CliError::classified(crate::ClientError::OperationAndCaptureShutdown {
            operation: crate::io::LiveIoError::Send {
                message: "send failed".to_owned(),
            },
            shutdown: crate::io::LiveIoError::Capture {
                message: "join failed".to_owned(),
            },
        });
        assert_eq!(dual.causes.len(), 2);
        let envelope =
            AggregateErrorOutput::error(Some(CommandName::Exchange), dual.output_error());
        let envelope = serde_json::to_value(envelope).unwrap();
        assert_eq!(envelope["error"]["causes"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn capture_driver_streams_bounded_frames_and_reports_statistics() {
        let frame =
            CapturedFrame::new(SystemTime::UNIX_EPOCH, LinkType::RAW, vec![1, 2, 3]).unwrap();
        let capture = ScriptedCapture {
            ready: Some(Ok(())),
            frames: VecDeque::from([Ok(Some(frame)), Ok(None)]),
            shutdown: Some(Ok(())),
            statistics: crate::io::CaptureStatistics {
                received_frames: 1,
                received_bytes: 3,
                ..crate::io::CaptureStatistics::default()
            },
        };
        let mut rendered = Vec::new();
        let outcome = drive_capture(
            capture,
            Duration::from_millis(10),
            CaptureQueueLimits::default(),
            test_capture_budget(),
            |frame, sequence| {
                rendered.push((sequence, frame.bytes.to_vec()));
                Ok(())
            },
        )
        .unwrap();

        assert_eq!(rendered, vec![(0, vec![1, 2, 3])]);
        assert_eq!(outcome.stats.packets_completed, 1);
        assert_eq!(outcome.stats.bytes, 3);
        assert_eq!(outcome.stats.capture.received_frames, 1);
    }

    #[test]
    fn zero_capture_window_is_a_clean_empty_timeout() {
        let capture = ScriptedCapture {
            ready: Some(Ok(())),
            frames: VecDeque::from([Err(LiveIoError::Capture {
                message: "must not be observed".to_owned(),
            })]),
            shutdown: Some(Ok(())),
            statistics: crate::io::CaptureStatistics::default(),
        };
        let outcome = drive_capture(
            capture,
            Duration::ZERO,
            CaptureQueueLimits::default(),
            test_capture_budget(),
            |_, _| unreachable!(),
        )
        .unwrap();
        assert_eq!(outcome.stats.packets_completed, 0);
    }

    #[test]
    fn readiness_and_cleanup_failures_remain_structured() {
        let capture = ScriptedCapture {
            ready: Some(Err(LiveIoError::Privilege {
                message: "capture permission denied".to_owned(),
            })),
            frames: VecDeque::new(),
            shutdown: Some(Err(LiveIoError::Capture {
                message: "capture worker did not join".to_owned(),
            })),
            statistics: crate::io::CaptureStatistics::default(),
        };
        let error = drive_capture(
            capture,
            Duration::from_millis(10),
            CaptureQueueLimits::default(),
            test_capture_budget(),
            |_, _| Ok(()),
        )
        .unwrap_err();

        assert_eq!(error.code, 4);
        assert_eq!(error.classification.code, "capability.privilege");
        assert_eq!(error.sequence, Some(0));
        assert_eq!(error.causes.len(), 2);
        assert!(error.causes[1].contains("did not join"));
    }

    #[test]
    fn capture_byte_budget_fails_before_emitting_the_excess_frame() {
        let frame =
            CapturedFrame::new(SystemTime::UNIX_EPOCH, LinkType::RAW, vec![1, 2, 3]).unwrap();
        let capture = ScriptedCapture {
            ready: Some(Ok(())),
            frames: VecDeque::from([Ok(Some(frame))]),
            shutdown: Some(Ok(())),
            statistics: crate::io::CaptureStatistics {
                received_frames: 1,
                received_bytes: 3,
                ..crate::io::CaptureStatistics::default()
            },
        };
        let mut emitted = false;
        let error = drive_capture(
            capture,
            Duration::from_millis(10),
            CaptureQueueLimits::default(),
            CaptureBudget {
                max_frames: 1,
                max_bytes: 2,
            },
            |_, _| {
                emitted = true;
                Ok(())
            },
        )
        .unwrap_err();

        assert!(!emitted);
        assert_eq!(error.code, 6);
        assert_eq!(error.classification.code, "policy.byte_limit");
        assert_eq!(error.sequence, Some(0));
    }

    #[test]
    fn pcapng_exchange_evidence_preserves_multiple_link_types() {
        let raw =
            CapturedFrame::new(SystemTime::UNIX_EPOCH, LinkType::RAW, vec![0x45, 0, 0, 0]).unwrap();
        let ethernet = CapturedFrame::new(
            SystemTime::UNIX_EPOCH + Duration::from_nanos(1),
            LinkType::ETHERNET,
            vec![0; 14],
        )
        .unwrap();
        let bytes =
            encode_capture_file(OutputFormat::Pcapng, [raw.clone(), ethernet.clone()]).unwrap();
        let mut reader = CaptureReader::new(std::io::Cursor::new(bytes)).unwrap();
        let decoded_raw = reader.next_frame().unwrap().unwrap();
        let decoded_ethernet = reader.next_frame().unwrap().unwrap();

        assert_eq!(decoded_raw.link_type, raw.link_type);
        assert_eq!(decoded_raw.bytes, raw.bytes);
        assert_eq!(decoded_raw.interface, Some(0));
        assert_eq!(decoded_ethernet.link_type, ethernet.link_type);
        assert_eq!(decoded_ethernet.bytes, ethernet.bytes);
        assert_eq!(decoded_ethernet.interface, Some(1));
        assert!(reader.next_frame().unwrap().is_none());

        let error = encode_capture_file(OutputFormat::Pcap, [raw, ethernet]).unwrap_err();
        assert_eq!(error.code, 5);
        assert!(error.message.contains("link type"));
    }

    #[test]
    fn replay_pcapng_evidence_preserves_source_timestamp_metadata() {
        let timestamp = SystemTime::UNIX_EPOCH
            .checked_sub(Duration::from_millis(500))
            .unwrap();
        let mut frame = CapturedFrame::new(timestamp, LinkType::RAW, vec![0x60; 40]).unwrap();
        frame.interface = Some(7);
        let evidence = crate::tools::ReplayFrameEvidence {
            source_sequence: 0,
            source_interface_id: Some(7),
            capture_interface: crate::io::CaptureInterface {
                link_type: LinkType::RAW,
                snap_len: 128,
                timestamp_resolution: crate::io::CaptureTimestampResolution::Binary(10),
                timestamp_offset: -1,
            },
            interface: InterfaceId {
                name: "test0".to_owned(),
                index: 1,
            },
            link_mode: LinkMode::Layer3,
            scheduled_delay: Duration::ZERO,
            bytes_sent: 40,
            frame: frame.clone(),
        };
        let mut writer = CaptureWriter::pcapng(Vec::new()).unwrap();
        let mut interfaces = Vec::new();
        write_replay_capture_evidence(
            &mut writer,
            CaptureFileFormat::PcapNg,
            &mut interfaces,
            evidence,
        )
        .unwrap();

        let mut reader = CaptureReader::new(std::io::Cursor::new(writer.into_inner())).unwrap();
        let decoded = reader.next_frame().unwrap().unwrap();
        frame.interface = Some(0);
        assert_eq!(decoded, frame);
        assert_eq!(
            reader.interfaces()[0],
            crate::io::CaptureInterface {
                link_type: LinkType::RAW,
                snap_len: 128,
                timestamp_resolution: crate::io::CaptureTimestampResolution::Binary(10),
                timestamp_offset: -1,
            }
        );
    }

    #[test]
    fn replay_policy_extracts_wire_destinations_even_from_malformed_network_layers() {
        let mut ipv4 = vec![0_u8; 20];
        ipv4[0] = 0x45;
        ipv4[16..20].copy_from_slice(&[8, 8, 8, 8]);
        let frame = CapturedFrame::new(SystemTime::UNIX_EPOCH, LinkType::RAW, ipv4).unwrap();
        assert_eq!(
            replay_wire_destinations(&frame),
            [IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))]
        );
        let mut authorizer = CliReplayAuthorizer {
            policy: TrafficPolicy::default(),
            registry: default_registry_arc().unwrap(),
            allow_malformed_live: true,
        };
        let error = authorizer.authorize(&frame, LinkMode::Layer3).unwrap_err();
        assert_eq!(error.classification().code, "policy.public_destination");

        let mut ethernet = vec![0_u8; 14 + 8 + 40 + 24];
        ethernet[12..14].copy_from_slice(&0x88a8_u16.to_be_bytes());
        ethernet[16..18].copy_from_slice(&0x8100_u16.to_be_bytes());
        ethernet[20..22].copy_from_slice(&0x86dd_u16.to_be_bytes());
        let ipv6 = 22;
        ethernet[ipv6] = 0x60;
        ethernet[ipv6 + 6] = 43;
        ethernet[ipv6 + 24..ipv6 + 40].copy_from_slice(&Ipv6Addr::LOCALHOST.octets());
        let srh = ipv6 + 40;
        ethernet[srh] = 59;
        ethernet[srh + 1] = 2;
        ethernet[srh + 2] = 4;
        ethernet[srh + 4] = 0;
        let public: Ipv6Addr = "2001:4860:4860::8888".parse().unwrap();
        ethernet[srh + 8..srh + 24].copy_from_slice(&public.octets());
        let frame =
            CapturedFrame::new(SystemTime::UNIX_EPOCH, LinkType::ETHERNET, ethernet).unwrap();
        assert_eq!(
            replay_wire_destinations(&frame),
            [IpAddr::V6(Ipv6Addr::LOCALHOST), IpAddr::V6(public)]
        );

        for mut unsupported in [vec![0_u8; 48], vec![0_u8; 40]] {
            unsupported[0] = 0x60;
            unsupported[6] = 43;
            unsupported[24..40].copy_from_slice(&Ipv6Addr::LOCALHOST.octets());
            if unsupported.len() == 48 {
                unsupported[40] = 59;
                unsupported[42] = 0;
            }
            let frame =
                CapturedFrame::new(SystemTime::UNIX_EPOCH, LinkType::RAW, unsupported).unwrap();
            assert!(replay_wire_policy(&frame).1);
            let mut authorizer = CliReplayAuthorizer {
                policy: TrafficPolicy::default(),
                registry: default_registry_arc().unwrap(),
                allow_malformed_live: true,
            };
            let error = authorizer.authorize(&frame, LinkMode::Layer3).unwrap_err();
            assert_eq!(
                error.classification().code,
                "capability.replay_routing_header"
            );
        }
    }
}
