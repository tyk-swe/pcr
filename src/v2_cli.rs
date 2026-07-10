// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#![forbid(unsafe_code)]

use std::fs::File;
use std::io::{self, IsTerminal, Read, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use clap::{Args, Parser, Subcommand, ValueEnum};
use serde::Serialize;

use crate::client::{
    Client, ExchangeOptions, LiveTarget, SendOptions, SystemHostnameResolver, TrafficPolicy,
    TrafficPolicyError,
};
use crate::core::{
    parse_packet_expression, BuildContext, BuildMode, BuildOptions, Builder, DecodeOptions,
    Dissector, DocumentFormat, ExpressionOptions, Packet, PacketDocument, PacketTemplate,
    DEFAULT_MAX_DOCUMENT_BYTES, DEFAULT_MAX_LAYERS,
};
use crate::error::{ClassifiedError, ErrorClassification, FailureKind};
use crate::io::{
    CaptureFileFormat, CaptureOverflowPolicy, CaptureProvider, CaptureQueueLimits, CaptureReader,
    CaptureSession, CaptureWriter, CapturedFrame, DispatchPacketIo, InterfaceId, InterfaceProvider,
    LinkMode, LinkType, LiveIoError, PacketIo, RouteProvider, SystemCaptureProvider,
    SystemInterfaceProvider, SystemLayer2Io, SystemLayer3Io, SystemNeighborResolver,
    SystemRouteProvider,
};
use crate::output::{
    AggregateErrorOutput, AggregateOutput, BuildCommandResult, CaptureFrameCommandResult,
    CommandName, DissectCommandResult, ExchangeCommandResult, ExchangeStreamCommandResult,
    FrameOutput, InterfacesCommandResult, OutputContractError, OutputError, OutputFormat,
    PlanCommandResult, ReadFrameCommandResult, RoutesCommandResult, SendCommandResult,
    StreamErrorRecord, StreamRecord,
};

#[derive(Debug, Parser)]
#[command(
    name = "packetcraftr",
    version,
    about = "Reflective packet construction, dissection, capture, and network tools",
    long_about = "PacketcraftR v0.2 alpha: arbitrary packet stacks, strict/permissive exact building, bounded dissection, passive route planning, and policy-gated live send/capture/exchange workflows. Native features, dependencies, and privileges determine which live paths are available."
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
    Replay(UnavailableArgs),
    /// Run a structured network scan.
    Scan(UnavailableArgs),
    /// Run structured traceroute probes.
    Traceroute(UnavailableArgs),
    /// Run a structured DNS operation.
    Dns(UnavailableArgs),
    /// Run bounded field-aware packet fuzzing.
    Fuzz(UnavailableArgs),
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
}

#[derive(Debug, Args)]
struct UnavailableArgs {
    /// Packet expression (accepted for forward-compatible scripts).
    #[arg(long)]
    packet: Option<String>,
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
        Command::Replay(arguments)
        | Command::Scan(arguments)
        | Command::Traceroute(arguments)
        | Command::Dns(arguments)
        | Command::Fuzz(arguments) => {
            let _ = arguments.packet;
            Err(CliError::new(
                4,
                "this live/tool workflow is capability-gated in 0.2.0-alpha.1",
            ))
        }
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
            return Err(CliError::classified(LiveIoError::CaptureQueueOverflow {
                dropped_frames: statistics.dropped_frames,
                dropped_bytes: statistics.dropped_bytes,
                overflow_events: statistics.overflow_events,
            })
            .at_sequence(frames));
        }
        diagnostics.push(crate::core::Diagnostic::warning(
            "capture.queue_overflow",
            format!(
                "capture backend reported {} overflow event(s), {} dropped frame(s), and {} dropped byte(s) under {:?}",
                statistics.overflow_events,
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
    let file = File::open(&arguments.path).map_err(|source| {
        CliError::new(
            5,
            format!("open {} failed: {source}", arguments.path.display()),
        )
    })?;
    let mut reader =
        CaptureReader::new(file).map_err(|source| CliError::new(3, source.to_string()))?;
    let mut sequence = 0_u64;
    loop {
        let Some(frame) = reader
            .next_frame()
            .map_err(|source| CliError::new(3, source.to_string()).at_sequence(sequence))?
        else {
            return Ok(());
        };
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
        sequence = sequence.checked_add(1).ok_or_else(|| {
            CliError::classified(OutputContractError::SequenceOverflow).at_sequence(sequence)
        })?;
    }
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
        return PacketDocument::parse(&input, format, DEFAULT_MAX_DOCUMENT_BYTES)
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
}
