// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

// Root parser, command hierarchy, and global CLI values.

use clap::{Parser, Subcommand, ValueEnum};
use packetcraftr::output;

use super::{
    BuildArgs, CaptureArgs, DissectArgs, DnsArgs, ExchangeArgs, FuzzArgs, ReadArgs, ReplayArgs,
    RouteArgs, ScanArgs, SendArgs, TracerouteArgs,
};

const ROOT_AFTER_HELP: &str = r#"Output formats:
  text    Human-readable summaries and diagnostics.
  json    One aggregate JSON document.
  ndjson  One JSON record per streamed event.
  hex     Exact frame bytes as hexadecimal text.
  raw     Exact frame bytes without text framing.
  pcap    Classic PCAP capture bytes.
  pcapng  PCAPNG capture bytes.

Output availability is command-specific. Machine formats never contain terminal colour codes.

Examples:
  packetcraftr build --packet 'raw(text=hello)'
  packetcraftr --output json dissect --hex '45000014000000004001f6e7c0000201c6336402'
  packetcraftr --output ndjson read capture.pcapng --max-frames 100

Run `packetcraftr <COMMAND> --help` for command-specific options and examples."#;
const BUILD_AFTER_HELP: &str = r#"Examples:
  packetcraftr build --packet 'raw(text=hello)'
  packetcraftr --output raw build --packet-file packet.json"#;
const DISSECT_AFTER_HELP: &str = r#"When neither --hex nor --file is supplied, raw frame bytes are read from standard input.

Examples:
  packetcraftr dissect --hex '45000014000000004001f6e7c0000201c6336402'
  packetcraftr --output json dissect --file frame.bin --link-type 1"#;
const READ_AFTER_HELP: &str = r#"Examples:
  packetcraftr read capture.pcapng --max-frames 100
  packetcraftr --output ndjson read capture.pcap"#;
const INTERFACES_AFTER_HELP: &str = r#"Examples:
  packetcraftr interfaces
  packetcraftr --output json interfaces"#;
const PLAN_AFTER_HELP: &str = r#"Route planning is passive: it performs no packet transmission.

Example:
  packetcraftr plan --packet 'ipv4(dst=192.0.2.53)/udp(dport=53)'"#;
const SEND_AFTER_HELP: &str = r#"Live transmission is policy-gated and may require native features, dependencies, and privileges.

Example:
  packetcraftr send --packet 'ipv4(dst=192.0.2.1)/icmpv4(type=8,code=0)'"#;
const EXCHANGE_AFTER_HELP: &str = r#"Live exchange is policy-gated and may require native features, dependencies, and privileges.

Example:
  packetcraftr exchange --packet 'ipv4(dst=192.0.2.1)/icmpv4(type=8,code=0)' --timeout-ms 1000"#;
const CAPTURE_AFTER_HELP: &str = r#"Live capture may require native features, dependencies, and privileges.

Example:
  packetcraftr capture --packet 'ipv4(dst=192.0.2.53)/udp(dport=53)' --timeout-ms 1000"#;
const REPLAY_AFTER_HELP: &str = r#"Replay is policy-gated and may require native features, dependencies, and privileges.

Examples:
  packetcraftr replay capture.pcapng --interface eth0 --timing immediate
  packetcraftr replay capture.pcap --interface 2 --rate 100"#;
const SCAN_AFTER_HELP: &str = r#"Examples:
  packetcraftr scan 192.0.2.10 --transport tcp --ports 22,80,443
  packetcraftr --output ndjson scan 198.51.100.10 --transport icmp"#;
const TRACEROUTE_AFTER_HELP: &str = r#"Examples:
  packetcraftr traceroute 192.0.2.1 --strategy icmp
  packetcraftr --output ndjson traceroute example.test --allow-hostname-resolution"#;
const DNS_AFTER_HELP: &str = r#"Examples:
  packetcraftr dns 192.0.2.53 example.test --type a
  packetcraftr --output json dns 192.0.2.53 _service._tcp.example.test --type srv"#;
const FUZZ_AFTER_HELP: &str = r#"Examples:
  packetcraftr fuzz --packet 'ipv4(dst=192.0.2.1)/udp(dport=9)/raw(text=hi)' --cases 16
  packetcraftr fuzz --packet-file packet.json --seed 7 --first-case 42 --cases 1"#;
const ROUTES_AFTER_HELP: &str = r#"Examples:
  packetcraftr routes
  packetcraftr --output json routes"#;

#[derive(Debug, Parser)]
#[command(
    name = "packetcraftr",
    bin_name = "packetcraftr",
    version,
    arg_required_else_help = true,
    about = "Reflective packet construction, dissection, capture, and network tools",
    long_about = "PacketcraftR builds and dissects arbitrary packet stacks with exact bytes, bounded parsing, passive route planning, and policy-gated live workflows. Native features, dependencies, and privileges determine which live paths are available.",
    after_long_help = ROOT_AFTER_HELP
)]
pub(in crate::cli) struct Cli {
    /// Select the output encoding; supported formats are command-specific.
    #[arg(
        long,
        global = true,
        value_enum,
        value_name = "FORMAT",
        help_heading = "Global options",
        default_value_t = CliOutputFormat::Text
    )]
    pub(in crate::cli) output: CliOutputFormat,
    /// Control terminal colours in human-facing output.
    #[arg(
        long,
        global = true,
        value_enum,
        value_name = "WHEN",
        help_heading = "Global options",
        default_value_t = CliColorChoice::Auto
    )]
    pub(in crate::cli) color: CliColorChoice,
    #[command(subcommand)]
    pub(in crate::cli) command: Command,
}

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
pub(in crate::cli) enum CliOutputFormat {
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

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
pub(in crate::cli) enum CliColorChoice {
    /// Use colour only when the destination supports it.
    #[default]
    Auto,
    /// Always emit colour for human-facing output.
    Always,
    /// Never emit colour.
    Never,
}

impl std::fmt::Display for CliColorChoice {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Auto => "auto",
            Self::Always => "always",
            Self::Never => "never",
        })
    }
}

impl CliColorChoice {
    pub(in crate::cli) fn write_global(self) {
        let choice = match self {
            Self::Auto => anstream::ColorChoice::Auto,
            Self::Always => anstream::ColorChoice::Always,
            Self::Never => anstream::ColorChoice::Never,
        };
        choice.write_global();
    }
}

#[derive(Debug, Subcommand)]
pub(in crate::cli) enum Command {
    /// Build exact packet bytes from an expression or document.
    #[command(after_long_help = BUILD_AFTER_HELP)]
    Build(BuildArgs),
    /// Decode a frame with bounded, registry-driven dissection.
    #[command(after_long_help = DISSECT_AFTER_HELP)]
    Dissect(DissectArgs),
    /// Stream frames from a classic PCAP or PCAPNG file.
    #[command(after_long_help = READ_AFTER_HELP)]
    Read(ReadArgs),
    /// Enumerate local interfaces.
    #[command(after_long_help = INTERFACES_AFTER_HELP)]
    Interfaces,
    /// Passively select route, source, MTU, and link mode.
    #[command(after_long_help = PLAN_AFTER_HELP)]
    Plan(RouteArgs),
    /// Transmit a packet under traffic policy.
    #[command(after_long_help = SEND_AFTER_HELP)]
    Send(SendArgs),
    /// Capture-ready request/response exchange.
    #[command(after_long_help = EXCHANGE_AFTER_HELP)]
    Exchange(ExchangeArgs),
    /// Stream live captured frames.
    #[command(after_long_help = CAPTURE_AFTER_HELP)]
    Capture(CaptureArgs),
    /// Replay a PCAP/PCAPNG stream.
    #[command(after_long_help = REPLAY_AFTER_HELP)]
    Replay(ReplayArgs),
    /// Run a structured network scan.
    #[command(after_long_help = SCAN_AFTER_HELP)]
    Scan(ScanArgs),
    /// Run bounded, policy-gated traceroute probes.
    #[command(
        long_about = "Run bounded, policy-gated traceroute probes. UDP starts at --port and increments the destination port for every probe; TCP keeps --port fixed. Each hop sends its attempts as one burst and shares one --timeout-ms response window. Traceroute supports text, JSON, and NDJSON output. Public destinations and hostname resolution require their respective explicit policy options.",
        after_long_help = TRACEROUTE_AFTER_HELP
    )]
    Traceroute(TracerouteArgs),
    /// Run a structured DNS operation.
    #[command(after_long_help = DNS_AFTER_HELP)]
    Dns(DnsArgs),
    /// Run bounded field-aware packet fuzzing.
    #[command(after_long_help = FUZZ_AFTER_HELP)]
    Fuzz(FuzzArgs),
    /// Enumerate passive interface-bound route decisions.
    #[command(after_long_help = ROUTES_AFTER_HELP)]
    Routes,
}
