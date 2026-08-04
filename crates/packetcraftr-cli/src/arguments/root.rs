// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use clap::{Parser, Subcommand, ValueEnum};
use packetcraftr::output;

use super::{
    BuildArgs, CaptureArgs, DissectArgs, DnsArgs, ExchangeArgs, ExpertArgs, FollowArgs, FuzzArgs,
    PlanArgs, ProtocolsArgs, ReadArgs, ReplayArgs, ScanArgs, SendArgs, StatsArgs, TracerouteArgs,
    build, capture, dissect, dns, exchange, expert, follow, fuzz, passive, plan, protocols, read,
    replay, scan, send, stats, traceroute,
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
pub(crate) struct Cli {
    /// Select the output encoding; supported formats are command-specific.
    #[arg(
        long,
        global = true,
        value_enum,
        value_name = "FORMAT",
        help_heading = "Global options",
        default_value_t = CliOutputFormat::Text
    )]
    pub(crate) output: CliOutputFormat,
    /// Control terminal colours in human-facing output.
    #[arg(
        long,
        global = true,
        value_enum,
        value_name = "WHEN",
        help_heading = "Global options",
        default_value_t = CliColorChoice::Auto
    )]
    pub(crate) color: CliColorChoice,
    #[command(subcommand)]
    pub(crate) command: Command,
}

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
pub(crate) enum CliOutputFormat {
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
pub(crate) enum CliColorChoice {
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
    pub(crate) fn write_global(self) {
        let choice = match self {
            Self::Auto => anstream::ColorChoice::Auto,
            Self::Always => anstream::ColorChoice::Always,
            Self::Never => anstream::ColorChoice::Never,
        };
        choice.write_global();
    }
}

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// Build exact packet bytes from an expression or document.
    #[command(after_long_help = build::AFTER_LONG_HELP)]
    Build(BuildArgs),
    /// Decode a frame with bounded, registry-driven dissection.
    #[command(after_long_help = dissect::AFTER_LONG_HELP)]
    Dissect(DissectArgs),
    /// List built-in protocols or describe one protocol.
    #[command(after_long_help = protocols::AFTER_LONG_HELP)]
    Protocols(ProtocolsArgs),
    /// Stream frames from a classic PCAP or PCAPNG file.
    #[command(after_long_help = read::AFTER_LONG_HELP)]
    Read(ReadArgs),
    /// Enumerate local interfaces.
    #[command(after_long_help = passive::INTERFACES_AFTER_HELP)]
    Interfaces,
    /// Passively select route, source, MTU, and link mode.
    #[command(after_long_help = plan::AFTER_LONG_HELP)]
    Plan(PlanArgs),
    /// Transmit a packet under traffic policy.
    #[command(after_long_help = send::AFTER_LONG_HELP)]
    Send(SendArgs),
    /// Capture-ready request/response exchange.
    #[command(after_long_help = exchange::AFTER_LONG_HELP)]
    Exchange(ExchangeArgs),
    /// Stream live captured frames.
    #[command(after_long_help = capture::AFTER_LONG_HELP)]
    Capture(CaptureArgs),
    /// Report protocol health findings over a capture file.
    #[command(after_long_help = expert::AFTER_LONG_HELP)]
    Expert(ExpertArgs),
    /// Extract one conversation's payload from a capture file.
    #[command(after_long_help = follow::AFTER_LONG_HELP)]
    Follow(FollowArgs),
    /// Replay a PCAP/PCAPNG stream.
    #[command(after_long_help = replay::AFTER_LONG_HELP)]
    Replay(ReplayArgs),
    /// Run a structured network scan.
    #[command(after_long_help = scan::AFTER_LONG_HELP)]
    Scan(ScanArgs),
    /// Compute aggregate statistics over a capture file.
    #[command(after_long_help = stats::AFTER_LONG_HELP)]
    Stats(StatsArgs),
    /// Run bounded, policy-gated traceroute probes.
    #[command(
        long_about = traceroute::LONG_ABOUT,
        after_long_help = traceroute::AFTER_LONG_HELP
    )]
    Traceroute(TracerouteArgs),
    /// Run a structured DNS operation.
    #[command(after_long_help = dns::AFTER_LONG_HELP)]
    Dns(DnsArgs),
    /// Run bounded field-aware packet fuzzing.
    #[command(after_long_help = fuzz::AFTER_LONG_HELP)]
    Fuzz(FuzzArgs),
    /// Enumerate passive interface-bound route decisions.
    #[command(after_long_help = passive::ROUTES_AFTER_HELP)]
    Routes,
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::{Cli, CliColorChoice};

    #[test]
    fn global_colour_choice_parses_before_or_after_the_subcommand() {
        for arguments in [
            [
                "packetcraftr",
                "--color",
                "always",
                "build",
                "--packet",
                "raw()",
            ],
            [
                "packetcraftr",
                "build",
                "--packet",
                "raw()",
                "--color",
                "always",
            ],
        ] {
            let cli = Cli::try_parse_from(arguments).unwrap();
            assert!(matches!(cli.color, CliColorChoice::Always));
        }
    }

    #[test]
    fn help_uses_the_frozen_cross_platform_binary_name() {
        let error = Cli::try_parse_from(["packetcraftr.exe", "build", "--help"]).unwrap_err();
        assert_eq!(error.kind(), clap::error::ErrorKind::DisplayHelp);
        let help = error.to_string();
        assert!(help.contains("Usage: packetcraftr build [OPTIONS]"));
        assert!(!help.contains("packetcraftr.exe"));
    }
}
