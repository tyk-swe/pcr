// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Command-line slices that own their arguments, conversion, execution, and rendering.

use clap::Subcommand;
use packetcraftr::output;

use crate::errors::CliError;

mod build;
mod capture;
mod dissect;
mod dns;
mod exchange;
mod expert;
mod follow;
mod fuzz;
mod interfaces;
mod offline_analysis;
mod plan;
mod protocols;
mod read;
mod replay;
mod routes;
mod scan;
mod send;
mod stats;
mod traceroute;

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// Build exact packet bytes from an expression or document.
    #[command(after_long_help = build::arguments::AFTER_LONG_HELP)]
    Build(build::arguments::BuildArgs),
    /// Decode a frame with bounded, registry-driven dissection.
    #[command(after_long_help = dissect::arguments::AFTER_LONG_HELP)]
    Dissect(dissect::arguments::DissectArgs),
    /// List built-in protocols or describe one protocol.
    #[command(after_long_help = protocols::arguments::AFTER_LONG_HELP)]
    Protocols(protocols::arguments::ProtocolsArgs),
    /// Stream frames from a classic PCAP or PCAPNG file.
    #[command(after_long_help = read::arguments::AFTER_LONG_HELP)]
    Read(read::arguments::ReadArgs),
    /// Enumerate local interfaces.
    #[command(after_long_help = interfaces::AFTER_LONG_HELP)]
    Interfaces,
    /// Passively select route, source, MTU, and link mode.
    #[command(after_long_help = plan::arguments::AFTER_LONG_HELP)]
    Plan(plan::arguments::PlanArgs),
    /// Transmit a packet under traffic policy.
    #[command(after_long_help = send::arguments::AFTER_LONG_HELP)]
    Send(send::arguments::SendArgs),
    /// Capture-ready request/response exchange.
    #[command(after_long_help = exchange::arguments::AFTER_LONG_HELP)]
    Exchange(exchange::arguments::ExchangeArgs),
    /// Stream live captured frames.
    #[command(after_long_help = capture::arguments::AFTER_LONG_HELP)]
    Capture(capture::arguments::CaptureArgs),
    /// Report protocol health findings over a capture file.
    #[command(after_long_help = expert::arguments::AFTER_LONG_HELP)]
    Expert(expert::arguments::ExpertArgs),
    /// Extract one conversation's payload from a capture file.
    #[command(after_long_help = follow::arguments::AFTER_LONG_HELP)]
    Follow(follow::arguments::FollowArgs),
    /// Replay a PCAP/PCAPNG stream.
    #[command(after_long_help = replay::arguments::AFTER_LONG_HELP)]
    Replay(replay::arguments::ReplayArgs),
    /// Run a structured network scan.
    #[command(after_long_help = scan::arguments::AFTER_LONG_HELP)]
    Scan(scan::arguments::ScanArgs),
    /// Compute aggregate statistics over a capture file.
    #[command(after_long_help = stats::arguments::AFTER_LONG_HELP)]
    Stats(stats::arguments::StatsArgs),
    /// Run bounded, policy-gated traceroute probes.
    #[command(
        long_about = traceroute::arguments::LONG_ABOUT,
        after_long_help = traceroute::arguments::AFTER_LONG_HELP
    )]
    Traceroute(traceroute::arguments::TracerouteArgs),
    /// Run a structured DNS operation.
    #[command(after_long_help = dns::arguments::AFTER_LONG_HELP)]
    Dns(dns::arguments::DnsArgs),
    /// Run bounded field-aware packet fuzzing.
    #[command(after_long_help = fuzz::arguments::AFTER_LONG_HELP)]
    Fuzz(fuzz::arguments::FuzzArgs),
    /// Enumerate passive interface-bound route decisions.
    #[command(after_long_help = routes::AFTER_LONG_HELP)]
    Routes,
}

impl Command {
    pub(crate) const fn name(&self) -> output::contract::Command {
        match self {
            Self::Build(_) => output::contract::Command::Build,
            Self::Dissect(_) => output::contract::Command::Dissect,
            Self::Protocols(_) => output::contract::Command::Protocols,
            Self::Read(_) => output::contract::Command::Read,
            Self::Interfaces => output::contract::Command::Interfaces,
            Self::Plan(_) => output::contract::Command::Plan,
            Self::Send(_) => output::contract::Command::Send,
            Self::Exchange(_) => output::contract::Command::Exchange,
            Self::Capture(_) => output::contract::Command::Capture,
            Self::Expert(_) => output::contract::Command::Expert,
            Self::Follow(_) => output::contract::Command::Follow,
            Self::Replay(_) => output::contract::Command::Replay,
            Self::Scan(_) => output::contract::Command::Scan,
            Self::Stats(_) => output::contract::Command::Stats,
            Self::Traceroute(_) => output::contract::Command::Traceroute,
            Self::Dns(_) => output::contract::Command::Dns,
            Self::Fuzz(_) => output::contract::Command::Fuzz,
            Self::Routes => output::contract::Command::Routes,
        }
    }

    pub(super) fn run(self, format: output::contract::Format) -> Result<(), CliError> {
        self.name()
            .require_format(format)
            .map_err(CliError::classified)?;
        match self {
            Self::Build(arguments) => build::run(arguments, format),
            Self::Dissect(arguments) => dissect::run(arguments, format),
            Self::Protocols(arguments) => protocols::run(arguments, format),
            Self::Read(arguments) => read::run(arguments, format),
            Self::Interfaces => interfaces::run(format),
            Self::Plan(arguments) => plan::run(arguments, format),
            Self::Send(arguments) => send::run(arguments, format),
            Self::Capture(arguments) => capture::run(arguments, format),
            Self::Expert(arguments) => expert::run(arguments, format),
            Self::Follow(arguments) => follow::run(arguments, format),
            Self::Exchange(arguments) => exchange::run(arguments, format),
            Self::Replay(arguments) => replay::run(arguments, format),
            Self::Scan(arguments) => scan::run(arguments, format),
            Self::Stats(arguments) => stats::run(arguments, format),
            Self::Traceroute(arguments) => traceroute::run(arguments, format),
            Self::Dns(arguments) => dns::run(arguments, format),
            Self::Fuzz(arguments) => fuzz::run(arguments, format),
            Self::Routes => routes::run(format),
        }
    }
}
