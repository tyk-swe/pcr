// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! One module per CLI command, plus the pieces several of them share.
//!
//! A command that fits in one screen stays in one file (`interfaces.rs`,
//! `routes.rs`, `send.rs`). A command splits into `arguments.rs`, `rendering.rs`,
//! and sometimes `conversion.rs` once those parts stop fitting together, which
//! is most of the live and capture-reading commands. [`format`] narrows the
//! global `--output` choice to what each command publishes; [`execution`] and
//! [`target_workflow`] hold what the probing commands share, and
//! [`render_aggregate_rows`] renders the Text/Json match the aggregate
//! commands share.

use packetcraftr::core::error::Kind;

use std::sync::Arc;

use clap::Subcommand;
use packetcraftr::{core, output};

use crate::errors::CliError;
use crate::rendering::{StreamEncoder, emit_aggregate, write_stdout_line};

mod build;
mod capture;
mod dissect;
mod dns;
mod exchange;
mod execution;
mod expert;
mod follow;
mod format;
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
mod target_workflow;
mod tls;
mod traceroute;

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// Build exact packet bytes from an expression or document.
    #[command(after_long_help = build::arguments::AFTER_LONG_HELP)]
    Build(build::arguments::Args),
    /// Decode a frame with bounded, registry-driven dissection.
    #[command(after_long_help = dissect::arguments::AFTER_LONG_HELP)]
    Dissect(dissect::arguments::Args),
    /// List built-in protocols or describe one protocol.
    #[command(after_long_help = protocols::arguments::AFTER_LONG_HELP)]
    Protocols(protocols::arguments::Args),
    /// Stream frames from a classic PCAP or PCAPNG file.
    #[command(after_long_help = read::arguments::AFTER_LONG_HELP)]
    Read(read::arguments::Args),
    /// Enumerate local interfaces.
    #[command(after_long_help = interfaces::AFTER_LONG_HELP)]
    Interfaces(interfaces::Args),
    /// Passively select route, source, MTU, and link mode.
    #[command(after_long_help = plan::arguments::AFTER_LONG_HELP)]
    Plan(plan::arguments::Args),
    /// Transmit a packet under traffic policy.
    #[command(after_long_help = send::AFTER_LONG_HELP)]
    Send(send::SendArgs),
    /// Capture-ready request/response exchange.
    #[command(after_long_help = exchange::arguments::AFTER_LONG_HELP)]
    Exchange(exchange::arguments::Args),
    /// Stream live captured frames.
    #[command(after_long_help = capture::arguments::AFTER_LONG_HELP)]
    Capture(capture::arguments::Args),
    /// Report protocol health findings over a capture file.
    #[command(after_long_help = expert::arguments::AFTER_LONG_HELP)]
    Expert(expert::arguments::Args),
    /// Extract one conversation's payload from a capture file.
    #[command(after_long_help = follow::arguments::AFTER_LONG_HELP)]
    Follow(follow::arguments::Args),
    /// Replay a PCAP/PCAPNG stream.
    #[command(after_long_help = replay::arguments::AFTER_LONG_HELP)]
    Replay(replay::arguments::Args),
    /// Run a structured network scan.
    #[command(after_long_help = scan::arguments::AFTER_LONG_HELP)]
    Scan(scan::arguments::Args),
    /// Compute aggregate statistics over a capture file.
    #[command(after_long_help = stats::arguments::AFTER_LONG_HELP)]
    Stats(stats::arguments::Args),
    /// Assemble TLS handshake sessions from a capture file.
    #[command(after_long_help = tls::arguments::AFTER_LONG_HELP)]
    Tls(tls::arguments::Args),
    /// Run bounded, policy-gated traceroute probes.
    #[command(
        long_about = traceroute::arguments::LONG_ABOUT,
        after_long_help = traceroute::arguments::AFTER_LONG_HELP
    )]
    Traceroute(traceroute::arguments::Args),
    /// Run DNS with bounded UDP-to-TCP fallback.
    #[command(
        long_about = dns::arguments::LONG_ABOUT,
        after_long_help = dns::arguments::AFTER_LONG_HELP
    )]
    Dns(dns::arguments::Args),
    /// Run bounded field-aware packet fuzzing.
    #[command(after_long_help = fuzz::arguments::AFTER_LONG_HELP)]
    Fuzz(fuzz::arguments::Args),
    /// Enumerate passive interface-bound route decisions.
    #[command(after_long_help = routes::AFTER_LONG_HELP)]
    Routes(routes::Args),
}

impl Command {
    pub(crate) const fn kind(&self) -> output::contract::Command {
        match self {
            Self::Build(_) => output::contract::Command::Build,
            Self::Dissect(_) => output::contract::Command::Dissect,
            Self::Protocols(_) => output::contract::Command::Protocols,
            Self::Read(_) => output::contract::Command::Read,
            Self::Interfaces(_) => output::contract::Command::Interfaces,
            Self::Plan(_) => output::contract::Command::Plan,
            Self::Send(_) => output::contract::Command::Send,
            Self::Exchange(_) => output::contract::Command::Exchange,
            Self::Capture(_) => output::contract::Command::Capture,
            Self::Expert(_) => output::contract::Command::Expert,
            Self::Follow(_) => output::contract::Command::Follow,
            Self::Replay(_) => output::contract::Command::Replay,
            Self::Scan(_) => output::contract::Command::Scan,
            Self::Stats(_) => output::contract::Command::Stats,
            Self::Tls(_) => output::contract::Command::Tls,
            Self::Traceroute(_) => output::contract::Command::Traceroute,
            Self::Dns(_) => output::contract::Command::Dns,
            Self::Fuzz(_) => output::contract::Command::Fuzz,
            Self::Routes(_) => output::contract::Command::Routes,
        }
    }

    /// Dispatches to the selected command.
    ///
    /// Each command's `run` narrows the global format first, so an unsupported
    /// `--output` is refused before any work is done.
    pub(crate) fn run(
        self,
        format: output::contract::Format,
        stream: &StreamEncoder,
    ) -> Result<(), CliError> {
        match self {
            Self::Build(arguments) => build::run(arguments, format),
            Self::Dissect(arguments) => dissect::run(arguments, format),
            Self::Protocols(arguments) => protocols::run(arguments, format),
            Self::Read(arguments) => read::run(arguments, format, stream),
            Self::Interfaces(arguments) => interfaces::run(arguments, format),
            Self::Plan(arguments) => plan::run(arguments, format),
            Self::Send(arguments) => send::run(arguments, format),
            Self::Capture(arguments) => capture::run(arguments, format, stream),
            Self::Expert(arguments) => expert::run(arguments, format, stream),
            Self::Follow(arguments) => follow::run(arguments, format, stream),
            Self::Exchange(arguments) => exchange::run(arguments, format, stream),
            Self::Replay(arguments) => replay::run(arguments, format, stream),
            Self::Scan(arguments) => scan::run(arguments, format, stream),
            Self::Stats(arguments) => stats::run(arguments, format),
            Self::Tls(arguments) => tls::run(arguments, format, stream),
            Self::Traceroute(arguments) => traceroute::run(arguments, format, stream),
            Self::Dns(arguments) => dns::run(arguments, format, stream),
            Self::Fuzz(arguments) => fuzz::run(arguments, format, stream),
            Self::Routes(arguments) => routes::run(arguments, format),
        }
    }
}

fn registry() -> Result<Arc<core::registry::Registry>, CliError> {
    registry_with_tls_ports(&[])
}

/// Renders one aggregate row per text line, or the whole result as one JSON
/// document.
fn render_aggregate_rows<T, R: serde::Serialize>(
    command: output::contract::Command,
    format: format::AggregateFormat,
    result: &R,
    rows: &[T],
    line: impl Fn(&T) -> String,
) -> Result<(), CliError> {
    match format {
        format::AggregateFormat::Text => {
            for row in rows {
                write_stdout_line(format_args!("{}", line(row)))?;
            }
            Ok(())
        }
        format::AggregateFormat::Json => emit_aggregate(command, result, Vec::new()),
    }
}

/// The built-in registry with extra TCP ports dissected as TLS.
///
/// `--tls-port` reaches every command that dissects capture bytes, so the
/// per-frame view of `read` and `dissect` agrees with the assembled view of
/// `tls`.
fn registry_with_tls_ports(ports: &[u16]) -> Result<Arc<core::registry::Registry>, CliError> {
    core::protocol::builtin::registry_with_tls_ports(ports)
        .map(Arc::new)
        .map_err(|source| {
            CliError::new(
                Kind::Internal,
                format!("built-in registry invariant failed: {source}"),
            )
        })
}

fn increment_counter(value: u64, counter: &'static str) -> Result<u64, CliError> {
    value
        .checked_add(1)
        .ok_or_else(|| CliError::new(Kind::Internal, format!("{counter} overflowed")))
}
