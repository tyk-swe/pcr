// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! One module per CLI command, plus the pieces several of them share.
//!
//! A command that fits in one screen stays in one file (`interfaces.rs`,
//! `routes.rs`, `send.rs`). A command splits into `arguments.rs`, `rendering.rs`,
//! and sometimes `conversion.rs` once those parts stop fitting together, which
//! is most of the live and capture-reading commands. [`format`] narrows the
//! global `--output` choice to what each command publishes; [`execution`] and
//! [`target_workflow`] hold what the probing commands share.

use std::sync::Arc;

use clap::Subcommand;
use packetcraftr::{core, output};

use crate::errors::CliError;
use crate::rendering::StreamEncoder;

mod build;
mod capture;
mod convert;
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
mod schema;
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
    /// Convert v1 packet documents to v2 format.
    #[command(after_long_help = convert::arguments::AFTER_LONG_HELP)]
    Convert(convert::arguments::Args),
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
    Interfaces,
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
    /// Run a structured DNS operation.
    #[command(after_long_help = dns::arguments::AFTER_LONG_HELP)]
    Dns(dns::arguments::Args),
    /// Run bounded field-aware packet fuzzing.
    #[command(after_long_help = fuzz::arguments::AFTER_LONG_HELP)]
    Fuzz(fuzz::arguments::Args),
    /// Enumerate passive interface-bound route decisions.
    #[command(after_long_help = routes::AFTER_LONG_HELP)]
    Routes,
    /// Emit a JSON schema for packet contracts.
    #[command(after_long_help = schema::arguments::AFTER_LONG_HELP)]
    Schema(schema::arguments::Args),
}

impl Command {
    pub(crate) const fn kind(&self) -> Option<output::contract::Command> {
        match self {
            Self::Build(_) => Some(output::contract::Command::Build),
            Self::Convert(_) => Some(output::contract::Command::Convert),
            Self::Dissect(_) => Some(output::contract::Command::Dissect),
            Self::Protocols(_) => Some(output::contract::Command::Protocols),
            Self::Read(_) => Some(output::contract::Command::Read),
            Self::Interfaces => Some(output::contract::Command::Interfaces),
            Self::Plan(_) => Some(output::contract::Command::Plan),
            Self::Send(_) => Some(output::contract::Command::Send),
            Self::Exchange(_) => Some(output::contract::Command::Exchange),
            Self::Capture(_) => Some(output::contract::Command::Capture),
            Self::Expert(_) => Some(output::contract::Command::Expert),
            Self::Follow(_) => Some(output::contract::Command::Follow),
            Self::Replay(_) => Some(output::contract::Command::Replay),
            Self::Scan(_) => Some(output::contract::Command::Scan),
            Self::Stats(_) => Some(output::contract::Command::Stats),
            Self::Tls(_) => Some(output::contract::Command::Tls),
            Self::Traceroute(_) => Some(output::contract::Command::Traceroute),
            Self::Dns(_) => Some(output::contract::Command::Dns),
            Self::Fuzz(_) => Some(output::contract::Command::Fuzz),
            Self::Routes => Some(output::contract::Command::Routes),
            Self::Schema(_) => None,
        }
    }

    pub(super) fn run(
        self,
        format: output::contract::Format,
        stream: &mut StreamEncoder,
    ) -> Result<(), CliError> {
        if let Some(kind) = self.kind() {
            kind.require_format(format).map_err(CliError::classified)?;
        }
        match self {
            Self::Build(arguments) => build::run(arguments, format),
            Self::Convert(arguments) => convert::run(arguments, format),
            Self::Dissect(arguments) => dissect::run(arguments, format),
            Self::Protocols(arguments) => protocols::run(arguments, format),
            Self::Read(arguments) => read::run(arguments, format, stream),
            Self::Interfaces => interfaces::run(format),
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
            Self::Routes => routes::run(format),
            Self::Schema(arguments) => schema::run(arguments, format),
        }
    }
}

fn registry() -> Result<Arc<core::registry::Registry>, CliError> {
    registry_with_tls_ports(&[])
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
            CliError::new(70, format!("built-in registry invariant failed: {source}"))
        })
}

fn increment_counter(value: u64, counter: &'static str) -> Result<u64, CliError> {
    value
        .checked_add(1)
        .ok_or_else(|| CliError::new(70, format!("{counter} overflowed")))
}
