// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! One module per CLI command, plus the pieces several of them share.
//!
//! Each command owns its `Args`: compact commands keep them beside `run` in a
//! single file (`interfaces.rs`, `routes.rs`), while larger commands split
//! into `arguments.rs`, `rendering.rs`, and sometimes `conversion.rs` — most
//! of the live and capture-reading commands. Clap groups several commands
//! share live under `command_options` instead (`SendArgs` serves `send` and
//! `exchange`). [`Command::run`] validates the global `--output`
//! choice before dispatch; [`execution`] composes the live probe providers, and
//! [`render_aggregate_rows`] renders the Text/Json match the aggregate
//! commands share.

use packetcraftr_cli::output::contract::Format;
use packetcraftr_core::error::Kind;

use clap::Subcommand;
use packetcraftr_cli::output;

use crate::errors::CliError;
use crate::rendering::{StreamEncoder, emit_aggregate, write_stdout_line};

mod application_output;
mod build;
mod capture;
mod dissect;
mod dns;
mod dns_read;
// `startup` dispatches documentation generation before contract stream setup.
pub(crate) mod documentation;
mod exchange;
mod execution;
mod expert;
mod export;
mod follow;
mod fragment;
mod fuzz;
mod http;
mod interfaces;
mod merge;
mod offline_analysis;
mod plan;
mod projection;
mod protocols;
mod read;
mod replay;
mod rewrite;
mod routes;
mod scan;
mod send;
mod stats;
mod tls;
mod traceroute;

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// Merge time-ordered captures into scoped PCAPNG.
    Merge(merge::Args),
    /// Explicitly split a complete IPv4/IPv6 recipe into bounded fragments.
    Fragment(fragment::Args),
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
    #[command(after_long_help = send::arguments::AFTER_LONG_HELP)]
    Send(send::arguments::Args),
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
    /// Run bounded DNS over UDP, TCP, or UDP with TCP fallback.
    #[command(
        long_about = dns::arguments::LONG_ABOUT,
        after_long_help = dns::arguments::AFTER_LONG_HELP
    )]
    Dns(dns::arguments::Args),
    /// Inspect captured UDP/TCP DNS messages and transaction evidence.
    DnsRead(dns_read::Args),
    /// Inspect cleartext HTTP/1 messages over captured TCP streams.
    Http(http::Args),
    /// Export streams and reassembled IP datagrams with their physical dependencies.
    Export(export::Args),
    /// Rewrite capture headers with checked lengths and transport checksums.
    Rewrite(rewrite::Args),
    /// Run bounded field-aware packet fuzzing.
    #[command(after_long_help = fuzz::arguments::AFTER_LONG_HELP)]
    Fuzz(fuzz::arguments::Args),
    /// Enumerate passive interface-bound route decisions.
    #[command(after_long_help = routes::AFTER_LONG_HELP)]
    Routes(routes::Args),
    /// Generate shell completions and man pages under a directory.
    Documentation(documentation::Args),
}

impl Command {
    /// The published machine-output kind; `None` for commands that generate
    /// files instead of producing contract output.
    pub(crate) const fn kind(&self) -> Option<output::contract::Command> {
        Some(match self {
            Self::Merge(_) => output::contract::Command::Merge,
            Self::Fragment(_) => output::contract::Command::Fragment,
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
            Self::DnsRead(_) => output::contract::Command::DnsRead,
            Self::Http(_) => output::contract::Command::Http,
            Self::Export(_) => output::contract::Command::Export,
            Self::Rewrite(_) => output::contract::Command::Rewrite,
            Self::Fuzz(_) => output::contract::Command::Fuzz,
            Self::Routes(_) => output::contract::Command::Routes,
            Self::Documentation(_) => return None,
        })
    }

    fn publication_duration(&self) -> Option<std::time::Duration> {
        let millis = match self {
            Self::Expert(args) => args.limits.max_duration_ms,
            Self::Follow(args) => args.limits.max_duration_ms,
            Self::Tls(args) => args.limits.max_duration_ms,
            Self::DnsRead(args) => args.limits.max_duration_ms,
            Self::Http(args) => args.limits.max_duration_ms,
            Self::Export(args) => args.limits.max_duration_ms,
            Self::Rewrite(args) => args.max_duration_ms,
            Self::Replay(args) => args.max_duration_ms,
            Self::Scan(args) => args.max_duration_ms,
            Self::Traceroute(args) => args.max_duration_ms,
            Self::Dns(args) => args.max_duration_ms,
            Self::Fuzz(args) => args.max_duration_ms,
            _ => return None,
        };
        Some(std::time::Duration::from_millis(millis))
    }

    /// Install shared cancellation before dispatch for these workflows.
    /// Build installs its handler after loading its blocking recipe input.
    pub(crate) fn supports_cancellation(&self) -> bool {
        matches!(
            self,
            Self::Merge(_)
                | Self::Fragment(_)
                | Self::Read(_)
                | Self::Send(_)
                | Self::Capture(_)
                | Self::Exchange(_)
                | Self::Expert(_)
                | Self::Follow(_)
                | Self::Replay(_)
                | Self::Scan(_)
                | Self::Stats(_)
                | Self::Tls(_)
                | Self::Traceroute(_)
                | Self::Rewrite(_)
                | Self::Export(_)
                | Self::Http(_)
                | Self::DnsRead(_)
                | Self::Dns(_)
                | Self::Fuzz(_)
        )
    }

    /// Dispatches to the selected command.
    ///
    /// Rejects unsupported output formats before any command performs work.
    /// Each arm narrows the shared [`Format`] into the command's own format
    /// enum, so command code matches exhaustively instead of trusting a
    /// catch-all `unreachable!`.
    pub(crate) fn run(self, format: Format, stream: &StreamEncoder) -> Result<(), CliError> {
        // Documentation generates files outside the output contract, so
        // startup dispatches it before stream setup and never reaches here.
        let kind = self
            .kind()
            .expect("non-documentation commands have an output contract kind");
        let publisher = self
            .publication_duration()
            .filter(|_| format == Format::Ndjson)
            .map(|duration| {
                stream.clone().with_deadline(std::sync::Arc::new(
                    packetcraftr_core::budget::Deadline::new(duration)
                        .with_cancellation(Some(crate::cancellation::signal().clone())),
                ))
            });
        let stream = publisher.as_ref().unwrap_or(stream);
        match self {
            Self::Merge(arguments) => merge::run(arguments, kind.require_format(format)?, stream),
            Self::Fragment(arguments) => {
                fragment::run(arguments, kind.require_format(format)?, stream)
            }
            Self::Build(arguments) => build::run(arguments, kind.require_format(format)?, stream),
            Self::Dissect(arguments) => {
                dissect::run(arguments, kind.require_format(format)?, stream)
            }
            Self::Protocols(arguments) => protocols::run(arguments, kind.require_format(format)?),
            Self::Read(arguments) => read::run(arguments, kind.require_format(format)?, stream),
            Self::Interfaces(arguments) => interfaces::run(arguments, kind.require_format(format)?),
            Self::Plan(arguments) => plan::run(arguments, kind.require_format(format)?),
            Self::Send(arguments) => send::run(arguments, kind.require_format(format)?),
            Self::Capture(arguments) => {
                capture::run(arguments, kind.require_format(format)?, stream)
            }
            Self::Expert(arguments) => expert::run(arguments, kind.require_format(format)?, stream),
            Self::Follow(arguments) => follow::run(arguments, kind.require_format(format)?, stream),
            Self::Exchange(arguments) => {
                exchange::run(arguments, kind.require_format(format)?, stream)
            }
            Self::Replay(arguments) => replay::run(arguments, kind.require_format(format)?, stream),
            Self::Scan(arguments) => scan::run(arguments, kind.require_format(format)?, stream),
            Self::Stats(arguments) => stats::run(arguments, kind.require_format(format)?),
            Self::Tls(arguments) => tls::run(arguments, kind.require_format(format)?, stream),
            Self::DnsRead(arguments) => {
                dns_read::run(arguments, kind.require_format(format)?, stream)
            }
            Self::Http(arguments) => http::run(arguments, kind.require_format(format)?, stream),
            Self::Export(arguments) => export::run(arguments, kind.require_format(format)?, stream),
            Self::Rewrite(arguments) => {
                rewrite::run(arguments, kind.require_format(format)?, stream)
            }
            Self::Traceroute(arguments) => {
                traceroute::run(arguments, kind.require_format(format)?, stream)
            }
            Self::Dns(arguments) => dns::run(arguments, kind.require_format(format)?, stream),
            Self::Fuzz(arguments) => fuzz::run(arguments, kind.require_format(format)?, stream),
            Self::Routes(arguments) => routes::run(arguments, kind.require_format(format)?),
            Self::Documentation(_) => unreachable!("documentation returned before dispatch"),
        }
    }
}

/// Renders one aggregate row per text line, or the whole result as one JSON
/// document.
fn render_aggregate_rows<T, R: serde::Serialize>(
    command: output::contract::Command,
    format: output::contract::AggregateFormat,
    result: &R,
    rows: &[T],
    line: impl Fn(&T) -> String,
) -> Result<(), CliError> {
    match format {
        output::contract::AggregateFormat::Text => {
            for row in rows {
                write_stdout_line(format_args!("{}", line(row)))?;
            }
            Ok(())
        }
        output::contract::AggregateFormat::Json => emit_aggregate(command, result, Vec::new()),
    }
}

fn increment_counter(value: u64, counter: &'static str) -> Result<u64, CliError> {
    value
        .checked_add(1)
        .ok_or_else(|| CliError::new(Kind::Internal, format!("{counter} overflowed")))
}
