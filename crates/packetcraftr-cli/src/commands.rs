// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! One module per CLI command, plus the pieces several of them share.
//!
//! Each command owns its `Args`: compact commands keep them beside `run` in a
//! single file (`interfaces.rs`, `routes.rs`), while larger commands split
//! into `arguments.rs`, `rendering.rs`, and sometimes `conversion.rs` — most
//! of the live and capture-reading commands. Clap groups several commands
//! share live under `command_options` instead (`SendArgs` serves `send` and
//! `exchange`).
//!
//! Every command's `Args` implements [`Spec`], and the `commands!` declaration
//! below lists each command once. Dispatch, the output contract, presets, and
//! resource diagnostics read their per-command facts from those two places, so
//! adding a command is one [`Spec`] implementation plus one declared variant.
//! [`execution`] composes the live probe providers, and
//! [`render_aggregate_rows`] renders the Text/Json match the aggregate
//! commands share.

use std::time::Duration;

use crate::output::contract::{Format, FormatSubset};
use packetcraftr_core::error::Kind as ErrorKind;
use serde::Serialize;

use crate::output;
use clap::Subcommand;

use crate::errors::CliError;
use crate::rendering::{StreamEncoder, emit_aggregate, write_stdout_line};
use crate::resources::Settings;
use crate::startup::Launch;

mod application_output;
mod build;
mod capture;
mod dissect;
mod dns;
mod dns_read;
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
mod preparation;
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
mod verify_forwarding;

/// What one command declares about itself, and how it runs.
///
/// Implemented by each command's `Args`. Dispatch, the output contract,
/// `--resource-preset`, and `--resource-diagnostics` read these facts instead
/// of keeping per-command tables of their own.
pub(crate) trait Spec: Sized {
    /// The narrow format enum `run` matches; its
    /// [`FORMATS`](FormatSubset::FORMATS) are the formats the command's
    /// output contract admits.
    type Format: FormatSubset;

    /// Whether shared cancellation is installed before dispatch. Build
    /// installs its own handler after loading its blocking recipe input.
    const CANCELLATION: bool;

    /// Whether the command analyzes capture files offline. Only offline
    /// commands accept `--resource-preset`, and their capture-reader bounds
    /// are physical-input settings rather than operation settings.
    const OFFLINE: bool = false;

    /// The operation deadline the invocation publishes under, if the command
    /// bounds its run time.
    fn publication_duration(&self) -> Option<Duration> {
        None
    }

    /// Declares the command's resource settings for `--resource-diagnostics`.
    fn resources(&self, _settings: &mut Settings<'_>) {}

    /// Runs the command with its format already narrowed and checked.
    fn run(self, format: Self::Format, stream: &StreamEncoder) -> Result<CommandExit, CliError>;
}

/// Declares every command once, in `--help` order.
///
/// A variant with a published name is an output-contract command: it gets a
/// [`Kind`] variant serialized under that name, which is also its
/// command-line name, and startup publishes it through the contract. A
/// variant without one (`documentation`) writes files instead of contract
/// output, so it has no kind.
macro_rules! commands {
    (@offline $arguments:ty) => { false };
    (@offline $arguments:ty, $name:literal) => { <$arguments as Spec>::OFFLINE };
    (@start $launch:ident, $arguments:ident, $variant:ident) => {
        $launch.generate($arguments)
    };
    (@start $launch:ident, $arguments:ident, $variant:ident, $name:literal) => {
        $launch.publish(Kind::$variant, $arguments)
    };
    // Expands to `$item`; naming `$name` makes the item repeat once per
    // published command only.
    (@published $name:literal, $item:expr) => { $item };
    (
        $(
            $(#[$attribute:meta])*
            $variant:ident($arguments:ty) $(= $name:literal)?,
        )*
    ) => {
        #[derive(Debug, Subcommand)]
        pub(crate) enum Command {
            $(
                $(#[$attribute])*
                $(#[command(name = $name)])?
                $variant($arguments),
            )*
        }

        impl Command {
            /// Whether `--resource-preset` applies to this command.
            pub(crate) const fn offline(&self) -> bool {
                match self {
                    $( Self::$variant(_) => commands!(@offline $arguments $(, $name)?), )*
                }
            }

            /// Runs the selected command under the startup options.
            pub(crate) fn start(self, launch: Launch<'_>) -> std::process::ExitCode {
                match self {
                    $(
                        Self::$variant(arguments) => {
                            commands!(@start launch, arguments, $variant $(, $name)?)
                        }
                    )*
                }
            }
        }

        /// CLI command identifier frozen into the output schema: every command
        /// that publishes through the output contract.
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
        pub enum Kind {
            $( $( #[serde(rename = $name)] $variant, )? )*
        }

        impl Kind {
            /// Complete command vocabulary, in `--help` order.
            pub const ALL: &'static [Self] = &[
                $( $( commands!(@published $name, Self::$variant), )? )*
            ];

            /// The serialized name, byte-identical to the command-line name.
            pub const fn as_str(self) -> &'static str {
                match self {
                    $( $( Self::$variant => $name, )? )*
                }
            }

            /// Formats deliberately supported by this command contract.
            pub const fn formats(self) -> &'static [Format] {
                match self {
                    $(
                        $(
                            Self::$variant => commands!(
                                @published $name,
                                <<$arguments as Spec>::Format as FormatSubset>::FORMATS
                            ),
                        )?
                    )*
                }
            }
        }
    };
}

commands! {
    /// Merge time-ordered captures into scoped PCAPNG.
    Merge(merge::Args) = "merge",
    /// Explicitly split a complete IPv4/IPv6 recipe into bounded fragments.
    Fragment(fragment::Args) = "fragment",
    /// Build exact packet bytes from an expression or document.
    #[command(after_long_help = build::arguments::AFTER_LONG_HELP)]
    Build(build::arguments::Args) = "build",
    /// Decode a frame with bounded, registry-driven dissection.
    #[command(after_long_help = dissect::arguments::AFTER_LONG_HELP)]
    Dissect(dissect::arguments::Args) = "dissect",
    /// List built-in protocols or describe one protocol.
    #[command(after_long_help = protocols::arguments::AFTER_LONG_HELP)]
    Protocols(protocols::arguments::Args) = "protocols",
    /// Stream frames from a classic PCAP or PCAPNG file.
    #[command(after_long_help = read::arguments::AFTER_LONG_HELP)]
    Read(read::arguments::Args) = "read",
    /// Enumerate local interfaces.
    #[command(after_long_help = interfaces::AFTER_LONG_HELP)]
    Interfaces(interfaces::Args) = "interfaces",
    /// Passively select route, source, MTU, and link mode.
    #[command(after_long_help = plan::arguments::AFTER_LONG_HELP)]
    Plan(plan::arguments::Args) = "plan",
    /// Transmit a packet under traffic policy.
    #[command(after_long_help = send::arguments::AFTER_LONG_HELP)]
    Send(send::arguments::Args) = "send",
    /// Capture-ready request/response exchange.
    #[command(after_long_help = exchange::arguments::AFTER_LONG_HELP)]
    Exchange(exchange::arguments::Args) = "exchange",
    /// Stream live captured frames.
    #[command(after_long_help = capture::arguments::AFTER_LONG_HELP)]
    Capture(capture::arguments::Args) = "capture",
    /// Report protocol health findings over a capture file.
    #[command(after_long_help = expert::arguments::AFTER_LONG_HELP)]
    Expert(expert::arguments::Args) = "expert",
    /// Extract one conversation's payload from a capture file.
    #[command(after_long_help = follow::arguments::AFTER_LONG_HELP)]
    Follow(follow::arguments::Args) = "follow",
    /// Replay a PCAP/PCAPNG stream.
    #[command(after_long_help = replay::arguments::AFTER_LONG_HELP)]
    Replay(replay::arguments::Args) = "replay",
    /// Run a structured network scan.
    #[command(after_long_help = scan::arguments::AFTER_LONG_HELP)]
    Scan(scan::arguments::Args) = "scan",
    /// Compute aggregate statistics over a capture file.
    #[command(after_long_help = stats::arguments::AFTER_LONG_HELP)]
    Stats(stats::arguments::Args) = "stats",
    /// Assemble TLS handshake sessions from a capture file.
    #[command(after_long_help = tls::arguments::AFTER_LONG_HELP)]
    Tls(tls::arguments::Args) = "tls",
    /// Run bounded, policy-gated traceroute probes.
    #[command(
        long_about = traceroute::arguments::LONG_ABOUT,
        after_long_help = traceroute::arguments::AFTER_LONG_HELP
    )]
    Traceroute(traceroute::arguments::Args) = "traceroute",
    /// Run bounded DNS over UDP, TCP, or UDP with TCP fallback.
    #[command(
        long_about = dns::arguments::LONG_ABOUT,
        after_long_help = dns::arguments::AFTER_LONG_HELP
    )]
    Dns(dns::arguments::Args) = "dns",
    /// Inspect captured UDP/TCP DNS messages and transaction evidence.
    DnsRead(dns_read::Args) = "dns-read",
    /// Inspect cleartext HTTP/1 messages over captured TCP streams.
    Http(http::Args) = "http",
    /// Export streams and reassembled IP datagrams with their physical dependencies.
    Export(export::Args) = "export",
    /// Rewrite capture headers with checked lengths and transport checksums.
    Rewrite(rewrite::Args) = "rewrite",
    /// Run bounded field-aware packet fuzzing.
    #[command(after_long_help = fuzz::arguments::AFTER_LONG_HELP)]
    Fuzz(fuzz::arguments::Args) = "fuzz",
    /// Enumerate passive interface-bound route decisions.
    #[command(after_long_help = routes::AFTER_LONG_HELP)]
    Routes(routes::Args) = "routes",
    /// Compare ingress and egress captures under explicit identity rules.
    #[command(after_long_help = verify_forwarding::arguments::AFTER_LONG_HELP)]
    VerifyForwarding(verify_forwarding::arguments::Args) = "verify-forwarding",
    /// Generate shell completions and man pages under a directory.
    Documentation(documentation::Args),
}

/// Runs one contract command: enters its publication deadline, rejects an
/// unsupported output format before any work, and dispatches.
pub(crate) fn execute<T: Spec>(
    kind: Kind,
    arguments: T,
    format: Format,
    stream: &StreamEncoder,
) -> Result<CommandExit, CliError> {
    let _invocation = crate::invocation::enter(arguments.publication_duration());
    let publisher =
        crate::invocation::deadline().map(|deadline| stream.clone().with_deadline(deadline));
    let stream = publisher.as_ref().unwrap_or(stream);
    arguments.run(kind.require_format(format)?, stream)
}

/// The process status of a command that published its output.
///
/// Almost every successful command exits [`CommandExit::SUCCESS`]. A command
/// whose result is a verdict rather than an operation — `verify-forwarding` —
/// reports the verdict's status through this without emitting a second,
/// contradictory error record over its completed output.
pub(crate) struct CommandExit(u8);

impl CommandExit {
    /// Exit status 0.
    pub(crate) const SUCCESS: Self = Self(0);

    /// An explicit non-success status for a completed command.
    pub(crate) const fn status(code: u8) -> Self {
        Self(code)
    }

    /// The process exit code.
    pub(crate) const fn get(self) -> u8 {
        self.0
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
        .ok_or_else(|| CliError::new(ErrorKind::Internal, format!("{counter} overflowed")))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use clap::{CommandFactory, FromArgMatches};

    use super::*;
    use crate::cli::Cli;
    use crate::command_options::Budget as _;

    /// A command line, and the check of its command's bound declarations.
    type Case = (&'static [&'static str], fn(&[&str]) -> Vec<String>);

    /// The `--max-*` bounds `arguments` accept but do not declare as resource
    /// settings.
    fn undeclared_bounds<T: Spec + FromArgMatches>(argv: &[&str]) -> Vec<String> {
        let matches = Cli::command()
            .try_get_matches_from(std::iter::once("packetcraftr").chain(argv.iter().copied()))
            .unwrap_or_else(|error| panic!("{argv:?}: {error}"));
        let (name, selected) = matches.subcommand().expect("a selected command");
        let arguments = T::from_arg_matches(selected).expect("typed arguments");
        let declared = crate::resources::settings(&matches, &arguments, None, None, Format::Json)
            .into_iter()
            .map(|(setting, _)| setting.name)
            .collect::<BTreeSet<_>>();
        Cli::command()
            .find_subcommand(name)
            .expect("selected command definition")
            .get_arguments()
            .filter(|arg| arg.get_id().as_str().starts_with("max_"))
            .filter_map(|arg| arg.get_long().map(|long| format!("--{long}")))
            .filter(|name| !declared.contains(name))
            .collect()
    }

    /// Resource diagnostics come from each command's typed declarations, so a
    /// new `--max-*` bound that its command forgets to declare would silently
    /// vanish from the report.
    #[test]
    fn every_command_declares_each_of_its_bounds() {
        const CAPTURE: &str = "capture.pcap";
        const PACKET: &str = "ipv4(destination=192.0.2.1)/raw(text=hello)";
        let cases: &[Case] = &[
            (
                &["merge", "--write", "m.pcapng", CAPTURE, CAPTURE],
                undeclared_bounds::<merge::Args>,
            ),
            (
                &["fragment", "--mtu", "576", "--packet", PACKET],
                undeclared_bounds::<fragment::Args>,
            ),
            (
                &["build", "--packet", PACKET],
                undeclared_bounds::<build::arguments::Args>,
            ),
            (
                &["dissect", "--hex", "00"],
                undeclared_bounds::<dissect::arguments::Args>,
            ),
            (
                &["protocols"],
                undeclared_bounds::<protocols::arguments::Args>,
            ),
            (
                &["read", CAPTURE],
                undeclared_bounds::<read::arguments::Args>,
            ),
            (&["interfaces"], undeclared_bounds::<interfaces::Args>),
            (
                &["plan", "--destination", "192.0.2.1"],
                undeclared_bounds::<plan::arguments::Args>,
            ),
            (
                &["send", "--packet", PACKET],
                undeclared_bounds::<send::arguments::Args>,
            ),
            (
                &["exchange", "--packet", PACKET],
                undeclared_bounds::<exchange::arguments::Args>,
            ),
            (
                &["capture", "--interface", "lo"],
                undeclared_bounds::<capture::arguments::Args>,
            ),
            (
                &["expert", CAPTURE],
                undeclared_bounds::<expert::arguments::Args>,
            ),
            (
                &["follow", "--stream", "tcp:0", CAPTURE],
                undeclared_bounds::<follow::arguments::Args>,
            ),
            (
                &["replay", "--interface", "lo", CAPTURE],
                undeclared_bounds::<replay::arguments::Args>,
            ),
            (
                &["scan", "192.0.2.1"],
                undeclared_bounds::<scan::arguments::Args>,
            ),
            (
                &["stats", CAPTURE],
                undeclared_bounds::<stats::arguments::Args>,
            ),
            (&["tls", CAPTURE], undeclared_bounds::<tls::arguments::Args>),
            (
                &["traceroute", "192.0.2.1"],
                undeclared_bounds::<traceroute::arguments::Args>,
            ),
            (
                &["dns", "192.0.2.53", "example.com"],
                undeclared_bounds::<dns::arguments::Args>,
            ),
            (&["dns-read", CAPTURE], undeclared_bounds::<dns_read::Args>),
            (&["http", CAPTURE], undeclared_bounds::<http::Args>),
            (
                &["export", "--write", "e.pcapng", CAPTURE],
                undeclared_bounds::<export::Args>,
            ),
            (
                &["rewrite", "--write", "r.pcapng", CAPTURE],
                undeclared_bounds::<rewrite::Args>,
            ),
            (
                &["fuzz", "--packet", PACKET],
                undeclared_bounds::<fuzz::arguments::Args>,
            ),
            (&["routes"], undeclared_bounds::<routes::Args>),
            (
                &[
                    "verify-forwarding",
                    CAPTURE,
                    CAPTURE,
                    "--identity",
                    "ipv4.identification",
                ],
                undeclared_bounds::<verify_forwarding::arguments::Args>,
            ),
        ];
        for (argv, undeclared) in cases {
            assert_eq!(undeclared(argv), Vec::<String>::new(), "{}", argv[0]);
        }
        let covered = cases
            .iter()
            .map(|(argv, _)| argv[0])
            .collect::<BTreeSet<_>>();
        let published = Kind::ALL
            .iter()
            .map(|kind| kind.as_str())
            .collect::<BTreeSet<_>>();
        assert_eq!(covered, published);
    }

    /// The budget a command ends up with is the one the policy enforces, so
    /// this walks the real clap parse rather than reading the trait back.
    fn budgets_for(arguments: &[&str]) -> (u64, u64) {
        let cli = <Cli as clap::Parser>::try_parse_from(arguments)
            .expect("command must parse with defaults");
        let policy = match cli.command {
            Command::Send(send) => send.send.policy.into_policy(),
            Command::Exchange(exchange) => exchange.send.policy.into_policy(),
            Command::Scan(scan) => scan.policy.into_policy(),
            Command::Fuzz(fuzz) => fuzz.policy.into_policy(),
            Command::Replay(replay) => replay.policy.into_policy(),
            Command::Capture(capture) => capture.budgets.into_policy(),
            other => panic!("unbudgeted command {other:?}"),
        };
        (
            policy.max_packets_per_operation,
            policy.max_bytes_per_operation,
        )
    }

    #[test]
    fn each_command_starts_from_the_budget_its_operation_calls_for() {
        let transmitted = (
            crate::command_options::Transmitted::max_packets(),
            crate::command_options::Transmitted::max_bytes(),
        );
        let captured = (
            capture::arguments::Captured::max_packets(),
            capture::arguments::Captured::max_bytes(),
        );

        assert_eq!(
            budgets_for(&[
                "packetcraftr",
                "replay",
                "capture.pcapng",
                "--interface",
                "7"
            ]),
            (
                packetcraftr_core::capture_file::DEFAULT_STREAM_FRAMES,
                packetcraftr_core::capture_file::DEFAULT_STREAM_BYTES
            ),
        );
        assert_eq!(
            budgets_for(&["packetcraftr", "send", "--packet", "raw(hex=00)"]),
            transmitted,
        );
        assert_eq!(
            budgets_for(&["packetcraftr", "exchange", "--packet", "raw(hex=00)"]),
            transmitted,
        );
        assert_eq!(
            budgets_for(&["packetcraftr", "scan", "192.0.2.1"]),
            transmitted,
        );
        assert_eq!(
            budgets_for(&["packetcraftr", "fuzz", "--packet", "raw(hex=00)"]),
            transmitted,
        );
        assert_eq!(
            budgets_for(&["packetcraftr", "capture", "--interface", "7"]),
            captured,
        );
        assert_eq!(
            captured,
            (capture::arguments::DEFAULT_CAPTURED_FRAMES, transmitted.1)
        );
    }
}
