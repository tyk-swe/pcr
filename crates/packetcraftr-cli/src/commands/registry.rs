// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use clap::Subcommand;
use serde::Serialize;

use super::dispatch::Launch;
use super::{
    Spec, build, capture, dissect, dns, dns_read, documentation, exchange, expert, export, follow,
    fragment, fuzz, http, http2, interfaces, merge, plan, protocols, read, replay, rewrite, routes,
    scan, send, stats, tls, topics, traceroute, verify_forwarding,
};
use crate::output::contract::{Format, FormatSubset};
use crate::resources::Settings;

/// Declares every command once, in `--help` order.
macro_rules! commands {
    (@offline $arguments:ty) => { false };
    (@offline $arguments:ty, $name:literal) => { <$arguments as Spec>::OFFLINE };
    (@start $launch:ident, $arguments:ident, $variant:ident) => {
        $launch.generate($arguments)
    };
    (@start $launch:ident, $arguments:ident, $variant:ident, $name:literal) => {
        $launch.publish(Command::$variant, $arguments)
    };
    (@presets $arguments:ident, $preset:ident) => {{
        let _ = ($arguments, $preset);
        std::collections::BTreeMap::new()
    }};
    (@presets $arguments:ident, $preset:ident, $name:literal) => {
        Settings::preset_defaults($preset, |settings| $arguments.resources(settings))
    };
    // Naming `$name` makes the item repeat once per published command only.
    (@published $name:literal, $item:expr) => { $item };
    (
        $(
            $(#[$attribute:meta])*
            $variant:ident($arguments:ty) $(= $name:literal)?,
        )*
    ) => {
        /// The parsed subcommand with its arguments.
        #[derive(Debug, Subcommand)]
        pub(crate) enum CommandLine {
            $(
                $(#[$attribute])*
                $(#[command(name = $name)])?
                $variant($arguments),
            )*
        }

        impl CommandLine {
            pub(crate) const fn offline(&self) -> bool {
                match self {
                    $( Self::$variant(_) => commands!(@offline $arguments $(, $name)?), )*
                }
            }

            pub(crate) fn preset_defaults(
                &self,
                preset: crate::resources::Preset,
            ) -> std::collections::BTreeMap<&'static str, &'static str> {
                match self {
                    $(
                        Self::$variant(arguments) => {
                            commands!(@presets arguments, preset $(, $name)?)
                        }
                    )*
                }
            }

            pub(super) fn start(self, launch: Launch<'_>) -> std::process::ExitCode {
                match self {
                    $(
                        Self::$variant(arguments) => {
                            commands!(@start launch, arguments, $variant $(, $name)?)
                        }
                    )*
                }
            }
        }

        /// CLI command identifier frozen into the output schema.
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
        pub enum Command {
            $( $( #[serde(rename = $name)] $variant, )? )*
        }

        impl Command {
            pub const ALL: &'static [Self] = &[
                $( $( commands!(@published $name, Self::$variant), )? )*
            ];

            pub const fn as_str(self) -> &'static str {
                match self {
                    $( $( Self::$variant => $name, )? )*
                }
            }

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
    #[command(after_long_help = merge::arguments::AFTER_LONG_HELP)]
    Merge(merge::arguments::Args) = "merge",
    /// Explicitly split a complete IPv4/IPv6 recipe into bounded fragments.
    #[command(after_long_help = fragment::arguments::AFTER_LONG_HELP)]
    Fragment(fragment::arguments::Args) = "fragment",
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
    #[command(after_long_help = interfaces::arguments::AFTER_LONG_HELP)]
    Interfaces(interfaces::arguments::Args) = "interfaces",
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
    #[command(after_long_help = dns_read::arguments::AFTER_LONG_HELP)]
    DnsRead(dns_read::arguments::Args) = "dns-read",
    /// Inspect cleartext HTTP/1 messages over captured TCP streams.
    #[command(after_long_help = http::arguments::AFTER_LONG_HELP)]
    Http(http::arguments::Args) = "http",
    #[command(
        about = "Inspect cleartext HTTP/2 and h2c over captured TCP streams.",
        after_long_help = http2::arguments::AFTER_LONG_HELP
    )]
    Http2(http2::arguments::Args) = "http2",
    /// Export streams and reassembled IP datagrams with their physical dependencies.
    #[command(after_long_help = export::arguments::AFTER_LONG_HELP)]
    Export(export::arguments::Args) = "export",
    /// Rewrite capture headers with checked lengths and transport checksums.
    #[command(after_long_help = rewrite::arguments::AFTER_LONG_HELP)]
    Rewrite(rewrite::arguments::Args) = "rewrite",
    /// Run bounded field-aware packet fuzzing.
    #[command(after_long_help = fuzz::arguments::AFTER_LONG_HELP)]
    Fuzz(fuzz::arguments::Args) = "fuzz",
    /// Enumerate passive interface-bound route decisions.
    #[command(after_long_help = routes::arguments::AFTER_LONG_HELP)]
    Routes(routes::arguments::Args) = "routes",
    /// Compare ingress and egress captures under explicit identity rules.
    #[command(after_long_help = verify_forwarding::arguments::AFTER_LONG_HELP)]
    VerifyForwarding(verify_forwarding::arguments::Args) = "verify-forwarding",
    /// Generate shell completions and man pages under a directory.
    Documentation(documentation::arguments::Args),
    /// Print built-in references for packet expressions, filters, formats, and exit codes.
    #[command(after_long_help = topics::arguments::AFTER_LONG_HELP)]
    Topics(topics::arguments::Args),
}
