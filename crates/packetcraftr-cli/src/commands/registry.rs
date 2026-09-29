// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use clap::Subcommand;
use serde::Serialize;

use super::dispatch::Launch;
use super::{
    Spec, build, capture, capture_transform, dissect, dns, dns_read, documentation, exchange,
    expert, export, follow, fragment, fuzz, http, interfaces, merge, plan, protocols, read, replay,
    rewrite, routes, scan, send, stats, tls, traceroute, verify_forwarding, websocket,
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
    /// Remove exact duplicate frames within a bounded recent input window.
    Dedup(capture_transform::DedupArgs) = "dedup",
    /// Split an offline capture into independently readable bounded files.
    Split(capture_transform::SplitArgs) = "split",
    /// Shift packet and known statistics timestamps by exact decimal seconds.
    ShiftTime(capture_transform::ShiftArgs) = "shift-time",
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
    /// Follow WebSocket data messages and control frames over a TCP conversation.
    #[command(after_long_help = websocket::AFTER_LONG_HELP)]
    Websocket(websocket::Args) = "websocket",
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
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use clap::{CommandFactory, FromArgMatches};

    use super::*;
    use crate::cli::Cli;

    type Case = (&'static [&'static str], fn(&[&str]) -> Vec<String>);

    fn undeclared_bounds<T: Spec + FromArgMatches>(argv: &[&str]) -> Vec<String> {
        let mut definition = Cli::command();
        let matches = definition
            .try_get_matches_from_mut(std::iter::once("packetcraftr").chain(argv.iter().copied()))
            .unwrap_or_else(|error| panic!("{argv:?}: {error}"));
        let (name, selected) = matches.subcommand().expect("a selected command");
        let arguments = T::from_arg_matches(selected).expect("typed arguments");
        let declared = crate::resources::collect_settings(
            &definition,
            &matches,
            T::OFFLINE,
            None,
            None,
            Format::Json,
            |settings| arguments.resources(settings),
        )
        .into_iter()
        .map(|(setting, _)| setting.name)
        .collect::<BTreeSet<_>>();
        definition
            .find_subcommand(name)
            .expect("selected command definition")
            .get_arguments()
            .filter(|arg| arg.get_id().as_str().starts_with("max_"))
            .filter_map(|arg| arg.get_long().map(|long| format!("--{long}")))
            .filter(|name| !declared.contains(name))
            .collect()
    }

    #[test]
    fn every_command_declares_each_of_its_bounds() {
        const CAPTURE: &str = "capture.pcap";
        const PACKET: &str = "ipv4(destination=192.0.2.1)/raw(text=hello)";
        let cases: &[Case] = &[
            (
                &["dedup", CAPTURE, "--write", "out.pcap"],
                undeclared_bounds::<capture_transform::DedupArgs>,
            ),
            (
                &["split", CAPTURE, "--write", "out", "--packets", "10"],
                undeclared_bounds::<capture_transform::SplitArgs>,
            ),
            (
                &[
                    "shift-time",
                    CAPTURE,
                    "--write",
                    "out.pcap",
                    "--seconds",
                    "-1.25",
                ],
                undeclared_bounds::<capture_transform::ShiftArgs>,
            ),
            (
                &["websocket", CAPTURE, "--stream", "tcp:0"],
                undeclared_bounds::<websocket::Args>,
            ),
            (
                &["merge", "--write", "m.pcapng", CAPTURE, CAPTURE],
                undeclared_bounds::<merge::arguments::Args>,
            ),
            (
                &["fragment", "--mtu", "576", "--packet", PACKET],
                undeclared_bounds::<fragment::arguments::Args>,
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
            (
                &["interfaces"],
                undeclared_bounds::<interfaces::arguments::Args>,
            ),
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
            (
                &["dns-read", CAPTURE],
                undeclared_bounds::<dns_read::arguments::Args>,
            ),
            (
                &["http", CAPTURE],
                undeclared_bounds::<http::arguments::Args>,
            ),
            (
                &["export", "--write", "e.pcapng", CAPTURE],
                undeclared_bounds::<export::arguments::Args>,
            ),
            (
                &["rewrite", "--write", "r.pcapng", CAPTURE],
                undeclared_bounds::<rewrite::arguments::Args>,
            ),
            (
                &["fuzz", "--packet", PACKET],
                undeclared_bounds::<fuzz::arguments::Args>,
            ),
            (&["routes"], undeclared_bounds::<routes::arguments::Args>),
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
        let published = Command::ALL
            .iter()
            .map(|kind| kind.as_str())
            .collect::<BTreeSet<_>>();
        assert_eq!(covered, published);
    }
}
