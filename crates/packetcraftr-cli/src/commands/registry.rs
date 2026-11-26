// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod help;

use clap::Subcommand;
use serde::Serialize;

use super::dispatch::Launch;
use super::{Spec, analyze, files, network, packet, reference};
use crate::output::contract::Format;
use crate::resources::Settings;

/// Declares every command once, in workflow `--help` order.
macro_rules! commands {
    (@identifier $canonical:literal) => { $canonical };
    (@identifier $canonical:literal, $name:literal) => { $name };
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
            $variant:ident($arguments:ty) $(= $name:literal)?
                => ($group:literal, $canonical:literal),
        )*
    ) => {
        /// The parsed subcommand with its arguments.
        #[derive(Debug, Subcommand)]
        #[allow(
            clippy::large_enum_variant,
            reason = "never constructed: it only supplies clap's leaf definitions"
        )]
        enum LeafDefinitions {
            $(
                $(#[$attribute])*
                #[command(name = commands!(@identifier $canonical $(, $name)?))]
                $variant($arguments),
            )*
        }

        #[derive(Debug)]
        #[allow(
            clippy::large_enum_variant,
            reason = "parsed once per process, so boxing the largest arguments saves nothing"
        )]
        pub(crate) enum CommandLine {
            $( $variant($arguments), )*
        }

        impl CommandLine {
            fn from_leaf(name: &str, values: &clap::ArgMatches) -> Result<Self, clap::Error> {
                $(
                    if name == commands!(@identifier $canonical $(, $name)?) {
                        return <$arguments as clap::FromArgMatches>::from_arg_matches(values)
                            .map(Self::$variant);
                    }
                )*
                Err(clap::Error::new(clap::error::ErrorKind::InvalidSubcommand))
            }
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
                                <$arguments as Spec>::FORMATS
                            ),
                        )?
                    )*
                }
            }
        }

        /// Every published command's output-schema definitions, collected
        /// from the `PUBLISHED` rows beside each command's own types.
        #[allow(
            dead_code,
            reason = "consumed by the published_rows_cover_every_command_exactly guard test and scripts/check_output_schema.py"
        )]
        pub(crate) const PUBLISHED: &[&[crate::output::contract::PublishedType]] = &[
            $( $( commands!(@published $name, <$arguments as Spec>::PUBLISHED), )? )*
        ];

        pub(crate) const INVENTORY: &[Entry] = &[
            $(
                Entry {
                    group: $group,
                    name: $canonical,
                    identifier: commands!(@identifier $canonical $(, $name)?),
                },
            )*
        ];
    };
}

commands! {
    /// Build exact packet bytes from an expression or document.
    #[command(after_long_help = packet::build::arguments::AFTER_LONG_HELP)]
    Build(packet::build::arguments::Args) = "build" => ("packet", "build"),
    /// Decode a frame with bounded, registry-driven dissection.
    #[command(after_long_help = packet::dissect::arguments::AFTER_LONG_HELP)]
    Dissect(packet::dissect::arguments::Args) = "dissect" => ("packet", "dissect"),
    /// Explicitly split a complete IPv4/IPv6 recipe into bounded fragments.
    #[command(after_long_help = packet::fragment::arguments::AFTER_LONG_HELP)]
    Fragment(packet::fragment::arguments::Args) = "fragment" => ("packet", "fragment"),
    /// Run bounded field-aware packet fuzzing.
    #[command(after_long_help = packet::fuzz::arguments::AFTER_LONG_HELP)]
    Fuzz(packet::fuzz::arguments::Args) = "fuzz" => ("packet", "fuzz"),
    /// Stream frames from a classic PCAP or PCAPNG file.
    #[command(after_long_help = files::read::arguments::AFTER_LONG_HELP)]
    Read(files::read::arguments::Args) = "read" => ("files", "read"),
    /// Merge time-ordered captures into scoped PCAPNG.
    #[command(after_long_help = files::merge::arguments::AFTER_LONG_HELP)]
    Merge(files::merge::arguments::Args) = "merge" => ("files", "merge"),
    /// Rewrite capture headers with checked lengths and transport checksums.
    #[command(after_long_help = files::rewrite::arguments::AFTER_LONG_HELP)]
    Rewrite(files::rewrite::arguments::Args) = "rewrite" => ("files", "rewrite"),
    /// Export streams and reassembled IP datagrams with their physical dependencies.
    #[command(after_long_help = files::export::arguments::AFTER_LONG_HELP)]
    Export(files::export::arguments::Args) = "export" => ("files", "export"),
    /// Compute aggregate statistics over a capture file.
    #[command(after_long_help = analyze::stats::arguments::AFTER_LONG_HELP)]
    Stats(analyze::stats::arguments::Args) = "stats" => ("analyze", "stats"),
    /// Report protocol health findings over a capture file.
    #[command(after_long_help = analyze::expert::arguments::AFTER_LONG_HELP)]
    Expert(analyze::expert::arguments::Args) = "expert" => ("analyze", "expert"),
    /// Extract one conversation's payload from a capture file.
    #[command(after_long_help = analyze::follow::arguments::AFTER_LONG_HELP)]
    Follow(analyze::follow::arguments::Args) = "follow" => ("analyze", "follow"),
    /// Inspect captured UDP/TCP DNS messages and transaction evidence.
    #[command(after_long_help = analyze::dns::arguments::AFTER_LONG_HELP)]
    DnsRead(analyze::dns::arguments::Args) = "dns-read" => ("analyze", "dns"),
    /// Inspect cleartext HTTP/1 messages over captured TCP streams.
    #[command(after_long_help = analyze::http::arguments::AFTER_LONG_HELP)]
    Http(analyze::http::arguments::Args) = "http" => ("analyze", "http"),
    #[command(
        about = "Inspect cleartext HTTP/2 and h2c over captured TCP streams.",
        after_long_help = analyze::http2::arguments::AFTER_LONG_HELP
    )]
    Http2(analyze::http2::arguments::Args) = "http2" => ("analyze", "http2"),
    /// Assemble TLS handshake sessions from a capture file.
    #[command(after_long_help = analyze::tls::arguments::AFTER_LONG_HELP)]
    Tls(analyze::tls::arguments::Args) = "tls" => ("analyze", "tls"),
    /// Compare ingress and egress captures under explicit identity rules.
    #[command(after_long_help = analyze::verify_forwarding::arguments::AFTER_LONG_HELP)]
    VerifyForwarding(analyze::verify_forwarding::arguments::Args) = "verify-forwarding" => ("analyze", "verify-forwarding"),
    /// Enumerate local interfaces.
    #[command(after_long_help = network::interfaces::AFTER_LONG_HELP)]
    Interfaces(network::interfaces::Args) = "interfaces" => ("network", "interfaces"),
    /// Enumerate passive interface-bound route decisions.
    #[command(after_long_help = network::routes::AFTER_LONG_HELP)]
    Routes(network::routes::Args) = "routes" => ("network", "routes"),
    /// Passively select route, source, MTU, and link mode.
    #[command(after_long_help = network::plan::AFTER_LONG_HELP)]
    Plan(network::plan::Args) = "plan" => ("network", "plan"),
    /// Stream live captured frames.
    #[command(after_long_help = network::capture::arguments::AFTER_LONG_HELP)]
    Capture(network::capture::arguments::Args) = "capture" => ("network", "capture"),
    /// Transmit a packet under traffic policy.
    #[command(after_long_help = network::send::arguments::AFTER_LONG_HELP)]
    Send(network::send::arguments::Args) = "send" => ("network", "send"),
    /// Capture-ready request/response exchange.
    #[command(after_long_help = network::exchange::arguments::AFTER_LONG_HELP)]
    Exchange(network::exchange::arguments::Args) = "exchange" => ("network", "exchange"),
    /// Replay a PCAP/PCAPNG stream.
    #[command(after_long_help = network::replay::arguments::AFTER_LONG_HELP)]
    Replay(network::replay::arguments::Args) = "replay" => ("network", "replay"),
    /// Run a structured network scan.
    #[command(after_long_help = network::scan::arguments::AFTER_LONG_HELP)]
    Scan(network::scan::arguments::Args) = "scan" => ("network", "scan"),
    /// Explicitly identify services at selected numeric TCP or UDP endpoints.
    #[command(after_long_help = network::identify::arguments::AFTER_LONG_HELP)]
    Identify(network::identify::arguments::Args) = "identify" => ("network", "identify"),
    /// Identify qualified OS families from bounded raw packet observations.
    #[command(after_long_help = "Requires a native raw packet provider and explicit destination authorization. Conclusions are qualified inferences, not authenticated identities.\n\nExample:\n  packetcraftr network identify-os 192.0.2.10 --open-port 80 --closed-port 81")]
    IdentifyOs(network::identify_os::Args) = "identify-os" => ("network", "identify-os"),
    /// Run bounded, policy-gated traceroute probes.
    #[command(
        long_about = network::traceroute::arguments::LONG_ABOUT,
        after_long_help = network::traceroute::arguments::AFTER_LONG_HELP
    )]
    Traceroute(network::traceroute::arguments::Args) = "traceroute" => ("network", "traceroute"),
    /// Run bounded DNS over UDP, TCP, or UDP with TCP fallback.
    #[command(
        long_about = network::dns::arguments::LONG_ABOUT,
        after_long_help = network::dns::arguments::AFTER_LONG_HELP
    )]
    Dns(network::dns::arguments::Args) = "dns" => ("network", "dns"),
    /// List built-in protocols or describe one protocol.
    #[command(after_long_help = reference::protocols::AFTER_LONG_HELP)]
    Protocols(reference::protocols::Args) = "protocols" => ("reference", "protocols"),
    /// Print built-in references for packet expressions, filters, formats, scope, and exit codes.
    #[command(after_long_help = reference::topics::AFTER_LONG_HELP)]
    Topics(reference::topics::Args) => ("reference", "topics"),
    /// Generate shell completions and man pages under a directory.
    #[command(after_long_help = "Writes completions for Bash, Elvish, Fish, PowerShell, and Zsh, and man pages for all grouped paths. Requires a writable directory.\n\nExample:\n  packetcraftr reference documentation --directory ./cli-docs")]
    Documentation(reference::documentation::Args) => ("reference", "documentation"),
    /// Match local indicators against capture endpoints and application evidence.
    #[command(after_long_help = "Example: packetcraftr analyze hunt capture.pcapng --indicators indicators.json")]
    Hunt(analyze::security::Hunt) = "hunt" => ("analyze", "hunt"),
    /// Report high NXDOMAIN ratios and repeated high-entropy query labels.
    #[command(after_long_help = "Defaults: 60-second windows, at least 20 matched responses and 50% NXDOMAIN, or 20 distinct leading labels of at least 32 bytes and 4 bits/byte entropy.\n\nExample: packetcraftr analyze dns-anomalies capture.pcapng")]
    DnsAnomalies(analyze::security::Dns) = "dns-anomalies" => ("analyze", "dns-anomalies"),
    /// Detect regularly spaced TCP connection attempts.
    #[command(after_long_help = "Defaults: six distinct SYN attempts, mean interval at least one second, coefficient of variation at most 0.10. Retransmissions are deduplicated, and clock regressions suppress timing conclusions.\n\nExample: packetcraftr analyze beacons capture.pcapng")]
    Beacons(analyze::security::Beacons) = "beacons" => ("analyze", "beacons"),
    /// Compare scoped endpoint states and scan coverage from native aggregate JSON.
    #[command(after_long_help = "Requires successful aggregate JSON from matching native scan methods. Missing endpoints are coverage changes, never presumed closed.\n\nExample: packetcraftr analyze scan-diff before.json after.json")]
    ScanDiff(analyze::scan_diff::ScanDiff) = "scan-diff" => ("analyze", "scan-diff"),
    /// Combine security results into a standalone local HTML assessment.
    #[command(after_long_help = "Accepts aggregate JSON from the security analysis and audit commands plus scan, differential, fuzz, exchange, and traceroute results, which are summarized as observations. Escapes captured content, records source-file hashes, and refuses existing HTML and Evidence bundle destinations.\n\nExample: packetcraftr analyze report hunt.json scan.json --html assessment.html --bundle bundle.json --scope-file scope.json")]
    Assessment(analyze::report::Assessment) = "report" => ("analyze", "report"),
    /// Audit an observed TLS handshake, certificate chain, and name matching.
    #[command(after_long_help = "Uses ordinary TCP sockets. Bundled WebPKI roots are replaced by --ca-file. --server-name sets SNI and certificate identity without resolving another target. No revocation fetching or protocol enumeration.\n\nExample: packetcraftr network audit-tls 192.0.2.10:443 --server-name example.test")]
    AuditTls(network::audit::AuditTls) = "audit-tls" => ("network", "audit-tls"),
    /// Audit HTTP response headers and redacted cookie attributes with one HEAD request.
    #[command(after_long_help = "Sends one HEAD request over HTTP/1.1 (path / by default) and follows no redirects. HTTPS sends the request only after certificate verification succeeds. Cookie values are redacted.\n\nExample: packetcraftr network audit-http 192.0.2.10:443 --tls --server-name example.test --host example.test")]
    AuditHttp(network::audit::AuditHttp) = "audit-http" => ("network", "audit-http"),
    /// Decode protocol messages over reassembled TCP streams.
    #[command(after_long_help = analyze::messages::AFTER_LONG_HELP)]
    Messages(analyze::messages::Args) = "messages" => ("analyze", "messages"),
    /// Run a differential Campaign against a cooperating Responder.
    #[command(after_long_help = network::differential::arguments::AFTER_LONG_HELP)]
    Differential(network::differential::arguments::Args) = "differential" => ("network", "differential"),
    /// Run the cooperating Responder for a differential Campaign.
    #[command(after_long_help = network::differential::responder::AFTER_LONG_HELP)]
    DifferentialResponder(network::differential::responder::Args) = "differential-responder" => ("network", "differential-responder"),
    /// Finalize a provisional Campaign from a Responder reception log.
    #[command(after_long_help = network::differential::join::AFTER_LONG_HELP)]
    DifferentialJoin(network::differential::join::Args) = "differential-join" => ("network", "differential-join"),
    /// Decrypt QUIC v1/v2 captures and reconstruct streams, with optional live capture and TLS key logs.
    #[command(after_long_help = "Examples:\n  packetcraftr analyze quic capture.pcapng --keylog keys.log\n  packetcraftr --output json analyze quic capture.pcapng --keylog keys.log --include-data")]
    Quic(analyze::quic::arguments::Args) = "quic" => ("analyze", "quic"),
    /// Passively report build, interface, and engagement scope readiness.
    #[command(after_long_help = network::preflight::AFTER_LONG_HELP)]
    Preflight(network::preflight::Args) => ("network", "preflight"),
    /// Inventory hosts, protocols, and observed ports in a capture file.
    #[command(after_long_help = analyze::inventory::arguments::AFTER_LONG_HELP)]
    Inventory(analyze::inventory::arguments::Args) = "inventory" => ("analyze", "inventory"),
    /// Reconstruct HTTP/3 exchanges from an encrypted QUIC capture.
    #[command(after_long_help = "Requires --keylog with NSS TLS secrets for the captured QUIC connections.\n\nExample:\n  packetcraftr analyze http3 capture.pcapng --keylog keys.log")]
    Http3(analyze::http3::Args) = "http3" => ("analyze", "http3"),
}

/// Workflow placement and compact identifiers used in machine output.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Entry {
    pub(crate) group: &'static str,
    pub(crate) name: &'static str,
    pub(crate) identifier: &'static str,
}

pub(crate) const GROUPS: &[(&str, &str)] = &[
    ("packet", "Construct, inspect, fragment, and fuzz packets"),
    ("files", "Read, combine, rewrite, and export capture files"),
    ("analyze", "Analyze captured traffic and compare forwarding"),
    (
        "network",
        "Inspect the local network and run policy-gated live workflows",
    ),
    (
        "reference",
        "Browse protocols, syntax, and generated documentation",
    ),
];

impl Entry {
    pub(crate) fn path(self) -> String {
        format!("{} {}", self.group, self.name)
    }
}

pub(crate) fn entry(identifier: &str) -> Option<&'static Entry> {
    INVENTORY
        .iter()
        .find(|entry| entry.identifier == identifier)
}

impl clap::FromArgMatches for CommandLine {
    fn from_arg_matches(matches: &clap::ArgMatches) -> Result<Self, clap::Error> {
        let (name, values) = matches
            .subcommand()
            .ok_or_else(|| clap::Error::new(clap::error::ErrorKind::MissingSubcommand))?;
        let (leaf, leaf_values) = values
            .subcommand()
            .ok_or_else(|| clap::Error::new(clap::error::ErrorKind::MissingSubcommand))?;
        let selected = INVENTORY
            .iter()
            .find(|entry| entry.group == name && entry.name == leaf)
            .ok_or_else(|| clap::Error::new(clap::error::ErrorKind::InvalidSubcommand))?;
        Self::from_leaf(selected.identifier, leaf_values)
    }

    fn update_from_arg_matches(&mut self, matches: &clap::ArgMatches) -> Result<(), clap::Error> {
        *self = Self::from_arg_matches(matches)?;
        Ok(())
    }
}

impl clap::Subcommand for CommandLine {
    fn augment_subcommands(command: clap::Command) -> clap::Command {
        let leaves = LeafDefinitions::augment_subcommands(clap::Command::new("packetcraftr"));
        let mut command = command;
        for (group, about) in GROUPS {
            let mut workflow = clap::Command::new(*group)
                .about(*about)
                .subcommand_required(true)
                .arg_required_else_help(true);
            for entry in INVENTORY.iter().filter(|entry| entry.group == *group) {
                let leaf = leaves
                    .find_subcommand(entry.identifier)
                    .expect("registered command")
                    .clone();
                workflow = workflow.subcommand(help::leaf(leaf.name(entry.name), entry));
            }
            command = command.subcommand(workflow);
        }
        command
    }

    fn augment_subcommands_for_update(command: clap::Command) -> clap::Command {
        Self::augment_subcommands(command)
    }

    fn has_subcommand(name: &str) -> bool {
        GROUPS.iter().any(|(group, _)| *group == name)
    }
}

#[cfg(test)]
mod tests {
    use super::{Command, PUBLISHED};
    use std::collections::BTreeSet;

    #[test]
    fn published_rows_cover_every_command_exactly() {
        let rows: Vec<_> = PUBLISHED.iter().flat_map(|rows| rows.iter()).collect();
        let names: BTreeSet<&str> = Command::ALL
            .iter()
            .map(|command| command.as_str())
            .collect();
        let mut pairs = BTreeSet::new();
        for row in &rows {
            assert!(
                names.contains(row.command),
                "{} names unknown command {}",
                row.definition,
                row.command
            );
            assert!(
                pairs.insert((row.definition, row.command)),
                "duplicate published row {}/{}",
                row.definition,
                row.command
            );
        }
        for name in names {
            assert!(
                rows.iter().any(|row| row.command == name),
                "command {name} publishes no output-schema row"
            );
        }
    }
}
