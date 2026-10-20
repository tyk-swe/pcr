// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use clap::Subcommand;
use serde::Serialize;

use super::dispatch::Launch;
use super::{Spec, analyze, files, network, packet, reference};
use crate::output::contract::Format;
use crate::resources::Settings;

/// Declares every command once, in `--help` order, with its workflow placement.
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
                => ($group:literal, $canonical:literal, $position:literal),
        )*
    ) => {
        /// The parsed subcommand with its arguments.
        #[derive(Debug, Subcommand)]
        #[allow(dead_code, clippy::large_enum_variant)]
        enum LeafDefinitions {
            $(
                $(#[$attribute])*
                #[command(name = commands!(@identifier $canonical $(, $name)?))]
                $variant($arguments),
            )*
        }

        #[derive(Debug)]
        #[allow(clippy::large_enum_variant)]
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
                                <$arguments as Spec>::FORMATS
                            ),
                        )?
                    )*
                }
            }
        }

        // Inventory positions preserve workflow order independently of declaration order.
        pub(crate) const INVENTORY: &[Entry] = &{
            const POSITIONS: &[usize] = &[ $( $position, )* ];
            let declarations = [
                $(
                    Entry {
                        group: $group,
                        name: $canonical,
                        identifier: commands!(@identifier $canonical $(, $name)?),
                    },
                )*
            ];
            let mut inventory = declarations;
            let mut assigned = [false; POSITIONS.len()];
            let mut index = 0;
            while index < declarations.len() {
                let position = POSITIONS[index];
                assert!(position < declarations.len(), "command inventory position out of bounds");
                assert!(!assigned[position], "duplicate command inventory position");
                inventory[position] = declarations[index];
                assigned[position] = true;
                index += 1;
            }
            inventory
        };
    };
}

commands! {
    /// Match local indicators against capture endpoints and application evidence.
    #[command(after_long_help = "Example: packetcraftr analyze hunt capture.pcapng --indicators indicators.json")]
    Hunt(analyze::security::Hunt) = "hunt" => ("analyze", "hunt", 31),
    /// Report high NXDOMAIN ratios and repeated high-entropy query labels.
    #[command(after_long_help = "Defaults: 60-second windows; at least 20 matched responses and 50% NXDOMAIN; or 20 distinct leading labels of at least 32 characters and 4 bits/character entropy.\n\nExample: packetcraftr analyze dns-anomalies capture.pcapng")]
    DnsAnomalies(analyze::security::Dns) = "dns-anomalies" => ("analyze", "dns-anomalies", 32),
    /// Detect regularly spaced TCP connection attempts.
    #[command(after_long_help = "Defaults: six distinct SYN attempts, mean interval at least one second, coefficient of variation at most 0.10. Retransmissions are deduplicated; clock regressions suppress timing conclusions.\n\nExample: packetcraftr analyze beacons capture.pcapng")]
    Beacons(analyze::security::Beacons) = "beacons" => ("analyze", "beacons", 33),
    /// Compare scoped endpoint states and scan coverage from native aggregate JSON.
    #[command(after_long_help = "Requires successful aggregate JSON from matching native scan methods. Missing endpoints are coverage changes, never presumed closed.\n\nExample: packetcraftr analyze scan-diff before.json after.json")]
    ScanDiff(analyze::scan_diff::ScanDiff) = "scan-diff" => ("analyze", "scan-diff", 34),
    /// Combine security results into a standalone local HTML assessment.
    #[command(after_long_help = "Accepts aggregate JSON from the six security analysis/audit commands. Escapes captured content, records source-file hashes, and refuses existing HTML destinations.\n\nExample: packetcraftr analyze report hunt.json tls.json --html assessment.html")]
    Assessment(analyze::report::Assessment) = "report" => ("analyze", "report", 35),
    /// Audit an observed TLS handshake, certificate chain, and name matching.
    #[command(after_long_help = "Uses ordinary TCP sockets. Bundled WebPKI roots are replaced by --ca-file. --server-name sets SNI and certificate identity without resolving another target. No revocation fetching or protocol enumeration.\n\nExample: packetcraftr network audit-tls 192.0.2.10:443 --server-name example.test")]
    AuditTls(network::audit::AuditTls) = "audit-tls" => ("network", "audit-tls", 36),
    /// Audit HTTP response headers and redacted cookie attributes with one HEAD request.
    #[command(after_long_help = "Sends one HEAD / over HTTP/1.1 by default and follows no redirects. HTTPS sends the request only after certificate verification succeeds. Cookie values are redacted.\n\nExample: packetcraftr network audit-http 192.0.2.10:443 --tls --server-name example.test --host example.test")]
    AuditHttp(network::audit::AuditHttp) = "audit-http" => ("network", "audit-http", 37),
    /// Merge time-ordered captures into scoped PCAPNG.
    #[command(after_long_help = files::merge::arguments::AFTER_LONG_HELP)]
    Merge(files::merge::arguments::Args) = "merge" => ("files", "merge", 5),
    /// Explicitly split a complete IPv4/IPv6 recipe into bounded fragments.
    #[command(after_long_help = packet::fragment::arguments::AFTER_LONG_HELP)]
    Fragment(packet::fragment::arguments::Args) = "fragment" => ("packet", "fragment", 2),
    /// Build exact packet bytes from an expression or document.
    #[command(after_long_help = packet::build::arguments::AFTER_LONG_HELP)]
    Build(packet::build::arguments::Args) = "build" => ("packet", "build", 0),
    /// Decode a frame with bounded, registry-driven dissection.
    #[command(after_long_help = packet::dissect::arguments::AFTER_LONG_HELP)]
    Dissect(packet::dissect::arguments::Args) = "dissect" => ("packet", "dissect", 1),
    /// List built-in protocols or describe one protocol.
    #[command(after_long_help = reference::protocols::AFTER_LONG_HELP)]
    Protocols(reference::protocols::Args) = "protocols" => ("reference", "protocols", 28),
    /// Stream frames from a classic PCAP or PCAPNG file.
    #[command(after_long_help = files::read::arguments::AFTER_LONG_HELP)]
    Read(files::read::arguments::Args) = "read" => ("files", "read", 4),
    /// Enumerate local interfaces.
    #[command(after_long_help = network::interfaces::AFTER_LONG_HELP)]
    Interfaces(network::interfaces::Args) = "interfaces" => ("network", "interfaces", 16),
    /// Passively select route, source, MTU, and link mode.
    #[command(after_long_help = network::plan::AFTER_LONG_HELP)]
    Plan(network::plan::Args) = "plan" => ("network", "plan", 18),
    /// Transmit a packet under traffic policy.
    #[command(after_long_help = network::send::arguments::AFTER_LONG_HELP)]
    Send(network::send::arguments::Args) = "send" => ("network", "send", 20),
    /// Capture-ready request/response exchange.
    #[command(after_long_help = network::exchange::arguments::AFTER_LONG_HELP)]
    Exchange(network::exchange::arguments::Args) = "exchange" => ("network", "exchange", 21),
    /// Stream live captured frames.
    #[command(after_long_help = network::capture::arguments::AFTER_LONG_HELP)]
    Capture(network::capture::arguments::Args) = "capture" => ("network", "capture", 19),
    /// Report protocol health findings over a capture file.
    #[command(after_long_help = analyze::expert::arguments::AFTER_LONG_HELP)]
    Expert(analyze::expert::arguments::Args) = "expert" => ("analyze", "expert", 9),
    /// Extract one conversation's payload from a capture file.
    #[command(after_long_help = analyze::follow::arguments::AFTER_LONG_HELP)]
    Follow(analyze::follow::arguments::Args) = "follow" => ("analyze", "follow", 10),
    /// Replay a PCAP/PCAPNG stream.
    #[command(after_long_help = network::replay::arguments::AFTER_LONG_HELP)]
    Replay(network::replay::arguments::Args) = "replay" => ("network", "replay", 22),
    /// Run a structured network scan.
    #[command(after_long_help = network::scan::arguments::AFTER_LONG_HELP)]
    Scan(network::scan::arguments::Args) = "scan" => ("network", "scan", 23),
    /// Explicitly identify services at selected numeric TCP or UDP endpoints.
    #[command(after_long_help = network::identify::arguments::AFTER_LONG_HELP)]
    Identify(network::identify::arguments::Args) = "identify" => ("network", "identify", 24),
    /// Identify qualified OS families from bounded raw packet observations.
    #[command(after_long_help = "Requires a native raw packet provider and explicit destination authorization. Conclusions are qualified inferences, not authenticated identities.\n\nExample:\n  packetcraftr network identify-os 192.0.2.10 --open-port 80 --closed-port 81")]
    IdentifyOs(network::identify_os::Args) = "identify-os" => ("network", "identify-os", 25),
    /// Compute aggregate statistics over a capture file.
    #[command(after_long_help = analyze::stats::arguments::AFTER_LONG_HELP)]
    Stats(analyze::stats::arguments::Args) = "stats" => ("analyze", "stats", 8),
    /// Assemble TLS handshake sessions from a capture file.
    #[command(after_long_help = analyze::tls::arguments::AFTER_LONG_HELP)]
    Tls(analyze::tls::arguments::Args) = "tls" => ("analyze", "tls", 14),
    /// Run bounded, policy-gated traceroute probes.
    #[command(
        long_about = network::traceroute::arguments::LONG_ABOUT,
        after_long_help = network::traceroute::arguments::AFTER_LONG_HELP
    )]
    Traceroute(network::traceroute::arguments::Args) = "traceroute" => ("network", "traceroute", 26),
    /// Run bounded DNS over UDP, TCP, or UDP with TCP fallback.
    #[command(
        long_about = network::dns::arguments::LONG_ABOUT,
        after_long_help = network::dns::arguments::AFTER_LONG_HELP
    )]
    Dns(network::dns::arguments::Args) = "dns" => ("network", "dns", 27),
    /// Inspect captured UDP/TCP DNS messages and transaction evidence.
    #[command(after_long_help = analyze::dns::arguments::AFTER_LONG_HELP)]
    DnsRead(analyze::dns::arguments::Args) = "dns-read" => ("analyze", "dns", 11),
    /// Inspect cleartext HTTP/1 messages over captured TCP streams.
    #[command(after_long_help = analyze::http::arguments::AFTER_LONG_HELP)]
    Http(analyze::http::arguments::Args) = "http" => ("analyze", "http", 12),
    #[command(
        about = "Inspect cleartext HTTP/2 and h2c over captured TCP streams.",
        after_long_help = analyze::http2::arguments::AFTER_LONG_HELP
    )]
    Http2(analyze::http2::arguments::Args) = "http2" => ("analyze", "http2", 13),
    /// Export streams and reassembled IP datagrams with their physical dependencies.
    #[command(after_long_help = files::export::arguments::AFTER_LONG_HELP)]
    Export(files::export::arguments::Args) = "export" => ("files", "export", 7),
    /// Rewrite capture headers with checked lengths and transport checksums.
    #[command(after_long_help = files::rewrite::arguments::AFTER_LONG_HELP)]
    Rewrite(files::rewrite::arguments::Args) = "rewrite" => ("files", "rewrite", 6),
    /// Run bounded field-aware packet fuzzing.
    #[command(after_long_help = packet::fuzz::arguments::AFTER_LONG_HELP)]
    Fuzz(packet::fuzz::arguments::Args) = "fuzz" => ("packet", "fuzz", 3),
    /// Enumerate passive interface-bound route decisions.
    #[command(after_long_help = network::routes::AFTER_LONG_HELP)]
    Routes(network::routes::Args) = "routes" => ("network", "routes", 17),
    /// Compare ingress and egress captures under explicit identity rules.
    #[command(after_long_help = analyze::verify_forwarding::arguments::AFTER_LONG_HELP)]
    VerifyForwarding(analyze::verify_forwarding::arguments::Args) = "verify-forwarding" => ("analyze", "verify-forwarding", 15),
    /// Generate shell completions and man pages under a directory.
    #[command(after_long_help = "Writes completions for Bash, Elvish, Fish, PowerShell, and Zsh, and man pages for all grouped paths. Requires a writable directory.\n\nExample:\n  packetcraftr reference documentation --directory ./cli-docs")]
    Documentation(reference::documentation::Args) => ("reference", "documentation", 30),
    /// Print built-in references for packet expressions, filters, formats, and exit codes.
    #[command(after_long_help = reference::topics::AFTER_LONG_HELP)]
    Topics(reference::topics::Args) => ("reference", "topics", 29),
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
                workflow =
                    workflow.subcommand(crate::cli::help::leaf(leaf.name(entry.name), entry));
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
