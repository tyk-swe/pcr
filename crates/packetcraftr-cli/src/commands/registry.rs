// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use clap::Subcommand;
use serde::Serialize;

use super::dispatch::Launch;
use super::{
    Spec, build, capture, dissect, dns, dns_read, documentation, exchange, expert, export, follow,
    fragment, fuzz, http, http2, identify, identify_os, interfaces, merge, plan, protocols, read,
    replay, rewrite, routes, scan, send, stats, tls, topics, traceroute, verify_forwarding,
};
use crate::output::contract::Format;
use crate::resources::Settings;

/// Declares every command once, in `--help` order.
macro_rules! commands {
    (@name Documentation) => { "documentation" };
    (@name Topics) => { "topics" };
    (@name $variant:ident, $name:literal) => { $name };
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
        #[allow(dead_code, clippy::large_enum_variant)]
        enum FlatDefinition {
            $(
                $(#[$attribute])*
                $(#[command(name = $name)])?
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
                    if name == commands!(@name $variant $(, $name)?) {
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
    #[command(after_long_help = protocols::AFTER_LONG_HELP)]
    Protocols(protocols::Args) = "protocols",
    /// Stream frames from a classic PCAP or PCAPNG file.
    #[command(after_long_help = read::arguments::AFTER_LONG_HELP)]
    Read(read::arguments::Args) = "read",
    /// Enumerate local interfaces.
    #[command(after_long_help = interfaces::AFTER_LONG_HELP)]
    Interfaces(interfaces::Args) = "interfaces",
    /// Passively select route, source, MTU, and link mode.
    #[command(after_long_help = plan::AFTER_LONG_HELP)]
    Plan(plan::Args) = "plan",
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
    /// Explicitly identify services at selected numeric TCP or UDP endpoints.
    #[command(after_long_help = identify::arguments::AFTER_LONG_HELP)]
    Identify(identify::arguments::Args) = "identify",
    /// Identify qualified OS families from bounded raw packet observations.
    #[command(after_long_help = "Requires a native raw packet provider and explicit destination authorization. Conclusions are qualified inferences, not authenticated identities.\n\nExample:\n  packetcraftr network identify-os 192.0.2.10 --open-port 80 --closed-port 81")]
    IdentifyOs(identify_os::Args) = "identify-os",
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
    #[command(after_long_help = routes::AFTER_LONG_HELP)]
    Routes(routes::Args) = "routes",
    /// Compare ingress and egress captures under explicit identity rules.
    #[command(after_long_help = verify_forwarding::arguments::AFTER_LONG_HELP)]
    VerifyForwarding(verify_forwarding::arguments::Args) = "verify-forwarding",
    /// Generate shell completions and man pages under a directory.
    #[command(after_long_help = "Writes completions for Bash, Elvish, Fish, PowerShell, and Zsh, and man pages for all canonical and legacy paths. Requires a writable directory.\n\nExample:\n  packetcraftr reference documentation --directory ./cli-docs")]
    Documentation(documentation::Args),
    /// Print built-in references for packet expressions, filters, formats, and exit codes.
    #[command(after_long_help = topics::AFTER_LONG_HELP)]
    Topics(topics::Args),
}

/// Workflow placement. Published identifiers deliberately remain the legacy names.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Entry {
    pub(crate) group: &'static str,
    pub(crate) name: &'static str,
    pub(crate) legacy: &'static str,
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

pub(crate) const INVENTORY: &[Entry] = &[
    Entry {
        group: "packet",
        name: "build",
        legacy: "build",
    },
    Entry {
        group: "packet",
        name: "dissect",
        legacy: "dissect",
    },
    Entry {
        group: "packet",
        name: "fragment",
        legacy: "fragment",
    },
    Entry {
        group: "packet",
        name: "fuzz",
        legacy: "fuzz",
    },
    Entry {
        group: "files",
        name: "read",
        legacy: "read",
    },
    Entry {
        group: "files",
        name: "merge",
        legacy: "merge",
    },
    Entry {
        group: "files",
        name: "rewrite",
        legacy: "rewrite",
    },
    Entry {
        group: "files",
        name: "export",
        legacy: "export",
    },
    Entry {
        group: "analyze",
        name: "stats",
        legacy: "stats",
    },
    Entry {
        group: "analyze",
        name: "expert",
        legacy: "expert",
    },
    Entry {
        group: "analyze",
        name: "follow",
        legacy: "follow",
    },
    Entry {
        group: "analyze",
        name: "dns",
        legacy: "dns-read",
    },
    Entry {
        group: "analyze",
        name: "http",
        legacy: "http",
    },
    Entry {
        group: "analyze",
        name: "http2",
        legacy: "http2",
    },
    Entry {
        group: "analyze",
        name: "tls",
        legacy: "tls",
    },
    Entry {
        group: "analyze",
        name: "verify-forwarding",
        legacy: "verify-forwarding",
    },
    Entry {
        group: "network",
        name: "interfaces",
        legacy: "interfaces",
    },
    Entry {
        group: "network",
        name: "routes",
        legacy: "routes",
    },
    Entry {
        group: "network",
        name: "plan",
        legacy: "plan",
    },
    Entry {
        group: "network",
        name: "capture",
        legacy: "capture",
    },
    Entry {
        group: "network",
        name: "send",
        legacy: "send",
    },
    Entry {
        group: "network",
        name: "exchange",
        legacy: "exchange",
    },
    Entry {
        group: "network",
        name: "replay",
        legacy: "replay",
    },
    Entry {
        group: "network",
        name: "scan",
        legacy: "scan",
    },
    Entry {
        group: "network",
        name: "identify",
        legacy: "identify",
    },
    Entry {
        group: "network",
        name: "identify-os",
        legacy: "identify-os",
    },
    Entry {
        group: "network",
        name: "traceroute",
        legacy: "traceroute",
    },
    Entry {
        group: "network",
        name: "dns",
        legacy: "dns",
    },
    Entry {
        group: "reference",
        name: "protocols",
        legacy: "protocols",
    },
    Entry {
        group: "reference",
        name: "topics",
        legacy: "topics",
    },
    Entry {
        group: "reference",
        name: "documentation",
        legacy: "documentation",
    },
];

impl Entry {
    pub(crate) fn path(self) -> String {
        format!("{} {}", self.group, self.name)
    }
}

pub(crate) fn entry(legacy: &str) -> Option<&'static Entry> {
    INVENTORY.iter().find(|entry| entry.legacy == legacy)
}

impl clap::FromArgMatches for CommandLine {
    fn from_arg_matches(matches: &clap::ArgMatches) -> Result<Self, clap::Error> {
        let (name, values) = matches
            .subcommand()
            .ok_or_else(|| clap::Error::new(clap::error::ErrorKind::MissingSubcommand))?;
        if GROUPS.iter().any(|(group, _)| *group == name) {
            let (leaf, _) = values
                .subcommand()
                .ok_or_else(|| clap::Error::new(clap::error::ErrorKind::MissingSubcommand))?;
            let selected = INVENTORY
                .iter()
                .find(|entry| entry.group == name && entry.name == leaf)
                .expect("clap validated the workflow command");
            let (_, leaf_values) = values.subcommand().expect("leaf exists");
            Self::from_leaf(selected.legacy, leaf_values)
        } else {
            Self::from_leaf(name, values)
        }
    }

    fn update_from_arg_matches(&mut self, matches: &clap::ArgMatches) -> Result<(), clap::Error> {
        *self = Self::from_arg_matches(matches)?;
        Ok(())
    }
}

impl clap::Subcommand for CommandLine {
    fn augment_subcommands(command: clap::Command) -> clap::Command {
        let flat = FlatDefinition::augment_subcommands(clap::Command::new("packetcraftr"));
        let mut command = command;
        for (group, about) in GROUPS {
            let mut workflow = clap::Command::new(*group)
                .about(*about)
                .subcommand_required(true)
                .arg_required_else_help(true);
            for entry in INVENTORY.iter().filter(|entry| entry.group == *group) {
                let leaf = flat
                    .find_subcommand(entry.legacy)
                    .expect("registered command")
                    .clone();
                workflow =
                    workflow.subcommand(crate::cli::help::leaf(leaf.name(entry.name), entry));
            }
            command = command.subcommand(workflow);
        }
        for entry in INVENTORY {
            let leaf = flat
                .find_subcommand(entry.legacy)
                .expect("registered command")
                .clone();
            command = command.subcommand(crate::cli::help::leaf(leaf, entry).hide(true));
        }
        command
    }

    fn augment_subcommands_for_update(command: clap::Command) -> clap::Command {
        Self::augment_subcommands(command)
    }

    fn has_subcommand(name: &str) -> bool {
        GROUPS.iter().any(|(group, _)| *group == name)
            || INVENTORY.iter().any(|entry| entry.legacy == name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn every_workflow_and_legacy_path_has_the_same_arguments_and_help() {
        let mut definition = crate::cli::Cli::command();
        definition.build();
        assert_eq!(INVENTORY.len(), 31);
        for entry in INVENTORY {
            let canonical = definition
                .find_subcommand(entry.group)
                .unwrap()
                .find_subcommand(entry.name)
                .unwrap();
            let legacy = definition.find_subcommand(entry.legacy).unwrap();
            assert!(legacy.is_hide_set());
            assert_eq!(
                canonical.get_about(),
                legacy.get_about(),
                "{}",
                entry.path()
            );
            let ids = |command: &clap::Command| {
                command
                    .get_arguments()
                    .map(|arg| arg.get_id().to_string())
                    .collect::<Vec<_>>()
            };
            assert_eq!(ids(canonical), ids(legacy));
            assert!(
                canonical
                    .get_after_long_help()
                    .unwrap()
                    .to_string()
                    .contains(&entry.path())
            );
        }
    }
}
