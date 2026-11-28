// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod help;

use clap::Subcommand;

use super::dispatch::Launch;
use super::{Spec, analyze, files, network, packet, reference};
use crate::command_catalog::command_catalog;
use crate::output::contract::Command;
use crate::resources::Settings;

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
            $variant:ident($arguments:ty) $(= $name:literal [$($format:ident),+])?
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

command_catalog!(commands);

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
