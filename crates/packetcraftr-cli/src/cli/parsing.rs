// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Preset-aware parsing, retaining the finalized definition for diagnostics.

use std::collections::BTreeMap;
use std::ffi::OsString;

use clap::{ArgMatches, CommandFactory, FromArgMatches};

use super::Cli;

/// The typed invocation and the parser metadata that produced it.
pub(crate) struct Parsed {
    pub(crate) cli: Cli,
    pub(crate) matches: ArgMatches,
    pub(crate) definition: clap::Command,
}

/// The command-line definition with `defaults`, the preset values the
/// selected command's typed arguments declare, as the named subcommand's
/// defaults.
fn preset_definition(
    subcommand: &str,
    defaults: &BTreeMap<&'static str, &'static str>,
) -> clap::Command {
    Cli::command().mut_subcommand(subcommand, |command| {
        command.mut_args(|arg| match defaults.get(arg.get_id().as_str()) {
            Some(value) => arg.default_value(*value),
            None => arg,
        })
    })
}

pub(crate) fn parse_from(arguments: Vec<OsString>) -> Result<Parsed, clap::Error> {
    let mut definition = Cli::command();
    let matches = definition.try_get_matches_from_mut(&arguments)?;
    let cli = Cli::from_arg_matches(&matches)?;
    let Some(preset) = cli.resource_preset else {
        return Ok(Parsed {
            cli,
            matches,
            definition,
        });
    };
    let subcommand = match matches.subcommand_name() {
        Some(subcommand) if cli.command.offline() => subcommand,
        _ => {
            return Err(Cli::command().error(
                clap::error::ErrorKind::ArgumentConflict,
                "--resource-preset applies only to offline capture commands",
            ));
        }
    };
    let defaults = cli.command.preset_defaults(preset);
    let mut definition = preset_definition(subcommand, &defaults);
    let matches = definition.try_get_matches_from_mut(arguments)?;
    let cli = Cli::from_arg_matches(&matches)?;
    Ok(Parsed {
        cli,
        matches,
        definition,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resources::Preset;

    #[test]
    fn both_presets_build_valid_command_trees() {
        let offline: &[&[&str]] = &[
            &["merge", "--write", "m.pcapng", "a.pcap", "b.pcap"],
            &["read", "a.pcap"],
            &["expert", "a.pcap"],
            &["follow", "--stream", "tcp:0", "a.pcap"],
            &["stats", "a.pcap"],
            &["tls", "a.pcap"],
            &["dns-read", "a.pcap"],
            &["http", "a.pcap"],
            &["export", "--write", "e.pcapng", "a.pcap"],
            &["rewrite", "--write", "r.pcapng", "a.pcap"],
            &[
                "verify-forwarding",
                "a.pcap",
                "b.pcap",
                "--identity",
                "ipv4.identification",
            ],
        ];
        for preset in [Preset::CiV1, Preset::WorkstationV1] {
            for arguments in offline {
                let cli = <Cli as clap::Parser>::try_parse_from(
                    std::iter::once("packetcraftr").chain(arguments.iter().copied()),
                )
                .expect("offline command parses");
                let defaults = cli.command.preset_defaults(preset);
                assert!(!defaults.is_empty(), "{arguments:?}");
                preset_definition(arguments[0], &defaults).debug_assert();
            }
        }
    }

    #[test]
    fn explicit_overrides_survive_a_preset_before_or_after_the_command() {
        for arguments in [
            vec![
                "packetcraftr",
                "--resource-preset",
                "ci-v1",
                "verify-forwarding",
                "a.pcap",
                "b.pcap",
                "--identity",
                "ipv4.identification",
                "--max-flows",
                "7",
            ],
            vec![
                "packetcraftr",
                "verify-forwarding",
                "a.pcap",
                "b.pcap",
                "--identity",
                "ipv4.identification",
                "--max-flows",
                "7",
                "--resource-preset",
                "ci-v1",
            ],
        ] {
            let Parsed { matches, .. } =
                parse_from(arguments.into_iter().map(OsString::from).collect())
                    .expect("valid preset");
            let (_, selected) = matches.subcommand().expect("comparison");
            assert_eq!(selected.get_one::<usize>("max_flows"), Some(&7));
            assert_eq!(
                selected.get_one::<usize>("max_detail_bytes"),
                Some(&1_048_576)
            );
            assert_eq!(
                selected.value_source("max_flows"),
                Some(clap::parser::ValueSource::CommandLine)
            );
        }
    }

    #[test]
    fn presets_cannot_change_live_authorization_or_traffic_limits() {
        let result = parse_from(
            ["packetcraftr", "--resource-preset", "ci-v1", "interfaces"]
                .into_iter()
                .map(OsString::from)
                .collect(),
        );
        assert!(result.is_err());
    }
}
