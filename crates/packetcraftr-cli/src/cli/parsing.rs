// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;
use std::ffi::OsString;

use clap::{ArgMatches, CommandFactory, FromArgMatches};

use super::Cli;

pub(crate) struct Parsed {
    pub(crate) cli: Cli,
    pub(crate) matches: ArgMatches,
    pub(crate) definition: clap::Command,
}

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
