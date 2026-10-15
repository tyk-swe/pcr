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
    path: &[&str],
    defaults: &BTreeMap<&'static str, &'static str>,
) -> clap::Command {
    fn apply(
        command: clap::Command,
        path: &[&str],
        defaults: &BTreeMap<&'static str, &'static str>,
    ) -> clap::Command {
        match path.split_first() {
            Some((name, rest)) => {
                command.mut_subcommand(name, |command| apply(command, rest, defaults))
            }
            None => command.mut_args(|arg| match defaults.get(arg.get_id().as_str()) {
                Some(value) => arg.default_value(*value),
                None => arg,
            }),
        }
    }
    apply(Cli::command(), path, defaults)
}

/// Resolve a validated invocation to its leaf without dropping value sources.
pub(crate) fn leaf<'a>(
    mut definition: &'a clap::Command,
    mut matches: &'a ArgMatches,
) -> (&'a clap::Command, &'a ArgMatches) {
    while let Some((name, nested)) = matches.subcommand() {
        definition = definition
            .find_subcommand(name)
            .expect("validated subcommand");
        matches = nested;
    }
    (definition, matches)
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
    let path = match matches
        .subcommand()
        .and_then(|(_, values)| values.subcommand_name())
    {
        Some(leaf) => vec![subcommand, leaf],
        None => vec![subcommand],
    };
    let mut definition = preset_definition(&path, &defaults);
    let matches = definition.try_get_matches_from_mut(arguments)?;
    let cli = Cli::from_arg_matches(&matches)?;
    Ok(Parsed {
        cli,
        matches,
        definition,
    })
}
