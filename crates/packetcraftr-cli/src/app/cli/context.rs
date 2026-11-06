// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::ffi::OsString;

use clap::{CommandFactory, parser::ValueSource};

use crate::output;

use super::{Cli, ColorChoice, Format};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MachineFormat {
    Json,
    Ndjson,
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Context {
    pub(crate) format: Option<MachineFormat>,
    pub(crate) color: ColorChoice,
    pub(crate) command: Option<output::contract::Command>,
}

/// Best-effort context for reporting a parse failure, read from the real
/// command definition with errors ignored so it can never disagree with the
/// parser about option spellings, clusters, or where globals may appear.
pub(crate) fn parse(arguments: &[OsString]) -> Context {
    let matches = Cli::command()
        .ignore_errors(true)
        .args_override_self(true)
        .get_matches_from(arguments);
    let supplied = |id| matches.value_source(id) == Some(ValueSource::CommandLine);
    let format = supplied("format")
        .then(|| {
            matches
                .get_many::<Format>("format")
                .and_then(|mut all| all.next_back().copied())
        })
        .flatten()
        .and_then(|format| match format {
            Format::Json => Some(MachineFormat::Json),
            Format::Ndjson => Some(MachineFormat::Ndjson),
            _ => None,
        });
    let color = supplied("color")
        .then(|| matches.get_one::<ColorChoice>("color").copied())
        .flatten()
        .unwrap_or_default();
    let command = matches.subcommand().and_then(|(group, values)| {
        let leaf = values.subcommand_name()?;
        crate::commands::registry::INVENTORY
            .iter()
            .find(|entry| entry.group == group && entry.name == leaf)
            .and_then(|entry| parse_command(entry.identifier))
    });
    Context {
        format,
        color,
        command,
    }
}

fn parse_command(value: &str) -> Option<output::contract::Command> {
    output::contract::Command::ALL
        .iter()
        .copied()
        .find(|command| command.as_str() == value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context(arguments: &[&str]) -> Context {
        parse(&arguments.iter().map(OsString::from).collect::<Vec<_>>())
    }

    #[test]
    fn reads_machine_format_before_and_after_the_command() {
        assert_eq!(
            context(&["packetcraftr", "--output", "ndjson", "badcmd"]).format,
            Some(MachineFormat::Ndjson)
        );
        let after = context(&[
            "packetcraftr",
            "packet",
            "build",
            "--output",
            "json",
            "--bogus",
        ]);
        assert_eq!(after.format, Some(MachineFormat::Json));
        assert_eq!(after.command, Some(output::contract::Command::Build));
    }

    #[test]
    fn clustered_short_flags_and_inline_values_parse() {
        let found = context(&[
            "packetcraftr",
            "-v",
            "--color=never",
            "--output=json",
            "badcmd",
        ]);
        assert_eq!(found.format, Some(MachineFormat::Json));
        assert_eq!(found.color, ColorChoice::Never);
    }

    #[test]
    fn repeated_output_keeps_the_last_valid_format() {
        assert_eq!(
            context(&[
                "packetcraftr",
                "--output",
                "json",
                "--output",
                "ndjson",
                "badcmd"
            ])
            .format,
            Some(MachineFormat::Ndjson)
        );
    }

    #[test]
    fn unknown_spellings_and_values_stay_text() {
        assert_eq!(
            context(&["packetcraftr", "--outp", "ndjson", "badcmd"]).format,
            None
        );
        assert_eq!(
            context(&["packetcraftr", "--output", "bogus", "badcmd"]).format,
            None
        );
        assert_eq!(
            context(&["packetcraftr", "packet", "badleaf"]).command,
            None
        );
    }
}
