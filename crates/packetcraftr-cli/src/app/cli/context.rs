// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::ffi::OsString;

use clap::{CommandFactory, ValueEnum};

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

/// Best-effort parse-failure context, scanning globals past argument errors
/// with option spellings and values from the real command definition.
pub(crate) fn parse(arguments: &[OsString]) -> Context {
    let definition = Cli::command();
    let mut format = None;
    let mut color = ColorChoice::default();
    let raw = clap_lex::RawArgs::new(arguments.iter().skip(1));
    let mut cursor = raw.cursor();
    while let Some(argument) = raw.next(&mut cursor) {
        if argument.is_escape() {
            break;
        }
        let Some((Ok(name), inline)) = argument.to_long() else {
            continue;
        };
        let Some(option) = definition.get_arguments().find(|option| {
            matches!(option.get_id().as_str(), "format" | "color")
                && option.get_long() == Some(name)
        }) else {
            continue;
        };
        let value = inline.or_else(|| {
            let next = raw.peek(&cursor)?;
            if next.is_escape() || next.is_long() || next.is_short() {
                return None;
            }
            raw.next_os(&mut cursor)
        });
        let Some(value) = value.and_then(|value| value.to_str()) else {
            continue;
        };
        match option.get_id().as_str() {
            "format" => {
                if let Ok(value) = Format::from_str(value, false) {
                    format = match value {
                        Format::Json => Some(MachineFormat::Json),
                        Format::Ndjson => Some(MachineFormat::Ndjson),
                        _ => None,
                    };
                }
            }
            "color" => {
                if let Ok(value) = ColorChoice::from_str(value, false) {
                    color = value;
                }
            }
            _ => {}
        }
    }
    let matches = definition
        .ignore_errors(true)
        .args_override_self(true)
        .get_matches_from(arguments);
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
    fn reads_globals_after_argument_errors() {
        for (options, format) in [
            (
                vec!["--bogus", "--output", "json", "--color", "never"],
                MachineFormat::Json,
            ),
            (
                vec!["--bogus", "--output=ndjson", "--color=never"],
                MachineFormat::Ndjson,
            ),
            (
                vec![
                    "--link-type",
                    "bogus",
                    "--output",
                    "json",
                    "--color",
                    "never",
                ],
                MachineFormat::Json,
            ),
            (
                vec!["--output", "bogus", "--output", "json", "--color", "never"],
                MachineFormat::Json,
            ),
            (
                vec!["--output", "--color", "never", "--output", "ndjson"],
                MachineFormat::Ndjson,
            ),
        ] {
            let arguments = ["packetcraftr", "packet", "build"]
                .into_iter()
                .chain(options)
                .collect::<Vec<_>>();
            let found = context(&arguments);
            assert_eq!(found.format, Some(format), "{arguments:?}");
            assert_eq!(found.color, ColorChoice::Never, "{arguments:?}");
            assert_eq!(
                found.command,
                Some(output::contract::Command::Build),
                "{arguments:?}"
            );
        }
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
                "--bogus",
                "--output",
                "ndjson",
                "--output",
                "invalid",
                "badcmd"
            ])
            .format,
            Some(MachineFormat::Ndjson)
        );
    }

    #[test]
    fn unknown_spellings_and_values_stay_text() {
        for arguments in [
            vec!["packetcraftr", "--outp", "ndjson", "badcmd"],
            vec!["packetcraftr", "--output", "bogus", "badcmd"],
            vec!["packetcraftr", "packet", "build", "--", "--output", "json"],
            vec!["packetcraftr", "packet", "build", "--packet=--output=json"],
            vec![
                "packetcraftr",
                "--output",
                "json",
                "--bogus",
                "--output=text",
            ],
        ] {
            assert_eq!(context(&arguments).format, None, "{arguments:?}");
        }
        assert_eq!(
            context(&["packetcraftr", "packet", "badleaf"]).command,
            None
        );
    }
}
