// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::ffi::OsString;

use clap::ValueEnum;

use crate::commands::registry::INVENTORY;
use crate::output;

use super::{ColorChoice, Format};

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

#[derive(Clone, Copy)]
enum CommandScan {
    NeedGroup,
    NeedLeaf(&'static str),
    Done(Option<output::contract::Command>),
}

/// Best-effort parse-failure context, scanning globals and the `(group, leaf)`
/// subcommand directly from `clap_lex` tokens without building `Cli::command()`.
pub(crate) fn parse(arguments: &[OsString]) -> Context {
    let mut format = None;
    let mut color = ColorChoice::default();
    let mut scan = CommandScan::NeedGroup;
    let raw = clap_lex::RawArgs::new(arguments.iter().skip(1));
    let mut cursor = raw.cursor();
    while let Some(argument) = raw.next(&mut cursor) {
        if argument.is_escape() {
            break;
        }
        if let Some((Ok(name), inline)) = argument.to_long() {
            match name {
                "output" | "color" | "resource-preset" | "output-timeout-ms" => {
                    let value = inline.or_else(|| next_option_value(&raw, &mut cursor));
                    if let Some(value) = value.and_then(|value| value.to_str()) {
                        match name {
                            "output" => {
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
                }
                _ => {}
            }
            continue;
        }
        if argument.is_long() || argument.is_short() {
            continue;
        }
        if let Ok(token) = argument.to_value() {
            scan = match scan {
                CommandScan::NeedGroup => INVENTORY
                    .iter()
                    .find(|entry| entry.group == token)
                    .map_or(CommandScan::Done(None), |entry| {
                        CommandScan::NeedLeaf(entry.group)
                    }),
                CommandScan::NeedLeaf(group) => CommandScan::Done(
                    INVENTORY
                        .iter()
                        .find(|entry| entry.group == group && entry.name == token)
                        .and_then(|entry| parse_command(entry.identifier)),
                ),
                CommandScan::Done(command) => CommandScan::Done(command),
            };
        }
    }
    let command = match scan {
        CommandScan::Done(command) => command,
        CommandScan::NeedGroup | CommandScan::NeedLeaf(_) => None,
    };
    Context {
        format,
        color,
        command,
    }
}

fn next_option_value<'a>(
    raw: &'a clap_lex::RawArgs,
    cursor: &mut clap_lex::ArgCursor,
) -> Option<&'a std::ffi::OsStr> {
    let next = raw.peek(cursor)?;
    if next.is_escape() || next.is_long() || next.is_short() {
        return None;
    }
    raw.next_os(cursor)
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

    #[test]
    fn resolves_command_past_value_taking_globals() {
        let found = context(&[
            "packetcraftr",
            "--resource-preset",
            "ci-v1",
            "--output-timeout-ms",
            "500",
            "-v",
            "network",
            "--output",
            "json",
            "scan",
            "--bogus",
        ]);
        assert_eq!(found.format, Some(MachineFormat::Json));
        assert_eq!(found.command, Some(output::contract::Command::Scan));
        assert_eq!(
            context(&["packetcraftr", "badgroup", "packet", "build"]).command,
            None
        );
    }
}
