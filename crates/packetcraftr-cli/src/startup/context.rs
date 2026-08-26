// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::ffi::{OsStr, OsString};

use packetcraftr::output;

use crate::cli::ColorChoice;

/// The formats that can carry a structured error document. A clap failure is
/// reported in one of these or, for everything else, as prose on stderr.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum MachineFormat {
    Json,
    Ndjson,
}

#[derive(Clone, Copy, Debug, Default)]
pub(super) struct Context {
    pub(super) format: Option<MachineFormat>,
    pub(super) color: ColorChoice,
    pub(super) command: Option<output::contract::Command>,
}

pub(super) fn from_env() -> Context {
    let arguments = std::env::args_os().collect::<Vec<_>>();
    parse(&arguments)
}

/// Reads the global options the way clap will read them: the last `--output`
/// and `--color` win, and the first bare word is the subcommand.
fn parse(arguments: &[OsString]) -> Context {
    let mut context = Context::default();
    let mut saw_root_positional = false;
    let mut index = 1;

    while let Some(argument) = arguments.get(index) {
        if argument.as_os_str() == "--" {
            break;
        }

        if argument.as_os_str() == "--output" {
            let value = separate_option_value(arguments, index);
            context.format = value.and_then(OsStr::to_str).and_then(parse_machine_format);
            index = index
                .saturating_add(usize::from(value.is_some()))
                .saturating_add(1);
            continue;
        }
        if argument.as_os_str() == "--color" {
            let value = separate_option_value(arguments, index);
            context.color = value
                .and_then(OsStr::to_str)
                .map_or(ColorChoice::Auto, parse_color_choice);
            index = index
                .saturating_add(usize::from(value.is_some()))
                .saturating_add(1);
            continue;
        }

        let argument = argument.to_str();
        if let Some(value) = argument.and_then(|argument| argument.strip_prefix("--output=")) {
            context.format = parse_machine_format(value);
            index = index.saturating_add(1);
            continue;
        }
        if let Some(value) = argument.and_then(|argument| argument.strip_prefix("--color=")) {
            context.color = parse_color_choice(value);
            index = index.saturating_add(1);
            continue;
        }

        let is_option =
            argument.is_some_and(|argument| argument.starts_with('-') && argument != "-");
        if !saw_root_positional && !is_option {
            saw_root_positional = true;
            context.command = argument.and_then(parse_command);
        }
        index = index.saturating_add(1);
    }

    context
}

fn separate_option_value(arguments: &[OsString], option_index: usize) -> Option<&OsStr> {
    arguments
        .get(option_index.saturating_add(1))
        .map(OsString::as_os_str)
        .filter(|value| {
            !value
                .to_str()
                .is_some_and(|value| value.starts_with('-') && value != "-")
        })
}

fn parse_machine_format(value: &str) -> Option<MachineFormat> {
    match value {
        "json" => Some(MachineFormat::Json),
        "ndjson" => Some(MachineFormat::Ndjson),
        _ => None,
    }
}

fn parse_color_choice(value: &str) -> ColorChoice {
    match value {
        "always" => ColorChoice::Always,
        "never" => ColorChoice::Never,
        _ => ColorChoice::Auto,
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

    /// The startup scan runs before clap, so it has to agree with clap on
    /// which repeat of a global option counts: the last one.
    #[test]
    fn startup_context_scans_global_options_without_guessing_commands() {
        struct Case {
            arguments: &'static [&'static str],
            format: Option<MachineFormat>,
            color: &'static str,
            command: Option<output::contract::Command>,
        }

        let cases = [
            Case {
                arguments: &[
                    "packetcraftr",
                    "protocols",
                    "--output",
                    "ndjson",
                    "--color=never",
                ],
                format: Some(MachineFormat::Ndjson),
                color: "never",
                command: Some(output::contract::Command::Protocols),
            },
            Case {
                arguments: &[
                    "packetcraftr",
                    "--output=json",
                    "--output=ndjson",
                    "--color",
                    "always",
                    "--color=never",
                    "build",
                ],
                format: Some(MachineFormat::Ndjson),
                color: "never",
                command: Some(output::contract::Command::Build),
            },
            Case {
                arguments: &["packetcraftr", "--output", "--color=never", "dissect"],
                format: None,
                color: "never",
                command: Some(output::contract::Command::Dissect),
            },
            Case {
                arguments: &["packetcraftr", "--output=ndjson", "tls", "capture.pcapng"],
                format: Some(MachineFormat::Ndjson),
                color: "auto",
                command: Some(output::contract::Command::Tls),
            },
            Case {
                arguments: &["packetcraftr", "--output=json", "invalid", "build"],
                format: Some(MachineFormat::Json),
                color: "auto",
                command: None,
            },
            Case {
                arguments: &["packetcraftr", "--output=json", "--", "build"],
                format: Some(MachineFormat::Json),
                color: "auto",
                command: None,
            },
        ];

        for case in cases {
            let arguments = case
                .arguments
                .iter()
                .map(OsString::from)
                .collect::<Vec<_>>();
            let context = parse(&arguments);

            assert_eq!(context.format, case.format, "{:?}", case.arguments);
            assert_eq!(
                context.color.to_string(),
                case.color,
                "{:?}",
                case.arguments
            );
            assert_eq!(context.command, case.command, "{:?}", case.arguments);
        }
    }
}
