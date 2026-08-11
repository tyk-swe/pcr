// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::ffi::{OsStr, OsString};

use packetcraftr::output;

use crate::cli::CliColorChoice;

#[derive(Clone, Copy, Debug, Default)]
pub(super) struct StartupContext {
    pub(super) machine_format: Option<output::contract::Format>,
    pub(super) color: CliColorChoice,
    pub(super) command: Option<output::contract::Command>,
}

pub(super) fn startup_context_from_env() -> StartupContext {
    let arguments = std::env::args_os().collect::<Vec<_>>();
    startup_context(&arguments)
}

fn startup_context(arguments: &[OsString]) -> StartupContext {
    let mut context = StartupContext::default();
    let mut saw_output = false;
    let mut saw_color = false;
    let mut saw_root_positional = false;
    let mut index = 1;

    while let Some(argument) = arguments.get(index) {
        if argument.as_os_str() == "--" {
            break;
        }

        if argument.as_os_str() == "--output" {
            let value = separate_option_value(arguments, index);
            if !saw_output {
                saw_output = true;
                context.machine_format =
                    value.and_then(OsStr::to_str).and_then(parse_machine_format);
            }
            index += usize::from(value.is_some()) + 1;
            continue;
        }
        if argument.as_os_str() == "--color" {
            let value = separate_option_value(arguments, index);
            if !saw_color {
                saw_color = true;
                context.color = value
                    .and_then(OsStr::to_str)
                    .map_or(CliColorChoice::Auto, parse_color_choice);
            }
            index += usize::from(value.is_some()) + 1;
            continue;
        }

        let argument = argument.to_str();
        if let Some(value) = argument.and_then(|argument| argument.strip_prefix("--output=")) {
            if !saw_output {
                saw_output = true;
                context.machine_format = parse_machine_format(value);
            }
            index += 1;
            continue;
        }
        if let Some(value) = argument.and_then(|argument| argument.strip_prefix("--color=")) {
            if !saw_color {
                saw_color = true;
                context.color = parse_color_choice(value);
            }
            index += 1;
            continue;
        }

        let is_option =
            argument.is_some_and(|argument| argument.starts_with('-') && argument != "-");
        if !saw_root_positional && !is_option {
            saw_root_positional = true;
            context.command = argument.and_then(parse_command);
        }
        index += 1;
    }

    context
}

fn separate_option_value(arguments: &[OsString], option_index: usize) -> Option<&OsStr> {
    arguments
        .get(option_index + 1)
        .map(OsString::as_os_str)
        .filter(|value| {
            !value
                .to_str()
                .is_some_and(|value| value.starts_with('-') && value != "-")
        })
}

fn parse_machine_format(value: &str) -> Option<output::contract::Format> {
    match value {
        "json" => Some(output::contract::Format::Json),
        "ndjson" => Some(output::contract::Format::Ndjson),
        _ => None,
    }
}

fn parse_color_choice(value: &str) -> CliColorChoice {
    match value {
        "always" => CliColorChoice::Always,
        "never" => CliColorChoice::Never,
        _ => CliColorChoice::Auto,
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

    #[test]
    fn startup_context_scans_global_options_without_guessing_commands() {
        struct Case {
            arguments: &'static [&'static str],
            format: Option<output::contract::Format>,
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
                format: Some(output::contract::Format::Ndjson),
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
                format: Some(output::contract::Format::Json),
                color: "always",
                command: Some(output::contract::Command::Build),
            },
            Case {
                arguments: &["packetcraftr", "--output", "--color=never", "dissect"],
                format: None,
                color: "never",
                command: Some(output::contract::Command::Dissect),
            },
            Case {
                arguments: &["packetcraftr", "--output=json", "invalid", "build"],
                format: Some(output::contract::Format::Json),
                color: "auto",
                command: None,
            },
            Case {
                arguments: &["packetcraftr", "--output=json", "--", "build"],
                format: Some(output::contract::Format::Json),
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
            let context = startup_context(&arguments);

            assert_eq!(context.machine_format, case.format, "{:?}", case.arguments);
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
