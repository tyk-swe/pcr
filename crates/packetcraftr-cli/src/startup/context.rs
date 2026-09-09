// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::ffi::OsString;

use packetcraftr_cli::output;

use crate::cli::ColorChoice;
use packetcraftr_cli::output::contract::Format;

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

/// Selects error rendering from global output/color options and the first
/// root positional. This scan never interprets command-specific options or
/// decides argument validity; Clap remains the argument parser.
fn parse(arguments: &[OsString]) -> Context {
    let mut context = Context::default();
    let mut saw_root_positional = false;
    let mut arguments = arguments.iter().skip(1).peekable();
    while let Some(raw) = arguments.next() {
        if raw == "--" {
            break;
        }
        let argument = raw.to_str();
        let (name, inline) = argument.map_or(("", None), |argument| {
            argument
                .split_once('=')
                .map_or((argument, None), |(name, value)| (name, Some(value)))
        });
        if matches!(name, "--output" | "--color" | "--output-timeout-ms") {
            let value = inline.or_else(|| {
                arguments
                    .next_if(|value| {
                        value
                            .to_str()
                            .is_none_or(|value| !value.starts_with('-') || value == "-")
                    })
                    .and_then(|value| value.to_str())
            });
            if name == "--output" {
                if let Some(format) = value.and_then(parse_machine_format) {
                    context.format = format;
                }
            } else if name == "--color"
                && let Some(color) = value.and_then(parse_color_choice)
            {
                context.color = color;
            }
        } else if !saw_root_positional
            && argument.is_none_or(|argument| !argument.starts_with('-') || argument == "-")
        {
            saw_root_positional = true;
            context.command = argument.and_then(parse_command);
        }
    }
    context
}

/// `None` for a value clap would reject, so the earlier choice stands;
/// `Some(None)` for a format clap accepts that cannot carry a structured
/// error document, so a parse failure is reported as prose.
fn parse_machine_format(value: &str) -> Option<Option<MachineFormat>> {
    let format = <Format as clap::ValueEnum>::from_str(value, false).ok()?;
    Some(match format {
        Format::Json => Some(MachineFormat::Json),
        Format::Ndjson => Some(MachineFormat::Ndjson),
        Format::Text | Format::Hex | Format::Raw | Format::Pcap | Format::PcapNg => None,
    })
}

/// `None` for a value clap would reject, so the earlier choice stands.
///
/// Delegating to `ValueEnum` keeps this pre-clap scan on exactly the spellings
/// clap itself accepts, as [`parse_machine_format`] does.
fn parse_color_choice(value: &str) -> Option<ColorChoice> {
    <ColorChoice as clap::ValueEnum>::from_str(value, false).ok()
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
            // A dangling repeat is clap's to reject, and the error document
            // still goes out in the format the earlier value asked for.
            Case {
                arguments: &["packetcraftr", "--output", "json", "build", "--output"],
                format: Some(MachineFormat::Json),
                color: "auto",
                command: Some(output::contract::Command::Build),
            },
            // A later format clap accepts wins even when it cannot carry a
            // structured document: the parse failure is then prose.
            Case {
                arguments: &[
                    "packetcraftr",
                    "--output",
                    "json",
                    "--output",
                    "text",
                    "build",
                ],
                format: None,
                color: "auto",
                command: Some(output::contract::Command::Build),
            },
            Case {
                arguments: &["packetcraftr", "--output=ndjson", "--output=hex", "build"],
                format: None,
                color: "auto",
                command: Some(output::contract::Command::Build),
            },
            // The renamed variant is recognized under clap's name for it.
            Case {
                arguments: &["packetcraftr", "--output=json", "--output=pcapng", "build"],
                format: None,
                color: "auto",
                command: Some(output::contract::Command::Build),
            },
            // clap is case-sensitive here, so a case-mismatched repeat is one
            // it rejects and the earlier choice stands.
            Case {
                arguments: &["packetcraftr", "--output=json", "--output=JSON", "build"],
                format: Some(MachineFormat::Json),
                color: "auto",
                command: Some(output::contract::Command::Build),
            },
            Case {
                arguments: &[
                    "packetcraftr",
                    "--output=json",
                    "--output",
                    "bogus",
                    "--color=never",
                    "--color=bogus",
                    "build",
                ],
                format: Some(MachineFormat::Json),
                color: "never",
                command: Some(output::contract::Command::Build),
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
