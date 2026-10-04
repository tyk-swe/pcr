// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::ffi::OsString;

use crate::output;

use crate::cli::{ColorChoice, Format};

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

pub(crate) fn parse(arguments: &[OsString]) -> Context {
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
        // Global options that take a value, so it is never mistaken for the root positional.
        if matches!(
            name,
            "--output" | "--color" | "--output-timeout-ms" | "--resource-preset"
        ) {
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
/// `Some(None)` for a format that cannot carry a structured error document.
fn parse_machine_format(value: &str) -> Option<Option<MachineFormat>> {
    let format = <Format as clap::ValueEnum>::from_str(value, false).ok()?;
    Some(match format {
        Format::Json => Some(MachineFormat::Json),
        Format::Ndjson => Some(MachineFormat::Ndjson),
        Format::Text | Format::Hex | Format::Raw | Format::Pcap | Format::PcapNg => None,
    })
}

fn parse_color_choice(value: &str) -> Option<ColorChoice> {
    <ColorChoice as clap::ValueEnum>::from_str(value, false).ok()
}

fn parse_command(value: &str) -> Option<output::contract::Command> {
    output::contract::Command::ALL
        .iter()
        .copied()
        .find(|command| command.as_str() == value)
}
