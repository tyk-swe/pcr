// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use clap::{Parser, ValueEnum};
use packetcraftr::output;

use crate::commands::Command;

const ROOT_AFTER_HELP: &str = r#"Output formats:
  text    Human-readable summaries and diagnostics.
  json    One aggregate JSON document.
  ndjson  One JSON record per streamed event.
  hex     Exact frame bytes as hexadecimal text.
  raw     Exact frame bytes without text framing.
  pcap    Classic PCAP capture bytes.
  pcapng  PCAPNG capture bytes.

Output availability is command-specific. Machine formats never contain terminal colour codes.

Examples:
  packetcraftr build --packet 'raw(text=hello)'
  packetcraftr --output json dissect --hex '45000014000000004001f6e7c0000201c6336402'
  packetcraftr --output ndjson read capture.pcapng --max-frames 100

Run `packetcraftr <COMMAND> --help` for command-specific options and examples."#;

#[derive(Debug, Parser)]
#[command(
    name = "packetcraftr",
    bin_name = "packetcraftr",
    version,
    arg_required_else_help = true,
    about = "Reflective packet construction, dissection, capture, and network tools",
    long_about = "PacketcraftR builds and dissects arbitrary packet stacks with exact bytes, bounded parsing, passive route planning, and policy-gated live workflows. Native features, dependencies, and privileges determine which live paths are available.",
    after_long_help = ROOT_AFTER_HELP
)]
pub(crate) struct Cli {
    /// Select the output encoding; supported formats are command-specific.
    #[arg(
        long,
        global = true,
        value_enum,
        value_name = "FORMAT",
        help_heading = "Global options",
        default_value_t = CliOutputFormat::Text
    )]
    pub(crate) output: CliOutputFormat,
    /// Control terminal colours in human-facing output.
    #[arg(
        long,
        global = true,
        value_enum,
        value_name = "WHEN",
        help_heading = "Global options",
        default_value_t = CliColorChoice::Auto
    )]
    pub(crate) color: CliColorChoice,
    #[command(subcommand)]
    pub(crate) command: Command,
}

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
pub(crate) enum CliOutputFormat {
    #[default]
    Text,
    Json,
    Ndjson,
    Hex,
    Raw,
    Pcap,
    Pcapng,
}

impl std::fmt::Display for CliOutputFormat {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(output::contract::Format::from(*self).as_str())
    }
}

impl From<CliOutputFormat> for output::contract::Format {
    fn from(value: CliOutputFormat) -> Self {
        match value {
            CliOutputFormat::Text => Self::Text,
            CliOutputFormat::Json => Self::Json,
            CliOutputFormat::Ndjson => Self::Ndjson,
            CliOutputFormat::Hex => Self::Hex,
            CliOutputFormat::Raw => Self::Raw,
            CliOutputFormat::Pcap => Self::Pcap,
            CliOutputFormat::Pcapng => Self::Pcapng,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
pub(crate) enum CliColorChoice {
    /// Use colour only when the destination supports it.
    #[default]
    Auto,
    /// Always emit colour for human-facing output.
    Always,
    /// Never emit colour.
    Never,
}

impl std::fmt::Display for CliColorChoice {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Auto => "auto",
            Self::Always => "always",
            Self::Never => "never",
        })
    }
}

impl CliColorChoice {
    pub(crate) fn write_global(self) {
        let choice = match self {
            Self::Auto => anstream::ColorChoice::Auto,
            Self::Always => anstream::ColorChoice::Always,
            Self::Never => anstream::ColorChoice::Never,
        };
        choice.write_global();
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use clap::{CommandFactory, Parser};
    use packetcraftr::output::contract::Command as CommandName;

    use super::{Cli, CliColorChoice};

    #[test]
    fn global_colour_choice_parses_before_or_after_the_subcommand() {
        for arguments in [
            [
                "packetcraftr",
                "--color",
                "always",
                "build",
                "--packet",
                "raw()",
            ],
            [
                "packetcraftr",
                "build",
                "--packet",
                "raw()",
                "--color",
                "always",
            ],
        ] {
            let cli = Cli::try_parse_from(arguments).unwrap();
            assert!(matches!(cli.color, CliColorChoice::Always));
        }
    }

    #[test]
    fn help_uses_the_frozen_cross_platform_binary_name() {
        let error = Cli::try_parse_from(["packetcraftr.exe", "build", "--help"]).unwrap_err();
        assert_eq!(error.kind(), clap::error::ErrorKind::DisplayHelp);
        let help = error.to_string();
        assert!(help.contains("Usage: packetcraftr build [OPTIONS]"));
        assert!(!help.contains("packetcraftr.exe"));
    }

    #[test]
    fn clap_top_level_commands_match_output_contract_vocabulary() {
        let clap_commands = Cli::command()
            .get_subcommands()
            .map(|command| command.get_name().to_owned())
            .collect::<BTreeSet<_>>();
        let contract_commands = CommandName::ALL
            .iter()
            .map(|command| command.as_str().to_owned())
            .collect::<BTreeSet<_>>();
        let clap_only = clap_commands
            .difference(&contract_commands)
            .cloned()
            .collect::<Vec<_>>();
        let contract_only = contract_commands
            .difference(&clap_commands)
            .cloned()
            .collect::<Vec<_>>();

        assert!(
            clap_only.is_empty() && contract_only.is_empty(),
            "commands present in Clap but absent from the output contract: {clap_only:?}; commands present in the output contract but absent from Clap: {contract_only:?}"
        );
    }
}
