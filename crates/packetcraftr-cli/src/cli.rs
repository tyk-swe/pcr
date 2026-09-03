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

Exit codes:
  0   Success.
  2   cli: the invocation or its input was invalid.
  3   packet: the packet could not be built, parsed, or dissected.
  4   capability: a native feature, backend, or privilege is unavailable.
  5   io: a system or network operation failed.
  6   policy: the traffic policy denied the operation.
  70  internal: an invariant failed; please report it.

The word after the code is the `error.kind` of the same failure in JSON and NDJSON output.

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
        long = "output",
        global = true,
        value_enum,
        value_name = "FORMAT",
        help_heading = "Global options",
        default_value_t = Format::Text
    )]
    pub(crate) format: Format,
    /// Control terminal colours in human-facing output.
    #[arg(
        long,
        global = true,
        value_enum,
        value_name = "WHEN",
        help_heading = "Global options",
        default_value_t = ColorChoice::Auto
    )]
    pub(crate) color: ColorChoice,
    #[command(subcommand)]
    pub(crate) command: Command,
}

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
pub(crate) enum Format {
    #[default]
    Text,
    Json,
    Ndjson,
    Hex,
    Raw,
    Pcap,
    #[value(name = "pcapng")]
    PcapNg,
}

impl std::fmt::Display for Format {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(output::contract::Format::from(*self).as_str())
    }
}

impl From<Format> for output::contract::Format {
    fn from(value: Format) -> Self {
        match value {
            Format::Text => Self::Text,
            Format::Json => Self::Json,
            Format::Ndjson => Self::Ndjson,
            Format::Hex => Self::Hex,
            Format::Raw => Self::Raw,
            Format::Pcap => Self::Pcap,
            Format::PcapNg => Self::PcapNg,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
pub(crate) enum ColorChoice {
    /// Use colour only when the destination supports it.
    #[default]
    Auto,
    /// Always emit colour for human-facing output.
    Always,
    /// Never emit colour.
    Never,
}

impl std::fmt::Display for ColorChoice {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Auto => "auto",
            Self::Always => "always",
            Self::Never => "never",
        })
    }
}

impl ColorChoice {
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
    use super::*;

    /// The whole command tree is rebuilt on every invocation, and several
    /// subcommands adjust arguments defined in other modules by id, so a
    /// renamed field turns *every* invocation into a clap panic. This asserts
    /// those ids, plus `requires`/`conflicts_with` targets, at unit-test speed.
    #[test]
    fn the_command_tree_is_valid() {
        <Cli as clap::CommandFactory>::command().debug_assert();
    }

    /// The exit-code table in the root help, as (code, kind name) pairs.
    fn documented_exit_codes() -> Vec<(u8, String)> {
        let (_, rest) = ROOT_AFTER_HELP
            .split_once("Exit codes:\n")
            .expect("the root help documents exit codes");
        rest.lines()
            .take_while(|line| !line.trim().is_empty())
            .filter_map(|line| {
                let mut words = line.split_whitespace();
                let code = words.next()?.parse().ok()?;
                let kind = words.next()?.trim_end_matches(':').to_owned();
                Some((code, kind))
            })
            .collect()
    }

    #[test]
    fn the_root_help_documents_every_exit_code_exactly_once() {
        use packetcraftr::core::error::Kind;

        let kinds = [
            Kind::Cli,
            Kind::Packet,
            Kind::Capability,
            Kind::Io,
            Kind::Policy,
            Kind::Internal,
        ];
        let mut expected = vec![(0, "Success.".to_owned())];
        expected.extend(kinds.iter().map(|kind| {
            (
                crate::errors::exit_code_for(*kind),
                kind.as_str().to_owned(),
            )
        }));
        assert_eq!(documented_exit_codes(), expected);
    }
}
