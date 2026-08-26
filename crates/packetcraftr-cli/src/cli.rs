// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use clap::{Parser, ValueEnum};
use packetcraftr::output;

use crate::commands::Command;

const ROOT_AFTER_HELP: &str = r#"Output formats:
  text      Human-readable summaries and diagnostics.
  json      One aggregate JSON document.
  ndjson    One JSON record per streamed event.
  hex       Exact frame bytes as hexadecimal text.
  raw       Exact frame bytes without text framing.
  pcap      Classic PCAP capture bytes.
  pcapng    PCAPNG capture bytes.
  document  A v2 packet document (YAML stream).

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
    Document,
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
            Format::Document => Self::Document,
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
