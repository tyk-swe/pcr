// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod context;
mod parsing;

pub(crate) use context::{Context, MachineFormat, parse as error_context};
pub(crate) use parsing::{Parsed, parse_from};

use std::sync::LazyLock;

use clap::{Parser, ValueEnum};

use crate::commands::CommandLine;
use crate::errors::exit_codes_help;
use crate::output::contract::{Format, OUTPUT_FORMATS_HELP};

const ROOT_HELP_EXAMPLES: &str = r"For codes 2 through 70, the word after the code is the `error.kind` of the same failure in JSON and NDJSON output; a cancellation reports kind `io`.

Examples:
  packetcraftr packet build --packet 'raw(text=hello)'
  packetcraftr --output json packet dissect --link-type 228 --hex '4500001c0000000040018eaac0000201c63364020800f7ff00000000'
  packetcraftr --output ndjson files read capture.pcapng --max-frames 100

Run `packetcraftr <group> <command> --help` for command-specific options and examples.";

fn root_after_help() -> String {
    let mut help = format!(
        "{OUTPUT_FORMATS_HELP}\n\nExit codes:\n{}",
        exit_codes_help()
    );
    help.push('\n');
    help.push_str(ROOT_HELP_EXAMPLES);
    help
}

fn long_version() -> &'static str {
    static LONG_VERSION: LazyLock<String> = LazyLock::new(|| {
        use packetcraftr_netio::{NativeCapability, link::Mode};
        let enabled = [
            ("native-route", NativeCapability::Route.check().is_ok()),
            (
                "native-layer2",
                NativeCapability::Transmission(Mode::Layer2).check().is_ok(),
            ),
            (
                "native-layer3",
                NativeCapability::Transmission(Mode::Layer3).check().is_ok(),
            ),
        ];
        let names = enabled
            .into_iter()
            .filter(|(_, on)| *on)
            .map(|(name, _)| name)
            .collect::<Vec<_>>();
        let features = if names.is_empty() {
            "none".to_owned()
        } else {
            names.join(", ")
        };
        format!("{}\nnative features: {features}", env!("CARGO_PKG_VERSION"))
    });
    &LONG_VERSION
}

#[derive(Debug, Parser)]
#[command(
    name = "packetcraftr",
    bin_name = "packetcraftr",
    version,
    long_version = long_version(),
    arg_required_else_help = true,
    about = "Reflective packet construction, dissection, capture, and network tools",
    long_about = "PacketcraftR builds and dissects arbitrary packet stacks with exact bytes, bounded parsing, passive route planning, and policy-gated live workflows. Native features, dependencies, and privileges determine which live paths are available.",
    after_help = "Examples:\n  packetcraftr packet build --packet 'raw(text=hello)'\n  packetcraftr files read capture.pcapng\n\nUse --help for formats, exit codes, and all global options.",
    after_long_help = root_after_help()
)]
pub(crate) struct Cli {
    /// Show retained evidence, provenance, and technical details in text output.
    #[arg(
        short,
        long,
        global = true,
        help_heading = "Global options",
        display_order = 10000
    )]
    pub(crate) verbose: bool,
    /// Select the output encoding; supported formats are command-specific.
    #[arg(
        long = "output",
        global = true,
        value_enum,
        value_name = "FORMAT",
        help_heading = "Global options", display_order = 10000,
        default_value_t = Format::Text
    )]
    pub(crate) format: Format,
    /// Include effective resource settings and worker snapshots in JSON/NDJSON.
    #[arg(
        long,
        global = true,
        help_heading = "Global options",
        display_order = 10000
    )]
    #[arg(hide_short_help = true)]
    pub(crate) resource_diagnostics: bool,
    /// Versioned offline resource defaults; explicit flags override the preset.
    #[arg(
        long,
        global = true,
        value_enum,
        help_heading = "Global options",
        display_order = 10000
    )]
    #[arg(hide_short_help = true)]
    pub(crate) resource_preset: Option<crate::resources::Preset>,
    /// NDJSON per-write wait in milliseconds (default 1000; range 1..=3600000).
    #[arg(long, global = true, value_parser = clap::value_parser!(u64).range(1..=3_600_000), help_heading = "Global options", display_order = 10000)]
    #[arg(hide_short_help = true)]
    pub(crate) output_timeout_ms: Option<u64>,
    /// Allow binary raw/PCAP/PCAPNG bytes to be written to an interactive terminal.
    #[arg(
        long,
        global = true,
        help_heading = "Global options",
        display_order = 10000
    )]
    #[arg(hide_short_help = true)]
    pub(crate) force_binary_stdout: bool,
    /// Control terminal colours in human-facing output.
    #[arg(
        long,
        global = true,
        value_enum,
        value_name = "WHEN",
        help_heading = "Global options", display_order = 10000,
        default_value_t = ColorChoice::Auto
    )]
    pub(crate) color: ColorChoice,
    #[command(subcommand)]
    pub(crate) command: CommandLine,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ValueEnum)]
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
