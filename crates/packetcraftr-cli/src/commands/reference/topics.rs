// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod text;

use std::fmt::Write as _;

use packetcraftr_core::error::{Classification, Kind};

use crate::commands::{Command, Generate};
use crate::errors::CliError;
use crate::output::contract::Format;
use crate::rendering::emit_stdout_document;

pub(crate) const AFTER_LONG_HELP: &str = r"Without NAME, lists the topics. Topics print text only and need no capture, network, or privileges.

Examples:
  packetcraftr reference topics
  packetcraftr reference topics expressions
  packetcraftr reference topics filters
  packetcraftr reference topics formats
  packetcraftr reference topics exit-codes";

#[derive(Debug, clap::Args)]
pub(crate) struct Args {
    /// Topic to print: expressions, filters, formats, or exit-codes. Omit to list them.
    #[arg(value_name = "NAME")]
    pub(crate) name: Option<String>,
}

struct Topic {
    name: &'static str,
    summary: &'static str,
    body: fn() -> String,
}

/// In listing order.
const TOPICS: &[Topic] = &[
    Topic {
        name: "expressions",
        summary: "Packet expression grammar, value forms, and field selectors.",
        body: || String::from(text::EXPRESSIONS),
    },
    Topic {
        name: "filters",
        summary: "Display-filter operators, literals, paths, and reserved fields.",
        body: || String::from(text::FILTERS),
    },
    Topic {
        name: "formats",
        summary: "Output formats and which commands offer each.",
        body: formats,
    },
    Topic {
        name: "exit-codes",
        summary: "Process exit statuses and their error kinds.",
        body: exit_codes,
    },
];

impl Generate for Args {
    fn generate(
        self,
        invocation: &crate::invocation::Invocation,
        format: Format,
    ) -> Result<(), CliError> {
        if format != Format::Text {
            return Err(CliError::new(
                Kind::Usage,
                format!("topics prints text only, not --output {format}"),
            ));
        }
        emit_stdout_document(invocation, &render(self.name.as_deref())?)
    }
}

fn render(name: Option<&str>) -> Result<String, CliError> {
    let Some(name) = name else {
        return Ok(listing());
    };
    TOPICS
        .iter()
        .find(|topic| topic.name.eq_ignore_ascii_case(name))
        .map(|topic| (topic.body)())
        .ok_or_else(|| {
            CliError::from_classification(
                Classification::new(
                    "cli.topic",
                    Kind::Usage,
                    Some("run `packetcraftr reference topics` to list the topics"),
                ),
                format!("unknown topic `{name}`; topics are {}", names().join(", ")),
                Vec::new(),
            )
        })
}

fn names() -> Vec<&'static str> {
    TOPICS.iter().map(|topic| topic.name).collect()
}

fn listing() -> String {
    let width = TOPICS
        .iter()
        .map(|topic| topic.name.len())
        .max()
        .unwrap_or(0);
    let mut listing = String::from("Topics:\n");
    for topic in TOPICS {
        let _ = writeln!(listing, "  {:<width$}  {}", topic.name, topic.summary);
    }
    listing.push_str("\nRun `packetcraftr reference topics NAME` to print one.\n");
    listing
}

fn formats() -> String {
    let commands = Command::ALL;
    let width = commands
        .iter()
        .map(|command| {
            crate::commands::registry::entry(command.as_str())
                .expect("registered command")
                .path()
                .len()
        })
        .max()
        .unwrap_or(0);
    let mut help = String::from(crate::app::cli::output_formats_help());
    help.push_str(
        "\n\nSelect one with --output FORMAT, before or after the subcommand. Binary formats \
         (raw, pcap, pcapng) refuse an interactive terminal unless --force-binary-stdout is \
         given. --resource-diagnostics requires json or ndjson, and --output-timeout-ms \
         requires ndjson.\n\nFormats by command:\n",
    );
    for command in commands {
        let names = command
            .formats()
            .iter()
            .map(|format| format.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        let _ = writeln!(
            help,
            "  {:<width$}  {names}",
            crate::commands::registry::entry(command.as_str())
                .expect("registered command")
                .path()
        );
    }
    help
}

fn exit_codes() -> String {
    format!(
        "Exit codes\n\n{}\nFor codes 2 through 70, the word after the code is the `error.kind` of the same \
         failure in JSON and NDJSON output; a cancellation reports kind `io`.\n",
        crate::app::cli::exit_codes_help()
    )
}
