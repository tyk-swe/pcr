// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

pub(super) mod arguments;
#[cfg(test)]
mod tests;
mod text;

use std::fmt::Write as _;

use packetcraftr_core::error::{Classification, Kind};

use self::arguments::Args;
use super::{Command, Generate};
use crate::errors::CliError;
use crate::output::contract::Format;
use crate::rendering::emit_stdout_document;

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
        body: || printable(text::EXPRESSIONS),
    },
    Topic {
        name: "filters",
        summary: "Display-filter operators, literals, paths, and reserved fields.",
        body: || printable(text::FILTERS),
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
    fn generate(self, format: Format) -> Result<(), CliError> {
        if format != Format::Text {
            return Err(CliError::new(
                Kind::Usage,
                format!("topics prints text only, not --output {format}"),
            ));
        }
        emit_stdout_document(&render(self.name.as_deref())?)
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
                    Some("run `packetcraftr topics` to list the topics"),
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
    listing.push_str("\nRun `packetcraftr topics NAME` to print one.\n");
    listing
}

/// Shows a topic's example lines as plain indented text, without their drift-test tags.
fn printable(source: &str) -> String {
    let mut text = String::with_capacity(source.len());
    for line in source.lines() {
        match example(line) {
            Some((_, example)) => {
                text.push_str("    ");
                text.push_str(example);
            }
            None => text.push_str(line),
        }
        text.push('\n');
    }
    text
}

/// The kind and text of a `  @KIND EXAMPLE` line.
fn example(line: &str) -> Option<(&str, &str)> {
    line.strip_prefix("  @")?.split_once(' ')
}

fn formats() -> String {
    let commands = Command::ALL;
    let width = commands
        .iter()
        .map(|command| command.as_str().len())
        .max()
        .unwrap_or(0);
    let mut help = String::from(crate::cli::output_formats_help());
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
        let _ = writeln!(help, "  {:<width$}  {names}", command.as_str());
    }
    help
}

fn exit_codes() -> String {
    format!(
        "Exit codes\n\n{}\nFor codes 2 through 70, the word after the code is the `error.kind` of the same \
         failure in JSON and NDJSON output; a cancellation reports kind `io`.\n",
        crate::cli::exit_codes_help()
    )
}
