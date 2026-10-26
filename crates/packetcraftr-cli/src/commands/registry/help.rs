// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Presentation metadata layered over command-owned argument definitions.

use super::{Command, Entry};

const COMMON: &[&str] = &[
    "packet",
    "packet_file",
    "hex",
    "file",
    "input",
    "directory",
    "name",
    "path",
    "targets",
    "targets_file",
    "interface",
    "server",
    "query",
    "ports",
    "table",
    "filter",
    "display_filter",
    "decode_as",
    "tree",
    "dissect",
    "field",
    "fields",
    "hex_file",
    "stream",
    "transport",
    "method",
    "connect",
    "list",
    "count",
    "timeout_ms",
    "max_frames",
    "max_duration_ms",
    "identity",
    "output_file",
    "output",
    "color",
    "verbose",
];

fn heading(id: &str) -> &'static str {
    if matches!(
        id,
        "allow"
            | "allow_host"
            | "allow_hostname"
            | "allow_cidr"
            | "allow_public"
            | "allow_broadcast"
            | "allow_multicast"
            | "allow_spoofing"
            | "confirm"
            | "dry_run"
    ) || id.starts_with("allow_")
        || id.contains("policy")
    {
        "Policy"
    } else if matches!(
        id,
        "packet"
            | "packet_file"
            | "hex"
            | "file"
            | "input"
            | "path"
            | "directory"
            | "name"
            | "targets"
            | "targets_file"
            | "server"
            | "query"
            | "interface"
    ) {
        "Input"
    } else if id.starts_with("discovery") || id == "unresponsive_hosts" {
        "Discovery"
    } else if id.starts_with("identify") || id.starts_with("reverse_dns") {
        "Identification"
    } else if id.contains("window")
        || id.contains("backoff")
        || matches!(
            id,
            "adaptive"
                | "host_timeout_ms"
                | "min_timeout_ms"
                | "max_timeout_ms"
                | "rate"
                | "max_in_flight"
        )
    {
        "Scheduling"
    } else if matches!(
        id,
        "filter"
            | "display_filter"
            | "decode_as"
            | "field"
            | "stream"
            | "table"
            | "frames"
            | "frame"
            | "every"
            | "link_type"
            | "family"
    ) || id.starts_with("exclude")
    {
        "Selection and decoding"
    } else if id.starts_with("max_") || id.ends_with("timeout_ms") || id == "count" {
        "Limits"
    } else if matches!(
        id,
        "tree" | "dissect" | "output_file" | "write" | "compression"
    ) || id.starts_with("output_")
    {
        "Output"
    } else {
        "Operation"
    }
}

pub(super) fn leaf(command: clap::Command, entry: &Entry) -> clap::Command {
    let examples = command
        .get_after_long_help()
        .map(ToString::to_string)
        .unwrap_or_default();
    let short_examples = short_examples(&examples);
    let formats = Command::ALL
        .iter()
        .find(|command| command.as_str() == entry.identifier)
        .map(|command| {
            command
                .formats()
                .iter()
                .map(|format| format.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        })
        .unwrap_or_else(|| "text".to_owned());
    let full = format!(
        "{examples}\n\nSupported output formats: {formats}.\nUse -v/--verbose for retained evidence and technical details in text output.\nCommand: packetcraftr {}.",
        entry.path()
    );
    let short = format!(
        "{}\n\nUse --help for all options, defaults, formats, and prerequisites.",
        short_examples.map_or_else(
            || format!("Example:\n  packetcraftr {} --help", entry.path()),
            |examples| format!("Examples:\n{examples}")
        )
    );
    let mut order = 0;
    command
        .mut_args(|arg| {
            let id = arg.get_id().as_str();
            if arg.is_global_set() {
                return arg;
            }
            let section = heading(id);
            let section_order = match section {
                "Input" => 1,
                "Selection and decoding" => 2,
                "Operation" => 3,
                "Discovery" => 4,
                "Identification" => 5,
                "Scheduling" => 6,
                "Output" => 7,
                "Limits" => 8,
                "Policy" => 9,
                _ => 10,
            };
            order += 1;
            let common = arg.is_positional()
                || arg.is_required_set()
                || COMMON.contains(&id)
                || section == "Policy";
            arg.help_heading(section)
                .display_order(section_order * 1000 + order)
                .hide_short_help(!common)
        })
        .after_help(short)
        .after_long_help(full)
}

fn short_examples(help: &str) -> Option<String> {
    let (_, examples) = help
        .split_once("Examples:")
        .or_else(|| help.split_once("Example:"))?;
    let examples = examples
        .trim_start_matches([' ', '\t', '\r', '\n'])
        .lines()
        .take_while(|line| !line.trim().is_empty())
        .take(3)
        .collect::<Vec<_>>()
        .join("\n");
    (!examples.is_empty()).then_some(examples)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inline_and_block_examples_survive_short_help() {
        assert_eq!(
            short_examples("About.\n\nExample: packetcraftr packet build --help").as_deref(),
            Some("packetcraftr packet build --help")
        );
        assert_eq!(
            short_examples("Examples:\n  one\n  two\n\nDetails").as_deref(),
            Some("one\n  two")
        );
    }

    #[test]
    fn rendered_read_help_groups_every_with_the_frame_selection_options() {
        use clap::CommandFactory;

        let mut command = crate::app::cli::Cli::command();
        command.build();
        let mut read = command
            .find_subcommand("files")
            .and_then(|files| files.find_subcommand("read"))
            .expect("files read is registered")
            .clone();
        let rendered =
            anstream::adapter::strip_str(&read.render_long_help().to_string()).to_string();
        let section = rendered
            .split_once("Selection and decoding:\n")
            .map(|(_, tail)| tail)
            .and_then(|tail| tail.split_once("\nGlobal options:"))
            .map(|(section, _)| section)
            .expect("read help renders a selection section before the global options");
        assert!(section.contains("--frames <RANGES>"));
        assert!(section.contains("--every <N>"));
    }
}
