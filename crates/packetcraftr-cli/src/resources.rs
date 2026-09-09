// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Invocation-local assembly of opt-in diagnostics. No protocol mechanics or
//! admission decisions depend on these observations.

use std::collections::BTreeMap;
use std::sync::{Mutex, OnceLock};

use clap::{ArgMatches, CommandFactory, parser::ValueSource};
use packetcraftr::progress::Runtime;
use packetcraftr_cli::output::{
    contract::{Command, Format},
    envelope::Envelope,
    resources::{Report, Setting, Value, Worker},
};

use crate::cli::Cli;

struct Context {
    settings: Vec<Setting>,
    runtimes: Mutex<Vec<(&'static str, Runtime)>>,
}
static CONTEXT: OnceLock<Context> = OnceLock::new();

pub(crate) fn configure(matches: &ArgMatches, command: Command, format: Format) {
    let settings = settings(matches, command, format);
    let _ = CONTEXT.set(Context {
        settings,
        runtimes: Mutex::new(Vec::new()),
    });
}

fn settings(matches: &ArgMatches, command: Command, format: Format) -> Vec<Setting> {
    let mut definition = Cli::command();
    definition.build();
    let mut settings = BTreeMap::new();
    let selected = matches.subcommand().map(|(_, values)| values);
    let tcp_enabled = matches!(command, Command::Expert | Command::Tls)
        || (command == Command::Follow
            && selected
                .and_then(|values| values.get_raw("stream"))
                .and_then(|mut values| values.next())
                .is_some_and(|value| !value.to_string_lossy().starts_with("udp:")));
    let selected_definition = definition.find_subcommand(command.as_str());
    for (values, definition) in
        std::iter::once((matches, &definition)).chain(selected.zip(selected_definition))
    {
        for arg in definition.get_arguments() {
            let id = arg.get_id().as_str();
            let Some(stage) = stage(id, command) else {
                continue;
            };
            let Some(raw) = values.get_raw(id).and_then(|mut values| values.next_back()) else {
                continue;
            };
            let raw = raw.to_string_lossy();
            let value = raw
                .parse::<u64>()
                .map_or_else(|_| Value::Policy(raw.into_owned()), Value::Number);
            let unit = if id.ends_with("_ms") {
                "milliseconds"
            } else if id.contains("bytes") || id == "snap_length" {
                "bytes"
            } else if matches!(id, "overflow_policy" | "ip_overlap") {
                "policy"
            } else {
                "count"
            };
            let name = format!("--{}", arg.get_long().unwrap_or(id));
            settings.insert(
                name.clone(),
                Setting {
                    enabled: !(id.starts_with("max_tcp_") || id == "tcp_idle_expiry_ms")
                        || tcp_enabled,
                    name,
                    value,
                    unit: unit.to_owned(),
                    stage: stage.to_owned(),
                    scope: arg
                        .get_long_help()
                        .or_else(|| arg.get_help())
                        .map(ToString::to_string)
                        .unwrap_or_default(),
                    source: if values.value_source(id) == Some(ValueSource::CommandLine) {
                        "override"
                    } else {
                        "default"
                    }
                    .to_owned(),
                },
            );
        }
    }
    if format == Format::Ndjson {
        settings
            .entry("--output-timeout-ms".to_owned())
            .or_insert(Setting {
                name: "--output-timeout-ms".to_owned(),
                value: Value::Number(1000),
                unit: "milliseconds".to_owned(),
                stage: "output".to_owned(),
                scope: "Per-write wait; clipped by the remaining operation deadline".to_owned(),
                source: "default".to_owned(),
                enabled: true,
            });
        for (name, value, unit, scope) in [
            (
                "output_record_bytes",
                packetcraftr_cli::output::stream::MAX_RECORD_BYTES as u64,
                "bytes",
                "One prepared NDJSON line, including newline",
            ),
            (
                "terminal_error_timeout_ms",
                1000,
                "milliseconds",
                "Separate terminal-error cleanup wait; cannot repair a failed write",
            ),
        ] {
            settings.insert(
                name.to_owned(),
                Setting {
                    name: name.to_owned(),
                    value: Value::Number(value),
                    unit: unit.to_owned(),
                    stage: "output".to_owned(),
                    scope: scope.to_owned(),
                    source: "fixed".to_owned(),
                    enabled: true,
                },
            );
        }
    }
    if matches!(command, Command::Expert | Command::Follow)
        && let Some(limit) = settings.get("--max-frames").cloned()
    {
        settings.insert(
            "retained_result_items".to_owned(),
            Setting {
                name: "retained_result_items".to_owned(),
                value: limit.value,
                unit: "count".to_owned(),
                stage: "result_retention".to_owned(),
                scope: "Aggregate JSON items; derived from the physical frame ceiling".to_owned(),
                source: "derived".to_owned(),
                enabled: format == Format::Json,
            },
        );
    }
    settings.into_values().collect()
}

fn stage(id: &str, command: Command) -> Option<&'static str> {
    let offline = matches!(
        command,
        Command::Read | Command::Stats | Command::Expert | Command::Follow | Command::Tls
    );
    Some(match id {
        "output_timeout_ms" => "output",
        "top"
        | "max_output_sessions"
        | "max_unmatched_frames"
        | "max_responses"
        | "max_undecoded"
        | "max_ip_outcomes"
        | "max_rejected_records" => "result_retention",
        "max_flows" | "max_scope_bytes" | "max_interfaces" => "indexed_metadata",
        "max_queue_frames" | "max_captured_bytes" | "snap_length" | "overflow_policy" => {
            "native_capture"
        }
        "max_frames" | "max_bytes" | "max_frame_bytes" if offline => "physical_input",
        "max_duration_ms" | "timeout_ms" => "operation",
        "tcp_idle_expiry_ms" | "ip_idle_expiry_ms" | "ip_overlap" => "active_state",
        id if id.starts_with("max_tcp_")
            || id.starts_with("max_ip_")
            || id.starts_with("max_tls_") =>
        {
            "active_state"
        }
        id if id.starts_with("max_") => "operation",
        _ => return None,
    })
}

/// Constructors remain isolated. Keeping a runtime clone observes admission;
/// it neither holds permits nor keeps callback captures alive.
pub(crate) fn runtime(name: &'static str, capacity: usize) -> Runtime {
    let runtime = Runtime::new(capacity);
    if let Some(context) = CONTEXT.get() {
        let mut runtimes = context
            .runtimes
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        // A CLI invocation constructs at most one runtime per assembly owner.
        // Keep the diagnostic registry bounded even if future commands change.
        if runtimes.len() < 16 {
            runtimes.push((name, runtime.clone()));
        }
    }
    runtime
}

pub(crate) fn snapshot() -> Option<Report> {
    let context = CONTEXT.get()?;
    let mut workers = vec![Worker::native(
        packetcraftr_netio::resources::native_snapshot(),
    )];
    workers.extend(
        context
            .runtimes
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .iter()
            .map(|(name, runtime)| Worker::progress(*name, runtime.snapshot())),
    );
    Some(Report {
        settings: context.settings.clone(),
        workers,
        cooperative_deadlines: true,
        hard_rss_limit: false,
    })
}

pub(crate) fn decorate<T>(envelope: Envelope<T>) -> Envelope<T> {
    match snapshot() {
        Some(resources) => envelope.with_resources(resources),
        None => envelope,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn resolved_options_preserve_defaults_overrides_and_scope() {
        let args = Cli::command()
            .try_get_matches_from([
                "packetcraftr",
                "--output",
                "json",
                "stats",
                "fixture.pcap",
                "--max-frames",
                "7",
            ])
            .unwrap();
        let settings = settings(&args, Command::Stats, Format::Json);
        let frames = settings
            .iter()
            .find(|setting| setting.name == "--max-frames")
            .unwrap();
        assert!(matches!(frames.value, Value::Number(7)));
        assert_eq!(frames.source, "override");
        assert_eq!(frames.stage, "physical_input");
        let flows = settings
            .iter()
            .find(|setting| setting.name == "--max-flows")
            .unwrap();
        assert_eq!(flows.source, "default");
        assert_eq!(flows.stage, "indexed_metadata");
    }
}
