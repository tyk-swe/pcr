// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Invocation-local assembly of opt-in diagnostics. No protocol mechanics or
//! admission decisions depend on these observations.

use std::collections::BTreeMap;
use std::sync::{Mutex, OnceLock, PoisonError};

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
    let preset = matches
        .get_one::<crate::presets::Preset>("resource_preset")
        .copied();
    let forwarding = command == Command::VerifyForwarding;
    let indexed_forwarding = forwarding && selected.is_some_and(forwarding_needs_index);
    let tcp_enabled = matches!(
        command,
        Command::Expert | Command::DnsRead | Command::Http | Command::Tls
    ) || (command == Command::Follow
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
                    enabled: if forwarding && id == "max_provenance_bytes" {
                        false
                    } else if forwarding
                        && (id.starts_with("max_ip_")
                            || matches!(
                                id,
                                "ip_idle_expiry_ms"
                                    | "ip_overlap"
                                    | "max_flows"
                                    | "max_scope_bytes"
                            ))
                    {
                        indexed_forwarding
                    } else {
                        !(id.starts_with("max_tcp_") || id == "tcp_idle_expiry_ms") || tcp_enabled
                    },
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
                        "override".to_owned()
                    } else if let Some(preset) = preset.filter(|preset| preset.value(id).is_some())
                    {
                        format!("preset:{}", preset.name())
                    } else {
                        "default".to_owned()
                    },
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

fn forwarding_needs_index(values: &ArgMatches) -> bool {
    use packetcraftr_core::analysis::forwarding::{Declarations, Rules};

    let registry = packetcraftr_core::protocol::builtin::registry();
    let fields = |id| {
        values
            .get_many::<String>(id)
            .map(|fields| fields.cloned().collect::<Vec<_>>())
            .unwrap_or_default()
    };
    let rules = Rules::compile_declarations(
        Declarations {
            identity: &fields("identity"),
            preserve: &fields("preserve"),
            preserve_presence: &fields("preserve_presence"),
            expect: &fields("expect"),
            expect_absent: &fields("expect_absent"),
        },
        &registry,
        *values
            .get_one::<usize>("max_field_bytes")
            .expect("forwarding field budget has a default"),
    );
    // Collection combines the compiled rules' requirements with each side's
    // filter. Diagnostics are enabled if either capture needs the stage.
    // Invalid input fails before analysis; conservatively keep stages enabled.
    rules.map_or(true, |rules| rules.requirements().stream_index)
        || ["ingress_filter", "egress_filter"].into_iter().any(|id| {
            values.get_one::<String>(id).is_some_and(|source| {
                crate::filtering::compile(
                    source,
                    &registry,
                    crate::filtering::Capabilities::stream_capable(),
                )
                .map_or(true, |filter| filter.requirements().stream_index)
            })
        })
}

fn stage(id: &str, command: Command) -> Option<&'static str> {
    let offline = matches!(
        command,
        Command::VerifyForwarding
            | Command::Rewrite
            | Command::Export
            | Command::Merge
            | Command::Read
            | Command::Stats
            | Command::Expert
            | Command::Follow
            | Command::Http
            | Command::DnsRead
            | Command::Tls
    );
    Some(match id {
        "output_timeout_ms" => "output",
        "rotate_bytes" | "rotate_interval_ms" | "rotate_files" | "retention" => "capture_storage",
        "max_prepared_bytes" => "preparation",
        "max_scratch_bytes" => "comparison",
        "max_evidence_bytes" | "max_field_bytes" => "observation_collection",
        "max_details"
        | "max_detail_bytes"
        | "max_application_output_bytes"
        | "max_projection_bytes"
        | "max_output_bytes"
        | "top"
        | "max_output_sessions"
        | "max_unmatched_frames"
        | "max_responses"
        | "max_undecoded"
        | "max_ip_outcomes"
        | "max_rejected_records" => "result_retention",
        "max_provenance_bytes" | "max_flows" | "max_scope_bytes" | "max_interfaces" => {
            "indexed_metadata"
        }
        "max_queue_frames" | "max_captured_bytes" | "snap_length" | "overflow_policy" => {
            "native_capture"
        }
        "max_frames" | "max_bytes" | "max_frame_bytes" | "max_encoded_bytes"
        | "max_decoded_bytes"
            if offline =>
        {
            "physical_input"
        }
        "max_duration_ms" | "timeout_ms" | "max_targets" | "max_in_flight" => "operation",
        "tcp_idle_expiry_ms" | "ip_idle_expiry_ms" | "ip_overlap" => "active_state",
        id if id.starts_with("max_tcp_")
            || id.starts_with("max_ip_")
            || id.starts_with("max_application_")
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
            .unwrap_or_else(PoisonError::into_inner);
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
    let mut tcp = Worker::native(packetcraftr_netio::resources::tcp_connect_snapshot());
    tcp.name = "tcp_connect_process".to_owned();
    workers.push(tcp);
    workers.extend(
        context
            .runtimes
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
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
