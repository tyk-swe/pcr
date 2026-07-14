// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

// Fuzz command execution and presentation.

use std::sync::Arc;
use std::time::Duration;

use packetcraftr::{client, net, output, packet, workflow};

use super::arguments::{CliBuildMode, FuzzArgs};
use super::capture::{render_diagnostics_text, render_output_diagnostics_text};
use super::errors::CliError;
use super::input::read_recipe;
use super::rendering::{emit_json, emit_json_compact, spaced_hex, write_stdout_line};
use super::runtime::{DeferredInterface, default_registry_arc, system_client};
use super::scan::validate_live_interface_selector;

pub(super) fn run_fuzz(
    arguments: FuzzArgs,
    output: output::contract::Format,
) -> Result<(), CliError> {
    let FuzzArgs {
        recipe,
        seed,
        first_case,
        cases,
        strategies,
        fields,
        mode,
        live,
        allow_malformed_live,
        destination,
        timeout_ms,
        rate,
        max_cases,
        max_total_bytes,
        max_field_bytes,
        max_list_items,
        max_shrink_steps,
        max_duration_ms,
        interface,
        source,
        link_mode,
        limits,
        policy,
    } = arguments;
    let registry = default_registry_arc()?;
    let packet = read_recipe(recipe, &registry)?;
    let targets = fields
        .into_iter()
        .map(|field| {
            field
                .parse::<workflow::fuzz::Target>()
                .map_err(|source| CliError::new(2, source.to_string()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let queue_limits = limits.into_limits();
    let build_mode = match mode {
        CliBuildMode::Strict => packet::build::Mode::Strict,
        CliBuildMode::Permissive => packet::build::Mode::Permissive,
    };
    let request = workflow::fuzz::Request {
        seed,
        first_case,
        cases,
        strategies: strategies.into_iter().map(Into::into).collect(),
        targets,
        build: packet::build::Options {
            mode: build_mode,
            max_packet_size: queue_limits.snap_length,
            ..packet::build::Options::default()
        },
        limits: workflow::fuzz::Limits {
            max_cases,
            max_packet_bytes: queue_limits.snap_length,
            max_total_bytes,
            max_field_bytes,
            max_list_items,
            max_shrink_steps,
            max_evidence_frames: queue_limits.max_frames,
            max_evidence_bytes: queue_limits.max_bytes,
            max_duration: Duration::from_millis(max_duration_ms),
        },
    };
    request.validate().map_err(fuzz_cli_error)?;

    let result = if live {
        let policy = policy.into_policy();
        policy.validate().map_err(CliError::classified)?;
        validate_live_interface_selector("fuzz", interface.as_deref())?;
        let mut exchange = client::exchange::Options {
            send: client::send::Options {
                destination,
                plan: net::route::Options {
                    link_mode: link_mode.into(),
                    interface: None,
                    preferred_source: source,
                },
                build: request.build.clone(),
                allow_permissive_live: allow_malformed_live,
            },
            timeout: Duration::from_millis(timeout_ms),
            max_template_packets: 1,
            max_unsolicited: queue_limits.max_frames,
            max_responses: queue_limits.max_frames,
            max_capture_queue_frames: queue_limits.max_frames,
            max_captured_bytes: queue_limits.max_bytes,
            capture_overflow_policy: queue_limits.overflow_policy,
            decode: packet::decode::Options::default(),
        };
        exchange.decode.max_packet_size = queue_limits.snap_length;
        exchange.validate().map_err(CliError::classified)?;
        let mut executor = CliFuzzExecutor {
            registry: Arc::clone(&registry),
            policy: policy.clone(),
            exchange,
            interface: DeferredInterface::new(interface),
        };
        let mut authorizer = workflow::fuzz::PolicyAuthorizer::new(&policy);
        let mut clock = workflow::clock::System;
        workflow::fuzz::run_live(
            &request,
            workflow::fuzz::LiveOptions {
                timeout: Duration::from_millis(timeout_ms),
                cases_per_second: rate,
                destination,
                allow_malformed_live,
            },
            packet,
            registry,
            &mut authorizer,
            &mut executor,
            &mut clock,
        )
        .map_err(fuzz_cli_error)?
    } else {
        // This branch intentionally never validates or resolves the live
        // interface and never constructs a native client.
        workflow::fuzz::run(&request, packet, registry).map_err(fuzz_cli_error)?
    };
    let (result, diagnostics, stats) =
        output::fuzz::Result::try_from_fuzz(result).map_err(CliError::classified)?;
    match output {
        output::contract::Format::Text => render_fuzz_text(result, diagnostics, stats),
        output::contract::Format::Json => emit_json(
            &output::envelope::Aggregate::success(
                output::contract::Command::Fuzz,
                result,
                diagnostics,
            )
            .with_stats(stats),
        ),
        output::contract::Format::Ndjson => render_fuzz_stream(result, diagnostics, stats),
        _ => Err(CliError::classified(
            output::contract::Error::UnsupportedFormat {
                command: output::contract::Command::Fuzz,
                format: output,
            },
        )),
    }
}

struct CliFuzzExecutor {
    registry: Arc<packet::registry::Registry>,
    policy: client::policy::Policy,
    exchange: client::exchange::Options,
    interface: DeferredInterface,
}

impl workflow::fuzz::Executor for CliFuzzExecutor {
    fn execute(
        &mut self,
        case: &workflow::fuzz::ExecutionCase,
        timeout: Duration,
    ) -> Result<workflow::fuzz::Execution, workflow::fuzz::ExecutionError> {
        self.interface
            .resolve_into(&mut self.exchange.send.plan)
            .map_err(|error| {
                workflow::fuzz::ExecutionError::new(
                    error.message,
                    error.classification,
                    error.causes,
                )
            })?;
        let client = system_client(Arc::clone(&self.registry), self.policy.clone());
        workflow::fuzz::ClientExecutor::new(&client, self.exchange.clone()).execute(case, timeout)
    }
}

pub(super) fn fuzz_cli_error(error: workflow::fuzz::Error) -> CliError {
    let sequence = error.sequence();
    let mut error = CliError::classified(error);
    if let Some(sequence) = sequence {
        error = error.at_sequence(sequence);
    }
    error
}

fn render_fuzz_text(
    result: output::fuzz::Result,
    diagnostics: Vec<packet::diagnostic::Diagnostic>,
    stats: output::envelope::Stats,
) -> Result<(), CliError> {
    write_stdout_line(format_args!(
        "mode={} seed={} first_case={} generated={} built={} rejected={}",
        fuzz_mode_name(result.mode),
        result.seed,
        result.first_case,
        result.cases_generated,
        result.cases_built,
        result.cases_rejected,
    ))?;
    for case in &result.cases {
        write_stdout_line(format_args!(
            "case={} seed={} strategy={} target={}.{} outcome={} length={} reproduce=--seed {} --first-case {} --cases 1",
            case.index,
            case.seed,
            case.mutation.strategy,
            case.mutation.layer,
            case.mutation.field,
            fuzz_outcome_name(case.outcome),
            case.frame.as_ref().map(|frame| frame.length).unwrap_or(0),
            case.reproduction.operation_seed,
            case.reproduction.case_index,
        ))?;
        let original = serde_json::to_string(&case.mutation.original).map_err(|source| {
            CliError::new(70, format!("serialize fuzz mutation failed: {source}"))
        })?;
        let value = serde_json::to_string(&case.mutation.value).map_err(|source| {
            CliError::new(70, format!("serialize fuzz mutation failed: {source}"))
        })?;
        write_stdout_line(format_args!("  original={original} value={value}"))?;
        if let Some(frame) = &case.frame {
            write_stdout_line(format_args!("  frame {}", spaced_hex(frame.bytes())))?;
        }
        if let Some(error) = &case.error {
            write_stdout_line(format_args!(
                "  error kind={} code={} message={}",
                error.kind.as_str(),
                error.code,
                error.message,
            ))?;
        }
        if let Some(sent) = &case.sent {
            write_stdout_line(format_args!(
                "  sent dlt={} caplen={} wirelen={} {}",
                sent.link_type,
                sent.captured_length,
                sent.original_length,
                spaced_hex(sent.bytes())
            ))?;
        }
        for (kind, frames) in [
            ("response", &case.responses),
            ("unmatched", &case.unmatched),
            ("undecoded", &case.undecoded),
        ] {
            for frame in frames {
                write_stdout_line(format_args!(
                    "  {kind} dlt={} caplen={} wirelen={} {}",
                    frame.link_type,
                    frame.captured_length,
                    frame.original_length,
                    spaced_hex(frame.bytes())
                ))?;
            }
        }
        render_output_diagnostics_text(&case.diagnostics)?;
    }
    write_stdout_line(format_args!(
        "fuzz completed {} case(s), {} packet operation(s), {} byte(s)",
        result.cases_generated, stats.packets_completed, stats.bytes
    ))?;
    render_diagnostics_text(&diagnostics)
}

fn render_fuzz_stream(
    result: output::fuzz::Result,
    diagnostics: Vec<packet::diagnostic::Diagnostic>,
    stats: output::envelope::Stats,
) -> Result<(), CliError> {
    let output::fuzz::Result {
        seed,
        first_case,
        mode,
        cases_generated,
        cases_built,
        cases_rejected,
        cases,
    } = result;
    let mut sequence = 0_u64;
    for case in cases {
        emit_fuzz_record(
            &mut sequence,
            output::fuzz::Event::Case {
                operation_seed: seed,
                case: Box::new(case),
            },
        )?;
    }
    emit_json_compact(
        &output::envelope::Stream::success(
            output::contract::Command::Fuzz,
            sequence,
            output::fuzz::Event::Complete {
                operation_seed: seed,
                first_case,
                mode,
                cases_generated,
                cases_built,
                cases_rejected,
            },
            diagnostics,
        )
        .with_stats(stats),
    )
    .map_err(|error| error.at_sequence(sequence))
}

fn emit_fuzz_record(sequence: &mut u64, result: output::fuzz::Event) -> Result<(), CliError> {
    emit_json_compact(&output::envelope::Stream::success(
        output::contract::Command::Fuzz,
        *sequence,
        result,
        Vec::new(),
    ))
    .map_err(|error| error.at_sequence(*sequence))?;
    *sequence = sequence.checked_add(1).ok_or_else(|| {
        CliError::classified(output::contract::Error::SequenceOverflow).at_sequence(*sequence)
    })?;
    Ok(())
}

fn fuzz_mode_name(value: output::fuzz::Mode) -> &'static str {
    match value {
        output::fuzz::Mode::Offline => "offline",
        output::fuzz::Mode::Live => "live",
    }
}

fn fuzz_outcome_name(value: output::fuzz::Outcome) -> &'static str {
    match value {
        output::fuzz::Outcome::Built => "built",
        output::fuzz::Outcome::Rejected => "rejected",
        output::fuzz::Outcome::Sent => "sent",
        output::fuzz::Outcome::Response => "response",
        output::fuzz::Outcome::Timeout => "timeout",
        output::fuzz::Outcome::Error => "error",
    }
}
