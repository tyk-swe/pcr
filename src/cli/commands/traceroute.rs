// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

// Traceroute command execution and presentation.

use std::sync::Arc;
use std::time::Duration;

use packetcraftr::{client, net, output, packet, workflow};

use super::super::arguments::TracerouteArgs;
use super::super::errors::CliError;
use super::super::rendering::{
    emit_json, emit_json_compact, emit_stream_record, output_timestamp_text, spaced_hex,
    write_stdout_line,
};
use super::super::runtime::{
    DeferredInterface, SystemClient, default_registry_arc, parse_workflow_target, system_client,
    workflow_exchange_options,
};
use super::capture::render_diagnostics_text;
use super::scan::validate_live_interface_selector;

pub(in crate::cli) fn run_traceroute(
    arguments: TracerouteArgs,
    output: output::contract::Format,
) -> Result<(), CliError> {
    let TracerouteArgs {
        target,
        strategy,
        family,
        port,
        first_hop,
        max_hops,
        attempts,
        timeout_ms,
        rate,
        max_probes,
        max_duration_ms,
        max_undecoded,
        interface,
        source,
        link_mode,
        limits,
        policy,
    } = arguments;
    let target = parse_workflow_target(target)?;
    let strategy: workflow::traceroute::Strategy = strategy.into();
    let destination_port = match strategy {
        workflow::traceroute::Strategy::Udp => {
            Some(port.unwrap_or(workflow::traceroute::DEFAULT_TRACEROUTE_UDP_PORT))
        }
        workflow::traceroute::Strategy::Tcp => {
            Some(port.unwrap_or(workflow::traceroute::DEFAULT_TRACEROUTE_TCP_PORT))
        }
        workflow::traceroute::Strategy::Icmp => port,
    };
    let queue_limits = limits.into_limits();
    let trace_limits = workflow::traceroute::Limits {
        max_probes,
        max_duration: Duration::from_millis(max_duration_ms),
        max_evidence_frames: queue_limits.max_frames,
        max_evidence_bytes: queue_limits.max_bytes,
        max_undecoded,
    };
    let request = workflow::traceroute::Request {
        target,
        strategy,
        address_family: family.into(),
        destination_port,
        first_hop,
        max_hops,
        probes_per_hop: attempts,
        timeout: Duration::from_millis(timeout_ms),
        probes_per_second: rate,
        limits: trace_limits,
    };
    request.validate().map_err(traceroute_cli_error)?;
    let policy = policy.into_policy();
    policy.validate().map_err(CliError::classified)?;
    validate_live_interface_selector("traceroute", interface.as_deref())?;
    let max_template_packets = usize::try_from(attempts).map_err(|_| {
        CliError::new(
            2,
            "traceroute attempt count exceeds the platform size limit",
        )
    })?;

    let registry = default_registry_arc()?;
    let exchange = workflow_exchange_options(
        client::send::Options {
            destination: None,
            plan: net::route::Options {
                link_mode: link_mode.into(),
                interface: None,
                preferred_source: source,
            },
            build: packet::build::Options::default(),
            allow_permissive_live: false,
        },
        request.timeout,
        max_template_packets,
        queue_limits,
    )?;

    let mut executor = CliTracerouteExecutor {
        client: system_client(Arc::clone(&registry), policy.clone()),
        exchange,
        interface: DeferredInterface::new(interface),
    };
    let resolver = client::target::SystemResolver;
    let mut authorizer = workflow::traceroute::PolicyAuthorizer::new(&policy, &resolver);
    let mut clock = workflow::clock::SystemClock;
    let result = workflow::traceroute::run(
        &request,
        &mut authorizer,
        &registry,
        &mut executor,
        &mut clock,
    )
    .map_err(traceroute_cli_error)?;
    let (result, diagnostics, stats) =
        output::traceroute::Result::try_from_traceroute(result).map_err(CliError::classified)?;

    match output {
        output::contract::Format::Text => render_traceroute_text(result, diagnostics, stats),
        output::contract::Format::Json => emit_json(
            &output::envelope::Aggregate::success(
                output::contract::Command::Traceroute,
                result,
                diagnostics,
            )
            .with_stats(stats),
        ),
        output::contract::Format::Ndjson => render_traceroute_stream(result, diagnostics, stats),
        _ => Err(CliError::classified(
            output::contract::Error::UnsupportedFormat {
                command: output::contract::Command::Traceroute,
                format: output,
            },
        )),
    }
}

struct CliTracerouteExecutor {
    client: SystemClient,
    exchange: client::exchange::Options,
    interface: DeferredInterface,
}

impl workflow::traceroute::Executor for CliTracerouteExecutor {
    fn execute(
        &mut self,
        batch: &workflow::traceroute::Batch,
    ) -> Result<workflow::traceroute::Execution, workflow::BoundaryError> {
        self.interface
            .resolve_into(&mut self.exchange.send.plan)
            .map_err(CliError::into_boundary_error)?;
        workflow::traceroute::ClientExecutor::new(&self.client, self.exchange.clone())
            .execute(batch)
    }
}

pub(in crate::cli) fn traceroute_cli_error(error: workflow::traceroute::Error) -> CliError {
    let sequence = error.sequence();
    CliError::classified_at_optional_sequence(error, sequence)
}

fn render_traceroute_text(
    result: output::traceroute::Result,
    diagnostics: Vec<packet::diagnostic::Diagnostic>,
    stats: output::envelope::Stats,
) -> Result<(), CliError> {
    write_stdout_line(format_args!(
        "target={} resolved={} destination={} strategy={} port={}",
        result.target,
        result
            .resolved_addresses
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(","),
        result.destination,
        result.strategy,
        result
            .destination_port
            .map(|value| value.to_string())
            .unwrap_or_else(|| "none".to_owned()),
    ))?;
    for hop in &result.hops {
        write_stdout_line(format_args!("hop={}", hop.hop_limit))?;
        for probe in &hop.probes {
            write_stdout_line(format_args!(
                "  sequence={} attempt={} status={} response={} sent={} received={} responder={} latency={} port={} reason={}",
                probe.sequence,
                probe.attempt,
                trace_probe_status_name(probe.status),
                probe
                    .response_kind
                    .map(trace_response_kind_name)
                    .unwrap_or("none"),
                output_timestamp_text(probe.sent_at),
                probe
                    .received_at
                    .map(output_timestamp_text)
                    .unwrap_or_else(|| "none".to_owned()),
                probe
                    .responder
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "none".to_owned()),
                probe
                    .latency
                    .map(|value| format!("{value:?}"))
                    .unwrap_or_else(|| "none".to_owned()),
                probe
                    .destination_port
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "none".to_owned()),
                probe.reason,
            ))?;
            if let Some(frame) = &probe.frame {
                write_stdout_line(format_args!(
                    "    frame dlt={} caplen={} wirelen={} {}",
                    frame.link_type,
                    frame.captured_length,
                    frame.original_length,
                    spaced_hex(frame.bytes())
                ))?;
            }
        }
    }
    for evidence in &result.undecoded {
        write_stdout_line(format_args!(
            "undecoded hop={} dlt={} caplen={} wirelen={} {}",
            evidence.hop_limit,
            evidence.frame.link_type,
            evidence.frame.captured_length,
            evidence.frame.original_length,
            spaced_hex(evidence.frame.bytes())
        ))?;
    }
    write_stdout_line(format_args!(
        "trace completion={} hops={} probes={} bytes={}",
        trace_completion_name(result.completion),
        result.hops.len(),
        stats.packets_completed,
        stats.bytes
    ))?;
    render_diagnostics_text(&diagnostics)
}

fn trace_probe_status_name(value: output::traceroute::ProbeStatus) -> &'static str {
    match value {
        output::traceroute::ProbeStatus::Response => "response",
        output::traceroute::ProbeStatus::Timeout => "timeout",
    }
}

fn trace_response_kind_name(value: output::traceroute::ResponseKind) -> &'static str {
    match value {
        output::traceroute::ResponseKind::Intermediate => "intermediate",
        output::traceroute::ResponseKind::DestinationReached => "destination_reached",
        output::traceroute::ResponseKind::Unreachable => "unreachable",
    }
}

fn trace_completion_name(value: output::traceroute::Completion) -> &'static str {
    match value {
        output::traceroute::Completion::DestinationReached => "destination_reached",
        output::traceroute::Completion::Unreachable => "unreachable",
        output::traceroute::Completion::MaximumHops => "maximum_hops",
        output::traceroute::Completion::Timeout => "timeout",
    }
}

fn render_traceroute_stream(
    result: output::traceroute::Result,
    diagnostics: Vec<packet::diagnostic::Diagnostic>,
    stats: output::envelope::Stats,
) -> Result<(), CliError> {
    let output::traceroute::Result {
        target,
        resolved_addresses,
        destination,
        strategy,
        destination_port,
        hops,
        undecoded,
        completion,
    } = result;
    let mut sequence = 0_u64;
    for hop in hops {
        emit_stream_record(
            output::contract::Command::Traceroute,
            &mut sequence,
            output::traceroute::Event::Hop {
                target: target.clone(),
                destination,
                hop,
            },
        )?;
    }
    for evidence in undecoded {
        emit_stream_record(
            output::contract::Command::Traceroute,
            &mut sequence,
            output::traceroute::Event::Undecoded {
                hop_limit: evidence.hop_limit,
                frame: evidence.frame,
            },
        )?;
    }
    emit_json_compact(
        &output::envelope::Stream::success(
            output::contract::Command::Traceroute,
            sequence,
            output::traceroute::Event::Complete {
                target,
                resolved_addresses,
                destination,
                strategy,
                destination_port,
                completion,
            },
            diagnostics,
        )
        .with_stats(stats),
    )
    .map_err(|error| error.at_sequence(sequence))
}
