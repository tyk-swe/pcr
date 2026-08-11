// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr::{core, output};

use crate::errors::CliError;
use crate::rendering::{
    captured_frame_text, comma_separated, emit_stream_record, emit_stream_with_stats,
    optional_display, output_timestamp_text, render_diagnostics_text, render_optional,
    write_stdout_line,
};

pub(super) fn render_traceroute_text(
    result: output::traceroute::Result,
    diagnostics: Vec<core::diagnostic::Diagnostic>,
    stats: output::envelope::Stats,
) -> Result<(), CliError> {
    write_stdout_line(format_args!(
        "target={} resolved={} destination={} strategy={} port={}",
        result.target,
        comma_separated(&result.resolved_addresses),
        result.destination,
        result.strategy,
        optional_display(result.destination_port),
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
                render_optional(probe.received_at, output_timestamp_text),
                optional_display(probe.responder),
                render_optional(probe.latency, |value| format!("{value:?}")),
                optional_display(probe.destination_port),
                probe.reason,
            ))?;
            if let Some(frame) = &probe.frame {
                write_stdout_line(format_args!("    frame {}", captured_frame_text(frame)))?;
            }
        }
    }
    for evidence in &result.undecoded {
        write_stdout_line(format_args!(
            "undecoded hop={} {}",
            evidence.hop_limit,
            captured_frame_text(&evidence.frame)
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

pub(super) fn trace_probe_status_name(value: output::traceroute::ProbeStatus) -> &'static str {
    match value {
        output::traceroute::ProbeStatus::Response => "response",
        output::traceroute::ProbeStatus::Timeout => "timeout",
    }
}

pub(super) fn trace_response_kind_name(value: output::traceroute::ResponseKind) -> &'static str {
    match value {
        output::traceroute::ResponseKind::Intermediate => "intermediate",
        output::traceroute::ResponseKind::DestinationReached => "destination_reached",
        output::traceroute::ResponseKind::Unreachable => "unreachable",
    }
}

pub(super) fn trace_completion_name(value: output::traceroute::Completion) -> &'static str {
    match value {
        output::traceroute::Completion::DestinationReached => "destination_reached",
        output::traceroute::Completion::Unreachable => "unreachable",
        output::traceroute::Completion::MaximumHops => "maximum_hops",
        output::traceroute::Completion::Timeout => "timeout",
    }
}

pub(super) fn render_traceroute_stream(
    result: output::traceroute::Result,
    diagnostics: Vec<core::diagnostic::Diagnostic>,
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
    emit_stream_with_stats(
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
        stats,
    )
}
