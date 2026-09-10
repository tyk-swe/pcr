// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::rendering::StreamEncoder;

use packetcraftr_core as core;

use packetcraftr_cli::output;

use crate::errors::CliError;
use crate::rendering::{
    captured_frame_text, comma_separated, optional_debug, optional_display,
    render_diagnostics_text, render_undecoded, write_stdout_line,
};

pub(super) fn render_text(
    result: output::traceroute::Report,
    diagnostics: Vec<core::diagnostic::Diagnostic>,
    stats: packetcraftr::Stats,
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
                probe.status.as_str(),
                probe
                    .response_kind
                    .map_or("none", packetcraftr::traceroute::ResponseKind::as_str),
                probe.sent_at,
                optional_display(probe.received_at),
                optional_display(probe.responder),
                optional_debug(probe.latency),
                optional_display(probe.destination_port),
                probe.reason,
            ))?;
            if let Some(frame) = &probe.frame {
                write_stdout_line(format_args!("    frame {}", captured_frame_text(frame)))?;
            }
        }
    }
    render_undecoded(
        result
            .undecoded
            .iter()
            .map(|evidence| (Some(format!("hop={}", evidence.hop_limit)), &evidence.frame)),
    )?;
    write_stdout_line(format_args!(
        "trace completion={} hops={} probes={} bytes={}",
        result.completion.as_str(),
        result.hops.len(),
        stats.packets_completed,
        stats.bytes
    ))?;
    render_diagnostics_text(&diagnostics)
}

/// Converts and writes one final workflow event at its publication boundary.
pub(super) fn emit_event(
    event: packetcraftr::traceroute::Event,
    stream: &StreamEncoder,
) -> Result<(), CliError> {
    let (record, diagnostics) =
        output::traceroute::Event::try_from_traceroute(event).map_err(CliError::classified)?;
    Ok(stream.emit_data(record, diagnostics)?)
}

pub(super) fn emit_complete(
    summary: packetcraftr::traceroute::Summary,
    stream: &StreamEncoder,
) -> Result<(), CliError> {
    let (record, diagnostics, stats) = output::traceroute::Event::complete_from_traceroute(summary);
    Ok(stream.complete_with_stats(record, diagnostics, stats)?)
}
