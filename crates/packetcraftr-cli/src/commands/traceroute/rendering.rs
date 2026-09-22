// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr_cli::output;

use crate::errors::CliError;
use crate::rendering::{
    captured_frame_text, comma_separated, optional_debug, optional_display,
    render_diagnostics_text, render_undecoded, write_stdout_line,
};

pub(super) fn render_text(
    output::workflow::Converted {
        result,
        diagnostics,
        stats,
        ..
    }: output::workflow::Converted<output::traceroute::Report>,
) -> Result<(), CliError> {
    let stats = stats.expect("traceroute conversion includes packet statistics");
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
