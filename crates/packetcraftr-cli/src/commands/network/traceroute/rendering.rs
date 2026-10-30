// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::invocation::StreamEncoder;

use crate::output;

use crate::errors::CliError;
use crate::rendering::{
    CapturedFrameText, comma_separated, duration_text, render_diagnostics_text, render_optional,
    render_undecoded, write_stdout_line,
};

pub(super) mod multipath;

pub(super) fn render_text(
    invocation: &crate::invocation::Invocation,
    published: output::envelope::Published<output::traceroute::Report>,
    presentation: crate::invocation::Presentation,
) -> Result<(), CliError> {
    let output::envelope::Published {
        result,
        diagnostics,
        stats,
    } = published;
    let stats = stats.unwrap_or_default();
    write_stdout_line(
        invocation,
        format_args!(
            "target={} resolved={} destination={} strategy={} port={}",
            result.target,
            comma_separated(&result.resolved_addresses),
            result.destination,
            result.strategy,
            render_optional(result.destination_port, |value| value.to_string()),
        ),
    )?;
    for hop in &result.hops {
        write_stdout_line(invocation, format_args!("hop={}", hop.hop_limit))?;
        for probe in &hop.probes {
            render_probe_text(invocation, "  ", probe, presentation)?;
        }
    }
    render_undecoded(
        invocation,
        result
            .undecoded
            .iter()
            .map(|evidence| (Some(format!("hop={}", evidence.hop_limit)), &evidence.frame)),
    )?;
    write_stdout_line(
        invocation,
        format_args!(
            "trace completion={} hops={} probes={} bytes={}",
            result.completion.as_str(),
            result.hops.len(),
            stats.packets_completed,
            stats.bytes
        ),
    )?;
    render_diagnostics_text(invocation, &diagnostics)
}

pub(super) fn emit_event(
    event: packetcraftr::traceroute::Event,
    stream: &StreamEncoder,
) -> Result<(), CliError> {
    let published = output::envelope::Published::<output::traceroute::Event>::try_from(event)
        .map_err(CliError::classified)?;
    Ok(stream.emit_published(published)?)
}

pub(super) fn emit_complete(
    summary: packetcraftr::traceroute::Report,
    stream: &StreamEncoder,
) -> Result<(), CliError> {
    Ok(stream.complete_published(
        output::envelope::Published::<output::traceroute::Event>::from(summary),
    )?)
}

/// One probe's evidence line after `lead`, with its frame beneath.
pub(in crate::commands) fn render_probe_text(
    invocation: &crate::invocation::Invocation,
    lead: &str,
    probe: &output::traceroute::Probe,
    presentation: crate::invocation::Presentation,
) -> Result<(), CliError> {
    write_stdout_line(
        invocation,
        format_args!(
            "{lead}sequence={} attempt={} status={} response={} sent={} received={} responder={} latency={} port={} reason={}",
            probe.sequence,
            probe.attempt,
            probe.status.as_str(),
            probe
                .response_kind
                .map_or("none", output::traceroute::ResponseKind::as_str),
            probe.sent_at,
            render_optional(probe.received_at, |value| value.to_string()),
            render_optional(probe.responder, |value| value.to_string()),
            render_optional(probe.latency, duration_text),
            render_optional(probe.destination_port, |value| value.to_string()),
            probe.reason,
        ),
    )?;
    if let Some(frame) = &probe.frame
        && presentation.verbose
    {
        write_stdout_line(
            invocation,
            format_args!("{lead}  frame {}", CapturedFrameText(frame)),
        )?;
    }
    Ok(())
}
