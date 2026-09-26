// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::rendering::StreamEncoder;

use crate::output;

use crate::errors::CliError;
use crate::rendering::{
    captured_frame_text, comma_separated, optional_debug, optional_display,
    render_diagnostics_text, render_undecoded, write_stdout_line, write_summary_line,
};

pub(super) fn render_text(
    published: output::envelope::Published<output::scan::Report>,
) -> Result<(), CliError> {
    let output::envelope::Published {
        result,
        diagnostics,
        stats,
    } = published;
    let stats = stats.unwrap_or_default();
    write_stdout_line(format_args!(
        "target={} resolved={}",
        result.target,
        comma_separated(&result.resolved_addresses)
    ))?;
    write_stdout_line(format_args!(
        "planned timeout+pacing {:?}; achieved {:.2} probes/s over {:?}",
        result.planned_duration,
        if stats.elapsed.is_zero() {
            0.0
        } else {
            stats.packets_completed as f64 / stats.elapsed.as_secs_f64()
        },
        stats.elapsed
    ))?;
    for endpoint in &result.endpoints {
        // ICMP has no port, so it names itself; the port-bearing transports
        // name the endpoint they probed.
        let endpoint_name = match endpoint.transport {
            output::probe::Transport::Icmp => endpoint.transport.to_string(),
            output::probe::Transport::Tcp | output::probe::Transport::Udp => {
                format!("{}/{}", endpoint.transport, optional_display(endpoint.port))
            }
        };
        write_stdout_line(format_args!(
            "{} {} classification={}",
            endpoint.address,
            endpoint_name,
            endpoint.classification.as_str()
        ))?;
        for evidence in &endpoint.probes {
            write_stdout_line(format_args!(
                "  sequence={} attempt={} status={} classification={} sent={} received={} responder={} latency={} reason={}",
                evidence.sequence,
                evidence.attempt,
                evidence.status.as_str(),
                evidence.classification.as_str(),
                evidence.sent_at,
                optional_display(evidence.received_at),
                optional_display(evidence.responder),
                optional_debug(evidence.latency),
                evidence.reason,
            ))?;
            if let Some(application) = &evidence.application {
                write_stdout_line(format_args!(
                    "    profile={} validation={:?}: {}",
                    application.profile, application.status, application.reason
                ))?;
            }
            if let Some(frame) = &evidence.frame {
                write_stdout_line(format_args!("    frame {}", captured_frame_text(frame)))?;
            }
        }
    }
    render_undecoded(result.undecoded.iter().map(|frame| (None, frame)))?;
    let rtt = result.rtt;
    write_summary_line(format_args!(
        "scanned {} endpoint(s) with {} completed probe(s), {} byte(s)",
        result.endpoints.len(),
        stats.packets_completed,
        stats.bytes
    ))?;
    write_summary_line(format_args!(
        "probes sent={} received={} lost={} rtt min/avg/max={}/{}/{}",
        rtt.sent,
        rtt.received,
        rtt.lost,
        optional_debug(rtt.min),
        optional_debug(rtt.avg),
        optional_debug(rtt.max),
    ))?;
    render_diagnostics_text(&diagnostics)
}

pub(super) fn emit_event(
    event: packetcraftr::scan::Event,
    stream: &StreamEncoder,
) -> Result<(), CliError> {
    let published = output::envelope::Published::<output::scan::Event>::try_from(event)
        .map_err(CliError::classified)?;
    Ok(stream.emit_published(published)?)
}

pub(super) fn emit_complete(
    summary: packetcraftr::scan::Report,
    stream: &StreamEncoder,
) -> Result<(), CliError> {
    Ok(
        stream.complete_published(output::envelope::Published::<output::scan::Event>::from(
            summary,
        ))?,
    )
}

pub(super) fn scan_error(error: packetcraftr::scan::Error) -> CliError {
    use packetcraftr_core::error::Classified;
    let mut cli =
        CliError::from_classification(error.classification(), error.to_string(), error.causes())
            .with_context(error.context());
    let mut source: Option<&(dyn std::error::Error + 'static)> = Some(&error);
    while let Some(error) = source {
        if let Some(pipeline) = error.downcast_ref::<packetcraftr::scan::PipelineFailure>() {
            match output::scan::Failure::try_from(pipeline) {
                Ok(partial) => cli = cli.with_scan(partial),
                Err(error) => cli
                    .causes
                    .push(format!("could not render pending scan evidence: {error}")),
            }
            break;
        }
        source = error.source();
    }
    cli
}

/// A TCP connect scan's endpoints and socket statistics.
pub(super) fn render_connect_text(report: &output::scan::connect::Report) -> Result<(), CliError> {
    for endpoint in &report.endpoints {
        write_stdout_line(format_args!(
            "{} tcp-connect/{} classification={}",
            endpoint.address,
            endpoint.port,
            endpoint.classification.as_str()
        ))?;
    }
    write_stdout_line(format_args!(
        "{} socket connections attempted; {} succeeded; elapsed {:?}",
        report.summary.socket_stats.connections_attempted,
        report.summary.socket_stats.connections_succeeded,
        report.summary.socket_stats.elapsed
    ))?;
    let rtt = &report.summary.socket_stats.rtt;
    write_stdout_line(format_args!(
        "probes sent={} received={} lost={} rtt min/avg/max={}/{}/{}",
        rtt.sent,
        rtt.received,
        rtt.lost,
        optional_debug(rtt.min),
        optional_debug(rtt.avg),
        optional_debug(rtt.max),
    ))
}
