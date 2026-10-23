// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::{
    errors::CliError,
    invocation::{Invocation, StreamEncoder},
    output::{self, contract::Format, envelope::Published},
    rendering::{render_diagnostics_text, write_stdout_line},
};
use packetcraftr::{
    Client, PacketProviders, TargetProviders, clock::Clock, traceroute::multipath as library,
};

pub(super) fn run<P: PacketProviders + TargetProviders, K: Clock>(
    invocation: &Invocation,
    client: &Client<P, K>,
    request: library::Request,
    format: Format,
    stream: &StreamEncoder,
) -> Result<(), CliError> {
    request.validate().map_err(CliError::classified)?;
    if format == Format::Json {
        let collector = library::Collector::default();
        let report = client
            .traceroute_multipath(request, collector.clone())
            .map_err(CliError::classified)?;
        let result = collector.finish(report).map_err(CliError::classified)?;
        invocation.check()?;
        return crate::rendering::emit_published(
            invocation,
            output::contract::Command::Traceroute,
            Published::<output::traceroute::multipath::Report>::try_from(result)
                .map_err(CliError::classified)?,
        );
    }
    let text_invocation = invocation.clone();
    let emitter = crate::commands::execution::emitter(invocation, move |event, stream| {
        if format == Format::Ndjson {
            return Ok(stream.emit_published(
                Published::<output::traceroute::multipath::Event>::try_from(event)
                    .map_err(CliError::classified)?,
            )?);
        }
        let mut controlled = text_invocation.clone();
        controlled.output = stream.clone();
        render_event(&controlled, event)
    });
    let report = client
        .traceroute_multipath(request, emitter)
        .map_err(CliError::classified)?;
    invocation.check()?;
    if format == Format::Ndjson {
        Ok(
            stream.complete_published(Published::<output::traceroute::multipath::Event>::from(
                report,
            ))?,
        )
    } else {
        render_complete(invocation, &report)
    }
}

fn render_event(invocation: &Invocation, event: library::Event) -> Result<(), CliError> {
    match event {
        library::Event::Flow(flow) => write_stdout_line(
            invocation,
            format_args!(
                "flow={} strategy={} source={} destination={} source_port={} destination_port={} icmp_id={} ipv6_flow_label={}",
                flow.id,
                flow.strategy,
                flow.source,
                flow.destination,
                flow.source_port
                    .map(|value| value.to_string())
                    .as_deref()
                    .unwrap_or("-"),
                flow.destination_port
                    .map(|value| value.to_string())
                    .as_deref()
                    .unwrap_or("-"),
                flow.icmp_identifier
                    .map(|value| value.to_string())
                    .as_deref()
                    .unwrap_or("-"),
                flow.ipv6_flow_label
                    .map(|value| value.to_string())
                    .as_deref()
                    .unwrap_or("-")
            ),
        ),
        library::Event::Probe(probe) => {
            write_stdout_line(
                invocation,
                format_args!(
                    "sweep={} hop={} flow={} sequence={} replies={} ambiguous={} incomplete={}",
                    probe.sweep,
                    probe.hop_limit,
                    probe.flow_id,
                    probe.sequence,
                    probe.replies_seen,
                    probe.ambiguous,
                    probe.incomplete
                ),
            )?;
            for reply in probe.replies {
                write_stdout_line(
                    invocation,
                    format_args!(
                        "  {} {:.3} ms {}",
                        reply.responder,
                        reply.latency.as_secs_f64() * 1000.,
                        reply.kind.as_str()
                    ),
                )?;
                if invocation.output.presentation().verbose {
                    let frame = output::frame::Captured::try_from(reply.frame)
                        .map_err(CliError::classified)?;
                    write_stdout_line(
                        invocation,
                        format_args!("  {}", crate::rendering::captured_frame_text(&frame)),
                    )?;
                }
            }
            Ok(())
        }
        library::Event::Topology(update) => {
            for edge in update.edges {
                write_stdout_line(
                    invocation,
                    format_args!(
                        "  observed {}@{} -> {}@{} probes={:?}",
                        edge.from.responder,
                        edge.from.hop_limit,
                        edge.to.responder,
                        edge.to.hop_limit,
                        edge.evidence
                    ),
                )?;
            }
            for change in update.changes {
                write_stdout_line(
                    invocation,
                    format_args!(
                        "  changed flow={} hop={} sweep={} {} -> {}",
                        change.flow_id, change.hop_limit, change.sweep, change.before, change.after
                    ),
                )?;
            }
            Ok(())
        }
        library::Event::FlowComplete(completion) => write_stdout_line(
            invocation,
            format_args!(
                "flow={} sweep={} completion={} last_hop={}",
                completion.flow_id,
                completion.sweep,
                completion.completion.as_str(),
                completion.last_hop
            ),
        ),
        library::Event::Diagnostic(diagnostic) => {
            render_diagnostics_text(invocation, &[diagnostic])
        }
        library::Event::Unmatched {
            sweep, hop_limit, ..
        } => write_stdout_line(
            invocation,
            format_args!("unmatched sweep={sweep} hop={hop_limit}; retained without attribution"),
        ),
    }
}

fn render_complete(invocation: &Invocation, report: &library::Report) -> Result<(), CliError> {
    write_stdout_line(
        invocation,
        format_args!(
            "multipath target={} destination={} strategy={} flows={} sweeps={}",
            report.target,
            report.destination,
            report.strategy,
            report.flows.len(),
            report.summary.sweeps_completed
        ),
    )?;
    for flow in &report.flow_summaries {
        write_stdout_line(
            invocation,
            format_args!(
                "  flow={} sent={} answered={} unanswered={} ambiguous={} reached_sweeps={}",
                flow.flow_id,
                flow.probes_sent,
                flow.answered_probes,
                flow.unanswered_probes,
                flow.ambiguous_probes,
                flow.sweeps_reached
            ),
        )?;
        if let Some(rtt) = &flow.destination_rtt {
            write_stdout_line(
                invocation,
                format_args!(
                    "    destination RTT samples={} min/median/max={:.3}/{:.3}/{:.3} ms",
                    rtt.samples,
                    rtt.minimum.as_secs_f64() * 1000.,
                    rtt.median.as_secs_f64() * 1000.,
                    rtt.maximum.as_secs_f64() * 1000.
                ),
            )?;
        }
    }
    for node in &report.topology.nodes {
        write_stdout_line(
            invocation,
            format_args!(
                "  hop={} {} samples={} RTT min/median/max={:.3}/{:.3}/{:.3} ms",
                node.key.hop_limit,
                node.key.responder,
                node.rtt.samples,
                node.rtt.minimum.as_secs_f64() * 1000.,
                node.rtt.median.as_secs_f64() * 1000.,
                node.rtt.maximum.as_secs_f64() * 1000.
            ),
        )?;
    }
    for edge in &report.topology.edges {
        write_stdout_line(
            invocation,
            format_args!(
                "  {}@{} -> {}@{} observations={}",
                edge.from.responder,
                edge.from.hop_limit,
                edge.to.responder,
                edge.to.hop_limit,
                edge.evidence.len()
            ),
        )?;
    }
    write_stdout_line(
        invocation,
        format_args!(
            "observed nodes={} edges={} branches={} rejoins={} changes={} probes={}/{} answered={} unanswered={} cleanup={} incomplete={}",
            report.summary.nodes,
            report.summary.edges,
            report.summary.branch_points,
            report.summary.rejoin_points,
            report.summary.changes,
            report.summary.probes_sent,
            report.summary.planned_probes,
            report.summary.answered_probes,
            report.summary.unanswered_probes,
            report.summary.cleanup_packets,
            report.summary.incomplete
        ),
    )?;
    write_stdout_line(
        invocation,
        format_args!(
            "Sampled traceroute adjacencies; unanswered probes are not measured forwarding loss."
        ),
    )
}
