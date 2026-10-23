// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::{
    errors::CliError,
    invocation::Invocation,
    output,
    rendering::{
        captured_frame_text, duration_text, optional_display, render_diagnostics_text,
        write_stdout_line,
    },
};
use packetcraftr::traceroute::multipath as library;

pub(in crate::commands::network::traceroute) fn render_event(
    invocation: &Invocation,
    event: library::Event,
) -> Result<(), CliError> {
    match event {
        library::Event::Flow(flow) => write_stdout_line(
            invocation,
            format_args!(
                "flow={} strategy={} source={} destination={} source_port={} destination_port={} icmp_id={} ipv6_flow_label={}",
                flow.id,
                flow.strategy,
                flow.source,
                flow.destination,
                optional_display(flow.source_port),
                optional_display(flow.destination_port),
                optional_display(flow.icmp_identifier),
                optional_display(flow.ipv6_flow_label),
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
                        "  responder={} latency={} kind={}",
                        reply.responder,
                        duration_text(reply.latency),
                        reply.kind.as_str()
                    ),
                )?;
                if invocation.output.presentation().verbose {
                    let frame = output::frame::Captured::try_from(reply.frame)
                        .map_err(CliError::classified)?;
                    write_stdout_line(
                        invocation,
                        format_args!("    frame {}", captured_frame_text(&frame)),
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
        library::Event::Unmatched(unmatched) => write_stdout_line(
            invocation,
            format_args!(
                "unmatched sweep={} hop={}; retained without attribution",
                unmatched.sweep, unmatched.hop_limit
            ),
        ),
    }
}

pub(in crate::commands::network::traceroute) fn render_complete(
    invocation: &Invocation,
    report: &library::Report,
) -> Result<(), CliError> {
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
                format_args!("    destination_rtt {}", rtt_text(rtt)),
            )?;
        }
    }
    for node in &report.topology.nodes {
        write_stdout_line(
            invocation,
            format_args!(
                "  hop={} responder={} {}",
                node.key.hop_limit,
                node.key.responder,
                rtt_text(&node.rtt)
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

fn rtt_text(rtt: &library::Rtt) -> String {
    format!(
        "samples={} min={} median={} max={}",
        rtt.samples,
        duration_text(rtt.minimum),
        duration_text(rtt.median),
        duration_text(rtt.maximum)
    )
}
