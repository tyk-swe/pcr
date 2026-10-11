// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Text rendering for a scan’s traceroute follow-up.

use crate::rendering::{
    comma_separated, duration_text, optional_display, render_undecoded, write_stdout_line,
    write_summary_line,
};
use crate::{errors::CliError, output};

/// The trace stage: one line per host, then its hops in hop order. A reused
/// hop is a claim from another host's trace, so it is marked apart from the
/// probes that observed a hop for this host.
pub(super) fn render_traceroute_text(
    trace: &output::traceroute::hosts::Report,
) -> Result<(), CliError> {
    use output::traceroute::hosts::Basis;

    let plan = &trace.plan;
    write_stdout_line(format_args!(
        "traceroute first-hop={} max-hops={} attempts={} max-probes={} strategy={} reuse-max-age={}",
        plan.first_hop,
        plan.max_hops,
        plan.attempts,
        plan.max_probes,
        plan.strategy.as_ref().map_or_else(
            || "-".to_owned(),
            |strategy| strategy_text(strategy.strategy, strategy.destination_port)
        ),
        plan.reuse
            .as_ref()
            .map_or_else(|| "-".to_owned(), |reuse| duration_text(reuse.max_age)),
    ))?;
    for host in &trace.hosts {
        let summary = &host.summary;
        let address = match &summary.scope {
            Some(scope) => format!("{}%{}", summary.address, scope.zone),
            None => summary.address.to_string(),
        };
        let selection = summary.selection.as_ref().map_or_else(
            || "-".to_owned(),
            |selection| {
                let basis = match (&selection.basis, &selection.observation) {
                    (Basis::Observed, Some(observation)) => format!(
                        "observed stage={} sequence={} reply={}",
                        observation.stage.as_str(),
                        observation.sequence,
                        observation.reply
                    ),
                    (basis, _) => basis.as_str().to_owned(),
                };
                format!(
                    "{} basis={basis}",
                    strategy_text(selection.strategy, selection.destination_port)
                )
            },
        );
        write_stdout_line(format_args!(
            "trace {address} status={} {} strategy={selection}",
            summary.status.as_str(),
            match (&summary.reason, &summary.completion) {
                (Some(reason), _) => format!("reason={}", reason.as_str()),
                (None, Some(completion)) => format!("completion={}", completion.as_str()),
                (None, None) => "completion=-".to_owned(),
            },
        ))?;
        let mut hops: Vec<(u8, Option<&output::traceroute::Hop>, Option<&_>)> = host
            .hops
            .iter()
            .map(|hop| (hop.hop_limit, Some(hop), None))
            .chain(
                summary
                    .reused_hops
                    .iter()
                    .map(|hop| (hop.hop_limit, None, Some(hop))),
            )
            .collect();
        hops.sort_by_key(|(hop_limit, _, _)| *hop_limit);
        for (hop_limit, fresh, reused) in hops {
            write_stdout_line(format_args!("  hop={hop_limit}"))?;
            if let Some(hop) = fresh {
                for probe in &hop.probes {
                    crate::commands::traceroute::rendering::render_probe_text("    ", probe)?;
                }
            }
            if let Some(hop) = reused {
                write_stdout_line(format_args!(
                    "    reused from={} age={} probes={} responders={} observed={}",
                    hop.source,
                    duration_text(hop.age),
                    comma_separated(&hop.probes),
                    comma_separated(&hop.responders),
                    optional_display(hop.observed_at.as_ref()),
                ))?;
            }
        }
    }
    render_undecoded(trace.undecoded.iter().map(|evidence| {
        (
            Some(format!(
                "destination={} hop={}",
                evidence.destination, evidence.hop_limit
            )),
            &evidence.frame,
        )
    }))?;
    write_summary_line(format_args!(
        "traced {} host(s); retained evidence {} byte(s)",
        traced_hosts(trace),
        trace.retained_evidence_bytes
    ))
}

/// Count complete and incomplete traces, excluding not-traced records.
fn traced_hosts(trace: &output::traceroute::hosts::Report) -> usize {
    trace
        .hosts
        .iter()
        .filter(|host| {
            matches!(
                host.summary.status,
                output::traceroute::hosts::Status::Complete
                    | output::traceroute::hosts::Status::Incomplete
            )
        })
        .count()
}

fn strategy_text(strategy: packetcraftr::probe::Transport, port: Option<u16>) -> String {
    match port {
        Some(port) => format!("{strategy}/{port}"),
        None => strategy.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use super::*;
    use output::traceroute::hosts::Status;

    fn traced_report(statuses: &[Status]) -> output::traceroute::hosts::Report {
        output::traceroute::hosts::Report {
            plan: output::traceroute::hosts::Plan {
                first_hop: 1,
                max_hops: 8,
                attempts: 1,
                max_probes: 1000,
                strategy: None,
                reuse: None,
            },
            hosts: statuses
                .iter()
                .map(|status| output::traceroute::hosts::Host {
                    summary: output::traceroute::hosts::Summary {
                        address: IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                        scope: None,
                        status: *status,
                        reason: None,
                        completion: None,
                        selection: None,
                        reused_hops: Vec::new(),
                    },
                    hops: Vec::new(),
                })
                .collect(),
            undecoded: Vec::new(),
            retained_evidence_bytes: 0,
        }
    }

    #[test]
    fn the_traced_count_covers_only_hosts_the_trace_probed() {
        let mixed = traced_report(&[Status::Complete, Status::Incomplete, Status::NotTraced]);
        assert_eq!(traced_hosts(&mixed), 2);
        let none = traced_report(&[Status::NotTraced, Status::NotTraced]);
        assert_eq!(traced_hosts(&none), 0);
    }
}
