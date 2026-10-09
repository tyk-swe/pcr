// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::rendering::StreamEncoder;

use crate::output;

use crate::errors::CliError;
use crate::rendering::{
    captured_frame_text, comma_separated, duration_text, optional_display, optional_duration,
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
        "{}",
        throughput_text(result.planned_duration, &stats)
    ))?;
    render_plan_text(&result.plan)?;
    for endpoint in &result.endpoints {
        let endpoint_name = match endpoint.transport {
            packetcraftr::probe::Transport::Icmp => endpoint.transport.to_string(),
            packetcraftr::probe::Transport::Tcp | packetcraftr::probe::Transport::Udp => {
                format!("{}/{}", endpoint.transport, optional_display(endpoint.port))
            }
        };
        write_stdout_line(format_args!(
            "{}",
            endpoint_text(
                endpoint.address,
                endpoint.scope.as_ref(),
                &endpoint_name,
                endpoint.classification,
            )
        ))?;
        render_inference_text(endpoint.port_hint, endpoint.inference.as_ref())?;
        for evidence in &endpoint.probes {
            render_probe_text("  ", evidence)?;
        }
    }
    render_undecoded(result.undecoded.iter().map(|frame| (None, frame)))?;
    for unattributed in &result.unattributed {
        write_stdout_line(format_args!(
            "unattributed attribution={} sequence={} frame {}",
            unattributed.attribution,
            optional_display(unattributed.sequence),
            captured_frame_text(&unattributed.frame)
        ))?;
    }
    render_hosts_text(&result.plan, &result.hosts, |probe| {
        render_probe_text("  probe ", probe)
    })?;
    let rtt = result.rtt;
    write_summary_line(format_args!(
        // The totals span discovery, neighbor requests, and enrichment too.
        "scanned {} endpoint(s); the operation completed {} packet(s), {} byte(s)",
        result.endpoints.len(),
        stats.packets_completed,
        stats.bytes
    ))?;
    write_summary_line(format_args!(
        "probes sent={} received={} lost={} rtt min/avg/max={}/{}/{}",
        rtt.sent,
        rtt.received,
        rtt.lost,
        optional_duration(rtt.min),
        optional_duration(rtt.avg),
        optional_duration(rtt.max),
    ))?;
    render_scheduling_text(&result.scheduling)?;
    if let Some(trace) = &result.traceroute {
        render_traceroute_text(trace)?;
    }
    render_diagnostics_text(&diagnostics)
}

fn render_scheduling_text(scheduling: &output::scan::Scheduling) -> Result<(), CliError> {
    let ceilings = match (scheduling.operation_ceiling, scheduling.process_ceiling) {
        (Some(operation), Some(process)) => {
            format!(" operation-ceiling={operation} process-ceiling={process}")
        }
        _ => String::new(),
    };
    write_summary_line(format_args!(
        "scheduling={} peak-window={} retries={}{}",
        scheduling.mode, scheduling.observed_peak_window, scheduling.retries_started, ceilings,
    ))?;
    for condition in &scheduling.conditions {
        let host = match &condition.host.scope {
            Some(scope) => format!("{}%{}", condition.host.address, scope.zone),
            None => condition.host.address.to_string(),
        };
        write_summary_line(format_args!(
            "condition {} host={} responder={} completed={} replies={} losses={} controls={} silent={} ({})",
            condition.kind,
            host,
            condition.control_responder,
            condition.completed,
            condition.replies,
            condition.losses,
            listed(&condition.control_sequences),
            listed(&condition.loss_sequences),
            condition.caveat,
        ))?;
    }
    for host in &scheduling.incomplete {
        let host = match &host.scope {
            Some(scope) => format!("{}%{}", host.address, scope.zone),
            None => host.address.to_string(),
        };
        write_summary_line(format_args!("host {host} scan=incomplete"))?;
    }
    Ok(())
}
/// The trace stage: one line per host, then its hops in hop order. A reused
/// hop is a claim from another host's trace, so it is marked apart from the
/// probes that observed a hop for this host.
fn render_traceroute_text(trace: &output::traceroute::hosts::Report) -> Result<(), CliError> {
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

pub(super) fn render_plan_text(plan: &output::scan::plan::Plan) -> Result<(), CliError> {
    let method = &plan.method;
    write_stdout_line(format_args!(
        "method={} requested={}{} port-catalog={}/{} excluded-endpoints={}",
        method.selected,
        method.requested,
        method
            .reason
            .as_ref()
            .map_or_else(String::new, |reason| format!(" reason=\"{reason}\"")),
        plan.port_catalog.name,
        plan.port_catalog.version,
        plan.excluded_endpoints,
    ))?;
    let discovery = &plan.discovery;
    write_stdout_line(format_args!(
        "discovery={} probes={} neighbor={} unresponsive={} reverse-dns={}",
        discovery.mode,
        listed(
            &discovery
                .probes
                .iter()
                .map(|probe| match probe.port {
                    Some(port) => format!("{}/{port}", probe.transport),
                    None => probe.transport.to_string(),
                })
                .collect::<Vec<_>>()
        ),
        discovery.neighbor,
        discovery.unresponsive,
        discovery.reverse_dns.as_ref().map_or_else(
            || "-".to_owned(),
            |server| format!("{}:{}", server.server, server.port)
        ),
    ))?;
    if let Some(curated) = &plan.curated_udp_payloads {
        write_stdout_line(format_args!(
            "curated-udp-payloads={}/{} applied={} overridden={}",
            curated.data_set.name,
            curated.data_set.version,
            listed(&curated.applied),
            listed(&curated.overridden),
        ))?;
    }
    Ok(())
}

/// Host records, when discovery or a reverse lookup was requested; the plan
/// line already says when neither was.
fn render_hosts_text<P>(
    plan: &output::scan::plan::Plan,
    hosts: &[output::scan::host::Host<P>],
    probe_text: impl Fn(&P) -> Result<(), CliError>,
) -> Result<(), CliError> {
    if plan.discovery.mode == output::scan::plan::DiscoveryMode::Omitted
        && plan.discovery.reverse_dns.is_none()
    {
        return Ok(());
    }
    for host in hosts {
        let address = match &host.scope {
            Some(scope) => format!("{}%{}", host.address, scope.zone),
            None => host.address.to_string(),
        };
        write_stdout_line(format_args!(
            "host {address} discovery={} scan={}",
            host.discovery, host.scan
        ))?;
        if let Some(neighbor) = &host.neighbor {
            write_stdout_line(format_args!("  {}", neighbor_text(neighbor)))?;
        }
        for reason in &host.reasons {
            write_stdout_line(format_args!(
                "  reason={} evidence={} basis={} probe={} link={} observed={}",
                reason.kind,
                reason.evidence,
                reason.basis,
                optional_display(reason.probe),
                optional_display(reason.link_address),
                optional_display(reason.observed_at.as_ref()),
            ))?;
        }
        // Discovery probes belong to no endpoint, so their evidence is shown
        // with the host it decided.
        for probe in &host.probes {
            probe_text(probe)?;
        }
        if let Some(lookup) = &host.reverse_dns {
            write_stdout_line(format_args!("  {}", reverse_dns_text(lookup)))?;
        }
    }
    Ok(())
}

/// A raw probe's evidence line after `lead`, with any application and frame
/// lines beneath it.
fn render_probe_text(lead: &str, evidence: &output::scan::Probe) -> Result<(), CliError> {
    write_stdout_line(format_args!(
        "{lead}sequence={} attempt={} status={} classification={} sent={} received={} responder={} latency={} reason={}",
        evidence.sequence,
        evidence.attempt,
        evidence.status.as_str(),
        evidence.classification.as_str(),
        evidence.sent_at,
        optional_display(evidence.received_at),
        optional_display(evidence.responder),
        optional_duration(evidence.latency),
        evidence.reason,
    ))?;
    let nested = " ".repeat(lead.len() + 2);
    if let Some(application) = &evidence.application {
        write_stdout_line(format_args!(
            "{nested}profile={} validation={}: {}",
            application.profile,
            application.status.as_str(),
            application.reason
        ))?;
    }
    if let Some(frame) = &evidence.frame {
        write_stdout_line(format_args!("{nested}frame {}", captured_frame_text(frame)))?;
    }
    Ok(())
}

/// A connect discovery probe's evidence line.
fn connect_probe_text(probe: &output::scan::connect::Probe) -> Result<(), CliError> {
    write_stdout_line(format_args!(
        "  probe sequence={} port={} attempt={} outcome={} classification={} scheduled={} finished={} elapsed={} error={}",
        probe.sequence,
        probe.port,
        probe.attempt,
        probe.outcome,
        probe.classification,
        probe.scheduled_at,
        optional_display(probe.finished_at.as_ref()),
        duration_text(probe.elapsed),
        optional_display(probe.error.as_ref().map(|error| &error.kind)),
    ))
}

/// A host's neighbor line, with when its outcome was observed: a silent,
/// routed, or inapplicable outcome has no reason that would carry it.
fn neighbor_text(neighbor: &output::scan::host::Neighbor) -> String {
    format!(
        "neighbor={} interface={} attempts={} link={} next-hop={} next-hop-link={} observed={}",
        neighbor.outcome,
        neighbor.interface.name,
        neighbor.attempts,
        link_text(neighbor.link.as_ref()),
        optional_display(neighbor.next_hop.as_ref().map(|hop| hop.address)),
        link_text(neighbor.next_hop.as_ref().and_then(|hop| hop.link.as_ref())),
        optional_display(neighbor.observed_at.as_ref()),
    )
}

/// The scan's planned duration against the operation's achieved packet rate,
/// which spans discovery, neighbor requests, and enrichment as well as probes;
/// the plan covers discovery and the scan, not enrichment.
fn throughput_text(planned: std::time::Duration, stats: &output::envelope::Stats) -> String {
    format!(
        "scan planned timeout+pacing {}; operation achieved {:.2} packets/s over {}",
        duration_text(planned),
        if stats.elapsed.is_zero() {
            0.0
        } else {
            stats.packets_completed as f64 / stats.elapsed.as_secs_f64()
        },
        duration_text(stats.elapsed)
    )
}

/// A host's reverse-DNS line, which marks names the scan's evidence byte
/// limit dropped so a partial list never reads as the whole answer.
fn reverse_dns_text(lookup: &output::scan::host::ReverseDns) -> String {
    format!(
        "reverse-dns={} status={} outcome={} names={} names_truncated={}{}",
        lookup.query_name,
        lookup.status,
        optional_display(lookup.outcome),
        listed(&lookup.names),
        lookup.names_truncated,
        lookup
            .error
            .as_ref()
            .map_or_else(String::new, |error| format!(" error=\"{error}\"")),
    )
}

fn link_text(link: Option<&output::scan::host::Link>) -> String {
    optional_display(link.map(|link| format!("{}/{}", link.address, link.entry.as_str())))
}

/// The inference line beneath an endpoint; the hint is labelled as such so
/// it never reads as an identified service.
pub(super) fn render_inference_text(
    port_hint: Option<&str>,
    inference: Option<&output::scan::plan::Inference>,
) -> Result<(), CliError> {
    let Some(inference) = inference else {
        return Ok(());
    };
    write_stdout_line(format_args!(
        "  inferred={} rule={} supporting={} conflicting={} unanswered={} failed={} port-hint={}",
        inference.state.unwrap_or("undetermined"),
        inference.rule,
        listed(&inference.supporting),
        listed(&inference.conflicting),
        listed(&inference.unanswered),
        listed(&inference.failed),
        port_hint.unwrap_or("-"),
    ))
}

/// A comma-separated list, or `-` when empty so every key keeps a value.
fn listed<T: std::fmt::Display>(values: &[T]) -> String {
    if values.is_empty() {
        "-".to_owned()
    } else {
        comma_separated(values)
    }
}

pub(super) fn emit_event(event: super::Event, stream: &StreamEncoder) -> Result<(), CliError> {
    match event {
        super::Event::Scan(event) => {
            let published = output::envelope::Published::<output::scan::Event>::try_from(event)
                .map_err(CliError::classified)?;
            Ok(stream.emit_published(published)?)
        }
        super::Event::Trace(packetcraftr::traceroute::hosts::Event::Diagnostic(diagnostic)) => {
            Ok(stream.emit_published(output::envelope::Published::new(
                output::scan::Event::Diagnostic {},
                vec![diagnostic],
            ))?)
        }
        super::Event::Trace(event) => {
            let record = output::traceroute::hosts::Event::publish(event)
                .map_err(CliError::classified)?
                .expect("only diagnostics have no trace record");
            Ok(stream.emit_data(record, Vec::new())?)
        }
    }
}

pub(super) fn emit_complete(
    streamed: super::Streamed,
    stream: &StreamEncoder,
) -> Result<(), CliError> {
    let super::Streamed {
        mut report,
        endpoints,
        plan,
        reverse_dns,
        traceroute,
    } = streamed;
    for endpoint in endpoints {
        stream.emit_published(output::envelope::Published::<output::scan::Event>::from(
            endpoint,
        ))?;
    }
    emit_hosts(std::mem::take(&mut report.hosts), reverse_dns, stream)?;
    Ok(
        stream.complete_published(output::envelope::Published::<output::scan::Event>::from((
            report, plan, traceroute,
        )))?,
    )
}

/// One `host` record per target after the last probe, before `complete`.
pub(super) fn emit_hosts(
    hosts: Vec<packetcraftr::scan::discovery::Host>,
    reverse_dns: Vec<Option<output::scan::host::ReverseDns>>,
    stream: &StreamEncoder,
) -> Result<(), CliError> {
    let mut reverse_dns = reverse_dns.into_iter();
    for host in hosts {
        let host = output::scan::host::Host::summarize(host, reverse_dns.next().flatten())
            .map_err(CliError::classified)?;
        stream.emit_data(host, Vec::new())?;
    }
    Ok(())
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

pub(super) fn render_connect_text(report: &output::scan::connect::Report) -> Result<(), CliError> {
    render_plan_text(&report.summary.plan)?;
    for endpoint in &report.endpoints {
        write_stdout_line(format_args!(
            "{}",
            endpoint_text(
                endpoint.address,
                endpoint.scope.as_ref(),
                &format!("tcp-connect/{}", endpoint.port),
                endpoint.classification,
            )
        ))?;
        render_inference_text(endpoint.port_hint, Some(&endpoint.inference))?;
    }
    render_hosts_text(&report.summary.plan, &report.hosts, connect_probe_text)?;
    write_stdout_line(format_args!(
        "{} socket connections attempted; {} succeeded; elapsed {}",
        report.summary.socket_stats.connections_attempted,
        report.summary.socket_stats.connections_succeeded,
        duration_text(report.summary.socket_stats.elapsed)
    ))?;
    let rtt = &report.summary.socket_stats.rtt;
    write_stdout_line(format_args!(
        "probes sent={} received={} lost={} rtt min/avg/max={}/{}/{}",
        rtt.sent,
        rtt.received,
        rtt.lost,
        optional_duration(rtt.min),
        optional_duration(rtt.avg),
        optional_duration(rtt.max),
    ))?;
    render_scheduling_text(&report.summary.scheduling)
}

fn endpoint_text(
    address: std::net::IpAddr,
    scope: Option<&output::scan::Scope>,
    endpoint_name: &str,
    classification: output::scan::Classification,
) -> String {
    let address = match scope {
        Some(scope) => format!("{address}%{}", scope.zone),
        None => address.to_string(),
    };
    format!(
        "{address} {endpoint_name} classification={}",
        classification.as_str()
    )
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use super::*;
    use output::traceroute::hosts::Status;
    use output::{network::InterfaceId, scan::Classification};

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

    #[test]
    fn text_endpoints_distinguish_identical_ipv6_addresses_on_different_interfaces() {
        let address = "fe80::1".parse().unwrap();
        let alpha = output::scan::Scope {
            zone: "alpha".to_owned(),
            interface: InterfaceId {
                name: "alpha".to_owned(),
                index: 2,
            },
        };
        let beta = output::scan::Scope {
            zone: "beta".to_owned(),
            interface: InterfaceId {
                name: "beta".to_owned(),
                index: 3,
            },
        };
        for endpoint_name in ["tcp/443", "udp/443", "icmp", "tcp-connect/443"] {
            assert_eq!(
                endpoint_text(address, Some(&alpha), endpoint_name, Classification::Open),
                format!("fe80::1%alpha {endpoint_name} classification=open"),
            );
            assert_eq!(
                endpoint_text(
                    address,
                    Some(&beta),
                    endpoint_name,
                    Classification::Filtered
                ),
                format!("fe80::1%beta {endpoint_name} classification=filtered"),
            );
        }
    }

    #[test]
    fn text_neighbors_carry_their_observation_time() {
        let neighbor = |observed_at| {
            output::scan::host::Neighbor::try_from(packetcraftr::scan::discovery::Neighbor {
                outcome: packetcraftr::scan::discovery::NeighborOutcome::Silent,
                interface: packetcraftr_netio::interface::Id {
                    name: "fixture0".to_owned(),
                    index: 1,
                },
                attempts: 1,
                observed_at,
            })
            .expect("a representable neighbor")
        };
        let observed = neighbor(Some(std::time::UNIX_EPOCH));
        let text = neighbor_text(&observed);
        assert!(
            text.ends_with(&format!(
                " observed={}",
                observed.observed_at.as_ref().expect("observed")
            )),
            "{text}"
        );
        assert!(neighbor_text(&neighbor(None)).ends_with(" observed=none"));
    }

    #[test]
    fn text_throughput_counts_the_operations_packets() {
        let stats = output::envelope::Stats {
            packets_completed: 6,
            elapsed: std::time::Duration::from_secs(2),
            ..Default::default()
        };
        let text = throughput_text(std::time::Duration::from_secs(1), &stats);

        assert!(text.starts_with("scan planned "), "{text}");
        assert!(text.contains("operation achieved 3.00 packets/s"), "{text}");
    }

    #[test]
    fn text_reverse_dns_discloses_dropped_names() {
        let lookup = output::scan::host::ReverseDns {
            names: vec!["a.example.".to_owned()],
            names_truncated: true,
            ..output::scan::host::ReverseDns::ended(
                "10.2.0.192.in-addr.arpa".to_owned(),
                crate::output::dns::QuestionStatus::Completed,
                None,
            )
        };
        assert_eq!(
            reverse_dns_text(&lookup),
            "reverse-dns=10.2.0.192.in-addr.arpa status=completed outcome=none \
             names=a.example. names_truncated=true",
        );
    }

    #[test]
    fn unscoped_text_endpoints_keep_plain_addresses() {
        for address in ["192.0.2.1", "2001:db8::1"] {
            for endpoint_name in ["tcp/443", "tcp-connect/443"] {
                assert_eq!(
                    endpoint_text(
                        address.parse().unwrap(),
                        None,
                        endpoint_name,
                        Classification::Closed,
                    ),
                    format!("{address} {endpoint_name} classification=closed"),
                );
            }
        }
    }
}
