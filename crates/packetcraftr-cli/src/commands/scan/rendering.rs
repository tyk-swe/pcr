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
        "planned timeout+pacing {}; achieved {:.2} probes/s over {}",
        duration_text(result.planned_duration),
        if stats.elapsed.is_zero() {
            0.0
        } else {
            stats.packets_completed as f64 / stats.elapsed.as_secs_f64()
        },
        duration_text(stats.elapsed)
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
            write_stdout_line(format_args!(
                "  sequence={} attempt={} status={} classification={} sent={} received={} responder={} latency={} reason={}",
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
            if let Some(application) = &evidence.application {
                write_stdout_line(format_args!(
                    "    profile={} validation={}: {}",
                    application.profile,
                    application.status.as_str(),
                    application.reason
                ))?;
            }
            if let Some(frame) = &evidence.frame {
                write_stdout_line(format_args!("    frame {}", captured_frame_text(frame)))?;
            }
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
    render_hosts_text(&result.plan, &result.hosts)?;
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
        optional_duration(rtt.min),
        optional_duration(rtt.avg),
        optional_duration(rtt.max),
    ))?;
    render_diagnostics_text(&diagnostics)
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
            write_stdout_line(format_args!(
                "  neighbor={} attempts={} link={} next-hop={} next-hop-link={}",
                neighbor.outcome,
                neighbor.attempts,
                link_text(neighbor.link.as_ref()),
                optional_display(neighbor.next_hop.as_ref().map(|hop| hop.address)),
                link_text(neighbor.next_hop.as_ref().and_then(|hop| hop.link.as_ref())),
            ))?;
        }
        for reason in &host.reasons {
            write_stdout_line(format_args!(
                "  reason={} evidence={} basis={} probe={} link={} observed={}",
                reason.kind,
                reason.evidence,
                reason.basis,
                optional_display(reason.probe),
                optional_display(reason.link_address),
                reason.observed_at,
            ))?;
        }
        if let Some(lookup) = &host.reverse_dns {
            write_stdout_line(format_args!(
                "  reverse-dns={} status={} outcome={} names={}{}",
                lookup.query_name,
                lookup.status,
                optional_display(lookup.outcome),
                listed(&lookup.names),
                lookup
                    .error
                    .as_ref()
                    .map_or_else(String::new, |error| format!(" error=\"{error}\"")),
            ))?;
        }
    }
    Ok(())
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

pub(super) fn emit_event(
    event: packetcraftr::scan::Event,
    stream: &StreamEncoder,
) -> Result<(), CliError> {
    let published = output::envelope::Published::<output::scan::Event>::try_from(event)
        .map_err(CliError::classified)?;
    Ok(stream.emit_published(published)?)
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
    } = streamed;
    for endpoint in endpoints {
        stream.emit_published(output::envelope::Published::<output::scan::Event>::from(
            endpoint,
        ))?;
    }
    emit_hosts(std::mem::take(&mut report.hosts), reverse_dns, stream)?;
    Ok(
        stream.complete_published(output::envelope::Published::<output::scan::Event>::from((
            report, plan,
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
    render_hosts_text(&report.summary.plan, &report.hosts)?;
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
    ))
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
    use super::*;
    use output::{network::InterfaceId, scan::Classification};

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
