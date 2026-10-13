// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod hosts;
mod traceroute;

use hosts::render_hosts_text;
use traceroute::render_traceroute_text;

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
    if let Some(tcp_scan) = plan.tcp_scan {
        write_stdout_line(format_args!("{}", tcp_scan_text(tcp_scan)))?;
    }
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

/// The effective TCP segment, with the heuristic caveat for non-SYN modes.
pub(super) fn tcp_scan_text(tcp_scan: output::scan::plan::TcpScan) -> String {
    let line = format!("tcp-scan={} flags={:#05x}", tcp_scan.mode, tcp_scan.flags);
    match tcp_scan.mode {
        "syn" => line,
        "custom" => {
            format!("{line} (observation-only: replies are reported, no port state is inferred)")
        }
        _ => format!(
            "{line} (stack-dependent heuristic: conclusions are inferences, never authenticated identity or proof of a listening service)"
        ),
    }
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
    if let Some(tcp_scan) = evidence.tcp_scan.filter(|scan| scan.mode != "syn") {
        write_stdout_line(format_args!(
            "{nested}tcp-scan={} flags={:#05x} tcp-window={}",
            tcp_scan.mode,
            tcp_scan.flags,
            optional_display(evidence.tcp_window),
        ))?;
    }
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
