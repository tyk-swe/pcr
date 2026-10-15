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
    invocation: &crate::invocation::Invocation,
    published: output::envelope::Published<output::scan::Report>,
    presentation: crate::rendering::Presentation,
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
            "target={} resolved={}",
            result.target,
            comma_separated(&result.resolved_addresses)
        ),
    )?;
    write_stdout_line(
        invocation,
        format_args!("{}", throughput_text(result.planned_duration, &stats)),
    )?;
    render_plan_text(invocation, &result.plan)?;
    for endpoint in &result.endpoints {
        let endpoint_name = match endpoint.transport {
            packetcraftr::probe::Transport::Icmp => endpoint.transport.to_string(),
            packetcraftr::probe::Transport::Ip => {
                format!(
                    "{}/{}",
                    endpoint.transport,
                    optional_display(endpoint.ip_protocol)
                )
            }
            packetcraftr::probe::Transport::Tcp
            | packetcraftr::probe::Transport::Udp
            | packetcraftr::probe::Transport::Sctp => {
                format!("{}/{}", endpoint.transport, optional_display(endpoint.port))
            }
        };
        write_stdout_line(
            invocation,
            format_args!(
                "{}",
                endpoint_text(
                    endpoint.address,
                    endpoint.scope.as_ref(),
                    &endpoint_name,
                    endpoint.classification,
                )
            ),
        )?;
        render_inference_text(invocation, endpoint.port_hint, endpoint.inference.as_ref())?;
        for evidence in visible_probes(&endpoint.probes, presentation) {
            render_probe_text(invocation, "  ", evidence, presentation)?;
        }
    }
    render_undecoded(
        invocation,
        result.undecoded.iter().map(|frame| (None, frame)),
    )?;
    for unattributed in &result.unattributed {
        write_stdout_line(
            invocation,
            format_args!(
                "unattributed attribution={} sequence={} frame {}",
                unattributed.attribution,
                optional_display(unattributed.sequence),
                captured_frame_text(&unattributed.frame)
            ),
        )?;
    }
    render_hosts_text(invocation, &result.plan, &result.hosts, |probe| {
        render_probe_text(invocation, "  probe ", probe, presentation)
    })?;
    let rtt = result.rtt;
    write_summary_line(
        invocation,
        format_args!(
            // The totals span discovery, neighbor requests, and enrichment too.
            "scanned {} endpoint(s); the operation completed {} packet(s), {} byte(s)",
            result.endpoints.len(),
            stats.packets_completed,
            stats.bytes
        ),
    )?;
    write_summary_line(
        invocation,
        format_args!(
            "probes sent={} received={} lost={} rtt min/avg/max={}/{}/{}",
            rtt.sent,
            rtt.received,
            rtt.lost,
            optional_duration(rtt.min),
            optional_duration(rtt.avg),
            optional_duration(rtt.max),
        ),
    )?;
    render_scheduling_text(invocation, &result.scheduling)?;
    if let Some(trace) = &result.traceroute {
        render_traceroute_text(invocation, trace, presentation)?;
    }
    render_diagnostics_text(invocation, &diagnostics)
}

fn render_scheduling_text(
    invocation: &crate::invocation::Invocation,
    scheduling: &output::scan::Scheduling,
) -> Result<(), CliError> {
    let ceilings = match (scheduling.operation_ceiling, scheduling.process_ceiling) {
        (Some(operation), Some(process)) => {
            format!(" operation-ceiling={operation} process-ceiling={process}")
        }
        _ => String::new(),
    };
    write_summary_line(
        invocation,
        format_args!(
            "scheduling={} peak-window={} retries={}{}",
            scheduling.mode, scheduling.observed_peak_window, scheduling.retries_started, ceilings,
        ),
    )?;
    for condition in &scheduling.conditions {
        let host = match &condition.host.scope {
            Some(scope) => format!("{}%{}", condition.host.address, scope.zone),
            None => condition.host.address.to_string(),
        };
        write_summary_line(
            invocation,
            format_args!(
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
            ),
        )?;
    }
    for host in &scheduling.incomplete {
        let host = match &host.scope {
            Some(scope) => format!("{}%{}", host.address, scope.zone),
            None => host.address.to_string(),
        };
        write_summary_line(invocation, format_args!("host {host} scan=incomplete"))?;
    }
    Ok(())
}

pub(super) fn render_plan_text(
    invocation: &crate::invocation::Invocation,
    plan: &output::scan::plan::Plan,
) -> Result<(), CliError> {
    let method = &plan.method;
    write_stdout_line(
        invocation,
        format_args!(
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
        ),
    )?;
    if let Some(tcp_scan) = plan.tcp_scan {
        write_stdout_line(invocation, format_args!("{}", tcp_scan_text(tcp_scan)))?;
    }
    if let Some(sctp_scan) = plan.sctp_scan {
        write_stdout_line(invocation, format_args!("{}", sctp_scan_text(sctp_scan)))?;
    }
    let discovery = &plan.discovery;
    write_stdout_line(
        invocation,
        format_args!(
            "discovery={} probes={} neighbor={} unresponsive={} reverse-dns={}",
            discovery.mode,
            listed(
                &discovery
                    .probes
                    .iter()
                    .map(|probe| {
                        if let Some(port) = probe.port {
                            if probe.tcp_scan.is_some_and(|scan| scan.mode == "ack") {
                                format!("tcp-ack/{port}")
                            } else {
                                format!("{}/{port}", probe.transport)
                            }
                        } else if let Some(protocol) = probe.ip_protocol {
                            format!("ip/{protocol}")
                        } else if let Some(kind) = probe.icmp_request {
                            format!("icmp-{kind}")
                        } else {
                            probe.transport.to_string()
                        }
                    })
                    .collect::<Vec<_>>()
            ),
            discovery.neighbor,
            discovery.unresponsive,
            discovery.reverse_dns.as_ref().map_or_else(
                || "-".to_owned(),
                |server| format!("{}:{}", server.server, server.port)
            ),
        ),
    )?;
    if let Some(curated) = &plan.curated_udp_payloads {
        write_stdout_line(
            invocation,
            format_args!(
                "curated-udp-payloads={}/{} applied={} overridden={}",
                curated.data_set.name,
                curated.data_set.version,
                listed(&curated.applied),
                listed(&curated.overridden),
            ),
        )?;
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

/// The effective SCTP chunk, with the heuristic caveat for COOKIE-ECHO.
pub(super) fn sctp_scan_text(sctp_scan: output::scan::plan::SctpScan) -> String {
    let line = format!(
        "sctp-scan={} chunk-type={}",
        sctp_scan.mode, sctp_scan.chunk_type
    );
    match sctp_scan.mode {
        "init" => line,
        _ => format!(
            "{line} (stack-dependent heuristic: conclusions are inferences, never authenticated identity or proof of a listening service)"
        ),
    }
}

fn visible_probes(
    probes: &[output::scan::Probe],
    presentation: crate::rendering::Presentation,
) -> impl Iterator<Item = &output::scan::Probe> {
    probes.iter().filter(move |evidence| {
        presentation.verbose
            || evidence.status == packetcraftr::probe::Status::Timeout
            || evidence.application.as_ref().is_some_and(|application| {
                application.status == output::scan::ApplicationStatus::Rejected
            })
    })
}

/// A raw probe's evidence line after `lead`, with any application and frame
/// lines beneath it.
fn render_probe_text(
    invocation: &crate::invocation::Invocation,
    lead: &str,
    evidence: &output::scan::Probe,
    presentation: crate::rendering::Presentation,
) -> Result<(), CliError> {
    write_stdout_line(
        invocation,
        format_args!(
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
        ),
    )?;
    let nested = " ".repeat(lead.len() + 2);
    if let Some(tcp_scan) = evidence.tcp_scan.filter(|scan| scan.mode != "syn") {
        write_stdout_line(
            invocation,
            format_args!(
                "{nested}tcp-scan={} flags={:#05x} tcp-window={}",
                tcp_scan.mode,
                tcp_scan.flags,
                optional_display(evidence.tcp_window),
            ),
        )?;
    }
    if let Some(sctp_scan) = evidence.sctp_scan.filter(|scan| scan.mode != "init") {
        write_stdout_line(
            invocation,
            format_args!(
                "{nested}sctp-scan={} chunk-type={}",
                sctp_scan.mode, sctp_scan.chunk_type,
            ),
        )?;
    }
    if let Some(application) = &evidence.application {
        write_stdout_line(
            invocation,
            format_args!(
                "{nested}profile={} validation={}: {}",
                application.profile,
                application.status.as_str(),
                application.reason
            ),
        )?;
    }
    if let Some(frame) = &evidence.frame
        && presentation.verbose
    {
        write_stdout_line(
            invocation,
            format_args!("{nested}frame {}", captured_frame_text(frame)),
        )?;
    }
    Ok(())
}

/// A connect discovery probe's evidence line.
fn connect_probe_text(
    invocation: &crate::invocation::Invocation,
    probe: &output::scan::connect::Probe,
) -> Result<(), CliError> {
    write_stdout_line(
        invocation,
        format_args!(
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
        ),
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

/// The inference line beneath an endpoint; the hint is labelled as such so
/// it never reads as an identified service.
pub(super) fn render_inference_text(
    invocation: &crate::invocation::Invocation,
    port_hint: Option<&str>,
    inference: Option<&output::scan::plan::Inference>,
) -> Result<(), CliError> {
    let Some(inference) = inference else {
        return Ok(());
    };
    write_stdout_line(
        invocation,
        format_args!(
            "  inferred={} rule={} supporting={} conflicting={} unanswered={} failed={} port-hint={}",
            inference.state.unwrap_or("undetermined"),
            inference.rule,
            listed(&inference.supporting),
            listed(&inference.conflicting),
            listed(&inference.unanswered),
            listed(&inference.failed),
            port_hint.unwrap_or("-"),
        ),
    )
}

/// A comma-separated list, or `-` when empty so every key keeps a value.
fn listed<T: std::fmt::Display>(values: &[T]) -> String {
    if values.is_empty() {
        "-".to_owned()
    } else {
        comma_separated(values)
    }
}

pub(super) fn render_connect_text(
    invocation: &crate::invocation::Invocation,
    report: &output::scan::connect::Report,
    presentation: crate::rendering::Presentation,
) -> Result<(), CliError> {
    render_plan_text(invocation, &report.summary.plan)?;
    for endpoint in &report.endpoints {
        write_stdout_line(
            invocation,
            format_args!(
                "{}",
                endpoint_text(
                    endpoint.address,
                    endpoint.scope.as_ref(),
                    &format!("tcp-connect/{}", endpoint.port),
                    endpoint.classification,
                )
            ),
        )?;
        render_inference_text(invocation, endpoint.port_hint, Some(&endpoint.inference))?;
    }
    render_hosts_text(invocation, &report.summary.plan, &report.hosts, |probe| {
        if presentation.verbose || probe.error.is_some() {
            connect_probe_text(invocation, probe)
        } else {
            Ok(())
        }
    })?;
    write_stdout_line(
        invocation,
        format_args!(
            "{} socket connections attempted; {} succeeded; elapsed {}",
            report.summary.socket_stats.connections_attempted,
            report.summary.socket_stats.connections_succeeded,
            duration_text(report.summary.socket_stats.elapsed)
        ),
    )?;
    let rtt = &report.summary.socket_stats.rtt;
    write_stdout_line(
        invocation,
        format_args!(
            "probes sent={} received={} lost={} rtt min/avg/max={}/{}/{}",
            rtt.sent,
            rtt.received,
            rtt.lost,
            optional_duration(rtt.min),
            optional_duration(rtt.avg),
            optional_duration(rtt.max),
        ),
    )?;
    render_scheduling_text(invocation, &report.summary.scheduling)
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
    fn compact_output_keeps_rejected_udp_checks_and_timeouts() {
        use output::scan::{ApplicationEvidence, ApplicationStatus, Probe, Protocol, Stage};
        use packetcraftr::probe;

        let probes = [
            (Some(ApplicationStatus::Confirmed), "dns", "DNS ID matched"),
            (Some(ApplicationStatus::Rejected), "dns", "DNS ID mismatch"),
            (Some(ApplicationStatus::Unchecked), "bytes", "no checks"),
            (Some(ApplicationStatus::Rejected), "bytes", "byte mismatch"),
            (None, "", ""),
            (Some(ApplicationStatus::NotObserved), "dns", "no reply"),
        ]
        .into_iter()
        .enumerate()
        .map(|(sequence, (application, profile, reason))| {
            let timeout = application == Some(ApplicationStatus::NotObserved);
            Probe {
                sequence: sequence as u64,
                stage: Stage::Scan,
                protocol: Protocol::Udp,
                destination: "192.0.2.1".parse().unwrap(),
                scope: None,
                destination_port: Some(53),
                ip_protocol: None,
                icmp_request: None,
                tcp_scan: None,
                sctp_scan: None,
                attempt: 1,
                status: if timeout {
                    probe::Status::Timeout
                } else {
                    probe::Status::Response
                },
                classification: if timeout {
                    Classification::Timeout
                } else {
                    Classification::Open
                },
                responder: None,
                sent_at: std::time::UNIX_EPOCH.try_into().unwrap(),
                received_at: None,
                latency: None,
                frame: None,
                reason: "fixture".to_owned(),
                application: application.map(|status| ApplicationEvidence {
                    profile: profile.to_owned(),
                    status,
                    reason: reason.to_owned(),
                }),
                tcp_window: None,
            }
        })
        .collect::<Vec<_>>();

        let sequences = |verbose| {
            visible_probes(&probes, crate::rendering::Presentation { verbose })
                .map(|probe| probe.sequence)
                .collect::<Vec<_>>()
        };
        assert_eq!(sequences(false), [1, 3, 5]);
        assert_eq!(sequences(true), [0, 1, 2, 3, 4, 5]);
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
