// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::output::envelope::Published;
use std::time::Duration;

use crate::command_options::{AddressFamily, HostnamePolicyArgs};
use crate::errors::CliError;
use crate::input::manifest::Declaration;
use crate::output::{self, contract::Format};
use crate::system::{Runtime, client};
use crate::terminal::{write_stdout_line, write_summary_line};
use packetcraftr::target::{Selection, plan};
use packetcraftr_core::diagnostic::{Diagnostic, Severity};

/// A validated `--list` request; execution only resolves targets and renders
/// the endpoint plan preparation already selected.
pub(super) struct Request {
    pub(super) selection: Selection,
    pub(super) origins: Vec<Declaration>,
    pub(super) ports: Option<super::output::plan::Ports>,
    pub(super) ip_protocols: Option<super::output::plan::IpProtocols>,
    pub(super) family: AddressFamily,
    pub(super) max_targets: usize,
    pub(super) max_duration: Duration,
    pub(super) shuffle_seed: Option<u64>,
    pub(super) policy: HostnamePolicyArgs,
    pub(super) plan: Option<crate::system::PlanSummary>,
    pub(super) preview: Option<PreviewInputs>,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct PreviewInputs {
    pub(super) attempts: u32,
    pub(super) rate: Option<u32>,
    pub(super) timeout: Duration,
    pub(super) portless_endpoints: usize,
}

pub(super) fn preview_lines(
    targets: usize,
    endpoints_per_target: usize,
    inputs: PreviewInputs,
) -> Vec<String> {
    let thresholds = packetcraftr_core::security::capture::BeaconOptions::default();
    let probes = (targets as u64)
        .saturating_mul(endpoints_per_target as u64)
        .saturating_mul(u64::from(inputs.attempts));
    let beacons = if (inputs.attempts as usize) < thresholds.min_attempts {
        "below_attempt_threshold"
    } else if inputs.timeout.as_secs_f64() < thresholds.min_interval_seconds {
        "below_interval_threshold"
    } else {
        "possible_if_unanswered"
    };
    vec![
        format!(
            "preview targets={targets} endpoints_per_target={endpoints_per_target} probes_max={probes} attempts_per_endpoint={} timeout_ms={} rate={}",
            inputs.attempts,
            inputs.timeout.as_millis(),
            inputs
                .rate
                .map_or_else(|| "unbounded".to_owned(), |value| value.to_string()),
        ),
        format!(
            "preview beacons={beacons} thresholds: attempts>={} interval>={}s cv<={} (projection; responses and retransmissions are not simulated)",
            thresholds.min_attempts, thresholds.min_interval_seconds, thresholds.max_cv,
        ),
        format!(
            "preview fanout distinct_destination_endpoints_max={} (no built-in detector covers destination fan-out)",
            (targets as u64).saturating_mul(endpoints_per_target as u64),
        ),
    ]
}

pub(super) fn run(
    invocation: &crate::invocation::Invocation,
    request: Request,
) -> Result<(), CliError> {
    let format = invocation.format;
    let stream = &invocation.output;
    let Request {
        selection,
        origins,
        ports,
        ip_protocols,
        family,
        max_targets,
        max_duration,
        shuffle_seed,
        policy,
        plan,
        preview,
    } = request;
    if preview.is_some() && format != Format::Text {
        return Err(CliError::new(
            packetcraftr_core::error::Kind::Usage,
            format!("--preview prints text only, not --output {format}"),
        ));
    }
    let policy = policy.into_policy();
    policy.validate().map_err(CliError::classified)?;
    let client = client(
        invocation,
        packetcraftr_core::protocol::builtin::registry(),
        policy,
        Runtime::Workflow,
    );
    let request = plan::Request {
        selection,
        family: family.into(),
        max_targets,
        max_duration,
    };
    let report = client.plan_targets(request).map_err(CliError::classified)?;
    let diagnostics = duplicate_diagnostics(&report.duplicates, &origins);
    match format {
        Format::Text => {
            render_text(
                invocation,
                &report,
                &origins,
                ports.as_ref(),
                ip_protocols.as_ref(),
                RenderExtras {
                    shuffle_seed,
                    plan: plan.as_ref(),
                    preview,
                },
            )?;
            crate::terminal::render_diagnostics_text(invocation, &diagnostics)
        }
        Format::Json => {
            let origins = published_origins(&origins);
            let published = super::output::list::Report::new(
                report,
                &origins,
                ports,
                ip_protocols,
                shuffle_seed,
            );
            crate::publication::emit_published(
                invocation,
                output::contract::Command::Scan,
                Published::new(published, diagnostics),
            )
        }
        Format::Ndjson => {
            let origins = published_origins(&origins);
            let published = super::output::list::Report::new(
                report,
                &origins,
                ports,
                ip_protocols,
                shuffle_seed,
            );
            for target in &published.targets {
                stream.emit_published(Published::new(
                    super::output::list::TargetEvent::from(target),
                    Vec::new(),
                ))?;
            }
            stream
                .complete_published(Published::new(
                    super::output::list::Complete::from(published),
                    diagnostics,
                ))
                .map_err(CliError::from)
        }
        other => other.unreachable(),
    }
}

/// Each declaration's published origin, at its declaration index.
fn published_origins(declarations: &[Declaration]) -> Vec<super::output::list::Origin> {
    declarations
        .iter()
        .zip(0_u32..)
        .map(|(declaration, index)| super::output::list::Origin {
            index,
            source: declaration.source.to_string(),
            line: declaration.line,
        })
        .collect()
}

/// The same warning a live scan raises for a coalesced declaration, naming where it was declared.
fn duplicate_diagnostics(duplicates: &[u32], origins: &[Declaration]) -> Vec<Diagnostic> {
    duplicates
        .iter()
        .filter_map(|index| {
            let declaration = origins.get(*index as usize)?;
            Some(Diagnostic::new(Severity::Warning,
                "scan.duplicate_declaration",
                format!(
                    "target declaration {} ({declaration}) duplicates an earlier declaration and was coalesced",
                    index + 1
                )))
        })
        .collect()
}

struct RenderExtras<'a> {
    shuffle_seed: Option<u64>,
    plan: Option<&'a crate::system::PlanSummary>,
    preview: Option<PreviewInputs>,
}

fn render_text(
    invocation: &crate::invocation::Invocation,
    report: &plan::Report,
    origins: &[Declaration],
    ports: Option<&super::output::plan::Ports>,
    ip_protocols: Option<&super::output::plan::IpProtocols>,
    extras: RenderExtras<'_>,
) -> Result<(), CliError> {
    let RenderExtras {
        shuffle_seed,
        plan: plan_summary,
        preview,
    } = extras;
    write_stdout_line(
        invocation,
        format_args!(
            "target={} resolution_performed={}",
            report.declared, report.resolution_performed
        ),
    )?;
    if report.resolution_performed {
        write_stdout_line(
            invocation,
            format_args!(
                "warning: hostname resolution ran during planning and may have used network I/O"
            ),
        )?;
    }
    for target in &report.targets {
        let scope = target
            .selected
            .scope
            .as_ref()
            .map(|scope| {
                format!(
                    "%{} (interface {} index {})",
                    scope.zone.as_str(),
                    scope.interface.name,
                    scope.interface.index
                )
            })
            .unwrap_or_default();
        let sources = target
            .declarations
            .iter()
            .filter_map(|index| origins.get(*index as usize))
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        write_stdout_line(
            invocation,
            format_args!(
                "{}{} declarations: {}",
                target.selected.address, scope, sources
            ),
        )?;
    }
    if let Some(seed) = shuffle_seed {
        write_stdout_line(invocation, format_args!("shuffle_seed={seed}"))?;
    }
    if let Some(plan) = plan_summary {
        write_stdout_line(
            invocation,
            format_args!(
                "plan_digest={} planned_probes_max={} policy_digest={}",
                plan.digest, plan.packets, plan.policy_digest
            ),
        )?;
    }
    if let Some(inputs) = preview {
        let endpoints_per_target = ports
            .map(|ports| ports.endpoints.len())
            .or_else(|| ip_protocols.map(|protocols| protocols.protocols.len()))
            .unwrap_or(inputs.portless_endpoints);
        for line in preview_lines(report.targets.len(), endpoints_per_target, inputs) {
            write_stdout_line(invocation, format_args!("{line}"))?;
        }
    }
    if let Some(ports) = ports {
        if let Some(tcp_scan) = ports.tcp_scan {
            write_stdout_line(
                invocation,
                format_args!("{}", super::rendering::tcp_scan_text(tcp_scan)),
            )?;
        }
        if let Some(sctp_scan) = ports.sctp_scan {
            write_stdout_line(
                invocation,
                format_args!("{}", super::rendering::sctp_scan_text(sctp_scan)),
            )?;
        }
        for endpoint in &ports.endpoints {
            write_stdout_line(
                invocation,
                format_args!(
                    "port {}/{} port-hint={}",
                    endpoint.transport,
                    endpoint.port,
                    endpoint.port_hint.unwrap_or("-")
                ),
            )?;
        }
        write_summary_line(
            invocation,
            format_args!(
                "planned {} port endpoint(s) per target, {} excluded, port-catalog={}/{}",
                ports.endpoints.len(),
                ports.excluded_endpoints,
                ports.port_catalog.name,
                ports.port_catalog.version
            ),
        )?;
    }
    if let Some(ip_protocols) = ip_protocols {
        for protocol in &ip_protocols.protocols {
            write_stdout_line(invocation, format_args!("ip-protocol ip/{protocol}"))?;
        }
        write_summary_line(
            invocation,
            format_args!(
                "planned {} IP protocol endpoint(s) per target, {} excluded",
                ip_protocols.protocols.len(),
                ip_protocols.excluded_protocols,
            ),
        )?;
    }
    write_summary_line(
        invocation,
        format_args!(
            "planned {} target(s), {} duplicate declaration(s)",
            report.targets.len(),
            report.duplicates.len()
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inputs(attempts: u32, timeout_ms: u64) -> PreviewInputs {
        PreviewInputs {
            attempts,
            rate: Some(100),
            timeout: Duration::from_millis(timeout_ms),
            portless_endpoints: 0,
        }
    }

    #[test]
    fn preview_projects_against_detector_threshold_boundaries() {
        let thresholds = packetcraftr_core::security::capture::BeaconOptions::default();
        let below_attempts = preview_lines(2, 3, inputs(thresholds.min_attempts as u32 - 1, 5_000));
        assert!(
            below_attempts[1].contains("beacons=below_attempt_threshold"),
            "{below_attempts:?}"
        );
        assert!(
            below_attempts[0].contains("probes_max=30"),
            "{below_attempts:?}"
        );

        let below_interval = preview_lines(2, 3, inputs(thresholds.min_attempts as u32, 999));
        assert!(
            below_interval[1].contains("beacons=below_interval_threshold"),
            "{below_interval:?}"
        );

        let possible = preview_lines(2, 3, inputs(thresholds.min_attempts as u32, 1_000));
        assert!(
            possible[1].contains("beacons=possible_if_unanswered"),
            "{possible:?}"
        );
        assert!(
            possible[2].contains("distinct_destination_endpoints_max=6"),
            "{possible:?}"
        );
    }
}
