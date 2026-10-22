// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

use crate::command_options::{AddressFamily, HostnamePolicyArgs};
use crate::errors::CliError;
use crate::input::manifest::Declaration;
use crate::invocation::StreamEncoder;
use crate::output::{self, contract::Format};
use crate::rendering::{write_stdout_line, write_summary_line};
use crate::system::{Runtime, client};
use packetcraftr::target::{Selection, plan};
use packetcraftr_core::diagnostic::Diagnostic;

/// A validated `--list` request; execution only resolves targets and renders
/// the endpoint plan preparation already selected.
pub(super) struct Request {
    pub(super) selection: Selection,
    pub(super) origins: Vec<Declaration>,
    pub(super) ports: Option<output::scan::plan::Ports>,
    pub(super) ip_protocols: Option<output::scan::plan::IpProtocols>,
    pub(super) family: AddressFamily,
    pub(super) max_targets: usize,
    pub(super) max_duration: Duration,
    pub(super) policy: HostnamePolicyArgs,
}

pub(super) fn run(
    invocation: &crate::invocation::Invocation,
    request: Request,
    format: Format,
    stream: &StreamEncoder,
) -> Result<(), CliError> {
    let Request {
        selection,
        origins,
        ports,
        ip_protocols,
        family,
        max_targets,
        max_duration,
        policy,
    } = request;
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
            )?;
            crate::rendering::render_diagnostics_text(invocation, &diagnostics)
        }
        Format::Json => {
            let origins = published_origins(&origins);
            let published = output::scan::list::Report::new(report, &origins, ports, ip_protocols);
            crate::rendering::emit_aggregate(
                invocation,
                output::contract::Command::Scan,
                published,
                diagnostics,
            )
        }
        Format::Ndjson => {
            let origins = published_origins(&origins);
            let published = output::scan::list::Report::new(report, &origins, ports, ip_protocols);
            for target in &published.targets {
                stream.emit_data(output::scan::list::TargetEvent::from(target), Vec::new())?;
            }
            stream
                .complete(output::scan::list::Complete::from(published), diagnostics)
                .map_err(CliError::from)
        }
        other => other.unreachable(),
    }
}

/// Each declaration's published origin, at its declaration index.
fn published_origins(declarations: &[Declaration]) -> Vec<output::scan::list::Origin> {
    declarations
        .iter()
        .zip(0_u32..)
        .map(|(declaration, index)| output::scan::list::Origin {
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
            Some(Diagnostic::warning(
                "scan.duplicate_declaration",
                format!(
                    "target declaration {} ({declaration}) duplicates an earlier declaration and was coalesced",
                    index + 1
                ),
            ))
        })
        .collect()
}

fn render_text(
    invocation: &crate::invocation::Invocation,
    report: &plan::Report,
    origins: &[Declaration],
    ports: Option<&output::scan::plan::Ports>,
    ip_protocols: Option<&output::scan::plan::IpProtocols>,
) -> Result<(), CliError> {
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
