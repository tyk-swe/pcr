// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

use crate::command_options::{AddressFamily, HostnamePolicyArgs};
use crate::errors::CliError;
use crate::input::manifest::Declaration;
use crate::output::{self, contract::Format};
use crate::rendering::{StreamEncoder, write_stdout_line, write_summary_line};
use crate::system::{Runtime, client};
use packetcraftr::probe::Transport;
use packetcraftr::scan::method;
use packetcraftr::target::{Selection, plan};
use packetcraftr_core::diagnostic::Diagnostic;
use packetcraftr_core::error::Kind;

use super::selection::select_endpoints;

/// The endpoint selection `--list` would publish, from the scan arguments it
/// reviews.
pub(super) struct Listing {
    pub requested: method::Requested,
    pub transports: Vec<Transport>,
    pub tcp_scan: packetcraftr::scan::TcpScan,
    pub sctp_scan: packetcraftr::scan::SctpScan,
    pub ports: Vec<super::arguments::PortTerm>,
    pub exclude_ports: Vec<super::arguments::PortTerm>,
    pub ip_protocols: Vec<super::arguments::IpProtocolTerm>,
    pub exclude_ip_protocols: Vec<super::arguments::IpProtocolTerm>,
    pub max_ports: usize,
}

impl Listing {
    pub(super) fn plan(
        self,
    ) -> Result<
        (
            Option<output::scan::plan::Ports>,
            Option<output::scan::plan::IpProtocols>,
        ),
        CliError,
    > {
        let Self {
            requested,
            transports,
            tcp_scan,
            sctp_scan,
            ports,
            exclude_ports,
            ip_protocols,
            exclude_ip_protocols,
            max_ports,
        } = self;
        // Listing needs no ports, but publishes the selection when given one
        // so the reviewed scope is exactly what a scan would probe.
        let diagnostic = !tcp_scan.is_syn();
        if diagnostic && requested == method::Requested::Connect {
            return Err(CliError::new(
                Kind::Usage,
                "--tcp-scan other than syn needs the raw method; drop --connect and --method tcp-connect",
            ));
        }
        let sctp_diagnostic = !sctp_scan.is_init();
        if sctp_diagnostic && requested == method::Requested::Connect {
            return Err(CliError::new(
                Kind::Usage,
                "--sctp-scan other than init needs the raw method; drop --connect and --method tcp-connect",
            ));
        }
        if transports == [Transport::Ip] && requested == method::Requested::Connect {
            return Err(CliError::new(
                Kind::Usage,
                "--transport ip needs the raw method; drop --connect and --method tcp-connect",
            ));
        }
        let (ports, ip_protocols) = if transports == [Transport::Ip] {
            if !ports.is_empty() || !exclude_ports.is_empty() {
                return Err(CliError::new(
                    Kind::Usage,
                    "--ports and --exclude-ports do not apply to portless IP-protocol scans; use --ip-protocols",
                ));
            }
            let ip_protocols = if ip_protocols.is_empty() && exclude_ip_protocols.is_empty() {
                None
            } else {
                let selected = select_endpoints(
                    &transports,
                    ports,
                    exclude_ports,
                    ip_protocols,
                    exclude_ip_protocols,
                    max_ports,
                )?;
                Some(output::scan::plan::IpProtocols::from(&selected))
            };
            (None, ip_protocols)
        } else {
            if !ip_protocols.is_empty() || !exclude_ip_protocols.is_empty() {
                return Err(CliError::new(
                    Kind::Usage,
                    "--ip-protocols and --exclude-ip-protocols require --transport ip",
                ));
            }
            let ports = if ports.is_empty() && exclude_ports.is_empty() {
                None
            } else {
                let selected = select_endpoints(
                    &transports,
                    ports,
                    exclude_ports,
                    ip_protocols,
                    exclude_ip_protocols,
                    max_ports,
                )?;
                let ports = output::scan::plan::Ports::from(&selected);
                Some(if requested == method::Requested::Connect {
                    ports
                } else {
                    ports.with_tcp_scan(tcp_scan).with_sctp_scan(sctp_scan)
                })
            };
            (ports, None)
        };
        if diagnostic && ports.as_ref().is_none_or(|ports| ports.tcp_scan.is_none()) {
            return Err(CliError::new(
                Kind::Usage,
                "--tcp-scan other than syn requires at least one TCP port endpoint",
            ));
        }
        if sctp_diagnostic && ports.as_ref().is_none_or(|ports| ports.sctp_scan.is_none()) {
            return Err(CliError::new(
                Kind::Usage,
                "--sctp-scan other than init requires at least one SCTP port endpoint",
            ));
        }
        Ok((ports, ip_protocols))
    }
}

pub(super) struct Options {
    pub origins: Vec<Declaration>,
    pub ports: Option<output::scan::plan::Ports>,
    pub ip_protocols: Option<output::scan::plan::IpProtocols>,
    pub family: AddressFamily,
    pub max_targets: usize,
    pub max_duration: Duration,
    pub policy: HostnamePolicyArgs,
}

pub(super) fn run(
    invocation: &crate::invocation::Invocation,
    selection: Selection,
    options: Options,
    format: Format,
    stream: &StreamEncoder,
) -> Result<(), CliError> {
    let Options {
        origins,
        ports,
        ip_protocols,
        family,
        max_targets,
        max_duration,
        policy,
    } = options;
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
            let published = output::scan::list::Report::new(report, &origins, ports, ip_protocols);
            crate::rendering::emit_aggregate(
                invocation,
                output::contract::Command::Scan,
                published,
                diagnostics,
            )
        }
        Format::Ndjson => {
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
