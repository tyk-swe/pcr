// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

use crate::command_options::{AddressFamily, HostnamePolicyArgs};
use crate::errors::CliError;
use crate::input::manifest::Declaration;
use crate::output::{self, contract::Format};
use crate::rendering::{StreamEncoder, write_stdout_line, write_summary_line};
use crate::system::{Runtime, client};
use packetcraftr::target::{Selection, plan};

pub(super) struct Options {
    pub origins: Vec<Declaration>,
    pub family: AddressFamily,
    pub max_targets: usize,
    pub max_duration: Duration,
    pub policy: HostnamePolicyArgs,
}

pub(super) fn run(
    selection: Selection,
    options: Options,
    format: Format,
    stream: &StreamEncoder,
) -> Result<(), CliError> {
    let Options {
        origins,
        family,
        max_targets,
        max_duration,
        policy,
    } = options;
    let policy = policy.into_policy();
    policy.validate().map_err(CliError::classified)?;
    let client = client(
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
    match format {
        Format::Text => {
            let report = client.plan_targets(request).map_err(CliError::classified)?;
            render_text(&report, &origins)
        }
        Format::Json => {
            let report = client.plan_targets(request).map_err(CliError::classified)?;
            let published = output::scan::list::Report::new(report, &origins);
            crate::rendering::emit_aggregate(output::contract::Command::Scan, published, Vec::new())
        }
        Format::Ndjson => {
            let report = client.plan_targets(request).map_err(CliError::classified)?;
            let published = output::scan::list::Report::new(report, &origins);
            for target in &published.targets {
                stream.emit_data(output::scan::list::TargetEvent::from(target), Vec::new())?;
            }
            stream
                .complete(output::scan::list::Complete::from(published), Vec::new())
                .map_err(CliError::from)
        }
        other => other.unreachable(),
    }
}

fn render_text(report: &plan::Report, origins: &[Declaration]) -> Result<(), CliError> {
    write_stdout_line(format_args!(
        "target={} resolution_performed={}",
        report.declared, report.resolution_performed
    ))?;
    if report.resolution_performed {
        write_stdout_line(format_args!(
            "warning: hostname resolution ran during planning and may have used network I/O"
        ))?;
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
            .map(|declaration| {
                let (text, _) = declaration.source.describe();
                match declaration.line {
                    Some(line) => format!("{text}:{line}"),
                    None => text,
                }
            })
            .collect::<Vec<_>>()
            .join(", ");
        write_stdout_line(format_args!(
            "{}{} declarations: {}",
            target.selected.address, scope, sources
        ))?;
    }
    write_summary_line(format_args!(
        "planned {} target(s), {} duplicate declaration(s)",
        report.targets.len(),
        report.duplicates.len()
    ))
}
