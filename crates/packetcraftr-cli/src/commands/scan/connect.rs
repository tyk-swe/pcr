// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::super::execution;
use crate::{
    errors::CliError,
    rendering::{StreamEncoder, write_stdout_line},
};
use packetcraftr_cli::output::{self, contract::ToolFormat};

pub(super) fn run(
    request: &packetcraftr::scan::Request,
    policy: crate::command_options::HostnamePolicyArgs,
    format: ToolFormat,
    stream: &StreamEncoder,
) -> Result<(), CliError> {
    let mut providers = execution::prepare_connect(policy)?;
    let mut session = providers.connect_session();
    execution::run_workflow(
        &mut session,
        format,
        stream,
        crate::cancellation::signal(),
        execution::Hooks {
            command: output::contract::Command::Scan,
            conversion: output::scan_connect::Conversion,
            run: Box::new(|session| {
                packetcraftr::scan::connect::run(
                    request,
                    &mut session.authorizer,
                    session.provider.clone(),
                    &mut session.clock,
                )
                .map_err(CliError::classified)
            }),
            run_with_events: Box::new(|session, emit| {
                packetcraftr::scan::connect::run_with_events(
                    request,
                    &mut session.authorizer,
                    session.provider.clone(),
                    &mut session.clock,
                    session.runtime,
                    emit,
                )
                .map_err(CliError::classified)
            }),
            render_text: Box::new(|converted, _| render_text(&converted.result)),
        },
    )
}

fn render_text(report: &output::scan_connect::Report) -> Result<(), CliError> {
    for endpoint in &report.endpoints {
        write_stdout_line(format_args!(
            "{} tcp-connect/{} classification={}",
            endpoint.address,
            endpoint.port,
            endpoint.classification.as_str()
        ))?;
    }
    write_stdout_line(format_args!(
        "{} socket connections attempted; {} succeeded; elapsed {:?}",
        report.summary.socket_stats.connections_attempted,
        report.summary.socket_stats.connections_succeeded,
        report.summary.socket_stats.elapsed
    ))?;
    let rtt = &report.summary.socket_stats.rtt;
    write_stdout_line(format_args!(
        "probes sent={} received={} lost={} rtt min/avg/max={}/{}/{}",
        rtt.sent,
        rtt.received,
        rtt.lost,
        crate::rendering::optional_debug(rtt.min),
        crate::rendering::optional_debug(rtt.avg),
        crate::rendering::optional_debug(rtt.max),
    ))
}
