// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::{
    errors::CliError,
    rendering::{StreamEncoder, write_stdout_line},
};
use packetcraftr_cli::output::{self, contract::ToolFormat};
use std::sync::Arc;

/// The pieces both connect entry points drive: the policy authorizer, the
/// cancellation-sharing clock, and the TCP provider.
struct Session<'a> {
    authorizer: packetcraftr::policy::PolicyAuthorizer<'a>,
    clock: packetcraftr::clock::CancellableClock,
    provider: Arc<packetcraftr_netio::tcp::SystemProvider>,
}

pub(super) fn run(
    request: &packetcraftr::scan::Request,
    policy: crate::command_options::HostnamePolicyArgs,
    format: ToolFormat,
    stream: &StreamEncoder,
) -> Result<(), CliError> {
    let policy = policy.into_policy();
    policy.validate().map_err(CliError::classified)?;
    let resolver = packetcraftr::target::SystemResolver;
    let mut session = Session {
        authorizer: packetcraftr::policy::PolicyAuthorizer::new(&policy, &resolver),
        clock: packetcraftr::clock::CancellableClock(crate::cancellation::signal().clone()),
        provider: Arc::new(packetcraftr_netio::tcp::SystemProvider),
    };
    crate::commands::execution::run_workflow(
        &mut session,
        format,
        stream,
        crate::cancellation::signal(),
        crate::commands::execution::Hooks {
            command: output::contract::Command::Scan,
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
                let runtime = crate::resources::runtime(
                    "scan_connect",
                    packetcraftr::progress::MAX_WORKER_CAPACITY,
                );
                packetcraftr::scan::connect::run_with_events(
                    request,
                    &mut session.authorizer,
                    session.provider.clone(),
                    &mut session.clock,
                    &runtime,
                    emit,
                )
                .map_err(CliError::classified)
            }),
            on_event: emit_event,
            into_result: Box::new(|report| {
                output::scan_connect::Report::try_from(report)
                    .map(|report| (report, Vec::new(), None))
                    .map_err(CliError::classified)
            }),
            render_text: Box::new(|report, _| {
                render_text(
                    &output::scan_connect::Report::try_from(report)
                        .map_err(CliError::classified)?,
                )
            }),
            complete: |summary, stream| {
                stream
                    .complete(output::scan_connect::Summary::from(summary), Vec::new())
                    .map_err(CliError::from)
            },
        },
    )
}

fn emit_event(
    probe: packetcraftr::scan::connect::Probe,
    stream: &StreamEncoder,
) -> Result<(), CliError> {
    let event = output::scan_connect::ProbeEvent::try_from(probe).map_err(CliError::classified)?;
    Ok(stream.emit_data(event, Vec::new())?)
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
