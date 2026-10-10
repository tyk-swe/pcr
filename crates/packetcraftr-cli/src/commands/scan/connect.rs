// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr::scan::{connect, followup};

use crate::output::{self, contract::Format};
use crate::system::{Client, Runtime, client};
use crate::{errors::CliError, rendering::StreamEncoder};

pub(super) fn run(
    request: followup::ConnectRequest,
    plan: output::scan::plan::Plan,
    policy: crate::command_options::HostnamePolicyArgs,
    format: Format,
    stream: &StreamEncoder,
) -> Result<(), CliError> {
    let policy = policy.into_policy();
    policy.validate().map_err(CliError::classified)?;
    let client: Client = client(
        packetcraftr_core::protocol::builtin::registry(),
        policy,
        Runtime::ScanConnect,
    );
    crate::commands::execution::run_workflow(
        format,
        stream,
        crate::cancellation::signal(),
        crate::commands::execution::Hooks {
            command: output::contract::Command::Scan,
            run: Box::new(|| {
                let collector = connect::Collector::default();
                let report = client
                    .scan_connect_with_followups(request.clone(), collector.clone())
                    .map_err(super::followup_error)?;
                let mut aggregate = collector
                    .finish(report.scan)
                    .map_err(CliError::classified)?;
                let lookups = report
                    .reverse_dns
                    .as_ref()
                    .and_then(|lookups| lookups.stats.clone());
                let names = super::reverse_dns_hosts(report.reverse_dns);
                // Socket statistics have no packet counters for the
                // lookups' exchanges, which publish their own; their time
                // still counts in elapsed.
                if let Some(lookups) = &lookups {
                    aggregate.report.stats.elapsed = aggregate
                        .report
                        .stats
                        .elapsed
                        .saturating_add(lookups.elapsed);
                }
                Ok((aggregate, names, lookups))
            }),
            run_with_events: Box::new({
                let plan = plan.clone();
                let client = &client;
                let request = &request;
                move |emit| {
                    let mut report = client
                        .scan_connect_with_followups(request.clone(), emit)
                        .map_err(super::followup_error)?;
                    let lookups = report
                        .reverse_dns
                        .as_ref()
                        .and_then(|lookups| lookups.stats.clone());
                    // Socket statistics have no packet counters for the
                    // lookups' exchanges, which publish their own; their time
                    // still counts in elapsed.
                    if let Some(lookups) = &lookups {
                        report.scan.stats.elapsed =
                            report.scan.stats.elapsed.saturating_add(lookups.elapsed);
                    }
                    Ok(Streamed {
                        report: report.scan,
                        endpoints: report.endpoints,
                        plan,
                        reverse_dns: super::reverse_dns_hosts(report.reverse_dns),
                        reverse_dns_stats: lookups,
                    })
                }
            }),
            on_event: emit_event,
            into_result: Box::new({
                let plan = plan.clone();
                move |(mut aggregate, names, lookups)| {
                    let diagnostics = std::mem::take(&mut aggregate.report.diagnostics);
                    output::scan::connect::Report::publish(aggregate, plan, names, lookups)
                        .map(|report| output::envelope::Published::new(report, diagnostics))
                        .map_err(CliError::classified)
                }
            }),
            render: Box::new(move |(mut aggregate, names, lookups), _| {
                let diagnostics = std::mem::take(&mut aggregate.report.diagnostics);
                super::rendering::render_connect_text(
                    &output::scan::connect::Report::publish(aggregate, plan, names, lookups)
                        .map_err(CliError::classified)?,
                )?;
                crate::rendering::render_diagnostics_text(&diagnostics)
            }),
            complete: |streamed, stream| {
                let Streamed {
                    mut report,
                    endpoints,
                    plan,
                    reverse_dns,
                    reverse_dns_stats,
                } = streamed;
                for endpoint in endpoints {
                    stream.emit_data(
                        output::scan::connect::EndpointEvent::from(endpoint),
                        Vec::new(),
                    )?;
                }
                super::rendering::emit_hosts(
                    std::mem::take(&mut report.hosts),
                    reverse_dns,
                    stream,
                )?;
                let diagnostics = std::mem::take(&mut report.diagnostics);
                stream
                    .complete(
                        output::scan::connect::Summary::new(report, plan, reverse_dns_stats),
                        diagnostics,
                    )
                    .map_err(CliError::from)
            },
        },
    )
}

struct Streamed {
    report: connect::Report,
    endpoints: Vec<connect::Endpoint>,
    plan: output::scan::plan::Plan,
    reverse_dns: Vec<Option<output::scan::host::ReverseDns>>,
    reverse_dns_stats: Option<packetcraftr::Stats>,
}

fn emit_event(event: connect::Event, stream: &StreamEncoder) -> Result<(), CliError> {
    let connect::Event::Probe(probe) = event;
    let event = output::scan::connect::ProbeEvent::try_from(probe).map_err(CliError::classified)?;
    Ok(stream.emit_data(event, Vec::new())?)
}
