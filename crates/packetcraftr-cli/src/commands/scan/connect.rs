// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Instant;

use packetcraftr::scan::connect;

use crate::output::{self, contract::Format};
use crate::system::{Client, Runtime, client};
use crate::{errors::CliError, rendering::StreamEncoder};

pub(super) fn run(
    request: &packetcraftr::scan::Request,
    plan: output::scan::plan::Plan,
    lookup: Option<&super::reverse::Lookup>,
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
                let started = Instant::now();
                let collector = connect::Collector::default();
                let report = client
                    .scan_connect(request.clone(), collector.clone())
                    .map_err(CliError::classified)?;
                let mut aggregate = collector.finish(report).map_err(CliError::classified)?;
                // Socket statistics have no packet counters for the
                // lookups' exchanges, which publish their own; their time
                // still counts in elapsed.
                let (names, lookups) = super::reverse::names(
                    lookup,
                    &client,
                    &aggregate.report.hosts,
                    started,
                    aggregate.report.stats.connections_attempted > 0,
                );
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
                move |mut emit| {
                    let started = Instant::now();
                    // Probe events stream as they settle; the tracker keeps
                    // only what each endpoint's inference needs.
                    let tracker = connect::Collector::default();
                    let mut tracked = tracker.clone();
                    let mut report = client
                        .scan_connect(request.clone(), move |event: connect::Event| {
                            packetcraftr::Sink::publish(&mut tracked, event.clone())?;
                            emit(event)
                        })
                        .map_err(CliError::classified)?;
                    let aggregate = tracker
                        .finish(report.clone())
                        .map_err(CliError::classified)?;
                    // Socket statistics have no packet counters for the
                    // lookups' exchanges, which publish their own; their time
                    // still counts in elapsed.
                    let (reverse_dns, lookups) = super::reverse::names(
                        lookup,
                        client,
                        &report.hosts,
                        started,
                        report.stats.connections_attempted > 0,
                    );
                    if let Some(lookups) = &lookups {
                        report.stats.elapsed = report.stats.elapsed.saturating_add(lookups.elapsed);
                    }
                    Ok(Streamed {
                        report,
                        endpoints: aggregate.endpoints,
                        plan,
                        reverse_dns,
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
            render_text: Box::new(move |(mut aggregate, names, lookups), _| {
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
