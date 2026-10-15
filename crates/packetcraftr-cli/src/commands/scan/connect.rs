// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr::scan::{connect, followup};

use crate::output::{self, contract::Format};
use crate::system::{Client, Runtime, client};
use crate::{errors::CliError, rendering::StreamEncoder};

pub(super) fn run(
    invocation: &crate::invocation::Invocation,
    request: followup::ConnectRequest,
    plan: output::scan::plan::Plan,
    policy: crate::command_options::HostnamePolicyArgs,
    format: Format,
    stream: &StreamEncoder,
) -> Result<(), CliError> {
    let policy = policy.into_policy();
    policy.validate().map_err(CliError::classified)?;
    let client: Client = client(
        invocation,
        packetcraftr_core::protocol::builtin::registry(),
        policy,
        Runtime::ScanConnect,
    );
    match format {
        Format::Ndjson => {
            let emit = crate::commands::execution::emitter(invocation, emit_event);
            let summary = {
                let plan = plan.clone();
                let client = &client;
                let request = &request;

                let emit = emit;

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
                Ok::<_, CliError>(Streamed {
                    report: report.scan,
                    endpoints: report.endpoints,
                    plan,
                    reverse_dns: super::reverse_dns_hosts(report.reverse_dns),
                    reverse_dns_stats: lookups,
                })
            }?;
            invocation.check()?;
            {
                let streamed = summary;
                let stream: &StreamEncoder = stream;

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
                super::streaming::emit_hosts(
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
            }
        }
        format => {
            let report = (|| -> Result<_, CliError> {
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
            })()?;
            invocation.check()?;
            if format == Format::Json {
                crate::rendering::emit_published(invocation, output::contract::Command::Scan, {
                    let plan = plan.clone();

                    let (mut aggregate, names, lookups) = report;

                    let diagnostics = std::mem::take(&mut aggregate.report.diagnostics);
                    output::scan::connect::Report::publish(aggregate, plan, names, lookups)
                        .map(|report| output::envelope::Published::new(report, diagnostics))
                        .map_err(CliError::classified)
                }?)
            } else {
                {
                    let (mut aggregate, names, lookups) = report;
                    let _ = format;

                    let diagnostics = std::mem::take(&mut aggregate.report.diagnostics);
                    super::rendering::render_connect_text(
                        invocation,
                        &output::scan::connect::Report::publish(aggregate, plan, names, lookups)
                            .map_err(CliError::classified)?,
                        stream.presentation(),
                    )?;
                    crate::rendering::render_diagnostics_text(invocation, &diagnostics)
                }
            }
        }
    }
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
