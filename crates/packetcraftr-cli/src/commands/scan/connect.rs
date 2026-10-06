// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr::scan::connect;

use crate::output::{self, contract::Format};
use crate::system::{Client, Runtime, client};
use crate::{errors::CliError, rendering::StreamEncoder};

pub(super) fn run(
    request: &packetcraftr::scan::Request,
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
                    .scan_connect(request.clone(), collector.clone())
                    .map_err(CliError::classified)?;
                collector.finish(report).map_err(CliError::classified)
            }),
            run_with_events: Box::new({
                let plan = plan.clone();
                let client = &client;
                move |mut emit| {
                    // Probe events stream as they settle; the tracker keeps
                    // only what each endpoint's inference needs.
                    let tracker = connect::Collector::default();
                    let mut tracked = tracker.clone();
                    let report = client
                        .scan_connect(request.clone(), move |event: connect::Event| {
                            packetcraftr::Sink::publish(&mut tracked, event.clone())?;
                            emit(event)
                        })
                        .map_err(CliError::classified)?;
                    let aggregate = tracker
                        .finish(report.clone())
                        .map_err(CliError::classified)?;
                    Ok(Streamed {
                        report,
                        endpoints: aggregate.endpoints,
                        plan,
                    })
                }
            }),
            on_event: emit_event,
            into_result: Box::new({
                let plan = plan.clone();
                move |mut aggregate| {
                    let diagnostics = std::mem::take(&mut aggregate.report.diagnostics);
                    output::scan::connect::Report::publish(aggregate, plan)
                        .map(|report| output::envelope::Published::new(report, diagnostics))
                        .map_err(CliError::classified)
                }
            }),
            render_text: Box::new(move |mut aggregate, _| {
                let diagnostics = std::mem::take(&mut aggregate.report.diagnostics);
                super::rendering::render_connect_text(
                    &output::scan::connect::Report::publish(aggregate, plan)
                        .map_err(CliError::classified)?,
                )?;
                crate::rendering::render_diagnostics_text(&diagnostics)
            }),
            complete: |streamed, stream| {
                let Streamed {
                    mut report,
                    endpoints,
                    plan,
                } = streamed;
                for endpoint in endpoints {
                    stream.emit_data(
                        output::scan::connect::EndpointEvent::from(endpoint),
                        Vec::new(),
                    )?;
                }
                let diagnostics = std::mem::take(&mut report.diagnostics);
                stream
                    .complete(
                        output::scan::connect::Summary::new(report, plan),
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
}

fn emit_event(event: connect::Event, stream: &StreamEncoder) -> Result<(), CliError> {
    let connect::Event::Probe(probe) = event;
    let event = output::scan::connect::ProbeEvent::try_from(probe).map_err(CliError::classified)?;
    Ok(stream.emit_data(event, Vec::new())?)
}
