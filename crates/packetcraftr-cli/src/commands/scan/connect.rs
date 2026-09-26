// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr::scan::connect;

use crate::output::{self, contract::ToolFormat};
use crate::system::{Client, client};
use crate::{errors::CliError, rendering::StreamEncoder};

pub(super) fn run(
    request: &packetcraftr::scan::Request,
    policy: crate::command_options::HostnamePolicyArgs,
    format: ToolFormat,
    stream: &StreamEncoder,
) -> Result<(), CliError> {
    let policy = policy.into_policy();
    policy.validate().map_err(CliError::classified)?;
    let mut client: Client = client(
        packetcraftr_core::protocol::builtin::registry(),
        policy,
        "scan_connect",
    );
    crate::commands::execution::run_workflow(
        &mut client,
        format,
        stream,
        crate::cancellation::signal(),
        crate::commands::execution::Hooks {
            command: output::contract::Command::Scan,
            run: Box::new(|client| {
                let collector = connect::Collector::default();
                let report = client
                    .scan_connect(request.clone(), collector.clone())
                    .map_err(CliError::classified)?;
                collector.finish(report).map_err(CliError::classified)
            }),
            run_with_events: Box::new(|client, emit| {
                client
                    .scan_connect(request.clone(), emit)
                    .map_err(CliError::classified)
            }),
            on_event: emit_event,
            into_result: Box::new(|aggregate| {
                output::scan::connect::Report::try_from(aggregate)
                    .map(|report| output::envelope::Published::new(report, Vec::new()))
                    .map_err(CliError::classified)
            }),
            render_text: Box::new(|aggregate, _| {
                super::rendering::render_connect_text(
                    &output::scan::connect::Report::try_from(aggregate)
                        .map_err(CliError::classified)?,
                )
            }),
            complete: |report, stream| {
                stream
                    .complete(output::scan::connect::Summary::from(report), Vec::new())
                    .map_err(CliError::from)
            },
        },
    )
}

fn emit_event(event: connect::Event, stream: &StreamEncoder) -> Result<(), CliError> {
    let connect::Event::Probe(probe) = event;
    let event = output::scan::connect::ProbeEvent::try_from(probe).map_err(CliError::classified)?;
    Ok(stream.emit_data(event, Vec::new())?)
}
