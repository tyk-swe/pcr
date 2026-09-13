// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::{
    errors::CliError,
    rendering::{StreamEncoder, emit_aggregate, write_stdout_line},
};
use packetcraftr_cli::output::{self, contract::Format};
use std::sync::Arc;

pub(super) fn run(
    request: &packetcraftr::scan::Request,
    policy: crate::command_options::HostnamePolicyArgs,
    format: Format,
    stream: &StreamEncoder,
) -> Result<(), CliError> {
    let policy = policy.into_policy();
    policy.validate().map_err(CliError::classified)?;
    let resolver = packetcraftr::target::SystemResolver;
    let mut authorizer = packetcraftr::policy::PolicyAuthorizer::new(&policy, &resolver);
    let mut clock = packetcraftr::clock::CancellableClock(crate::cancellation::signal().clone());
    let provider = Arc::new(packetcraftr_netio::tcp::SystemProvider);
    if format == Format::Ndjson {
        let events = stream.clone();
        let runtime = crate::resources::runtime(
            "scan_connect",
            packetcraftr::progress::Runtime::default().capacity(),
        );
        let summary = packetcraftr::scan::connect::run_with_events(
            request,
            &mut authorizer,
            provider,
            &mut clock,
            &runtime,
            move |probe| {
                let event = output::scan_connect::ProbeEvent::try_from(probe)
                    .map_err(|source| CliError::classified(source).into_boundary_error())?;
                events
                    .emit_data(event, Vec::new())
                    .map_err(|source| CliError::classified(source).into_boundary_error())
            },
        )
        .map_err(CliError::classified)?;
        stream.complete(output::scan_connect::Summary::from(summary), Vec::new())?;
        Ok(())
    } else {
        let report =
            packetcraftr::scan::connect::run(request, &mut authorizer, provider, &mut clock)
                .map_err(CliError::classified)?;
        let report =
            output::scan_connect::Report::try_from(report).map_err(CliError::classified)?;
        if format == Format::Json {
            emit_aggregate(output::contract::Command::Scan, report, Vec::new())
        } else {
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
            ))
        }
    }
}
