// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Traceroute CLI command logic.

pub(super) mod arguments;
mod execution;
mod rendering;

use std::sync::Arc;
use std::time::Duration;

use packetcraftr::{live as client, live as workflow, network as net, output, packet};

use self::arguments::TracerouteArgs;
use crate::errors::CliError;
use crate::rendering::emit_aggregate_with_stats;
use crate::system::{
    DeferredInterface, default_registry_arc, parse_workflow_target, system_client,
    workflow_exchange_options,
};

use super::scan::validate_live_interface_selector;
use execution::CliTracerouteExecutor;
use rendering::{render_traceroute_stream, render_traceroute_text};

pub(super) fn run(
    arguments: TracerouteArgs,
    output: output::contract::Format,
) -> Result<(), CliError> {
    let TracerouteArgs {
        target,
        strategy,
        family,
        port,
        first_hop,
        max_hops,
        attempts,
        timeout_ms,
        rate,
        max_probes,
        max_duration_ms,
        max_undecoded,
        interface,
        source,
        link_mode,
        limits,
        policy,
    } = arguments;
    let target = parse_workflow_target(target)?;
    let strategy: workflow::traceroute::Strategy = strategy.into();
    let destination_port = match strategy {
        workflow::traceroute::Strategy::Udp => {
            Some(port.unwrap_or(workflow::traceroute::DEFAULT_TRACEROUTE_UDP_PORT))
        }
        workflow::traceroute::Strategy::Tcp => {
            Some(port.unwrap_or(workflow::traceroute::DEFAULT_TRACEROUTE_TCP_PORT))
        }
        workflow::traceroute::Strategy::Icmp => port,
    };
    let queue_limits = limits.into_limits();
    let trace_limits = workflow::traceroute::Limits {
        max_probes,
        max_duration: Duration::from_millis(max_duration_ms),
        max_evidence_frames: queue_limits.max_frames,
        max_evidence_bytes: queue_limits.max_bytes,
        max_undecoded,
    };
    let request = workflow::traceroute::Request {
        target,
        strategy,
        address_family: family.into(),
        destination_port,
        first_hop,
        max_hops,
        probes_per_hop: attempts,
        timeout: Duration::from_millis(timeout_ms),
        probes_per_second: rate,
        limits: trace_limits,
    };
    request.validate().map_err(traceroute_cli_error)?;
    let policy = policy.into_policy();
    policy.validate().map_err(CliError::classified)?;
    validate_live_interface_selector("traceroute", interface.as_deref())?;
    let max_template_packets = usize::try_from(attempts).map_err(|_| {
        CliError::new(
            2,
            "traceroute attempt count exceeds the platform size limit",
        )
    })?;

    let registry = default_registry_arc()?;
    let exchange = workflow_exchange_options(
        client::send::Options {
            destination: None,
            plan: net::route::Options {
                link_mode: link_mode.into(),
                interface: None,
                preferred_source: source,
            },
            build: packet::build::Options::default(),
            allow_permissive_live: false,
        },
        request.timeout,
        max_template_packets,
        queue_limits,
    )?;

    let mut executor = CliTracerouteExecutor {
        client: system_client(Arc::clone(&registry), policy.clone()),
        exchange,
        interface: DeferredInterface::new(interface),
    };
    let resolver = client::target::SystemResolver;
    let mut authorizer = workflow::traceroute::PolicyAuthorizer::new(&policy, &resolver);
    let mut clock = workflow::clock::SystemClock;
    let result = workflow::traceroute::run(
        &request,
        &mut authorizer,
        &registry,
        &mut executor,
        &mut clock,
    )
    .map_err(traceroute_cli_error)?;
    let (result, diagnostics, stats) =
        output::traceroute::Result::try_from_traceroute(result).map_err(CliError::classified)?;

    match output {
        output::contract::Format::Text => render_traceroute_text(result, diagnostics, stats),
        output::contract::Format::Json => emit_aggregate_with_stats(
            output::contract::Command::Traceroute,
            result,
            diagnostics,
            stats,
        ),
        output::contract::Format::Ndjson => render_traceroute_stream(result, diagnostics, stats),
        _ => Err(CliError::classified(
            output::contract::Error::UnsupportedFormat {
                command: output::contract::Command::Traceroute,
                format: output,
            },
        )),
    }
}

pub(crate) fn traceroute_cli_error(error: workflow::traceroute::Error) -> CliError {
    let sequence = error.sequence();
    CliError::classified_at_optional_sequence(error, sequence)
}
