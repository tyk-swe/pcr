// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Traceroute CLI command logic.

pub(super) mod arguments;
mod execution;
mod rendering;

use std::sync::Arc;
use std::time::Duration;

use packetcraftr::{core, netio as net, output};

use self::arguments::TracerouteArgs;
use crate::errors::CliError;
use crate::rendering::emit_aggregate_with_stats;
use crate::system::{
    DeferredInterface, default_registry_arc, parse_workflow_target, system_client,
    validate_live_interface_selector, workflow_exchange_options,
};

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
        route,
        limits,
        policy,
    } = arguments;
    let target = parse_workflow_target(target)?;
    let strategy: packetcraftr::traceroute::Strategy = strategy.into();
    let destination_port = match strategy {
        packetcraftr::traceroute::Strategy::Udp => {
            Some(port.unwrap_or(packetcraftr::traceroute::DEFAULT_TRACEROUTE_UDP_PORT))
        }
        packetcraftr::traceroute::Strategy::Tcp => {
            Some(port.unwrap_or(packetcraftr::traceroute::DEFAULT_TRACEROUTE_TCP_PORT))
        }
        packetcraftr::traceroute::Strategy::Icmp => port,
    };
    let queue_limits = limits.into_limits();
    let trace_limits = packetcraftr::traceroute::Limits {
        max_probes,
        max_duration: Duration::from_millis(max_duration_ms),
        max_evidence_frames: queue_limits.max_frames,
        max_evidence_bytes: queue_limits.max_bytes,
        max_undecoded,
    };
    let request = packetcraftr::traceroute::Request {
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
    validate_live_interface_selector("traceroute", route.interface.as_deref())?;
    let max_template_packets = usize::try_from(attempts).map_err(|_| {
        CliError::new(
            2,
            "traceroute attempt count exceeds the platform size limit",
        )
    })?;

    let registry = default_registry_arc()?;
    let exchange = workflow_exchange_options(
        packetcraftr::send::Options {
            destination: None,
            plan: net::route::Options {
                link_mode: route.link_mode.into(),
                interface: None,
                preferred_source: route.source,
            },
            build: core::build::BuildOptions::default(),
            allow_permissive_live: false,
        },
        request.timeout,
        max_template_packets,
        queue_limits,
    )?;

    let mut executor = CliTracerouteExecutor {
        client: system_client(Arc::clone(&registry), policy.clone()),
        exchange,
        interface: DeferredInterface::new(route.interface),
    };
    let resolver = packetcraftr::target::SystemResolver;
    let mut authorizer = packetcraftr::target::PolicyAuthorizer::new(&policy, &resolver);
    let mut clock = packetcraftr::clock::SystemClock;
    let result = packetcraftr::traceroute::run(
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
        _ => unreachable!("traceroute format is checked before command dispatch"),
    }
}

pub(crate) fn traceroute_cli_error(error: packetcraftr::traceroute::Error) -> CliError {
    let sequence = error.sequence();
    CliError::classified_at_optional_sequence(error, sequence)
}
