// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Traceroute CLI command logic.

use packetcraftr_cli::output::contract::Format;

use packetcraftr_core::error::Kind;

pub(super) mod arguments;
mod rendering;

use std::time::Duration;

use packetcraftr_netio as net;

use packetcraftr_cli::output;

use self::arguments::Args;
use super::execution;
use crate::errors::CliError;
use crate::input::parse_target;
use crate::rendering::StreamEncoder;

pub(super) fn run(arguments: Args, format: Format, stream: &StreamEncoder) -> Result<(), CliError> {
    let queue_limits = arguments.limits.clone().into_limits();
    let request = prepare_request(&arguments, queue_limits)?;
    let max_template_packets = usize::try_from(arguments.attempts).map_err(|_| {
        CliError::new(
            Kind::Cli,
            "traceroute attempt count exceeds the platform size limit",
        )
    })?;
    let mut providers = execution::prepare(
        arguments.route,
        arguments.policy,
        request.timeout,
        max_template_packets,
        queue_limits,
    )?;
    let resolver = packetcraftr::target::SystemResolver;
    let mut authorizer = packetcraftr::policy::PolicyAuthorizer::new(&providers.policy, &resolver);
    let mut clock = packetcraftr::clock::SystemClock;
    if format == Format::Ndjson {
        let events = stream.clone();
        let summary = packetcraftr::traceroute::run_with_events(
            &request,
            &mut authorizer,
            &providers.registry,
            &mut providers.executor,
            &mut clock,
            &providers.runtime,
            move |event| {
                rendering::emit_event(event, &events).map_err(CliError::into_boundary_error)
            },
        )
        .map_err(CliError::classified)?;
        rendering::emit_complete(summary, stream)
    } else {
        let report = packetcraftr::traceroute::run(
            &request,
            &mut authorizer,
            &providers.registry,
            &mut providers.executor,
            &mut clock,
        )
        .map_err(CliError::classified)?;
        let (result, diagnostics, stats) = output::traceroute::Report::try_from_traceroute(report)
            .map_err(CliError::classified)?;
        if format == Format::Text {
            rendering::render_text(result, diagnostics, stats)
        } else {
            crate::rendering::emit_aggregate_with_stats(
                output::contract::Command::Traceroute,
                result,
                diagnostics,
                stats,
            )
        }
    }
}

fn prepare_request(
    arguments: &Args,
    queue_limits: net::capture::Limits,
) -> Result<packetcraftr::traceroute::Request, CliError> {
    let strategy: packetcraftr::traceroute::Strategy = arguments.strategy.into();
    let destination_port = match strategy {
        packetcraftr::traceroute::Strategy::Udp => Some(
            arguments
                .port
                .unwrap_or(packetcraftr::traceroute::DEFAULT_UDP_PORT),
        ),
        packetcraftr::traceroute::Strategy::Tcp => Some(
            arguments
                .port
                .unwrap_or(packetcraftr::traceroute::DEFAULT_TCP_PORT),
        ),
        packetcraftr::traceroute::Strategy::Icmp => arguments.port,
    };
    let trace_limits = packetcraftr::traceroute::Limits {
        max_probes: arguments.max_probes,
        max_duration: Duration::from_millis(arguments.max_duration_ms),
        max_evidence_frames: queue_limits.max_frames,
        max_evidence_bytes: queue_limits.max_bytes,
        max_undecoded: arguments.max_undecoded,
    };
    let request = packetcraftr::traceroute::Request {
        target: parse_target(arguments.target.clone())?,
        strategy,
        address_family: arguments.family.into(),
        destination_port,
        source_port: arguments.source_port,
        first_hop: arguments.first_hop,
        max_hops: arguments.max_hops,
        probes_per_hop: arguments.attempts,
        timeout: Duration::from_millis(arguments.timeout_ms),
        probes_per_second: arguments.rate,
        limits: trace_limits,
    };
    request.validate().map_err(CliError::classified)?;
    Ok(request)
}
