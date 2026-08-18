// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Traceroute CLI command logic.

pub(super) mod arguments;
mod execution;
mod rendering;

use std::sync::Arc;
use std::time::Duration;

use packetcraftr::{core, netio as net, output};

use self::arguments::Args;
use super::registry;
use crate::errors::CliError;
use crate::input::parse_target;
use crate::system::{DeferredInterface, client, exchange, validate_selector};

use execution::Executor;

pub(super) fn run(arguments: Args, format: output::contract::Format) -> Result<(), CliError> {
    let queue_limits = arguments.limits.clone().into_limits();
    let request = prepare_request(&arguments, queue_limits)?;
    let policy = arguments.policy.clone().into_policy();
    policy.validate().map_err(CliError::classified)?;
    validate_selector(arguments.route.interface.as_deref()).map(|_| ())?;
    let max_template_packets = usize::try_from(arguments.attempts).map_err(|_| {
        CliError::new(
            2,
            "traceroute attempt count exceeds the platform size limit",
        )
    })?;
    let registry = registry()?;
    let exchange = prepare_exchange(&arguments, &request, queue_limits, max_template_packets)?;
    let mut executor = Executor {
        client: client(Arc::clone(&registry), policy.clone()),
        exchange,
        interface: DeferredInterface::new(arguments.route.interface),
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
    .map_err(classified_error)?;
    let (result, diagnostics, stats) =
        output::traceroute::Result::try_from_traceroute(result).map_err(CliError::classified)?;

    match format {
        output::contract::Format::Text => rendering::render_text(result, diagnostics, stats),
        output::contract::Format::Json => rendering::render_aggregate(result, diagnostics, stats),
        output::contract::Format::Ndjson => rendering::render_stream(result, diagnostics, stats),
        _ => unreachable!("traceroute format is checked before command dispatch"),
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
                .unwrap_or(packetcraftr::traceroute::DEFAULT_TRACEROUTE_UDP_PORT),
        ),
        packetcraftr::traceroute::Strategy::Tcp => Some(
            arguments
                .port
                .unwrap_or(packetcraftr::traceroute::DEFAULT_TRACEROUTE_TCP_PORT),
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
        first_hop: arguments.first_hop,
        max_hops: arguments.max_hops,
        probes_per_hop: arguments.attempts,
        timeout: Duration::from_millis(arguments.timeout_ms),
        probes_per_second: arguments.rate,
        limits: trace_limits,
    };
    request.validate().map_err(classified_error)?;
    Ok(request)
}

fn prepare_exchange(
    arguments: &Args,
    request: &packetcraftr::traceroute::Request,
    queue_limits: net::capture::Limits,
    max_template_packets: usize,
) -> Result<packetcraftr::exchange::Options, CliError> {
    exchange::options(
        packetcraftr::send::Options {
            destination: None,
            plan: net::route::Options {
                link_mode: arguments.route.link_mode.into(),
                interface: None,
                preferred_source: arguments.route.source,
            },
            build: core::build::Options::default(),
            confirm_live_opt_in: false,
        },
        request.timeout,
        max_template_packets,
        queue_limits,
    )
}

pub(crate) fn classified_error(error: packetcraftr::traceroute::Error) -> CliError {
    let sequence = error.sequence();
    CliError::classified_at_optional_sequence(error, sequence)
}
