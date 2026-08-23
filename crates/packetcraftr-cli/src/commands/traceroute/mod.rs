// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Traceroute CLI command logic.

pub(super) mod arguments;
mod conversion;
mod rendering;

use std::sync::Arc;

use packetcraftr::{core, netio as net, output};

use self::arguments::Args;
use super::registry;
use crate::rendering::{NdjsonStream, emit_aggregate_with_stats};
use crate::system::{client, exchange, validate_selector};
use packetcraftr::BoundaryError;

use crate::system::Executor;

pub(super) fn run(
    arguments: Args,
    format: output::contract::Format,
    stream: &mut NdjsonStream,
) -> Result<(), BoundaryError> {
    let queue_limits = arguments.limits.clone().into_limits();
    let request = conversion::prepare_request(&arguments, queue_limits)?;
    let policy = arguments.policy.clone().into_policy();
    policy.validate().map_err(BoundaryError::from_error)?;
    validate_selector(arguments.route.interface.as_deref()).map(|_| ())?;
    let max_template_packets = usize::try_from(arguments.attempts).map_err(|_| {
        BoundaryError::from_error(packetcraftr::Error::InvalidRequest {
            field: "attempts",
            message: "traceroute attempt count exceeds the platform size limit".to_owned(),
        })
    })?;
    let registry = registry()?;
    let exchange = prepare_exchange(&arguments, &request, queue_limits, max_template_packets)?;
    let mut executor = Executor {
        client: client(Arc::clone(&registry), policy.clone()),
        exchange,
        interface: arguments.route.interface,
    };
    let resolver = packetcraftr::target::SystemResolver;
    let mut clock = packetcraftr::clock::SystemClock;
    match format {
        output::contract::Format::Text | output::contract::Format::Json => {
            let result = packetcraftr::traceroute::run(
                &request,
                &policy,
                &resolver,
                &registry,
                &mut executor,
                &mut clock,
            )
            .map_err(BoundaryError::from_error)?;
            let (result, diagnostics, stats) =
                output::traceroute::Result::try_from_traceroute(result)
                    .map_err(BoundaryError::from_error)?;
            if format == output::contract::Format::Text {
                rendering::render_text(result, diagnostics, stats)
            } else {
                emit_aggregate_with_stats(
                    output::contract::Command::Traceroute,
                    result,
                    diagnostics,
                    stats,
                )
            }
        }
        output::contract::Format::Ndjson => {
            let event_stream = stream.clone();
            let summary = packetcraftr::traceroute::run_with_events(
                &request,
                &policy,
                &resolver,
                &registry,
                &mut executor,
                &mut clock,
                move |event| rendering::render_event(event, &event_stream),
            )
            .map_err(BoundaryError::from_error)?;
            rendering::render_complete(summary, stream)
        }
        _ => unreachable!("traceroute format is checked before command dispatch"),
    }
}

fn prepare_exchange(
    arguments: &Args,
    request: &packetcraftr::traceroute::Request,
    queue_limits: net::capture::Limits,
    max_template_packets: usize,
) -> Result<packetcraftr::exchange::Options, BoundaryError> {
    exchange::options(
        packetcraftr::send::Options {
            destination: None,
            plan: net::route::Options {
                link_mode: arguments.route.link_mode.into(),
                interface: None,
                preferred_source: arguments.route.source,
            },
            build: core::build::Options::default(),
            allow_permissive_live: false,
        },
        request.timeout,
        max_template_packets,
        queue_limits,
    )
}
