// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Scan CLI command logic.

pub(super) mod arguments;
mod conversion;
mod rendering;

use std::sync::Arc;
use std::time::Duration;

use packetcraftr::{core, netio as net, output};

use self::arguments::Args;
use super::registry;
use crate::input::parse_target;
use crate::rendering::{NdjsonStream, emit_aggregate_with_stats};
use crate::system::{client, exchange, validate_selector};
use packetcraftr::BoundaryError;

use super::execution::Executor;

pub(super) fn run(
    arguments: Args,
    format: output::contract::Format,
    stream: &mut NdjsonStream,
) -> Result<(), BoundaryError> {
    let Args {
        target,
        transport,
        family,
        ports,
        attempts,
        timeout_ms,
        rate,
        batch_size,
        max_ports,
        max_probes,
        max_duration_ms,
        max_undecoded,
        route,
        limits,
        policy,
    } = arguments;
    let target = parse_target(target)?;
    let queue_limits = limits.into_limits();
    let workflow_limits = packetcraftr::scan::Limits {
        max_ports,
        max_probes,
        batch_size,
        max_duration: Duration::from_millis(max_duration_ms),
        max_evidence_frames: queue_limits.max_frames,
        max_evidence_bytes: queue_limits.max_bytes,
        max_undecoded,
    };
    workflow_limits
        .validate()
        .map_err(BoundaryError::from_error)?;
    let ports =
        conversion::expand_port_specs(&ports, max_ports).map_err(BoundaryError::from_error)?;
    let policy = policy.into_policy();
    policy.validate().map_err(BoundaryError::from_error)?;
    validate_selector(route.interface.as_deref()).map(|_| ())?;
    let request = packetcraftr::scan::Request {
        target,
        transport: transport.into(),
        address_family: family.into(),
        ports,
        attempts,
        timeout: Duration::from_millis(timeout_ms),
        probes_per_second: rate,
        limits: workflow_limits,
    };
    let registry = registry()?;
    let exchange = exchange::options(
        packetcraftr::send::Options {
            destination: None,
            plan: net::route::Options {
                link_mode: route.link_mode.into(),
                interface: None,
                preferred_source: route.source,
            },
            build: core::build::Options::default(),
            allow_permissive_live: false,
        },
        request.timeout,
        batch_size,
        queue_limits,
    )?;

    let mut executor = Executor {
        client: client(Arc::clone(&registry), policy.clone()),
        exchange,
        interface: route.interface,
    };
    let resolver = packetcraftr::target::SystemResolver;
    let mut clock = packetcraftr::clock::SystemClock;
    match format {
        output::contract::Format::Text | output::contract::Format::Json => {
            let result = packetcraftr::scan::run(
                &request,
                &policy,
                &resolver,
                &registry,
                &mut executor,
                &mut clock,
            )
            .map_err(BoundaryError::from_error)?;
            let (result, diagnostics, stats) =
                output::scan::Result::try_from_scan(result).map_err(BoundaryError::from_error)?;
            if format == output::contract::Format::Text {
                rendering::render_text(result, diagnostics, stats)
            } else {
                emit_aggregate_with_stats(
                    output::contract::Command::Scan,
                    result,
                    diagnostics,
                    stats,
                )
            }
        }
        output::contract::Format::Ndjson => {
            let event_stream = stream.clone();
            let summary = packetcraftr::scan::run_with_events(
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
        _ => unreachable!("scan format is checked before command dispatch"),
    }
}
