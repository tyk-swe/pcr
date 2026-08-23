// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! DNS CLI command logic.

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

use crate::system::Executor;

pub(super) fn run(
    arguments: Args,
    format: output::contract::Format,
    stream: &mut NdjsonStream,
) -> Result<(), BoundaryError> {
    let queue_limits = arguments.limits.clone().into_limits();
    let request = prepare_request(&arguments, queue_limits)?;
    let policy = arguments.policy.clone().into_policy();
    policy.validate().map_err(BoundaryError::from_error)?;
    validate_selector(arguments.route.interface.as_deref()).map(|_| ())?;
    let registry = registry()?;
    let exchange = prepare_exchange(&arguments, &request, queue_limits)?;
    let mut executor = Executor {
        client: client(Arc::clone(&registry), policy.clone()),
        exchange,
        interface: arguments.route.interface,
    };
    let resolver = packetcraftr::target::SystemResolver;
    let mut clock = packetcraftr::clock::SystemClock;
    match format {
        output::contract::Format::Text | output::contract::Format::Json => {
            let result = packetcraftr::dns::run(
                &request,
                &policy,
                &resolver,
                &registry,
                &mut executor,
                &mut clock,
            )
            .map_err(BoundaryError::from_error)?;
            let (result, diagnostics, stats) =
                output::dns::Result::try_from_dns(result).map_err(BoundaryError::from_error)?;
            if format == output::contract::Format::Text {
                rendering::render_text(result, diagnostics, stats)
            } else {
                emit_aggregate_with_stats(
                    output::contract::Command::Dns,
                    result,
                    diagnostics,
                    stats,
                )
            }
        }
        output::contract::Format::Ndjson => {
            let event_stream = stream.clone();
            let summary = packetcraftr::dns::run_with_events(
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
        _ => unreachable!("dns format is checked before command dispatch"),
    }
}

fn prepare_request(
    arguments: &Args,
    queue_limits: net::capture::Limits,
) -> Result<packetcraftr::dns::Request, BoundaryError> {
    let request = packetcraftr::dns::Request {
        server: parse_target(arguments.server.clone())?,
        address_family: arguments.family.into(),
        server_port: arguments.port,
        source_port: arguments
            .source_port
            .unwrap_or_else(conversion::source_port),
        query_name: arguments.name.clone(),
        query_type: arguments.query_type.into(),
        transaction_id: arguments
            .transaction_id
            .unwrap_or_else(conversion::transaction_id),
        recursion_desired: !arguments.no_recursion,
        attempts: arguments.attempts,
        timeout: Duration::from_millis(arguments.timeout_ms),
        queries_per_second: arguments.rate,
        limits: packetcraftr::dns::Limits {
            max_message_bytes: arguments.max_message_bytes,
            max_records: arguments.max_records,
            max_name_pointers: arguments.max_name_pointers,
            max_txt_strings: arguments.max_txt_strings,
            max_txt_bytes: arguments.max_txt_bytes,
            max_rejected_records: arguments.max_rejected_records,
            max_evidence_frames: queue_limits.max_frames,
            max_evidence_bytes: queue_limits.max_bytes,
            max_undecoded: arguments.max_undecoded,
            max_duration: Duration::from_millis(arguments.max_duration_ms),
        },
    };
    Ok(request)
}

fn prepare_exchange(
    arguments: &Args,
    request: &packetcraftr::dns::Request,
    queue_limits: net::capture::Limits,
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
        1,
        queue_limits,
    )
}
