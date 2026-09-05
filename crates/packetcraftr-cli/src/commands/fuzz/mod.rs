// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Fuzz CLI command logic.

use packetcraftr::output::contract::Format;

use packetcraftr::core::error::Kind;

pub(super) mod arguments;
mod rendering;

use std::sync::Arc;
use std::time::Duration;

use packetcraftr::{core, netio as net, output};

use self::arguments::Args;
use super::registry;
use crate::errors::CliError;
use crate::input::read_recipe;
use crate::rendering::{StreamEncoder, emit_aggregate_with_stats};
use crate::system::{InterfaceSelector, client, exchange};

use super::execution::Executor;

struct PreparedLive {
    options: packetcraftr::fuzz::LiveOptions,
    policy: packetcraftr::policy::Policy,
    exchange: packetcraftr::exchange::Options,
    interface: Option<InterfaceSelector>,
}

pub(super) fn run(arguments: Args, format: Format, stream: &StreamEncoder) -> Result<(), CliError> {
    let request = prepare_request(&arguments)?;
    let live = prepare_live(&arguments, &request)?;
    let registry = registry()?;
    let packet = read_recipe(arguments.recipe, &registry, request.build.max_layers)?;
    execute_and_render(request, packet, registry, live, format, stream)
}

fn prepare_request(arguments: &Args) -> Result<core::fuzz::Request, CliError> {
    let targets = arguments
        .fields
        .iter()
        .map(|field| {
            field
                .parse::<core::fuzz::Target>()
                .map_err(|source| CliError::new(Kind::Cli, source.to_string()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let request = core::fuzz::Request {
        seed: arguments.seed,
        first_case: arguments.first_case,
        cases: arguments.cases,
        strategies: arguments
            .strategies
            .iter()
            .copied()
            .map(Into::into)
            .collect(),
        targets,
        build: core::build::Options {
            mode: arguments.mode.into(),
            max_packet_size: arguments.max_packet_bytes,
            ..core::build::Options::default()
        },
        limits: core::fuzz::Limits {
            max_cases: arguments.max_cases,
            max_packet_bytes: arguments.max_packet_bytes,
            max_total_bytes: arguments.max_total_bytes,
            max_field_bytes: arguments.max_field_bytes,
            max_list_items: arguments.max_list_items,
            max_shrink_steps: arguments.max_shrink_steps,
            max_duration: Duration::from_millis(arguments.max_duration_ms),
        },
    };
    request.validate().map_err(CliError::classified)?;
    Ok(request)
}

fn prepare_live(
    arguments: &Args,
    request: &core::fuzz::Request,
) -> Result<Option<PreparedLive>, CliError> {
    if !arguments.live {
        return Ok(None);
    }
    let queue_limits = arguments.limits.clone().into_limits();
    let options = packetcraftr::fuzz::LiveOptions {
        timeout: Duration::from_millis(arguments.timeout_ms),
        cases_per_second: arguments.rate,
        destination: arguments.destination,
        allow_malformed_live: arguments.allow_permissive_live,
        limits: packetcraftr::fuzz::LiveLimits {
            max_evidence_frames: queue_limits.max_frames,
            max_evidence_bytes: queue_limits.max_bytes,
        },
    };
    options.validate().map_err(CliError::classified)?;
    let policy = arguments.policy.clone().into_policy();
    policy.validate().map_err(CliError::classified)?;
    let interface = InterfaceSelector::parse_optional(arguments.route.interface.as_deref())?;
    let exchange = exchange::options(
        packetcraftr::send::Options {
            destination: arguments.destination,
            plan: net::route::Options {
                link_mode: arguments.route.link_mode.into(),
                interface: None,
                preferred_source: arguments.route.source,
            },
            build: request.build.clone(),
            allow_permissive_live: arguments.allow_permissive_live,
        },
        Duration::from_millis(arguments.timeout_ms),
        1,
        queue_limits,
    )?;
    Ok(Some(PreparedLive {
        options,
        policy,
        exchange,
        interface,
    }))
}

fn execute_and_render(
    request: core::fuzz::Request,
    packet: core::Packet,
    registry: Arc<core::registry::Registry>,
    live: Option<PreparedLive>,
    format: Format,
    stream: &StreamEncoder,
) -> Result<(), CliError> {
    if let Some(live) = live {
        execute_live(request, packet, registry, live, format, stream)
    } else {
        execute_offline(request, packet, registry, format, stream)
    }
}

fn execute_offline(
    request: core::fuzz::Request,
    packet: core::Packet,
    registry: Arc<core::registry::Registry>,
    format: Format,
    stream: &StreamEncoder,
) -> Result<(), CliError> {
    if format == Format::Ndjson {
        let event_stream = stream.clone();
        let runtime = packetcraftr::progress::Runtime::default();
        let summary = packetcraftr::fuzz::run_offline_with_events(
            &request,
            packet,
            registry,
            &runtime,
            move |case| {
                output::fuzz::Event::try_from_offline(case)
                    .map_err(CliError::classified)
                    .and_then(|event| Ok(event_stream.emit_data(event, Vec::new())?))
                    .map_err(CliError::into_boundary_error)
            },
        )
        .map_err(CliError::classified)?;
        return rendering::render_offline_complete(summary, stream);
    }
    let result = core::fuzz::run(&request, packet, registry).map_err(CliError::classified)?;
    let (result, diagnostics, stats) =
        output::fuzz::Report::try_from_offline(result).map_err(CliError::classified)?;
    render_collected(result, diagnostics, stats, format)
}

fn execute_live(
    request: core::fuzz::Request,
    packet: core::Packet,
    registry: Arc<core::registry::Registry>,
    live: PreparedLive,
    format: Format,
    stream: &StreamEncoder,
) -> Result<(), CliError> {
    let mut executor = Executor {
        client: client(Arc::clone(&registry), live.policy.clone()),
        exchange: live.exchange,
        interface: live.interface,
    };
    let mut authorizer = packetcraftr::fuzz::PolicyAuthorizer::for_packets(&live.policy);
    let mut clock = packetcraftr::clock::SystemClock;
    if format == Format::Ndjson {
        let event_stream = stream.clone();
        let runtime = packetcraftr::progress::Runtime::default();
        let summary = packetcraftr::fuzz::run_with_events(
            packetcraftr::fuzz::RunInput {
                request: &request,
                live: live.options,
                packet,
                registry,
            },
            &mut authorizer,
            &mut executor,
            &mut clock,
            &runtime,
            move |case| {
                output::fuzz::Event::try_from_live(case)
                    .map_err(CliError::classified)
                    .and_then(|event| Ok(event_stream.emit_data(event, Vec::new())?))
                    .map_err(CliError::into_boundary_error)
            },
        )
        .map_err(CliError::classified)?;
        return rendering::render_live_complete(summary, stream);
    }
    let result = packetcraftr::fuzz::run(
        packetcraftr::fuzz::RunInput {
            request: &request,
            live: live.options,
            packet,
            registry,
        },
        &mut authorizer,
        &mut executor,
        &mut clock,
    )
    .map_err(CliError::classified)?;
    let (result, diagnostics, stats) =
        output::fuzz::Report::try_from_live(result).map_err(CliError::classified)?;
    render_collected(result, diagnostics, stats, format)
}

fn render_collected(
    result: output::fuzz::Report,
    diagnostics: Vec<core::diagnostic::Diagnostic>,
    stats: output::envelope::Stats,
    format: Format,
) -> Result<(), CliError> {
    match format {
        Format::Text => rendering::render_text(result, diagnostics, stats),
        Format::Json => {
            emit_aggregate_with_stats(output::contract::Command::Fuzz, result, diagnostics, stats)
        }
        _ => unreachable!("streaming returned before aggregate rendering"),
    }
}
