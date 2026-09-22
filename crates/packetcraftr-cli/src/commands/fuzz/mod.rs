// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Fuzz CLI command logic.

use packetcraftr_cli::output::contract::ToolFormat;

pub(super) mod arguments;
mod rendering;

use std::sync::Arc;
use std::time::Duration;

use packetcraftr_cli::output;
use packetcraftr_core as core;

use self::arguments::Args;
use super::execution;
use crate::errors::CliError;
use crate::input::read_recipe;
use crate::rendering::StreamEncoder;

pub(super) fn run(
    arguments: Args,
    format: ToolFormat,
    stream: &StreamEncoder,
) -> Result<(), CliError> {
    let request = prepare_request(&arguments)?;
    let live = prepare_live(&arguments, &request)?;
    let registry = live.as_ref().map_or_else(
        packetcraftr_core::protocol::builtin::registry,
        execution::FuzzLive::registry,
    );
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
                .map_err(CliError::classified)
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
) -> Result<Option<execution::FuzzLive>, CliError> {
    if !arguments.live {
        return Ok(None);
    }
    execution::prepare_fuzz_live(execution::FuzzSettings {
        route: arguments.route.clone(),
        policy: arguments.policy.clone(),
        build: request.build.clone(),
        timeout: Duration::from_millis(arguments.timeout_ms),
        rate: arguments.rate,
        destination: arguments.destination,
        allow_permissive_live: arguments.allow_permissive_live,
        queue_limits: arguments.limits.clone().into_limits(),
    })
    .map(Some)
}

fn execute_and_render(
    request: core::fuzz::Request,
    packet: core::packet::Packet,
    registry: Arc<core::registry::Registry>,
    live: Option<execution::FuzzLive>,
    format: ToolFormat,
    stream: &StreamEncoder,
) -> Result<(), CliError> {
    if let Some(live) = live {
        execute_live(request, packet, live, format, stream)
    } else {
        execute_offline(request, packet, registry, format, stream)
    }
}

/// The shared inputs both offline campaign entry points consume.
struct OfflineSession {
    packet: core::packet::Packet,
    registry: Arc<core::registry::Registry>,
}

fn execute_offline(
    request: core::fuzz::Request,
    packet: core::packet::Packet,
    registry: Arc<core::registry::Registry>,
    format: ToolFormat,
    stream: &StreamEncoder,
) -> Result<(), CliError> {
    crate::cancellation::check()?;
    let mut session = OfflineSession { packet, registry };
    execution::run_workflow(
        &mut session,
        format,
        stream,
        crate::cancellation::signal(),
        execution::Hooks {
            command: output::contract::Command::Fuzz,
            conversion: output::fuzz::Offline,
            run: Box::new(|session| {
                let mut cases = Vec::new();
                let summary = core::fuzz::run_observed(
                    &request,
                    session.packet.clone(),
                    Arc::clone(&session.registry),
                    |case, _| {
                        crate::cancellation::check().map_err(|error| {
                            core::fuzz::Error::Output {
                                source: error.into_boundary_error(),
                            }
                        })?;
                        cases.push(case);
                        Ok(())
                    },
                )
                .map_err(CliError::classified)?;
                Ok(core::fuzz::Report::from_summary(summary, cases))
            }),
            run_with_events: Box::new(|session, emit| {
                let runtime = crate::resources::runtime(
                    "fuzz_progress",
                    packetcraftr::progress::MAX_WORKER_CAPACITY,
                );
                packetcraftr::fuzz::run_offline_with_events(
                    &request,
                    session.packet.clone(),
                    Arc::clone(&session.registry),
                    &runtime,
                    emit,
                )
                .map_err(CliError::classified)
            }),
            render_text: Box::new(|converted, _| rendering::render_text(converted)),
        },
    )
}

fn execute_live(
    request: core::fuzz::Request,
    packet: core::packet::Packet,
    mut live: execution::FuzzLive,
    format: ToolFormat,
    stream: &StreamEncoder,
) -> Result<(), CliError> {
    let options = live.options;
    let registry = live.registry();
    let mut session = live.session();
    execution::run_workflow(
        &mut session,
        format,
        stream,
        crate::cancellation::signal(),
        execution::Hooks {
            command: output::contract::Command::Fuzz,
            conversion: output::fuzz::Live,
            run: Box::new(|session| {
                packetcraftr::fuzz::run(
                    packetcraftr::fuzz::RunInput {
                        request: &request,
                        live: options,
                        packet: packet.clone(),
                        registry: Arc::clone(&registry),
                    },
                    &mut session.authorizer,
                    session.executor,
                    &mut session.clock,
                )
                .map_err(CliError::classified)
            }),
            run_with_events: Box::new(|session, emit| {
                packetcraftr::fuzz::run_with_events(
                    packetcraftr::fuzz::RunInput {
                        request: &request,
                        live: options,
                        packet: packet.clone(),
                        registry: Arc::clone(&registry),
                    },
                    &mut session.authorizer,
                    session.executor,
                    &mut session.clock,
                    session.runtime,
                    emit,
                )
                .map_err(CliError::classified)
            }),
            render_text: Box::new(|converted, _| rendering::render_text(converted)),
        },
    )
}
