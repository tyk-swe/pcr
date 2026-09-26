// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Fuzz CLI command logic.

use crate::output::contract::ToolFormat;

pub(super) mod arguments;
mod rendering;

use std::sync::Arc;

use packetcraftr_core as core;
use packetcraftr_netio as net;

use crate::output;

use self::arguments::Args;
use crate::errors::CliError;
use crate::input::read_recipe;
use crate::rendering::StreamEncoder;
use crate::system::{InterfaceSelector, client, exchange};

use super::execution::{self, Executor};

struct PreparedLive {
    options: packetcraftr::fuzz::LiveOptions,
    policy: packetcraftr::policy::Policy,
    exchange: packetcraftr::exchange::Options,
    interface: Option<InterfaceSelector>,
}

impl super::Spec for Args {
    type Format = crate::output::contract::ToolFormat;
    const CANCELLATION: bool = true;

    fn publication_duration(&self) -> Option<std::time::Duration> {
        Some(self.duration.max_duration())
    }

    fn resources(&self, settings: &mut crate::resources::Settings<'_>) {
        crate::resources::declare!(settings, self, [
            max_cases: Count @ Operation,
            max_packet_bytes: Bytes @ Operation,
            max_total_bytes: Bytes @ Operation,
            max_field_bytes: Bytes @ ObservationCollection,
            max_list_items: Count @ Operation,
            max_shrink_steps: Count @ Operation,
        ]);
        self.timeout.resources(settings);
        self.duration.resources(settings);
        self.limits.resources(settings);
        self.policy.resources(settings);
    }

    fn run(
        self,
        format: Self::Format,
        stream: &crate::rendering::StreamEncoder,
    ) -> Result<super::CommandExit, CliError> {
        run(self, format, stream).map(|()| super::CommandExit::SUCCESS)
    }
}

pub(super) fn run(
    arguments: Args,
    format: ToolFormat,
    stream: &StreamEncoder,
) -> Result<(), CliError> {
    let request = prepare_request(&arguments)?;
    let live = prepare_live(&arguments, &request)?;
    let registry = packetcraftr_core::protocol::builtin::registry();
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
            max_duration: arguments.duration.max_duration(),
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
        timeout: arguments.timeout.timeout(),
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
    let interface = arguments.route.interface.clone();
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
        arguments.timeout.timeout(),
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
    packet: core::packet::Packet,
    registry: Arc<core::registry::Registry>,
    live: Option<PreparedLive>,
    format: ToolFormat,
    stream: &StreamEncoder,
) -> Result<(), CliError> {
    if let Some(live) = live {
        execute_live(request, packet, registry, live, format, stream)
    } else {
        execute_offline(request, packet, registry, format, stream)
    }
}

/// The shared inputs both offline campaign entry points consume.
struct OfflineSession {
    packet: core::packet::Packet,
    registry: Arc<core::registry::Registry>,
}

/// The live campaign's session: the packet-level authorizer, the
/// cancellation-sharing clock, the exchange executor, and the shared inputs
/// both entry points consume.
struct LiveSession<'a> {
    authorizer: packetcraftr::policy::PolicyAuthorizer<'a>,
    clock: packetcraftr::clock::CancellableClock,
    executor: Executor,
    options: packetcraftr::fuzz::LiveOptions,
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
            on_event: |case, stream| {
                let event =
                    output::fuzz::Event::try_from_offline(case).map_err(CliError::classified)?;
                Ok(stream.emit_data(event, Vec::new())?)
            },
            into_result: Box::new(|report| {
                output::fuzz::Report::try_from_offline(report)
                    .map(|(result, diagnostics, stats)| (result, diagnostics, Some(stats)))
                    .map_err(CliError::classified)
            }),
            render_text: Box::new(|report, _| {
                let (result, diagnostics, stats) =
                    output::fuzz::Report::try_from_offline(report).map_err(CliError::classified)?;
                rendering::render_text(result, diagnostics, stats)
            }),
            complete: rendering::render_offline_complete,
        },
    )
}

fn execute_live(
    request: core::fuzz::Request,
    packet: core::packet::Packet,
    registry: Arc<core::registry::Registry>,
    live: PreparedLive,
    format: ToolFormat,
    stream: &StreamEncoder,
) -> Result<(), CliError> {
    let mut session = LiveSession {
        authorizer: packetcraftr::policy::PolicyAuthorizer::for_packets(&live.policy),
        clock: packetcraftr::clock::CancellableClock(crate::cancellation::signal().clone()),
        executor: Executor {
            client: client(Arc::clone(&registry), live.policy.clone()),
            exchange: live.exchange,
            interface: live.interface,
        },
        options: live.options,
        packet,
        registry,
    };
    execution::run_workflow(
        &mut session,
        format,
        stream,
        crate::cancellation::signal(),
        execution::Hooks {
            command: output::contract::Command::Fuzz,
            run: Box::new(|session| {
                packetcraftr::fuzz::run(
                    packetcraftr::fuzz::RunInput {
                        request: &request,
                        live: session.options,
                        packet: session.packet.clone(),
                        registry: Arc::clone(&session.registry),
                    },
                    &mut session.authorizer,
                    &mut session.executor,
                    &mut session.clock,
                )
                .map_err(CliError::classified)
            }),
            run_with_events: Box::new(|session, emit| {
                let runtime = crate::resources::runtime(
                    "fuzz_progress",
                    packetcraftr::progress::MAX_WORKER_CAPACITY,
                );
                packetcraftr::fuzz::run_with_events(
                    packetcraftr::fuzz::RunInput {
                        request: &request,
                        live: session.options,
                        packet: session.packet.clone(),
                        registry: Arc::clone(&session.registry),
                    },
                    &mut session.authorizer,
                    &mut session.executor,
                    &mut session.clock,
                    &runtime,
                    emit,
                )
                .map_err(CliError::classified)
            }),
            on_event: |case, stream| {
                let event =
                    output::fuzz::Event::try_from_live(case).map_err(CliError::classified)?;
                Ok(stream.emit_data(event, Vec::new())?)
            },
            into_result: Box::new(|report| {
                output::fuzz::Report::try_from_live(report)
                    .map(|(result, diagnostics, stats)| (result, diagnostics, Some(stats)))
                    .map_err(CliError::classified)
            }),
            render_text: Box::new(|report, _| {
                let (result, diagnostics, stats) =
                    output::fuzz::Report::try_from_live(report).map_err(CliError::classified)?;
                rendering::render_text(result, diagnostics, stats)
            }),
            complete: rendering::render_live_complete,
        },
    )
}
