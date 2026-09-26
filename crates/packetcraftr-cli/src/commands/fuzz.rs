// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Fuzz CLI command logic.

use crate::output::contract::ToolFormat;

pub(super) mod arguments;
mod rendering;

use std::sync::Arc;

use packetcraftr_core as core;

use crate::output;

use self::arguments::Args;
use crate::errors::CliError;
use crate::input::read_recipe;
use crate::rendering::StreamEncoder;
use crate::system::{Runtime, Workflow, prepare_workflow};

use super::execution;

/// A validated live campaign still waiting for its template packet, and the
/// prepared workflow its client runs it under.
struct PreparedLive {
    request: packetcraftr::fuzz::Request,
    workflow: Workflow,
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
    let packet = read_recipe(arguments.recipe, &registry, request.build.limits.max_layers)?;
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
            limits: core::packet::Limits {
                max_packet_size: arguments.max_packet_bytes,
                ..core::packet::Limits::default()
            },
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
    // The template packet is read after every option is validated.
    let live = packetcraftr::fuzz::Request {
        timeout: arguments.timeout.timeout(),
        cases_per_second: arguments.rate,
        destination: arguments.destination,
        allow_permissive_live: arguments.allow_permissive_live,
        max_evidence_frames: queue_limits.max_frames,
        max_evidence_bytes: queue_limits.max_bytes,
        ..packetcraftr::fuzz::Request::new(request.clone(), core::packet::Packet::new())
    };
    live.validate().map_err(CliError::classified)?;
    // Each case is one probe.
    let workflow = prepare_workflow(
        &arguments.route,
        arguments.policy.clone().into_policy(),
        arguments.timeout.timeout(),
        1,
        queue_limits,
    )?;
    Ok(Some(PreparedLive {
        request: live,
        workflow,
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
        execute_live(packet, live, format, stream)
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
                publish_offline(
                    &request,
                    session.packet.clone(),
                    Arc::clone(&session.registry),
                    emit,
                )
                .map_err(CliError::classified)
            }),
            on_event: |case, stream| {
                let event = output::fuzz::Event::try_from(case).map_err(CliError::classified)?;
                Ok(stream.emit_data(event, Vec::new())?)
            },
            into_result: Box::new(|report| {
                output::envelope::Published::<output::fuzz::Report>::try_from(report)
                    .map_err(CliError::classified)
            }),
            render_text: Box::new(|report, _| {
                rendering::render_text(
                    output::envelope::Published::try_from(report).map_err(CliError::classified)?,
                )
            }),
            complete: rendering::render_offline_complete,
        },
    )
}

fn execute_live(
    packet: core::packet::Packet,
    live: PreparedLive,
    format: ToolFormat,
    stream: &StreamEncoder,
) -> Result<(), CliError> {
    let PreparedLive { request, workflow } = live;
    let client = workflow.client(Runtime::Fuzz);
    let request = packetcraftr::fuzz::Request {
        packet,
        route: workflow.route,
        collection: workflow.collection,
        ..request
    };
    // The client admits, paces, and publishes the campaign itself, so the
    // driver vends no session state.
    execution::run_workflow(
        &mut (),
        format,
        stream,
        crate::cancellation::signal(),
        execution::Hooks {
            command: output::contract::Command::Fuzz,
            run: Box::new(|_| {
                let collector = packetcraftr::fuzz::Collector::default();
                let report = client
                    .fuzz(request.clone(), collector.clone())
                    .map_err(CliError::classified)?;
                Ok(collector.finish(report))
            }),
            run_with_events: Box::new(|_, emit| {
                client
                    .fuzz(request.clone(), emit)
                    .map_err(CliError::classified)
            }),
            on_event: |event, stream| {
                let event = output::fuzz::Event::try_from(event).map_err(CliError::classified)?;
                Ok(stream.emit_data(event, Vec::new())?)
            },
            into_result: Box::new(|aggregate| {
                output::envelope::Published::<output::fuzz::Report>::try_from(aggregate)
                    .map_err(CliError::classified)
            }),
            render_text: Box::new(|aggregate, _| {
                rendering::render_text(
                    output::envelope::Published::try_from(aggregate)
                        .map_err(CliError::classified)?,
                )
            }),
            complete: rendering::render_live_complete,
        },
    )
}

/// Generates the offline campaign, publishing each case to `emit` on a
/// worker admitted by the command's own runtime and waiting, within the
/// campaign deadline, for each answer.
fn publish_offline(
    request: &core::fuzz::Request,
    packet: core::packet::Packet,
    registry: Arc<core::registry::Registry>,
    emit: execution::Emit<core::fuzz::Case>,
) -> Result<core::fuzz::Summary, core::fuzz::Error> {
    let runtime = crate::system::runtime(Runtime::Fuzz);
    let worker = packetcraftr::runtime::Worker::new_in(&runtime, emit)
        .map_err(|source| core::fuzz::Error::Output { source })?;
    core::fuzz::run_observed(request, packet, registry, |case, deadline| {
        worker.emit(case, deadline).map_err(|error| match error {
            packetcraftr::runtime::Error::Deadline(error) => error.into(),
            packetcraftr::runtime::Error::Output(source) => core::fuzz::Error::Output { source },
            // A publication failure this command does not know yet.
            error => core::fuzz::Error::Output {
                source: CliError::new(
                    core::error::Kind::Internal,
                    format!("fuzz progressive output failed: {error}"),
                )
                .into_boundary_error(),
            },
        })
    })
}
