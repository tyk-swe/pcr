// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::output::contract::Format;

pub(in crate::commands) mod arguments;
mod rendering;

use std::sync::Arc;

use packetcraftr_core as core;
use packetcraftr_core::layer::selector::Selector;

use crate::output;

use self::arguments::Args;
use crate::errors::CliError;
use crate::input::read_recipe;
use crate::invocation::StreamEncoder;
use crate::system::{Runtime, Workflow, prepare_workflow};

struct PreparedLive {
    request: packetcraftr::fuzz::Request,
    workflow: Workflow,
}

impl crate::commands::Spec for Args {
    const FORMATS: &'static [crate::output::contract::Format] = &[
        crate::output::contract::Format::Text,
        crate::output::contract::Format::Json,
        crate::output::contract::Format::Ndjson,
    ];
    const CANCELLATION: bool = true;

    fn run_time(&self) -> Option<&dyn crate::command_options::Bounded> {
        Some(&self.duration)
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
        invocation: &crate::invocation::Invocation,
    ) -> Result<crate::commands::CommandExit, CliError> {
        run(invocation, self, invocation.format, &invocation.output)
            .map(|()| crate::commands::CommandExit::SUCCESS)
    }
}

pub(super) fn run(
    invocation: &crate::invocation::Invocation,
    arguments: Args,
    format: Format,
    stream: &StreamEncoder,
) -> Result<(), CliError> {
    let (mut request, selectors) = prepare_request(&arguments)?;
    let mut live = prepare_live(&arguments, &request)?;
    let registry = packetcraftr_core::protocol::builtin::registry();
    let packet = read_recipe(arguments.recipe, &registry, request.build.limits.max_layers)?;
    // Selectors name layers by protocol, so they resolve once the recipe is
    // known; everything after this point sees numeric layer indexes.
    request.targets =
        core::fuzz::Target::select(&selectors, &packet, &registry).map_err(CliError::classified)?;
    if let Some(live) = &mut live {
        live.request.campaign.targets.clone_from(&request.targets);
    }
    execute_and_render(invocation, request, packet, registry, live, format, stream)
}

/// The request without its targets, and the `--field` selectors that become
/// them once the recipe is read.
fn prepare_request(arguments: &Args) -> Result<(core::fuzz::Request, Vec<Selector>), CliError> {
    let selectors = arguments
        .fields
        .iter()
        .map(|field| field.parse::<Selector>().map_err(CliError::classified))
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
        targets: Vec::new(),
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
    Ok((request, selectors))
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
    let workflow = prepare_workflow(
        &arguments.route,
        arguments.policy.clone().into_policy(),
        arguments.timeout.timeout(),
        queue_limits,
    )?;
    Ok(Some(PreparedLive {
        request: live,
        workflow,
    }))
}

fn execute_and_render(
    invocation: &crate::invocation::Invocation,
    request: core::fuzz::Request,
    packet: core::packet::Packet,
    registry: Arc<core::registry::Registry>,
    live: Option<PreparedLive>,
    format: Format,
    stream: &StreamEncoder,
) -> Result<(), CliError> {
    if let Some(live) = live {
        execute_live(invocation, packet, live, format, stream)
    } else {
        execute_offline(invocation, request, packet, registry, format, stream)
    }
}

fn execute_offline(
    invocation: &crate::invocation::Invocation,
    request: core::fuzz::Request,
    packet: core::packet::Packet,
    registry: Arc<core::registry::Registry>,
    format: Format,
    stream: &StreamEncoder,
) -> Result<(), CliError> {
    invocation.check()?;
    match format {
        Format::Ndjson => {
            let emit = crate::commands::execution::emitter(invocation, |case, stream| {
                let event = output::fuzz::Event::try_from(case).map_err(CliError::classified)?;
                Ok(stream.emit_data(event, Vec::new())?)
            });
            let summary = publish_offline(
                invocation,
                &request,
                packet.clone(),
                Arc::clone(&registry),
                emit,
            )
            .map_err(CliError::classified)?;
            invocation.check()?;
            rendering::render_offline_complete(summary, stream)
        }
        _ => {
            let report = {
                let mut cases = Vec::new();
                let summary = core::fuzz::run_observed(
                    &request,
                    packet.clone(),
                    Arc::clone(&registry),
                    |case, _| {
                        invocation
                            .check()
                            .map_err(|error| core::fuzz::Error::Output {
                                source: error.into_boundary_error(),
                            })?;
                        cases.push(case);
                        Ok(())
                    },
                )
                .map_err(CliError::classified)?;
                core::fuzz::Report::from_summary(summary, cases)
            };
            invocation.check()?;
            if format == Format::Json {
                crate::rendering::emit_published(
                    invocation,
                    output::contract::Command::Fuzz,
                    output::envelope::Published::<output::fuzz::Report>::try_from(report)
                        .map_err(CliError::classified)?,
                )
            } else {
                rendering::render_text(
                    invocation,
                    output::envelope::Published::try_from(report).map_err(CliError::classified)?,
                    stream.presentation(),
                )
            }
        }
    }
}

fn execute_live(
    invocation: &crate::invocation::Invocation,
    packet: core::packet::Packet,
    live: PreparedLive,
    format: Format,
    stream: &StreamEncoder,
) -> Result<(), CliError> {
    let PreparedLive { request, workflow } = live;
    let client = workflow.client(invocation, Runtime::Fuzz);
    let request = packetcraftr::fuzz::Request {
        packet,
        route: workflow.route,
        collection: workflow.collection,
        ..request
    };
    match format {
        Format::Ndjson => {
            let emit = crate::commands::execution::emitter(invocation, |event, stream| {
                let event = output::fuzz::Event::try_from(event).map_err(CliError::classified)?;
                Ok(stream.emit_data(event, Vec::new())?)
            });
            let summary = client
                .fuzz(request.clone(), emit)
                .map_err(CliError::classified)?;
            invocation.check()?;
            rendering::render_live_complete(summary, stream)
        }
        _ => {
            let report = {
                let collector = packetcraftr::fuzz::Collector::default();
                let report = client
                    .fuzz(request.clone(), collector.clone())
                    .map_err(CliError::classified)?;
                collector.finish(report)
            };
            invocation.check()?;
            if format == Format::Json {
                crate::rendering::emit_published(
                    invocation,
                    output::contract::Command::Fuzz,
                    output::envelope::Published::<output::fuzz::Report>::try_from(report)
                        .map_err(CliError::classified)?,
                )
            } else {
                rendering::render_text(
                    invocation,
                    output::envelope::Published::try_from(report).map_err(CliError::classified)?,
                    stream.presentation(),
                )
            }
        }
    }
}

fn publish_offline(
    invocation: &crate::invocation::Invocation,
    request: &core::fuzz::Request,
    packet: core::packet::Packet,
    registry: Arc<core::registry::Registry>,
    mut emit: impl packetcraftr::Sink<core::fuzz::Case, Ack = ()>,
) -> Result<core::fuzz::Summary, core::fuzz::Error> {
    let runtime = crate::system::runtime(invocation, Runtime::Fuzz);
    if emit.delivery() == packetcraftr::Delivery::Cooperative {
        return core::fuzz::run_observed(request, packet, registry, |case, deadline| {
            let control = deadline.detach()?;
            control.enforce()?;
            let result = emit
                .publish_controlled(case, &control)
                .map_err(|source| core::fuzz::Error::Output { source });
            control.enforce()?;
            result
        });
    }
    let worker = packetcraftr::runtime::Worker::new_in(
        &runtime,
        move |(case, control): (core::fuzz::Case, core::budget::Deadline)| {
            emit.publish_controlled(case, &control)
        },
    )
    .map_err(|source| core::fuzz::Error::Output { source })?;
    core::fuzz::run_observed(request, packet, registry, |case, deadline| {
        let control = deadline.detach()?;
        worker
            .emit((case, control.clone()), &control)
            .map_err(|error| match error {
                packetcraftr::runtime::Error::Deadline(error) => error.into(),
                packetcraftr::runtime::Error::Output(source) => {
                    core::fuzz::Error::Output { source }
                }
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
