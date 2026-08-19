// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Fuzz CLI command logic.

pub(super) mod arguments;
mod execution;
mod rendering;

use std::sync::Arc;
use std::time::Duration;

use packetcraftr::{core, netio as net, output};

use self::arguments::Args;
use super::registry;
use crate::errors::CliError;
use crate::input::read_recipe;
use crate::rendering::NdjsonStream;
use crate::system::{DeferredInterface, client, exchange, validate_selector};

use execution::Executor;

struct PreparedLive {
    options: packetcraftr::fuzz::LiveOptions,
    policy: packetcraftr::policy::Policy,
    exchange: packetcraftr::exchange::Options,
    interface: Option<String>,
}

pub(super) fn run(
    arguments: Args,
    format: output::contract::Format,
    stream: &mut NdjsonStream,
) -> Result<(), CliError> {
    let request = prepare_request(&arguments)?;
    let live = prepare_live(&arguments, &request)?;
    let registry = registry()?;
    let packet = read_recipe(arguments.recipe, &registry)?;
    execute_and_render(request, packet, registry, live, format, stream)
}

fn prepare_request(arguments: &Args) -> Result<core::fuzz::Request, CliError> {
    let targets = arguments
        .fields
        .iter()
        .map(|field| {
            field
                .parse::<core::fuzz::Target>()
                .map_err(|source| CliError::new(2, source.to_string()))
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
        allow_malformed_live: arguments.allow_malformed_live,
        limits: packetcraftr::fuzz::LiveLimits {
            max_evidence_frames: queue_limits.max_frames,
            max_evidence_bytes: queue_limits.max_bytes,
        },
    }
    .validate()
    .map_err(classified_error)?;
    let policy = arguments.policy.clone().into_policy();
    policy.validate().map_err(CliError::classified)?;
    validate_selector(arguments.route.interface.as_deref()).map(|_| ())?;
    let exchange = exchange::options(
        packetcraftr::send::Options {
            destination: arguments.destination,
            plan: net::route::Options {
                link_mode: arguments.route.link_mode.into(),
                interface: None,
                preferred_source: arguments.route.source,
            },
            build: request.build.clone(),
            allow_permissive_live: arguments.allow_malformed_live,
        },
        Duration::from_millis(arguments.timeout_ms),
        1,
        queue_limits,
    )?;
    Ok(Some(PreparedLive {
        options,
        policy,
        exchange,
        interface: arguments.route.interface.clone(),
    }))
}

fn execute_and_render(
    request: core::fuzz::Request,
    packet: core::Packet,
    registry: Arc<core::registry::Registry>,
    live: Option<PreparedLive>,
    format: output::contract::Format,
    stream: &mut NdjsonStream,
) -> Result<(), CliError> {
    let mut observer = Observer::new(format, stream);
    if let Some(live) = live {
        let mut executor = Executor {
            client: client(Arc::clone(&registry), live.policy.clone()),
            exchange: live.exchange,
            interface: DeferredInterface::new(live.interface),
        };
        let mut authorizer = packetcraftr::fuzz::PolicyAuthorizer::new(&live.policy);
        let mut clock = packetcraftr::clock::SystemClock;
        let summary = packetcraftr::fuzz::run_with_events(
            &request,
            live.options,
            packet,
            registry,
            &mut authorizer,
            &mut executor,
            &mut clock,
            |event| {
                observer
                    .observe_live(request.seed, event)
                    .map_err(CliError::into_boundary_error)
            },
        )
        .map_err(classified_error)?;
        observer.finish_live(summary, format)
    } else {
        let summary = core::fuzz::run_with_events(&request, packet, registry, |event| {
            observer
                .observe_offline(request.seed, event)
                .map_err(CliError::into_boundary_error)
        })
        .map_err(CliError::classified)?;
        observer.finish_offline(summary, format)
    }
}

struct Observer<'a> {
    stream: Option<&'a mut NdjsonStream>,
    cases: Vec<output::fuzz::Case>,
}

impl<'a> Observer<'a> {
    fn new(format: output::contract::Format, stream: &'a mut NdjsonStream) -> Self {
        Self {
            stream: (format == output::contract::Format::Ndjson).then_some(stream),
            cases: Vec::new(),
        }
    }

    fn observe_offline(
        &mut self,
        operation_seed: u64,
        event: core::fuzz::Event,
    ) -> Result<(), CliError> {
        let event = output::fuzz::Event::try_from_offline(operation_seed, event)
            .map_err(CliError::classified)?;
        self.observe(event)
    }

    fn observe_live(
        &mut self,
        operation_seed: u64,
        event: packetcraftr::fuzz::Event,
    ) -> Result<(), CliError> {
        let event = output::fuzz::Event::try_from_live(operation_seed, event)
            .map_err(CliError::classified)?;
        self.observe(event)
    }

    fn observe(&mut self, event: output::fuzz::Event) -> Result<(), CliError> {
        if let Some(stream) = self.stream.as_deref_mut() {
            return rendering::render_event(event, stream);
        }
        let output::fuzz::Event::Case { case, .. } = event else {
            unreachable!("execution observers receive only fuzz case events")
        };
        self.cases.push(*case);
        Ok(())
    }

    fn finish_offline(
        self,
        summary: core::fuzz::Summary,
        format: output::contract::Format,
    ) -> Result<(), CliError> {
        if let Some(stream) = self.stream {
            return rendering::render_offline_complete(&summary, stream);
        }
        let result = output::fuzz::Result::from_offline_events(&summary, self.cases);
        let stats = (&summary.stats).into();
        render_collected(result, summary.diagnostics, stats, format)
    }

    fn finish_live(
        self,
        summary: packetcraftr::fuzz::Summary,
        format: output::contract::Format,
    ) -> Result<(), CliError> {
        if let Some(stream) = self.stream {
            return rendering::render_live_complete(&summary, stream);
        }
        let result = output::fuzz::Result::from_live_events(&summary, self.cases);
        let stats = (&summary.stats).into();
        render_collected(result, summary.diagnostics, stats, format)
    }
}

fn render_collected(
    result: output::fuzz::Result,
    diagnostics: Vec<core::diagnostic::Diagnostic>,
    stats: output::envelope::Stats,
    format: output::contract::Format,
) -> Result<(), CliError> {
    match format {
        output::contract::Format::Text => rendering::render_text(result, diagnostics, stats),
        output::contract::Format::Json => rendering::render_aggregate(result, diagnostics, stats),
        _ => unreachable!("fuzz format is checked before command dispatch"),
    }
}

pub(crate) fn classified_error(error: packetcraftr::fuzz::Error) -> CliError {
    CliError::classified(error)
}
