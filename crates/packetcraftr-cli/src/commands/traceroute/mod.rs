// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Traceroute CLI command logic.

use packetcraftr::core::error::Kind;

pub(super) mod arguments;
mod rendering;

use std::time::Duration;

use packetcraftr::{core, netio as net, output};

use self::arguments::Args;
use super::execution::Executor;
use super::format::ToolFormat;
use super::target_workflow::{self, Document, TargetWorkflow};
use crate::errors::CliError;
use crate::input::parse_target;
use crate::rendering::StreamEncoder;

pub(super) fn run(
    arguments: Args,
    format: output::contract::Format,
    stream: &StreamEncoder,
) -> Result<(), CliError> {
    let format = ToolFormat::narrow(output::contract::Command::Traceroute, format)?;
    let queue_limits = arguments.limits.clone().into_limits();
    let request = prepare_request(&arguments, queue_limits)?;
    let max_template_packets = usize::try_from(arguments.attempts).map_err(|_| {
        CliError::new(
            Kind::Cli,
            "traceroute attempt count exceeds the platform size limit",
        )
    })?;
    let mut providers = target_workflow::prepare(
        arguments.route,
        arguments.policy,
        request.timeout,
        max_template_packets,
        queue_limits,
    )?;
    target_workflow::run::<Traceroute>(&request, &mut providers, format, stream)
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
                .unwrap_or(packetcraftr::traceroute::DEFAULT_UDP_PORT),
        ),
        packetcraftr::traceroute::Strategy::Tcp => Some(
            arguments
                .port
                .unwrap_or(packetcraftr::traceroute::DEFAULT_TCP_PORT),
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
    request.validate().map_err(CliError::classified)?;
    Ok(request)
}

/// The `traceroute` workflow.
pub(super) struct Traceroute;

impl TargetWorkflow for Traceroute {
    const COMMAND: output::contract::Command = output::contract::Command::Traceroute;

    type Request = packetcraftr::traceroute::Request;
    type Event = packetcraftr::traceroute::Event;
    type Summary = packetcraftr::traceroute::Summary;
    type Document = output::traceroute::Report;
    type Record = output::traceroute::Event;

    fn execute(
        request: &Self::Request,
        authorizer: &mut impl packetcraftr::target::Authorizer,
        registry: &core::registry::Registry,
        executor: &mut Executor,
        clock: &mut impl packetcraftr::clock::Clock,
    ) -> Result<Document<Self::Document>, CliError> {
        let result = packetcraftr::traceroute::run(request, authorizer, registry, executor, clock)
            .map_err(CliError::classified)?;
        let (result, diagnostics, stats) = output::traceroute::Report::try_from_traceroute(result)
            .map_err(CliError::classified)?;
        Ok(Document::new(result, diagnostics, stats))
    }

    fn stream(
        request: &Self::Request,
        authorizer: &mut impl packetcraftr::target::Authorizer,
        registry: &core::registry::Registry,
        executor: &mut Executor,
        clock: &mut impl packetcraftr::clock::Clock,
        runtime: &packetcraftr::progress::Runtime,
        stream: &StreamEncoder,
    ) -> Result<(), CliError> {
        let event_stream = stream.clone();
        let summary = packetcraftr::traceroute::run_with_events(
            request,
            authorizer,
            registry,
            executor,
            clock,
            runtime,
            move |event| {
                Self::emit_event(event, &event_stream).map_err(CliError::into_boundary_error)
            },
        )
        .map_err(CliError::classified)?;
        Self::emit_complete(summary, stream)
    }

    fn render_text(document: Document<Self::Document>) -> Result<(), CliError> {
        rendering::render_text(document.result, document.diagnostics, document.stats)
    }

    fn convert_event(
        event: Self::Event,
    ) -> Result<(Self::Record, Vec<core::diagnostic::Diagnostic>), CliError> {
        output::traceroute::Event::try_from_traceroute(event).map_err(CliError::classified)
    }

    fn convert_complete(
        summary: Self::Summary,
    ) -> Result<
        (
            Self::Record,
            Vec<core::diagnostic::Diagnostic>,
            output::envelope::Stats,
        ),
        CliError,
    > {
        Ok(output::traceroute::Event::complete_from_traceroute(summary))
    }
}
