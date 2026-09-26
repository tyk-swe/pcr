// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Traceroute CLI command logic.

use crate::output::contract::ToolFormat;

use packetcraftr_core::error::Kind;

pub(super) mod arguments;
mod rendering;

use packetcraftr_netio as net;

use crate::output;

use self::arguments::Args;
use super::execution;
use crate::errors::CliError;
use crate::input::parse_target;
use crate::rendering::StreamEncoder;

impl super::Spec for Args {
    type Format = crate::output::contract::ToolFormat;
    const CANCELLATION: bool = true;

    fn publication_duration(&self) -> Option<std::time::Duration> {
        Some(self.duration.max_duration())
    }

    fn resources(&self, settings: &mut crate::resources::Settings<'_>) {
        crate::resources::declare!(settings, self, [
            max_hops: Count @ Operation,
            max_probes: Count @ Operation,
            max_undecoded: Count @ ResultRetention,
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
    let queue_limits = arguments.limits.clone().into_limits();
    let request = prepare_request(&arguments, queue_limits)?;
    let max_template_packets = usize::try_from(arguments.attempts).map_err(|_| {
        CliError::new(
            Kind::Usage,
            "traceroute attempt count exceeds the platform size limit",
        )
    })?;
    let mut providers = execution::prepare(
        arguments.route,
        arguments.policy,
        request.timeout,
        max_template_packets,
        queue_limits,
    )?;
    let mut session = providers.session();
    execution::run_workflow(
        &mut session,
        format,
        stream,
        crate::cancellation::signal(),
        execution::Hooks {
            command: output::contract::Command::Traceroute,
            run: Box::new(|session| {
                packetcraftr::traceroute::run(
                    &request,
                    &mut session.authorizer,
                    session.registry,
                    session.executor,
                    &mut session.clock,
                )
                .map_err(CliError::classified)
            }),
            run_with_events: Box::new(|session, emit| {
                packetcraftr::traceroute::run_with_events(
                    &request,
                    &mut session.authorizer,
                    session.registry,
                    session.executor,
                    &mut session.clock,
                    session.runtime,
                    emit,
                )
                .map_err(CliError::classified)
            }),
            on_event: rendering::emit_event,
            into_result: Box::new(|report| {
                output::envelope::Published::<output::traceroute::Report>::try_from(report)
                    .map_err(CliError::classified)
            }),
            render_text: Box::new(|report, _| {
                rendering::render_text(
                    output::envelope::Published::try_from(report).map_err(CliError::classified)?,
                )
            }),
            complete: rendering::emit_complete,
        },
    )
}

fn prepare_request(
    arguments: &Args,
    queue_limits: net::capture::Limits,
) -> Result<packetcraftr::traceroute::Request, CliError> {
    let strategy: packetcraftr::probe::Transport = arguments.strategy.into();
    let destination_port = match strategy {
        packetcraftr::probe::Transport::Udp => Some(
            arguments
                .port
                .unwrap_or(packetcraftr::traceroute::DEFAULT_UDP_PORT),
        ),
        packetcraftr::probe::Transport::Tcp => Some(
            arguments
                .port
                .unwrap_or(packetcraftr::traceroute::DEFAULT_TCP_PORT),
        ),
        packetcraftr::probe::Transport::Icmp => arguments.port,
    };
    let trace_limits = packetcraftr::traceroute::Limits {
        max_probes: arguments.max_probes,
        max_duration: arguments.duration.max_duration(),
        max_evidence_frames: queue_limits.max_frames,
        max_evidence_bytes: queue_limits.max_bytes,
        max_undecoded: arguments.max_undecoded,
    };
    let request = packetcraftr::traceroute::Request {
        target: parse_target(arguments.target.clone())?,
        strategy,
        address_family: arguments.family.into(),
        destination_port,
        source_port: arguments.source_port,
        first_hop: arguments.first_hop,
        max_hops: arguments.max_hops,
        probes_per_hop: arguments.attempts,
        timeout: arguments.timeout.timeout(),
        probes_per_second: arguments.rate,
        limits: trace_limits,
    };
    request.validate().map_err(CliError::classified)?;
    Ok(request)
}
