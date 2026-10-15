// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::output::contract::Format;

pub(super) mod arguments;
pub(super) mod rendering;

use packetcraftr_netio as net;

use crate::output;

use self::arguments::Args;
use crate::command_options::parse_target;
use crate::errors::CliError;
use crate::rendering::StreamEncoder;
use crate::system::{Runtime, prepare_workflow};

impl super::Spec for Args {
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
        invocation: &crate::invocation::Invocation,
    ) -> Result<super::CommandExit, CliError> {
        let format = invocation.format;
        let stream = &invocation.output;
        run(invocation, self, format, stream).map(|()| super::CommandExit::SUCCESS)
    }
}

pub(super) fn run(
    invocation: &crate::invocation::Invocation,
    arguments: Args,
    format: Format,
    stream: &StreamEncoder,
) -> Result<(), CliError> {
    let queue_limits = arguments.limits.clone().into_limits();
    let request = prepare_request(&arguments, queue_limits)?;
    let workflow = prepare_workflow(
        &arguments.route,
        arguments.policy.into_policy(),
        request.timeout,
        queue_limits,
    )?;
    let client = workflow.client(invocation, Runtime::Workflow);
    let request = packetcraftr::traceroute::Request {
        route: workflow.route,
        collection: workflow.collection,
        ..request
    };
    match format {
        Format::Ndjson => {
            let emit = crate::commands::execution::emitter(invocation, rendering::emit_event);
            let summary = {
                let emit = emit;

                client
                    .traceroute(request.clone(), emit)
                    .map_err(CliError::classified)
            }?;
            invocation.check()?;
            (rendering::emit_complete)(summary, stream)
        }
        format => {
            let report = (|| -> Result<_, CliError> {
                let collector = packetcraftr::traceroute::Collector::default();
                let report = client
                    .traceroute(request.clone(), collector.clone())
                    .map_err(CliError::classified)?;
                collector.finish(report).map_err(CliError::classified)
            })()?;
            invocation.check()?;
            if format == Format::Json {
                crate::rendering::emit_published(
                    invocation,
                    output::contract::Command::Traceroute,
                    {
                        let report = report;

                        output::envelope::Published::<output::traceroute::Report>::try_from(report)
                            .map_err(CliError::classified)
                    }?,
                )
            } else {
                {
                    let report = report;
                    let _ = format;

                    rendering::render_text(
                        invocation,
                        output::envelope::Published::try_from(report)
                            .map_err(CliError::classified)?,
                        stream.presentation(),
                    )
                }
            }
        }
    }
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
        packetcraftr::probe::Transport::Icmp
        | packetcraftr::probe::Transport::Sctp
        | packetcraftr::probe::Transport::Ip => arguments.port,
    };
    let trace_limits = packetcraftr::traceroute::Limits {
        max_probes: arguments.max_probes,
        max_duration: arguments.duration.max_duration(),
        evidence: packetcraftr::evidence::Limits {
            max_frames: queue_limits.max_frames,
            max_bytes: queue_limits.max_bytes,
            max_undecoded: arguments.max_undecoded,
        },
    };
    let request = packetcraftr::traceroute::Request {
        target: parse_target(arguments.target.clone())?,
        strategy,
        address_family: arguments.family.into(),
        destination_port,
        source_port: arguments.source_port,
        payload_size: arguments.payload_size,
        dont_fragment: arguments.dont_fragment,
        dscp: arguments.dscp,
        first_hop: arguments.first_hop,
        max_hops: arguments.max_hops,
        probes_per_hop: arguments.attempts,
        timeout: arguments.timeout.timeout(),
        probes_per_second: arguments.rate,
        limits: trace_limits,
        route: packetcraftr::route::Options::default(),
        collection: packetcraftr::exchange::Collection::default(),
    };
    request.validate().map_err(CliError::classified)?;
    Ok(request)
}
