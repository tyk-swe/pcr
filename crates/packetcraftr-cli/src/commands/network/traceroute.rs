// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::output::contract::Format;

pub(in crate::commands) mod arguments;
mod multipath;
pub(super) mod rendering;

use packetcraftr_netio as net;

use crate::output;

use self::arguments::Args;
use crate::command_options::parse_target;
use crate::errors::CliError;
use crate::invocation::StreamEncoder;
use crate::system::{Runtime, prepare_workflow};

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
            max_hops: Count @ Operation,
            max_probes: Count @ Operation,
            max_undecoded: Count @ ResultRetention,
        ]);
        settings.declare(crate::resources::Field {
            id: "flows",
            value: crate::resources::SettingValue::setting_value(&u32::from(
                self.flows
                    .unwrap_or(packetcraftr::traceroute::multipath::DEFAULT_FLOWS),
            )),
            unit: crate::resources::Unit::Count,
            stage: crate::resources::Stage::Operation,
            enabled: self.multipath.into(),
            preset: None,
        });
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
    if arguments.multipath {
        return multipath::run(
            invocation,
            &client,
            packetcraftr::traceroute::multipath::Request {
                trace: request,
                flows: arguments
                    .flows
                    .unwrap_or(packetcraftr::traceroute::multipath::DEFAULT_FLOWS),
            },
            format,
            stream,
        );
    }
    match format {
        Format::Ndjson => {
            let emit = crate::commands::execution::emitter(invocation, rendering::emit_event);
            let summary = client
                .traceroute(request.clone(), emit)
                .map_err(CliError::classified)?;
            invocation.check()?;
            rendering::emit_complete(summary, stream)
        }
        _ => {
            let report = {
                let collector = packetcraftr::traceroute::Collector::default();
                let report = client
                    .traceroute(request.clone(), collector.clone())
                    .map_err(CliError::classified)?;
                collector.finish(report).map_err(CliError::classified)?
            };
            invocation.check()?;
            if format == Format::Json {
                crate::rendering::emit_published(
                    invocation,
                    output::contract::Command::Traceroute,
                    output::envelope::Published::<output::traceroute::Report>::try_from(report)
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
    if arguments.multipath {
        let mut trace = request.clone();
        trace.collection = crate::system::collection(trace.timeout, queue_limits)?;
        packetcraftr::traceroute::multipath::Request {
            trace,
            flows: arguments
                .flows
                .unwrap_or(packetcraftr::traceroute::multipath::DEFAULT_FLOWS),
        }
        .validate()
        .map_err(CliError::classified)?;
    } else {
        request.validate().map_err(CliError::classified)?;
    }
    Ok(request)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::{CommandFactory, FromArgMatches};

    fn arguments(extra: &[&str]) -> Result<Args, clap::Error> {
        let mut argv = vec!["packetcraftr", "network", "traceroute", "10.0.0.9"];
        argv.extend_from_slice(extra);
        let matches = crate::app::cli::Cli::command().try_get_matches_from(argv)?;
        let matches = matches
            .subcommand_matches("network")
            .unwrap()
            .subcommand_matches("traceroute")
            .unwrap();
        Args::from_arg_matches(matches)
    }

    #[test]
    fn multipath_arguments_require_opt_in_and_preserve_legacy_defaults() {
        assert!(arguments(&["--flows", "2"]).is_err());
        assert!(arguments(&["--multipath", "--flows", "65"]).is_err());
        assert!(arguments(&["--multipath", "--flows", "0"]).is_err());
        let legacy = arguments(&[]).unwrap();
        assert!(!legacy.multipath);
        assert!(legacy.flows.is_none());
        let mut args = arguments(&[
            "--multipath",
            "--flows",
            "1",
            "--attempts",
            "3",
            "--max-undecoded",
            "1",
        ])
        .unwrap();
        let mut limits = args.limits.clone().into_limits();
        limits.max_frames = 1;
        // Three sweeps require capacity for one concurrent flow, not three attempts.
        assert!(prepare_request(&args, limits).is_ok());
        args.source_port = Some(u16::MAX);
        args.flows = Some(2);
        assert!(prepare_request(&args, args.limits.clone().into_limits()).is_err());
    }
}
