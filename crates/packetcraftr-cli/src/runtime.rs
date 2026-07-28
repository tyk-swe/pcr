// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

// Entrypoint dispatch and live runtime composition.

use std::net::IpAddr;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use packetcraftr::{
    client::{self, Client},
    net::{self, exchange::Composite},
    output,
    packet::{self, Packet},
    protocol, workflow,
};

use super::arguments::{Cli, Command, RouteArgs};
use super::commands::{
    run_build, run_capture, run_dissect, run_dns, run_exchange, run_expert, run_follow, run_fuzz,
    run_interfaces, run_plan, run_protocols, run_read, run_replay, run_routes, run_scan, run_send,
    run_stats, run_traceroute,
};
use super::errors::{CliError, color_choice_from_env, command_from_env, machine_format_from_env};
use super::input::read_recipe;
use super::rendering::{
    emit_json, emit_json_compact, emit_stderr_document, emit_stderr_error, emit_stdout_document,
    terminal_document,
};

pub(super) struct PreparedRouteRequest {
    pub(super) packet: Packet,
    pub(super) destination: Option<IpAddr>,
    pub(super) options: net::route::Options,
    pub(super) policy: client::policy::Policy,
}

#[derive(Debug)]
pub(super) enum DeferredInterface {
    Pending(String),
    Resolved,
}

impl DeferredInterface {
    pub(super) fn new(selector: Option<String>) -> Self {
        match selector {
            Some(selector) => Self::Pending(selector),
            None => Self::Resolved,
        }
    }

    pub(super) fn resolve_into(
        &mut self,
        options: &mut net::route::Options,
    ) -> Result<(), CliError> {
        let Self::Pending(selector) = self else {
            return Ok(());
        };
        options.interface =
            resolve_interface(Some(selector.clone()), &net::interface::SystemProvider)?;
        *self = Self::Resolved;
        Ok(())
    }
}

pub(crate) fn run_entrypoint() -> ExitCode {
    color_choice_from_env().write_global();
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => {
            let code = u8::try_from(error.exit_code()).unwrap_or(70);
            let raw_message = error.to_string();
            let message = terminal_document(&raw_message);
            if error.use_stderr()
                && let Some(output) = machine_format_from_env()
            {
                let error = CliError::new(code, message);
                let emitted = match output {
                    output::contract::Format::Json => {
                        emit_json(&output::envelope::AggregateError::error(
                            command_from_env(),
                            error.output_error(),
                        ))
                    }
                    output::contract::Format::Ndjson => {
                        emit_json_compact(&output::envelope::StreamError::error(
                            command_from_env(),
                            0,
                            error.output_error(),
                        ))
                    }
                    _ => unreachable!("machine_format_from_env returns structured formats"),
                };
                return match emitted {
                    Ok(()) => ExitCode::from(code),
                    Err(write_error) => {
                        let _ = emit_stderr_error(&write_error.message);
                        ExitCode::from(write_error.exit_code)
                    }
                };
            }
            let emitted = if error.use_stderr() {
                emit_stderr_document(&raw_message)
            } else {
                emit_stdout_document(&raw_message)
            };
            return match emitted {
                Ok(()) => ExitCode::from(code),
                Err(_) => ExitCode::from(5),
            };
        }
    };
    cli.color.write_global();
    let output = output::contract::Format::from(cli.output);
    let command = cli.command.name();
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let emitted = match output {
                output::contract::Format::Json => emit_json(
                    &output::envelope::AggregateError::error(Some(command), error.output_error()),
                ),
                output::contract::Format::Ndjson => {
                    emit_json_compact(&output::envelope::StreamError::error(
                        Some(command),
                        error.sequence.unwrap_or(0),
                        error.output_error(),
                    ))
                }
                _ => emit_stderr_error(&error.message),
            };
            if let Err(write_error) = emitted {
                if matches!(
                    output,
                    output::contract::Format::Json | output::contract::Format::Ndjson
                ) {
                    let _ = emit_stderr_error(&write_error.message);
                }
                return ExitCode::from(write_error.exit_code);
            }
            ExitCode::from(error.exit_code)
        }
    }
}

impl Command {
    fn name(&self) -> output::contract::Command {
        match self {
            Self::Build(_) => output::contract::Command::Build,
            Self::Dissect(_) => output::contract::Command::Dissect,
            Self::Protocols(_) => output::contract::Command::Protocols,
            Self::Read(_) => output::contract::Command::Read,
            Self::Interfaces => output::contract::Command::Interfaces,
            Self::Plan(_) => output::contract::Command::Plan,
            Self::Send(_) => output::contract::Command::Send,
            Self::Exchange(_) => output::contract::Command::Exchange,
            Self::Capture(_) => output::contract::Command::Capture,
            Self::Expert(_) => output::contract::Command::Expert,
            Self::Follow(_) => output::contract::Command::Follow,
            Self::Replay(_) => output::contract::Command::Replay,
            Self::Scan(_) => output::contract::Command::Scan,
            Self::Stats(_) => output::contract::Command::Stats,
            Self::Traceroute(_) => output::contract::Command::Traceroute,
            Self::Dns(_) => output::contract::Command::Dns,
            Self::Fuzz(_) => output::contract::Command::Fuzz,
            Self::Routes => output::contract::Command::Routes,
        }
    }
}

pub(super) fn run(cli: Cli) -> Result<(), CliError> {
    let output = output::contract::Format::from(cli.output);
    cli.command
        .name()
        .require_format(output)
        .map_err(CliError::classified)?;
    match cli.command {
        Command::Build(arguments) => run_build(arguments, output),
        Command::Dissect(arguments) => run_dissect(arguments, output),
        Command::Protocols(arguments) => run_protocols(arguments, output),
        Command::Read(arguments) => run_read(arguments, output),
        Command::Interfaces => run_interfaces(output),
        Command::Plan(arguments) => run_plan(arguments, output),
        Command::Send(arguments) => run_send(arguments, output),
        Command::Capture(arguments) => run_capture(arguments, output),
        Command::Expert(arguments) => run_expert(arguments, output),
        Command::Follow(arguments) => run_follow(arguments, output),
        Command::Exchange(arguments) => run_exchange(arguments, output),
        Command::Replay(arguments) => run_replay(arguments, output),
        Command::Scan(arguments) => run_scan(arguments, output),
        Command::Stats(arguments) => run_stats(arguments, output),
        Command::Traceroute(arguments) => run_traceroute(arguments, output),
        Command::Dns(arguments) => run_dns(arguments, output),
        Command::Fuzz(arguments) => run_fuzz(arguments, output),
        Command::Routes => run_routes(output),
    }
}

type SystemPacketIo =
    net::transmit::Dispatch<net::transmit::SystemLayer2, net::transmit::SystemLayer3>;
type SystemExchangeIo = Composite<SystemPacketIo, net::capture::SystemProvider>;
pub(super) type SystemClient =
    Client<net::route::SystemProvider, net::neighbor::SystemResolver, SystemExchangeIo>;

pub(super) fn default_registry_arc() -> Result<Arc<packet::registry::Registry>, CliError> {
    protocol::builtin::registry()
        .map(Arc::new)
        .map_err(|source| {
            CliError::new(70, format!("built-in registry invariant failed: {source}"))
        })
}

pub(super) fn system_client(
    registry: Arc<packet::registry::Registry>,
    policy: client::policy::Policy,
) -> SystemClient {
    Client::new(
        registry,
        net::route::SystemProvider,
        net::neighbor::SystemResolver::default(),
        Composite::new(
            net::transmit::Dispatch::new(net::transmit::SystemLayer2, net::transmit::SystemLayer3),
            net::capture::SystemProvider,
        ),
        policy,
    )
}

pub(super) fn parse_workflow_target(target: String) -> Result<workflow::target::Target, CliError> {
    match target
        .parse::<client::target::Target>()
        .map_err(CliError::classified)?
    {
        client::target::Target::Address(address) => Ok(workflow::target::Target::Address(address)),
        client::target::Target::Hostname(hostname) => {
            Ok(workflow::target::Target::Hostname(hostname.to_string()))
        }
    }
}

pub(super) fn workflow_exchange_options(
    send: client::send::Options,
    timeout: Duration,
    max_template_packets: usize,
    limits: net::capture::Limits,
) -> Result<client::exchange::Options, CliError> {
    let mut options = client::exchange::Options {
        send,
        timeout,
        max_template_packets,
        max_unsolicited: limits.max_frames,
        max_responses: limits.max_frames,
        max_capture_queue_frames: limits.max_frames,
        max_captured_bytes: limits.max_bytes,
        capture_overflow_policy: limits.overflow_policy,
        decode: packet::decode::Options::default(),
    };
    options.decode.max_packet_size = limits.snap_length;
    options.validate().map_err(CliError::classified)?;
    Ok(options)
}

pub(super) fn prepare_route_request(
    arguments: RouteArgs,
    registry: &packet::registry::Registry,
) -> Result<PreparedRouteRequest, CliError> {
    let RouteArgs {
        recipe,
        destination,
        interface,
        source,
        link_mode,
        policy,
    } = arguments;
    let packet = read_recipe(recipe, registry)?;
    let policy = policy.into_policy();
    policy.validate().map_err(CliError::classified)?;
    // This check intentionally precedes interface discovery and route lookup.
    policy
        .authorize_packet_destinations(&packet)
        .map_err(CliError::classified)?;
    let destination = resolve_live_destination(destination, &packet, &policy)?;
    let interface = resolve_interface(interface, &net::interface::SystemProvider)?;
    Ok(PreparedRouteRequest {
        packet,
        destination,
        options: net::route::Options {
            link_mode: link_mode.into(),
            interface,
            preferred_source: source,
        },
        policy,
    })
}

fn resolve_live_destination(
    destination: Option<String>,
    packet: &Packet,
    policy: &client::policy::Policy,
) -> Result<Option<IpAddr>, CliError> {
    let Some(destination) = destination else {
        return Ok(None);
    };
    let target = destination
        .parse::<client::target::Target>()
        .map_err(CliError::classified)?;
    let resolved = policy
        .resolve_target(&target, &client::target::SystemResolver)
        .map_err(CliError::classified)?;
    let ip_version = packet
        .iter()
        .find_map(|layer| match layer.protocol_id().as_str() {
            "ipv4" => Some(client::target::IpVersion::V4),
            "ipv6" => Some(client::target::IpVersion::V6),
            _ => None,
        });
    match ip_version {
        Some(version) => resolved
            .address_for_version(version)
            .map(Some)
            .ok_or_else(|| {
                CliError::classified(client::target::Error::AddressFamilyUnavailable {
                    family: version.label(),
                })
            }),
        None => Ok(Some(resolved.selected_address())),
    }
}

fn resolve_interface<I: net::interface::Provider>(
    selector: Option<String>,
    provider: &I,
) -> Result<Option<net::interface::Id>, CliError> {
    let Some(selector) = selector else {
        return Ok(None);
    };
    let requested_index = validate_interface_selector("route", Some(&selector))?;
    let interfaces = provider.interfaces().map_err(CliError::classified)?;
    interfaces
        .into_iter()
        .find(|interface| {
            requested_index.map_or_else(
                || interface.id.name == selector,
                |index| interface.id.index == index,
            )
        })
        .map(|interface| Some(interface.id))
        .ok_or_else(|| {
            CliError::classified(net::Error::Device {
                interface: selector,
                message: "no interface matches the requested name or index".to_owned(),
            })
        })
}

/// Validates an optional interface selector without consulting a platform
/// provider. Decimal selectors are always indexes: zero and values outside
/// the public `u32` index domain must not fall back to interface-name lookup.
pub(super) fn validate_interface_selector(
    command: &str,
    selector: Option<&str>,
) -> Result<Option<u32>, CliError> {
    let Some(selector) = selector else {
        return Ok(None);
    };
    if selector.is_empty() {
        return Err(CliError::new(
            2,
            format!("{command} interface cannot be empty"),
        ));
    }
    if !selector.bytes().all(|byte| byte.is_ascii_digit()) {
        return Ok(None);
    }
    let index = selector.parse::<u32>().map_err(|_| {
        CliError::new(
            2,
            format!("{command} interface index must be within 1..={}", u32::MAX),
        )
    })?;
    if index == 0 {
        return Err(CliError::new(
            2,
            format!("{command} interface index must be non-zero"),
        ));
    }
    Ok(Some(index))
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use clap::Parser;
    use packetcraftr::{client, net, workflow};

    use super::{
        parse_workflow_target, run, validate_interface_selector, workflow_exchange_options,
    };
    use crate::arguments::Cli;

    #[test]
    fn scan_request_validation_fails_before_route_or_live_io() {
        let cli = Cli::try_parse_from([
            "packetcraftr",
            "scan",
            "192.168.56.10",
            "--transport",
            "icmp",
            "--ports",
            "80",
        ])
        .unwrap();
        let error = run(cli).unwrap_err();
        assert_eq!(error.classification.code, "cli.scan_limit");
        assert!(error.message.contains("ICMP scans are portless"));
    }

    #[test]
    fn dns_request_validation_fails_before_route_or_live_io() {
        let cli =
            Cli::try_parse_from(["packetcraftr", "dns", "10.0.0.53", "bad name.example"]).unwrap();
        let error = run(cli).unwrap_err();
        assert_eq!(error.classification.code, "packet.dns_query");
        assert!(error.message.contains("invalid"));
    }

    #[test]
    fn traceroute_request_validation_fails_before_route_or_live_io() {
        let cli = Cli::try_parse_from([
            "packetcraftr",
            "traceroute",
            "192.168.56.10",
            "--strategy",
            "icmp",
            "--port",
            "80",
        ])
        .unwrap();
        let error = run(cli).unwrap_err();
        assert_eq!(error.classification.code, "cli.traceroute_limit");
        assert!(error.message.contains("ICMP traceroute is portless"));
    }

    #[test]
    fn traceroute_rejects_zero_udp_and_tcp_ports_before_live_io() {
        for strategy in ["udp", "tcp"] {
            let cli = Cli::try_parse_from([
                "packetcraftr",
                "traceroute",
                "192.168.56.10",
                "--strategy",
                strategy,
                "--port",
                "0",
            ])
            .unwrap();
            let error = run(cli).unwrap_err();
            assert_eq!(error.classification.code, "cli.traceroute_limit");
            assert!(
                error
                    .message
                    .contains("UDP and TCP traceroute require a non-zero destination port")
            );
        }
    }

    #[test]
    fn traceroute_rejects_unsupported_output_before_request_validation_or_live_io() {
        let cli = Cli::try_parse_from([
            "packetcraftr",
            "--output",
            "pcap",
            "traceroute",
            "not a valid target",
        ])
        .unwrap();
        let error = run(cli).unwrap_err();
        assert_eq!(error.classification.code, "cli.output_format");
    }

    #[test]
    fn decimal_interface_selectors_never_fall_back_to_names() {
        assert_eq!(
            validate_interface_selector("test", Some("7")).unwrap(),
            Some(7)
        );
        assert_eq!(
            validate_interface_selector("test", Some("eth0")).unwrap(),
            None
        );

        for selector in ["", "0", "4294967296", "999999999999999999999999"] {
            let error = validate_interface_selector("test", Some(selector)).unwrap_err();
            assert_eq!(error.exit_code, 2, "{selector:?}");
        }
    }

    #[test]
    fn workflow_target_parsing_uses_the_shared_client_target_grammar() {
        let address = parse_workflow_target("192.0.2.1".to_owned()).unwrap();
        assert!(matches!(
            address,
            workflow::target::Target::Address(std::net::IpAddr::V4(_))
        ));

        let hostname = parse_workflow_target("example.test".to_owned()).unwrap();
        assert_eq!(
            hostname,
            workflow::target::Target::Hostname("example.test".to_owned())
        );
        assert!(parse_workflow_target("invalid target".to_owned()).is_err());
    }

    #[test]
    fn workflow_exchange_options_share_capture_bounds_and_decode_limit() {
        let limits = net::capture::Limits::default();
        let timeout = Duration::from_millis(25);
        let options =
            workflow_exchange_options(client::send::Options::default(), timeout, 3, limits)
                .unwrap();

        assert_eq!(options.timeout, timeout);
        assert_eq!(options.max_template_packets, 3);
        assert_eq!(options.max_unsolicited, limits.max_frames);
        assert_eq!(options.max_responses, limits.max_frames);
        assert_eq!(options.max_capture_queue_frames, limits.max_frames);
        assert_eq!(options.max_captured_bytes, limits.max_bytes);
        assert_eq!(options.capture_overflow_policy, limits.overflow_policy);
        assert_eq!(options.decode.max_packet_size, limits.snap_length);
    }
}
