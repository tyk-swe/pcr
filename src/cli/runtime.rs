// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

// Entrypoint dispatch and live runtime composition.

use std::net::IpAddr;
use std::process::ExitCode;
use std::sync::Arc;

use clap::Parser;
use packetcraftr::{
    client::{self, Client},
    net::{self, exchange::Composite},
    output,
    packet::{self, Packet},
    protocol,
};

use super::arguments::{Cli, Command, RouteArgs};
use super::capture::{run_capture, run_exchange};
use super::dns::run_dns;
use super::errors::{CliError, command_from_env, exit_code, machine_format_from_env};
use super::fuzz::run_fuzz;
use super::input::read_recipe;
use super::interfaces::run_interfaces;
use super::network::{run_plan, run_routes, run_send};
use super::offline::{run_build, run_dissect, run_read};
use super::rendering::{emit_json, emit_json_compact, emit_stderr_error, emit_stderr_message};
use super::replay::run_replay;
use super::scan::run_scan;
use super::traceroute::run_traceroute;

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
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => {
            let code = if error.use_stderr() { 2 } else { 0 };
            if code != 0
                && let Some(output) = machine_format_from_env()
            {
                let message = error.to_string();
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
                    Ok(()) => exit_code(code),
                    Err(write_error) => {
                        let _ = emit_stderr_error(&write_error.message);
                        exit_code(write_error.exit_code)
                    }
                };
            }
            return if code == 0 {
                if error.print().is_ok() {
                    ExitCode::SUCCESS
                } else {
                    exit_code(5)
                }
            } else {
                match emit_stderr_message(&error.to_string()) {
                    Ok(()) => exit_code(code),
                    Err(_) => exit_code(5),
                }
            };
        }
    };
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
                return exit_code(write_error.exit_code);
            }
            exit_code(error.exit_code)
        }
    }
}

impl Command {
    fn name(&self) -> output::contract::Command {
        match self {
            Self::Build(_) => output::contract::Command::Build,
            Self::Dissect(_) => output::contract::Command::Dissect,
            Self::Read(_) => output::contract::Command::Read,
            Self::Interfaces => output::contract::Command::Interfaces,
            Self::Plan(_) => output::contract::Command::Plan,
            Self::Send(_) => output::contract::Command::Send,
            Self::Exchange(_) => output::contract::Command::Exchange,
            Self::Capture(_) => output::contract::Command::Capture,
            Self::Replay(_) => output::contract::Command::Replay,
            Self::Scan(_) => output::contract::Command::Scan,
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
        Command::Read(arguments) => run_read(arguments, output),
        Command::Interfaces => run_interfaces(output),
        Command::Plan(arguments) => run_plan(arguments, output),
        Command::Send(arguments) => run_send(arguments, output),
        Command::Capture(arguments) => run_capture(arguments, output),
        Command::Exchange(arguments) => run_exchange(arguments, output),
        Command::Replay(arguments) => run_replay(arguments, output),
        Command::Scan(arguments) => run_scan(arguments, output),
        Command::Traceroute(arguments) => run_traceroute(arguments, output),
        Command::Dns(arguments) => run_dns(arguments, output),
        Command::Fuzz(arguments) => run_fuzz(arguments, output),
        Command::Routes => run_routes(output),
    }
}

type SystemPacketIo =
    net::transmit::Dispatch<net::transmit::SystemLayer2, net::transmit::SystemLayer3>;
type SystemExchangeIo = Composite<SystemPacketIo, net::capture::SystemProvider>;
type SystemClient =
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
