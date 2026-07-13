// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

// Entrypoint dispatch and live runtime composition.

struct PreparedRouteRequest {
    packet: Packet,
    destination: Option<IpAddr>,
    options: crate::net::PlanOptions,
    policy: TrafficPolicy,
}

pub(crate) fn run_entrypoint() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => {
            let code = if error.use_stderr() { 2 } else { 0 };
            if code != 0 {
                if let Some(output) = machine_format_from_env() {
                    let message = error.to_string();
                    let error = CliError::new(code, message);
                    let emitted = match output {
                        OutputFormat::Json => emit_json(&AggregateErrorOutput::error(
                            command_from_env(),
                            error.output_error(),
                        )),
                        OutputFormat::Ndjson => emit_json_compact(&StreamErrorRecord::error(
                            command_from_env(),
                            0,
                            error.output_error(),
                        )),
                        _ => unreachable!("machine_format_from_env returns structured formats"),
                    };
                    return match emitted {
                        Ok(()) => exit_code(code),
                        Err(write_error) => {
                            let _ = emit_stderr_error(&write_error.message);
                            exit_code(write_error.code)
                        }
                    };
                }
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
    let output = OutputFormat::from(cli.output);
    let command = cli.command.name();
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let emitted = match output {
                OutputFormat::Json => emit_json(&AggregateErrorOutput::error(
                    Some(command),
                    error.output_error(),
                )),
                OutputFormat::Ndjson => emit_json_compact(&StreamErrorRecord::error(
                    Some(command),
                    error.sequence.unwrap_or(0),
                    error.output_error(),
                )),
                _ => emit_stderr_error(&error.message),
            };
            if let Err(write_error) = emitted {
                if matches!(output, OutputFormat::Json | OutputFormat::Ndjson) {
                    let _ = emit_stderr_error(&write_error.message);
                }
                return exit_code(write_error.code);
            }
            exit_code(error.code)
        }
    }
}

impl Command {
    fn name(&self) -> CommandName {
        match self {
            Self::Build(_) => CommandName::Build,
            Self::Dissect(_) => CommandName::Dissect,
            Self::Read(_) => CommandName::Read,
            Self::Interfaces => CommandName::Interfaces,
            Self::Plan(_) => CommandName::Plan,
            Self::Send(_) => CommandName::Send,
            Self::Exchange(_) => CommandName::Exchange,
            Self::Capture(_) => CommandName::Capture,
            Self::Replay(_) => CommandName::Replay,
            Self::Scan(_) => CommandName::Scan,
            Self::Traceroute(_) => CommandName::Traceroute,
            Self::Dns(_) => CommandName::Dns,
            Self::Fuzz(_) => CommandName::Fuzz,
            Self::Routes => CommandName::Routes,
        }
    }
}

fn run(cli: Cli) -> Result<(), CliError> {
    let output = OutputFormat::from(cli.output);
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

type SystemPackets = DispatchPacketIo<SystemLayer2Io, SystemLayer3Io>;
type SystemLiveIo = Composite<SystemPackets, SystemCaptureProvider>;
type SystemClient = Client<SystemRouteProvider, SystemNeighborResolver, SystemLiveIo>;

fn default_registry_arc() -> Result<Arc<crate::packet::internal::ProtocolRegistry>, CliError> {
    crate::protocol::internal::default_registry()
        .map(Arc::new)
        .map_err(|source| {
            CliError::new(70, format!("built-in registry invariant failed: {source}"))
        })
}

fn system_client(
    registry: Arc<crate::packet::internal::ProtocolRegistry>,
    policy: TrafficPolicy,
) -> SystemClient {
    Client::new(
        registry,
        SystemRouteProvider,
        SystemNeighborResolver::default(),
        Composite::new(
            DispatchPacketIo::new(SystemLayer2Io, SystemLayer3Io),
            SystemCaptureProvider,
        ),
        policy,
    )
}

fn prepare_route_request(
    arguments: RouteArgs,
    registry: &crate::packet::internal::ProtocolRegistry,
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
    let interface = resolve_interface(interface, &SystemInterfaceProvider)?;
    Ok(PreparedRouteRequest {
        packet,
        destination,
        options: crate::net::PlanOptions {
            link_mode: link_mode.into(),
            interface,
            preferred_source: source,
        },
        policy,
    })
}

fn resolve_live_destination(
    value: Option<String>,
    packet: &Packet,
    policy: &TrafficPolicy,
) -> Result<Option<IpAddr>, CliError> {
    let Some(value) = value else {
        return Ok(None);
    };
    let target = value.parse::<LiveTarget>().map_err(CliError::classified)?;
    let resolved = policy
        .resolve_target(&target, &SystemHostnameResolver)
        .map_err(CliError::classified)?;
    let family = packet
        .iter()
        .find_map(|layer| match layer.protocol_id().as_str() {
            "ipv4" => Some(true),
            "ipv6" => Some(false),
            _ => None,
        });
    match family {
        Some(ipv4) => resolved.address_for_family(ipv4).map(Some).ok_or_else(|| {
            CliError::classified(crate::client::target::Error::AddressFamilyUnavailable {
                family: if ipv4 { "IPv4" } else { "IPv6" },
            })
        }),
        None => Ok(Some(resolved.selected_address())),
    }
}

fn resolve_interface<I: InterfaceProvider>(
    selector: Option<String>,
    provider: &I,
) -> Result<Option<InterfaceId>, CliError> {
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
            CliError::classified(LiveIoError::Device {
                interface: selector,
                message: "no interface matches the requested name or index".to_owned(),
            })
        })
}

/// Validates an optional interface selector without consulting a platform
/// provider. Decimal selectors are always indexes: zero and values outside
/// the public `u32` index domain must not fall back to interface-name lookup.
fn validate_interface_selector(
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
