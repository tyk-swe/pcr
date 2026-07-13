// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

// Entrypoint dispatch and live runtime composition.

struct PreparedRouteRequest {
    packet: Packet,
    destination: Option<IpAddr>,
    options: crate::net::PlanOptions,
    policy: TrafficPolicy,
}

static PROCESS_OPERATION: std::sync::OnceLock<crate::operation::Context> =
    std::sync::OnceLock::new();

fn current_operation() -> &'static crate::operation::Context {
    #[cfg(test)]
    return PROCESS_OPERATION.get_or_init(|| {
        crate::operation::Context::new(crate::operation::Id::from_bytes([0; 16]))
    });

    #[cfg(not(test))]
    PROCESS_OPERATION
        .get()
        .expect("CLI operation context is installed before command dispatch")
}

#[derive(Debug)]
enum DeferredInterface {
    Pending(String),
    Resolved,
}

impl DeferredInterface {
    fn new(selector: Option<String>) -> Self {
        match selector {
            Some(selector) => Self::Pending(selector),
            None => Self::Resolved,
        }
    }

    fn resolve_into(&mut self, options: &mut crate::net::PlanOptions) -> Result<(), CliError> {
        let Self::Pending(selector) = self else {
            return Ok(());
        };
        options.interface = resolve_interface(
            Some(selector.clone()),
            &SystemInterfaceProvider,
        )?;
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
                && let Some(output) = machine_format_from_env() {
                    let context = best_effort_envelope_context(None);
                    let _ = install_process_context(context.clone());
                    let message = error.to_string();
                    let error = CliError::new(code, message);
                    let emitted = match output {
                        OutputFormat::Json => emit_json(
                            &AggregateErrorOutput::error(command_from_env(), error.output_error())
                                .with_context(&context),
                        ),
                        OutputFormat::Ndjson => emit_json_compact(&StreamRecord::<()>::start(
                            command_from_env(),
                            &context,
                        ))
                        .and_then(|()| {
                            emit_json_compact(&StreamErrorRecord::error(
                                command_from_env(),
                                0,
                                error.output_error(),
                            ))
                        }),
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
    let output = OutputFormat::from(cli.output);
    let command = cli.command.name();
    let operation_id = match cli.operation_id {
        Some(operation_id) => operation_id,
        None => match crate::operation::Id::generate() {
            Ok(operation_id) => operation_id,
            Err(source) => {
                let error = CliError::classified(source);
                let context = best_effort_envelope_context(Some(crate::operation::Id::default()));
                let _ = install_process_context(context.clone());
                let emitted = match output {
                    OutputFormat::Json => emit_json(
                        &AggregateErrorOutput::error(Some(command), error.output_error())
                            .with_context(&context),
                    ),
                    OutputFormat::Ndjson => emit_json_compact(&StreamRecord::<()>::start(
                        Some(command),
                        &context,
                    ))
                    .and_then(|()| {
                        emit_json_compact(&StreamErrorRecord::error(
                            Some(command),
                            0,
                            error.output_error(),
                        ))
                    }),
                    _ => emit_stderr_error(&error.message),
                };
                return match emitted {
                    Ok(()) => exit_code(error.exit_code),
                    Err(write_error) => exit_code(write_error.exit_code),
                };
            }
        },
    };
    let warnings = operator_warnings(&cli.command);
    let operation = crate::operation::Context::new(operation_id);
    if PROCESS_OPERATION.set(operation).is_err() {
        let _ = emit_stderr_error("operation context was already initialized");
        return exit_code(70);
    }
    let context = best_effort_envelope_context(Some(operation_id)).with_diagnostics(warnings.clone());
    if install_process_context(context.clone()).is_err() {
        let _ = emit_stderr_error("structured output context was already initialized");
        return exit_code(70);
    }
    let cancellation = current_operation().cancellation().clone();
    if let Err(error) = install_signal_handlers(cancellation.clone()) {
        let _ = emit_stderr_error(&error.message);
        return exit_code(error.exit_code);
    }
    if output == OutputFormat::Ndjson
        && let Err(error) = emit_json_compact(&StreamRecord::<()>::start(Some(command), &context))
    {
        let _ = emit_stderr_error(&error.message);
        return exit_code(error.exit_code);
    }
    if !matches!(output, OutputFormat::Json | OutputFormat::Ndjson) {
        for warning in &warnings {
            if let Err(error) = emit_stderr_message(&format!(
                "warning: {}: {}",
                warning.code, warning.message
            )) {
                return exit_code(error.exit_code);
            }
        }
    }
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let cancelled = cancellation.reason();
            let cleanup_failed = is_cleanup_failure(&error);
            let emitted = match (output, cancelled.filter(|_| !cleanup_failed)) {
                (OutputFormat::Json, Some(_)) => emit_json(
                    &AggregateErrorOutput::cancelled(Some(command), error.output_error())
                        .with_context(&context),
                ),
                (OutputFormat::Ndjson, Some(_)) => {
                    emit_json_compact(&StreamErrorRecord::cancelled(
                        Some(command),
                        error.sequence.unwrap_or(0),
                        error.output_error(),
                    ))
                }
                (OutputFormat::Json, None) => emit_json(
                    &AggregateErrorOutput::error(Some(command), error.output_error())
                        .with_context(&context),
                ),
                (OutputFormat::Ndjson, None) => emit_json_compact(&StreamErrorRecord::error(
                    Some(command),
                    error.sequence.unwrap_or(0),
                    error.output_error(),
                )),
                (_, _) => emit_stderr_error(&error.message),
            };
            if let Err(write_error) = emitted {
                if matches!(output, OutputFormat::Json | OutputFormat::Ndjson) {
                    let _ = emit_stderr_error(&write_error.message);
                }
                return exit_code(write_error.exit_code);
            }
            exit_code(
                cancelled
                    .filter(|_| !cleanup_failed)
                    .map_or(error.exit_code, crate::operation::CancellationReason::exit_code),
            )
        }
    }
}

fn is_cleanup_failure(error: &CliError) -> bool {
    error.classification.category == crate::error::Category::Cleanup
}

fn operator_warnings(command: &Command) -> Vec<crate::packet::internal::Diagnostic> {
    let mut warnings = Vec::new();
    let capture = match command {
        Command::Capture(arguments) => Some(&arguments.limits),
        Command::Exchange(arguments) => Some(&arguments.limits),
        Command::Scan(arguments) => Some(&arguments.limits),
        Command::Traceroute(arguments) => Some(&arguments.limits),
        Command::Dns(arguments) => Some(&arguments.limits),
        Command::Fuzz(arguments) if arguments.live => Some(&arguments.limits),
        _ => None,
    };
    if capture.is_some_and(|limits| {
        matches!(limits.capture_mode, CliCaptureMode::Promiscuous)
            && !limits.auto_filter
            && limits.capture_filter.is_none()
    }) {
        warnings.push(crate::packet::internal::Diagnostic::warning(
            "capture.promiscuous_unfiltered",
            "promiscuous capture is active without a BPF filter; unrelated interface traffic may be observed",
        ));
    }

    let unthrottled = match command {
        Command::Scan(arguments) => {
            arguments.rate.is_none()
                && usize::try_from(arguments.attempts)
                    .ok()
                    .and_then(|attempts| attempts.checked_mul(arguments.ports.len().max(1)))
                    .is_some_and(|count| count > 1)
        }
        Command::Traceroute(arguments) => {
            arguments.rate.is_none()
                && u32::from(arguments.max_hops.saturating_sub(arguments.first_hop))
                    .saturating_add(1)
                    .saturating_mul(arguments.attempts)
                    > 1
        }
        Command::Dns(arguments) => arguments.rate.is_none() && arguments.attempts > 1,
        Command::Fuzz(arguments) => arguments.live && arguments.rate.is_none() && arguments.cases > 1,
        _ => false,
    };
    if unthrottled {
        warnings.push(crate::packet::internal::Diagnostic::warning(
            "traffic.unthrottled",
            "no active rate ceiling is configured; packets may be sent as quickly as bounded workflow batches complete",
        ));
    }
    warnings
}

fn best_effort_envelope_context(operation_id: Option<crate::operation::Id>) -> EnvelopeContext {
    EnvelopeContext::new(
        operation_id.unwrap_or_default(),
        serde_json::json!({
            "arguments": std::env::args().skip(1).collect::<Vec<_>>()
        }),
    )
}

#[cfg(not(windows))]
fn install_signal_handlers(
    cancellation: crate::operation::Cancellation,
) -> Result<(), CliError> {
    use signal_hook::consts::signal::{SIGINT, SIGTERM};

    let mut signals = signal_hook::iterator::Signals::new([SIGINT, SIGTERM])
        .map_err(|source| CliError::new(70, format!("install signal handlers failed: {source}")))?;
    std::thread::Builder::new()
        .name("packetcraftr-signals".to_owned())
        .spawn(move || {
            let mut first_signal = true;
            for signal in signals.forever() {
                if !first_signal {
                    let _ = signal_hook::low_level::emulate_default_handler(signal);
                    continue;
                }
                first_signal = false;
                let reason = if signal == SIGTERM {
                    crate::operation::CancellationReason::Terminate
                } else {
                    crate::operation::CancellationReason::Interrupt
                };
                cancellation.cancel(reason);
            }
        })
        .map(|_| ())
        .map_err(|source| CliError::new(70, format!("start signal handler failed: {source}")))
}

#[cfg(windows)]
fn install_signal_handlers(
    cancellation: crate::operation::Cancellation,
) -> Result<(), CliError> {
    ctrlc::set_handler(move || {
        cancellation.cancel(crate::operation::CancellationReason::Interrupt);
    })
    .map_err(|source| CliError::new(70, format!("install signal handler failed: {source}")))
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
            Self::Doctor(_) => CommandName::Doctor,
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
        Command::Doctor(arguments) => run_doctor(arguments, output),
    }
}

type SystemPacketIo = DispatchPacketIo<SystemLayer2Io, SystemLayer3Io>;
type SystemExchangeIo = Composite<SystemPacketIo, SystemCaptureProvider>;
type SystemClient = Client<SystemRouteProvider, SystemNeighborResolver, SystemExchangeIo>;

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
    destination: Option<String>,
    packet: &Packet,
    policy: &TrafficPolicy,
) -> Result<Option<IpAddr>, CliError> {
    let Some(destination) = destination else {
        return Ok(None);
    };
    let target = destination
        .parse::<LiveTarget>()
        .map_err(CliError::classified)?;
    let resolved = policy
        .resolve_target(&target, &SystemHostnameResolver)
        .map_err(CliError::classified)?;
    let ip_version = packet
        .iter()
        .find_map(|layer| match layer.protocol_id().as_str() {
            "ipv4" => Some(IpVersion::V4),
            "ipv6" => Some(IpVersion::V6),
            _ => None,
        });
    match ip_version {
        Some(version) => resolved.address_for_version(version).map(Some).ok_or_else(|| {
            CliError::classified(crate::client::target::Error::AddressFamilyUnavailable {
                family: version.label(),
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
