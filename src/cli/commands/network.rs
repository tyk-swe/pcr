// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

// Route planning, route enumeration, and transmission commands.

fn run_plan(arguments: RouteArgs, output: OutputFormat) -> Result<(), CliError> {
    let registry = default_registry_arc()?;
    let request = prepare_route_request(arguments, &registry)?;
    let client = system_client(Arc::clone(&registry), request.policy);
    let route = client
        .plan(&request.packet, request.destination, &request.options)
        .map_err(CliError::classified)?;
    let result = PlanCommandResult {
        route: route.into(),
    };
    match output {
        OutputFormat::Text => render_planned_route(&result.route),
        OutputFormat::Json => emit_json(&AggregateOutput::success(
            CommandName::Plan,
            result,
            Vec::new(),
        )),
        _ => Err(CliError::classified(
            OutputContractError::UnsupportedFormat {
                command: CommandName::Plan,
                format: output,
            },
        )),
    }
}

fn render_planned_route(route: &crate::output::network::plan::Plan) -> Result<(), CliError> {
    write_stdout_line(format_args!(
        "interface={} index={} mode={:?} mtu={} link_type={}",
        route.route.interface.name,
        route.route.interface.index,
        route.mode,
        route.route.mtu,
        route.route.link_type.0
    ))?;
    write_stdout_line(format_args!(
        "lookup_destination={} final_destination={} source={} next_hop={} destination_mac={}",
        optional_display(route.lookup_destination),
        optional_display(route.final_destination),
        optional_display(route.packet_source),
        optional_display(route.route.next_hop),
        route
            .destination_mac
            .map(|value| value.to_string())
            .unwrap_or_else(|| "unresolved".to_owned())
    ))
}

fn optional_display<T: std::fmt::Display>(value: Option<T>) -> String {
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|| "none".to_owned())
}

fn run_routes(output: OutputFormat) -> Result<(), CliError> {
    let interfaces = SystemInterfaceProvider
        .interfaces()
        .map_err(CliError::classified)?;
    let provider = SystemRouteProvider;
    let mut routes = Vec::new();
    for interface in interfaces
        .into_iter()
        .filter(|interface| interface.flags.up)
    {
        let route = provider.lookup_interface(&interface.id).map_err(|source| {
            CliError::from_classification(
                provider.classify_error(&source),
                source.to_string(),
                Vec::new(),
            )
        })?;
        if let Some(route) = route {
            routes.push(route);
        }
    }
    routes.sort_by_key(|route| (route.interface.index, route.interface.name.clone()));
    routes.dedup_by(|left, right| left.interface == right.interface);
    let result = RoutesCommandResult {
        routes: routes.into_iter().map(Into::into).collect(),
    };
    match output {
        OutputFormat::Text => {
            for route in result.routes {
                write_stdout_line(format_args!(
                    "{} (index {}): source={} mtu={} capability={:?} link_type={}",
                    route.interface.name,
                    route.interface.index,
                    optional_display(route.selected_address.or(route.preferred_source)),
                    route.mtu,
                    route.capability,
                    route.link_type.0
                ))?;
            }
            Ok(())
        }
        OutputFormat::Json => emit_json(&AggregateOutput::success(
            CommandName::Routes,
            result,
            Vec::new(),
        )),
        _ => Err(CliError::classified(
            OutputContractError::UnsupportedFormat {
                command: CommandName::Routes,
                format: output,
            },
        )),
    }
}

fn run_send(arguments: SendArgs, output: OutputFormat) -> Result<(), CliError> {
    let SendArgs {
        route,
        mode,
        allow_permissive_live,
    } = arguments;
    let registry = default_registry_arc()?;
    let request = prepare_route_request(route, &registry)?;
    let client = system_client(Arc::clone(&registry), request.policy);
    let report = client
        .send(
            request.packet,
            SendOptions {
                destination: request.destination,
                plan: request.options,
                build: BuildOptions {
                    mode: cli_build_mode(mode),
                    ..BuildOptions::default()
                },
                allow_permissive_live,
            },
        )
        .map_err(CliError::classified)?;
    let capture_link_type = send_capture_link_type(
        report.route.plan.mode,
        report.route.plan.route.link_type,
    )?;
    let (result, diagnostics, stats) =
        SendCommandResult::try_from_report(report).map_err(CliError::classified)?;
    match output {
        OutputFormat::Text => {
            write_stdout_line(format_args!(
                "sent {} bytes via {} (index {}, {:?})",
                result.frame.length,
                result.route.plan.route.interface.name,
                result.route.plan.route.interface.index,
                result.route.plan.mode
            ))?;
            for diagnostic in diagnostics {
                write_stdout_line(format_args!(
                    "{:?} {}: {}",
                    diagnostic.severity, diagnostic.code, diagnostic.message
                ))?;
            }
            Ok(())
        }
        OutputFormat::Json => emit_json(
            &AggregateOutput::success(CommandName::Send, result, diagnostics).with_stats(stats),
        ),
        OutputFormat::Hex => write_stdout_line(format_args!("{}", result.frame.bytes_hex())),
        OutputFormat::Raw => write_raw(result.frame.bytes()),
        OutputFormat::Pcap | OutputFormat::Pcapng => {
            let frame = Frame::new(
                SystemTime::now(),
                capture_link_type,
                result.frame.bytes().to_vec(),
            )
            .map_err(|source| CliError::new(3, source.to_string()))?;
            write_capture_file(output, [frame])
        }
        _ => Err(CliError::classified(
            OutputContractError::UnsupportedFormat {
                command: CommandName::Send,
                format: output,
            },
        )),
    }
}

fn send_capture_link_type(mode: LinkMode, route_link_type: LinkType) -> Result<LinkType, CliError> {
    match mode {
        LinkMode::Layer2 => Ok(route_link_type),
        LinkMode::Layer3 => Ok(LinkType::RAW),
        LinkMode::Auto => Err(CliError::new(
            70,
            "send result retained an unresolved automatic link mode",
        )),
    }
}
