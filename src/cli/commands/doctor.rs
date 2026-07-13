// Passive environment diagnostics and an explicitly requested zero-transmit
// capture-readiness probe.

fn run_doctor(arguments: DoctorArgs, output: OutputFormat) -> Result<(), CliError> {
    let DoctorArgs {
        interface,
        probe_capture,
        require,
    } = arguments;

    let interface_result = SystemInterfaceProvider.interfaces();
    let (interfaces, interface_error) = match interface_result {
        Ok(interfaces) => (interfaces, None),
        Err(error) => (Vec::new(), Some(error)),
    };
    let selected = select_doctor_interface(interface.as_deref(), &interfaces)?;

    let route_provider = SystemRouteProvider;
    let mut route_decisions = Vec::<RouteDecision>::new();
    let mut route_error = None;
    for candidate in interfaces.iter().filter(|candidate| {
        candidate.flags.up
            && selected
                .as_ref()
                .is_none_or(|selected| candidate.id == *selected)
    }) {
        match route_provider.lookup_interface(&candidate.id) {
            Ok(Some(route)) => route_decisions.push(route),
            Ok(None) => {}
            Err(error) => {
                route_error.get_or_insert_with(|| error.to_string());
            }
        }
    }
    route_decisions.sort_by_key(|route| (route.interface.index, route.interface.name.clone()));
    route_decisions.dedup_by(|left, right| left.interface == right.interface);

    let mut capabilities = vec![
        doctor_capability(
            "interfaces",
            if interface_error.is_none() && selected.as_ref().is_none_or(|_| !interfaces.is_empty()) {
                DoctorReadiness::Ready
            } else {
                DoctorReadiness::Unavailable
            },
            interface_error.as_ref().map_or_else(
                || format!("{} interface(s) discovered", interfaces.len()),
                ToString::to_string,
            ),
        ),
        doctor_capability(
            "routes",
            if !cfg!(feature = "native-route") {
                DoctorReadiness::NotBuilt
            } else if route_error.is_none() && !route_decisions.is_empty() {
                DoctorReadiness::Ready
            } else {
                DoctorReadiness::Unavailable
            },
            route_error.clone().unwrap_or_else(|| {
                if cfg!(feature = "native-route") {
                    format!("{} interface-bound route(s) discovered", route_decisions.len())
                } else {
                    "binary was built without native-route".to_owned()
                }
            }),
        ),
        doctor_link_capability("layer2", cfg!(feature = "native-layer2"), &interfaces, selected.as_ref(), true),
        doctor_link_capability("layer3", cfg!(feature = "native-layer3"), &interfaces, selected.as_ref(), false),
        doctor_capability(
            "capture",
            if cfg!(feature = "native-layer2") {
                DoctorReadiness::Unverified
            } else {
                DoctorReadiness::NotBuilt
            },
            if cfg!(feature = "native-layer2") {
                "capture was not opened; pass --probe-capture to verify it".to_owned()
            } else {
                "binary was built without native-layer2 capture".to_owned()
            },
        ),
    ];

    if probe_capture {
        let route = doctor_probe_route(selected.as_ref(), &route_decisions).ok_or_else(|| {
            CliError::from_classification(
                Classification::new(
                    "capability.doctor_capture_route",
                    Kind::Capability,
                    Some("select an up interface with an interface-bound route"),
                ),
                "capture probe requires an available interface-bound route",
                Vec::new(),
            )
        })?;
        probe_doctor_capture(route)?;
        if let Some(capture) = capabilities.iter_mut().find(|entry| entry.name == "capture") {
            capture.status = DoctorReadiness::Ready;
            capture.detail =
                "host-only filtered capture opened, reached readiness, and shut down".to_owned();
        }
    }

    for required in require {
        let name = required.as_str();
        let capability = capabilities
            .iter()
            .find(|capability| capability.name == name)
            .expect("doctor publishes every accepted capability");
        if capability.status != DoctorReadiness::Ready {
            return Err(CliError::from_classification(
                Classification::new(
                    "capability.doctor_required",
                    Kind::Capability,
                    Some("install the required native support or correct the selected device, then retry"),
                ),
                format!(
                    "required doctor capability {name} is {}: {}",
                    capability.status.as_str(),
                    capability.detail
                ),
                Vec::new(),
            ));
        }
    }

    let result = DoctorCommandResult {
        version: env!("CARGO_PKG_VERSION").to_owned(),
        build_target: env!("PACKETCRAFTR_BUILD_TARGET").to_owned(),
        platform: format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH),
        compiled_features: doctor_features(),
        interfaces: InterfacesCommandResult::new(interfaces).interfaces,
        routes: route_decisions.into_iter().map(Into::into).collect(),
        capabilities,
        capture_probe_attempted: probe_capture,
    };
    match output {
        OutputFormat::Text => render_doctor(result),
        OutputFormat::Json => emit_json(&AggregateOutput::success(
            CommandName::Doctor,
            result,
            Vec::new(),
        )),
        _ => Err(CliError::classified(
            OutputContractError::UnsupportedFormat {
                command: CommandName::Doctor,
                format: output,
            },
        )),
    }
}

fn doctor_capability(
    name: &str,
    status: DoctorReadiness,
    detail: impl Into<String>,
) -> DoctorCapabilityOutput {
    DoctorCapabilityOutput {
        name: name.to_owned(),
        status,
        detail: detail.into(),
    }
}

fn doctor_link_capability(
    name: &str,
    built: bool,
    interfaces: &[InterfaceInfo],
    selected: Option<&InterfaceId>,
    layer2: bool,
) -> DoctorCapabilityOutput {
    if !built {
        return doctor_capability(
            name,
            DoctorReadiness::NotBuilt,
            format!("binary was built without native-{name}"),
        );
    }
    let ready = interfaces.iter().any(|interface| {
        interface.flags.up
            && selected.is_none_or(|selected| interface.id == *selected)
            && if layer2 {
                matches!(
                    interface.capability,
                    LinkCapability::Layer2 | LinkCapability::Layer2And3
                )
            } else {
                matches!(
                    interface.capability,
                    LinkCapability::Layer3 | LinkCapability::Layer2And3
                )
            }
    });
    doctor_capability(
        name,
        if ready {
            DoctorReadiness::Ready
        } else {
            DoctorReadiness::Unavailable
        },
        if ready {
            format!("an up interface advertises {name} readiness")
        } else {
            format!("no selected up interface advertises {name} readiness")
        },
    )
}

fn select_doctor_interface(
    selector: Option<&str>,
    interfaces: &[InterfaceInfo],
) -> Result<Option<InterfaceId>, CliError> {
    let Some(selector) = selector else {
        return Ok(None);
    };
    let index = validate_interface_selector("doctor", Some(selector))?;
    interfaces
        .iter()
        .find(|interface| index.map_or(interface.id.name == selector, |index| interface.id.index == index))
        .map(|interface| Some(interface.id.clone()))
        .ok_or_else(|| {
            CliError::classified(LiveIoError::Device {
                interface: selector.to_owned(),
                message: "no interface matches the requested name or index".to_owned(),
            })
        })
}

fn doctor_probe_route(
    selected: Option<&InterfaceId>,
    routes: &[RouteDecision],
) -> Option<PlannedRoute> {
    let decision = routes
        .iter()
        .find(|route| selected.is_none_or(|selected| route.interface == *selected))?
        .clone();
    Some(PlannedRoute {
        packet_source: decision.selected_address.or(decision.preferred_source),
        source_mac: decision.source_mac,
        route: decision,
        mode: LinkMode::Layer2,
        lookup_destination: None,
        final_destination: None,
        visited_destinations: Vec::new(),
        neighbor_source: None,
        neighbor_target: None,
        destination_mac: None,
        neighbor_vlan_tags: Vec::new(),
        synthesized_ethernet: false,
    })
}

fn probe_doctor_capture(route: PlannedRoute) -> Result<(), CliError> {
    probe_doctor_capture_with_provider(&SystemCaptureProvider, route, current_operation())
}

fn probe_doctor_capture_with_provider<P>(
    provider: &P,
    route: PlannedRoute,
    operation: &crate::operation::Context,
) -> Result<(), CliError>
where
    P: crate::net::capture::Provider,
{
    operation
        .cancellation()
        .check()
        .map_err(CliError::classified)?;
    let limits = CaptureQueueLimits {
        max_frames: 1,
        max_bytes: 65_535,
        snap_length: 65_535,
        overflow_policy: CaptureOverflowPolicy::Fail,
    };
    let options = CaptureOptions {
        mode: CaptureMode::HostOnly,
        filter: CaptureFilter::Bpf("ip or ip6".to_owned()),
        discard_unmatched: true,
    };
    let mut capture = provider
        .arm_capture_with_options(&route, limits, options)
        .map_err(CliError::classified)?;
    if let Err(operation) = capture.wait_ready(Duration::from_secs(1)) {
        let mut error = CliError::classified(operation);
        if let Err(cleanup) = capture.shutdown() {
            error = error.with_cleanup(cleanup);
        }
        return Err(error);
    }
    capture.shutdown().map_err(CliError::classified)?;
    operation
        .cancellation()
        .check()
        .map_err(CliError::classified)
}

fn doctor_features() -> Vec<String> {
    let mut features = Vec::new();
    if cfg!(feature = "live") {
        features.push("live".to_owned());
    }
    if cfg!(feature = "native") {
        features.push("native".to_owned());
    }
    if cfg!(feature = "native-route") {
        features.push("native-route".to_owned());
    }
    if cfg!(feature = "native-layer2") {
        features.push("native-layer2".to_owned());
    }
    if cfg!(feature = "native-layer3") {
        features.push("native-layer3".to_owned());
    }
    features
}

fn render_doctor(result: DoctorCommandResult) -> Result<(), CliError> {
    write_stdout_line(format_args!(
        "packetcraftr {} target={} platform={} features={}",
        result.version,
        result.build_target,
        result.platform,
        result.compiled_features.join(",")
    ))?;
    write_stdout_line(format_args!(
        "interfaces={} routes={} capture_probe_attempted={}",
        result.interfaces.len(),
        result.routes.len(),
        result.capture_probe_attempted
    ))?;
    for capability in result.capabilities {
        write_stdout_line(format_args!(
            "{}: {} ({})",
            capability.name,
            capability.status.as_str(),
            capability.detail
        ))?;
    }
    Ok(())
}
