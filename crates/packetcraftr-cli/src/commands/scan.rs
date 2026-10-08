// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

pub(super) mod arguments;
mod connect;
mod list;
mod payload;
mod profiles;
mod rendering;
mod reverse;

use crate::output::contract::Format;

use crate::output;

use packetcraftr_core::error::{Classified, Kind};

use std::time::Instant;

use packetcraftr::probe::{ProbeEndpoint, Transport};
use packetcraftr::scan::{discovery, method, profile::curated};

use self::arguments::Args;
use super::execution;
use crate::command_options::parse_target;
use crate::errors::CliError;
use crate::input::manifest;
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
            max_in_flight: Count @ Operation,
            max_targets: Count @ Operation,
            max_ports: Count @ Operation,
            max_probes: Count @ Operation,
            max_undecoded: Count @ ResultRetention,
            max_prepared_bytes: Bytes @ Preparation,
        ]);
        self.timeout.resources(settings);
        self.duration.resources(settings);
        self.limits.resources(settings);
        self.policy.resources(settings);
    }

    fn run(
        self,
        format: Format,
        stream: &crate::rendering::StreamEncoder,
    ) -> Result<super::CommandExit, CliError> {
        run(self, format, stream).map(|()| super::CommandExit::SUCCESS)
    }
}

pub(super) fn run(arguments: Args, format: Format, stream: &StreamEncoder) -> Result<(), CliError> {
    let Args {
        connect,
        method,
        max_in_flight,
        max_prepared_bytes,
        list,
        targets,
        targets_file,
        exclude_file,
        max_manifest_bytes,
        max_manifest_lines,
        exclusions,
        max_targets,
        transport,
        udp_payload_hex,
        udp_payload_file,
        udp_profiles,
        family,
        ports,
        exclude_ports,
        discovery,
        discovery_probes,
        discovery_ports,
        unresponsive_hosts,
        reverse_dns,
        reverse_dns_port,
        attempts,
        timeout,
        rate,
        max_ports,
        max_probes,
        duration,
        max_undecoded,
        curated_udp_payloads,
        route,
        limits,
        policy,
    } = arguments;
    let requested = if connect {
        method::Requested::Connect
    } else {
        method.into()
    };
    let transports = transports(&transport)?;
    let stdin_consumers = targets_file
        .iter()
        .chain(exclude_file.iter())
        .filter(|path| manifest::is_stdin(path))
        .count()
        + usize::from(udp_payload_file.as_deref().is_some_and(manifest::is_stdin))
        + usize::from(udp_profiles.as_deref().is_some_and(manifest::is_stdin));
    if stdin_consumers > 1 {
        return Err(CliError::new(
            Kind::Usage,
            "stdin (`-`) can supply at most one of --targets-file, --exclude-file, --udp-payload-file, or --udp-profiles",
        ));
    }
    let selection = ingest_targets(
        &targets,
        &targets_file,
        &exclusions,
        &exclude_file,
        max_manifest_bytes,
        max_manifest_lines,
    )?;
    selection.targets.validate().map_err(CliError::classified)?;
    let targets = selection.targets;
    if list {
        if discovery.is_some() || reverse_dns.is_some() {
            return Err(CliError::new(
                Kind::Usage,
                "--list sends no probe; remove --discovery and --reverse-dns",
            ));
        }
        // Listing needs no ports, but publishes the selection when given one
        // so the reviewed scope is exactly what a scan would probe.
        let ports = if ports.is_empty() && exclude_ports.is_empty() {
            None
        } else {
            let selected = select_endpoints(&transports, ports, exclude_ports, max_ports)?;
            Some(output::scan::plan::Ports::from(&selected))
        };
        return list::run(
            targets,
            list::Options {
                origins: selection.origins,
                ports,
                family,
                max_targets,
                max_duration: duration.max_duration(),
                policy,
            },
            format,
            stream,
        );
    }
    let (discovery, discovery_excluded) = discovery_options(
        discovery,
        &discovery_probes,
        discovery_ports,
        &exclude_ports,
        unresponsive_hosts,
        max_ports,
    )?;
    let scanning = discovery.mode != discovery::Mode::Only;
    let udp = (scanning && transports.contains(&Transport::Udp))
        || discovery
            .probes
            .iter()
            .any(|probe| probe.transport() == Transport::Udp);
    let udp_payload = payload::read(udp, udp_payload_hex.as_deref(), udp_payload_file.as_deref())?;
    let operator_profiles = profiles::load(udp_profiles.as_deref(), udp)?;
    if curated_udp_payloads && !udp {
        return Err(CliError::new(
            Kind::Usage,
            "--curated-udp-payloads requires UDP scan or discovery probes",
        ));
    }
    let queue_limits = limits.into_limits();
    let scan_limits = packetcraftr::scan::Limits {
        max_prepared_bytes,
        max_targets,
        max_ports,
        max_probes,
        max_duration: duration.max_duration(),
        max_evidence_frames: queue_limits.max_frames,
        max_evidence_bytes: queue_limits.max_bytes,
        max_undecoded,
    };
    scan_limits.validate().map_err(CliError::classified)?;
    let selected = if scanning {
        select_endpoints(&transports, ports, exclude_ports, max_ports)?
    } else if !ports.is_empty() {
        return Err(CliError::new(
            Kind::Usage,
            "--discovery only probes no scan port; remove --ports",
        ));
    } else {
        packetcraftr::scan::Selected {
            endpoints: Vec::new(),
            excluded: 0,
        }
    };
    let (udp_profiles, curated) = if curated_udp_payloads {
        let mut planned = selected.endpoints.clone();
        for probe in &discovery.probes {
            if !planned.contains(probe) {
                planned.push(*probe);
            }
        }
        let mut merged = curated::merge(operator_profiles, &planned);
        let profiles = std::mem::take(&mut merged.profiles);
        (profiles, Some(merged.into()))
    } else {
        (operator_profiles, None)
    };
    let request = packetcraftr::scan::Request {
        max_in_flight,
        targets,
        target_sources: selection.origins.iter().map(ToString::to_string).collect(),
        udp_payload,
        udp_profiles,
        address_family: family.into(),
        endpoints: selected.endpoints,
        discovery,
        attempts,
        timeout: timeout.timeout(),
        probes_per_second: rate,
        limits: scan_limits,
        route: packetcraftr::route::Options::default(),
        collection: packetcraftr::exchange::Collection::default(),
    };
    let selection = method::select(
        requested,
        &request,
        method::Capabilities {
            raw: raw_capability(route.link_mode.into()),
            packet_route: !route.supports_kernel_tcp(),
        },
    )
    .map_err(CliError::classified)?;
    let selected_method = selection.method;
    let plan = output::scan::plan::Plan {
        method: selection.into(),
        port_catalog: packetcraftr::scan::catalog::data_set().into(),
        excluded_endpoints: selected.excluded,
        curated_udp_payloads: curated,
        discovery: output::scan::plan::Discovery::new(
            &request.discovery,
            discovery_excluded,
            reverse_dns
                .as_ref()
                .map(|server| output::scan::plan::ReverseDnsServer {
                    server: server.clone(),
                    port: reverse_dns_port,
                }),
        ),
    };
    let reverse_dns = reverse_dns.map(parse_target).transpose()?;
    if selected_method == method::Method::Connect {
        let lookup = reverse_dns
            .map(|server| {
                reverse::Lookup::new(
                    server,
                    reverse_dns_port,
                    packetcraftr::dns::TransportMode::Tcp,
                    &request,
                )
            })
            .transpose()?;
        return connect::run(&request, plan, lookup.as_ref(), policy, format, stream);
    }
    let workflow = prepare_workflow(&route, policy.into_policy(), request.timeout, queue_limits)?;
    let client = workflow.client(Runtime::Workflow);
    let request = packetcraftr::scan::Request {
        route: workflow.route,
        collection: workflow.collection,
        ..request
    };
    // DNS over TCP cannot follow a packet route override.
    let lookup = reverse_dns
        .map(|server| {
            let transport = if route.supports_kernel_tcp() {
                packetcraftr::dns::TransportMode::UdpThenTcp
            } else {
                packetcraftr::dns::TransportMode::Udp
            };
            reverse::Lookup::new(server, reverse_dns_port, transport, &request)
        })
        .transpose()?;
    let lookup = lookup.as_ref();
    execution::run_workflow(
        format,
        stream,
        crate::cancellation::signal(),
        execution::Hooks {
            command: output::contract::Command::Scan,
            run: Box::new(|| {
                let started = Instant::now();
                let collector = packetcraftr::scan::Collector::default();
                let report = client
                    .scan(request.clone(), collector.clone())
                    .map_err(rendering::scan_error)?;
                let mut aggregate = collector.finish(report).map_err(rendering::scan_error)?;
                // The lookups' sends, bytes, and time count in this scan's
                // reported statistics.
                let (names, lookups) = reverse::names(lookup, &client, &aggregate.hosts, started);
                aggregate
                    .stats
                    .checked_add_assign(&lookups)
                    .map_err(|error| CliError::caused(Kind::Internal, &error))?;
                Ok((aggregate, names))
            }),
            run_with_events: Box::new({
                let plan = plan.clone();
                let client = &client;
                let request = &request;
                move |mut emit| {
                    let started = Instant::now();
                    // Events stream as they settle; the tracker keeps each
                    // attempt without its frame, for the endpoint inferences.
                    let tracker = packetcraftr::scan::Collector::default();
                    let mut tracked = tracker.clone();
                    let mut report = client
                        .scan(request.clone(), move |event: packetcraftr::scan::Event| {
                            if let packetcraftr::scan::Event::Probe { target, probe } = &event {
                                let probe = packetcraftr::scan::ProbeEvidence {
                                    response: None,
                                    ..probe.clone()
                                };
                                packetcraftr::Sink::publish(
                                    &mut tracked,
                                    packetcraftr::scan::Event::Probe {
                                        target: target.clone(),
                                        probe,
                                    },
                                )?;
                            }
                            emit(event)
                        })
                        .map_err(rendering::scan_error)?;
                    let aggregate = tracker
                        .finish(report.clone())
                        .map_err(rendering::scan_error)?;
                    // The lookups' sends, bytes, and time count in this
                    // scan's reported statistics.
                    let (reverse_dns, lookups) =
                        reverse::names(lookup, client, &report.hosts, started);
                    report
                        .stats
                        .checked_add_assign(&lookups)
                        .map_err(|error| CliError::caused(Kind::Internal, &error))?;
                    Ok(Streamed {
                        report,
                        endpoints: aggregate.endpoints,
                        plan,
                        reverse_dns,
                    })
                }
            }),
            on_event: rendering::emit_event,
            into_result: Box::new({
                let plan = plan.clone();
                move |(report, names)| {
                    output::scan::Report::publish(report, plan, names).map_err(CliError::classified)
                }
            }),
            render_text: Box::new(move |(report, names), _| {
                rendering::render_text(
                    output::scan::Report::publish(report, plan, names)
                        .map_err(CliError::classified)?,
                )
            }),
            complete: rendering::emit_complete,
        },
    )
}

pub(super) struct Streamed {
    pub(super) report: packetcraftr::scan::Report,
    pub(super) endpoints: Vec<packetcraftr::scan::Endpoint>,
    pub(super) plan: output::scan::plan::Plan,
    /// Each host's PTR lookup, by position; empty when none ran.
    pub(super) reverse_dns: Vec<Option<output::scan::host::ReverseDns>>,
}

/// The requested transports in first-seen order. ICMP echo is portless and
/// cannot share a plan with port endpoints.
fn transports(requested: &[arguments::Transport]) -> Result<Vec<Transport>, CliError> {
    let mut transports: Vec<Transport> = Vec::with_capacity(requested.len());
    for transport in requested {
        let transport = Transport::from(*transport);
        if !transports.contains(&transport) {
            transports.push(transport);
        }
    }
    if transports.len() > 1 && transports.contains(&Transport::Icmp) {
        return Err(CliError::new(
            Kind::Usage,
            "--transport icmp is portless and cannot be combined with tcp or udp",
        ));
    }
    Ok(transports)
}

/// The discovery stage the flags select, with the endpoints --exclude-ports
/// removed from it. Port probes take --discovery-ports through the scan's
/// catalog and --exclude-ports, so discovery never probes an excluded
/// endpoint; ICMP echo is the default probe.
fn discovery_options(
    mode: Option<arguments::Discovery>,
    probes: &[arguments::DiscoveryProbe],
    ports: Vec<arguments::PortTerm>,
    exclude_ports: &[arguments::PortTerm],
    unresponsive: Option<arguments::UnresponsiveHosts>,
    max_ports: usize,
) -> Result<(discovery::Options, usize), CliError> {
    let Some(mode) = mode else {
        return Ok((discovery::Options::default(), 0));
    };
    let mut options = discovery::Options {
        mode: mode.into(),
        unresponsive: unresponsive.map_or_else(Default::default, Into::into),
        ..discovery::Options::default()
    };
    let probes = if probes.is_empty() && options.runs() {
        &[arguments::DiscoveryProbe::Icmp][..]
    } else {
        probes
    };
    let mut transports = Vec::new();
    for probe in probes {
        let transport = match probe {
            arguments::DiscoveryProbe::Neighbor => {
                options.neighbor = true;
                continue;
            }
            arguments::DiscoveryProbe::Icmp => Transport::Icmp,
            arguments::DiscoveryProbe::Tcp => Transport::Tcp,
            arguments::DiscoveryProbe::Udp => Transport::Udp,
        };
        if !transports.contains(&transport) {
            transports.push(transport);
        }
    }
    // ICMP echo is portless and leads; port probes follow in term order.
    if let Some(index) = transports
        .iter()
        .position(|transport| *transport == Transport::Icmp)
    {
        transports.remove(index);
        options.probes.push(ProbeEndpoint::Icmp);
    }
    if transports.is_empty() {
        if !ports.is_empty() {
            return Err(CliError::new(
                Kind::Usage,
                "--discovery-ports needs tcp or udp among --discovery-probes",
            ));
        }
        return Ok((options, 0));
    }
    if ports.is_empty() {
        return Err(CliError::new(
            Kind::Usage,
            "tcp and udp discovery probes need --discovery-ports",
        ));
    }
    // An exclusion prefixed with a transport discovery does not probe
    // applies only to the scan's endpoints.
    let exclude = exclude_ports
        .iter()
        .filter(|term| {
            term.0
                .transport
                .is_none_or(|transport| transports.contains(&transport))
        })
        .map(|term| term.0.clone())
        .collect();
    let selected = packetcraftr::scan::select_endpoints(
        &packetcraftr::scan::PortSelection {
            transports,
            include: ports.into_iter().map(|term| term.0).collect(),
            exclude,
        },
        packetcraftr::scan::catalog::bundled(),
        max_ports,
    )
    .map_err(|error| {
        CliError::from_classification(
            error.classification(),
            format!("--discovery-ports: {error}"),
            error.causes(),
        )
    })?;
    options.probes.extend(selected.endpoints);
    Ok((options, selected.excluded))
}

fn select_endpoints(
    transports: &[Transport],
    ports: Vec<arguments::PortTerm>,
    exclude_ports: Vec<arguments::PortTerm>,
    max_ports: usize,
) -> Result<packetcraftr::scan::Selected, CliError> {
    if transports == [Transport::Icmp] {
        if !ports.is_empty() || !exclude_ports.is_empty() {
            return Err(CliError::new(
                Kind::Usage,
                "--ports and --exclude-ports do not apply to portless ICMP echo scans",
            ));
        }
        return Ok(packetcraftr::scan::Selected {
            endpoints: vec![packetcraftr::probe::ProbeEndpoint::Icmp],
            excluded: 0,
        });
    }
    packetcraftr::scan::select_endpoints(
        &packetcraftr::scan::PortSelection {
            transports: transports.to_vec(),
            include: ports.into_iter().map(|term| term.0).collect(),
            exclude: exclude_ports.into_iter().map(|term| term.0).collect(),
        },
        packetcraftr::scan::catalog::bundled(),
        max_ports,
    )
    .map_err(CliError::classified)
}

/// Raw scans need packet capture and transmission in the requested link mode.
fn raw_capability(
    link_mode: packetcraftr_netio::link::Mode,
) -> Result<(), packetcraftr_netio::Unsupported> {
    use packetcraftr_netio::NativeCapability;
    NativeCapability::Capture.check()?;
    NativeCapability::Transmission(link_mode).check()
}

pub(super) struct Ingested {
    pub(crate) targets: packetcraftr::target::Selection,
    pub(crate) origins: Vec<manifest::Declaration>,
}

fn ingest_targets(
    positional: &[String],
    targets_file: &[std::path::PathBuf],
    exclusions: &[packetcraftr::target::Network],
    exclude_file: &[std::path::PathBuf],
    max_manifest_bytes: Option<usize>,
    max_manifest_lines: Option<usize>,
) -> Result<Ingested, CliError> {
    let bounds = manifest::ManifestBounds::new(
        max_manifest_bytes.unwrap_or(manifest::MAX_MANIFEST_BYTES),
        max_manifest_lines.unwrap_or(manifest::MAX_MANIFEST_LINES),
    )?;
    let mut budget = bounds.budget();
    let mut origins = positional
        .iter()
        .enumerate()
        .map(|(position, target)| manifest::Declaration {
            token: target.clone(),
            source: manifest::DeclarationSource::Argument {
                position: position + 1,
            },
            line: None,
        })
        .collect::<Vec<_>>();
    origins.extend(manifest::read_with_budget(
        &manifest_sources(targets_file),
        &mut budget,
    )?);
    let include = parse_declarations(&origins)?;
    if include.is_empty() {
        return Err(CliError::new(
            Kind::Usage,
            "at least one target is required: pass TARGET or --targets-file",
        ));
    }
    let mut exclude = exclusions.to_vec();
    exclude.extend(parse_declarations::<packetcraftr::target::Network>(
        &manifest::read_with_budget(&manifest_sources(exclude_file), &mut budget)?,
    )?);
    Ok(Ingested {
        targets: packetcraftr::target::Selection { include, exclude },
        origins,
    })
}

fn manifest_sources(paths: &[std::path::PathBuf]) -> Vec<manifest::ManifestSource> {
    paths
        .iter()
        .map(|path| manifest::ManifestSource::open(path))
        .collect()
}

fn parse_declarations<T>(declarations: &[manifest::Declaration]) -> Result<Vec<T>, CliError>
where
    T: std::str::FromStr,
    T::Err: Classified,
{
    declarations
        .iter()
        .map(|declaration| {
            declaration
                .token
                .parse()
                .map_err(|source| declaration_error(source, declaration))
        })
        .collect()
}

fn declaration_error(source: impl Classified, declaration: &manifest::Declaration) -> CliError {
    CliError::from_classification(
        source.classification(),
        format!("invalid declaration at {declaration}: {source}"),
        crate::errors::source_causes(&source),
    )
    .with_context(source.context())
}
