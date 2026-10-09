// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

pub(super) mod arguments;
mod connect;
mod list;
mod payload;
mod profiles;
mod rendering;
mod reverse;
mod traceroute;

use crate::output::contract::Format;

use crate::output;

use packetcraftr_core::error::{Classified, Kind};

use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant, SystemTime};

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
            traceroute_max_hops: Count @ Operation if self.traceroute,
            traceroute_max_probes: Count @ Operation if self.traceroute,
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
        adaptive,
        timeout,
        rate,
        max_ports,
        max_probes,
        duration,
        max_undecoded,
        curated_udp_payloads,
        traceroute,
        traceroute_strategy,
        traceroute_port,
        traceroute_first_hop,
        traceroute_max_hops,
        traceroute_attempts,
        traceroute_max_probes,
        traceroute_reuse_max_age_ms,
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
        if discovery.is_some() || reverse_dns.is_some() || traceroute {
            return Err(CliError::new(
                Kind::Usage,
                "--list sends no probe; remove --discovery, --reverse-dns, and --traceroute",
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
        adaptive: adaptive.into_adaptive(timeout.timeout(), duration.max_duration(), max_in_flight),
        timeout: timeout.timeout(),
        probes_per_second: rate,
        limits: scan_limits,
        route: packetcraftr::route::Options::default(),
        collection: crate::system::exchange::collection(timeout.timeout(), queue_limits)?,
    };
    let trace_stage = traceroute
        .then(|| {
            traceroute::Stage::new(
                &traceroute::Options {
                    strategy: traceroute_strategy,
                    port: traceroute_port,
                    first_hop: traceroute_first_hop,
                    max_hops: traceroute_max_hops,
                    attempts: traceroute_attempts,
                    max_probes: traceroute_max_probes,
                    reuse_max_age: traceroute_reuse_max_age_ms.map(Duration::from_millis),
                },
                &request,
            )
        })
        .transpose()?;
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
    if trace_stage.is_some() && selected_method == method::Method::Connect {
        return Err(CliError::new(
            Kind::Usage,
            "--traceroute needs the raw method; use --method raw, or drop --connect and --method tcp-connect",
        ));
    }
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
    // Reverse-DNS lookups can share the scan's next hop, so their neighbor
    // requests are authorized like its probes'.
    let client = workflow
        .client(Runtime::Workflow)
        .with_neighbor_request_authorization();
    // The trace stage resolves its own neighbors, so it takes an independent
    // workflow client with neighbor-request authorization rather than the
    // scan's neighbor-narrowed one.
    let trace_client = trace_stage.is_some().then(|| {
        workflow
            .client(Runtime::Workflow)
            .with_neighbor_request_authorization()
    });
    // The finalized template is validated again before the scan runs, so a
    // queue configuration the trace stage cannot use fails before any probe.
    let trace_stage = trace_stage
        .map(|stage| stage.with_workflow(workflow.route.clone(), workflow.collection.clone()))
        .transpose()?;
    let request = packetcraftr::scan::Request {
        route: workflow.route,
        collection: workflow.collection,
        ..request
    };
    // The lookups resolve any next hop within the scan's bounds, reusing its
    // answers; without them the scan bounds its own resolutions.
    let client = if reverse_dns.is_some() {
        client
            .with_scan_neighbors(&request)
            .map_err(CliError::classified)?
    } else {
        client
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
    let trace = trace_stage.as_ref().zip(trace_client.as_ref());
    let trace_plan = trace_stage.as_ref().map(traceroute::Stage::plan);
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
                let scan_sent = last_scan_transmission(&aggregate);
                let mut traced = None;
                if let Some((stage, trace_client)) = trace {
                    let result = stage.collect(trace_client, &aggregate, started, scan_sent)?;
                    aggregate
                        .stats
                        .checked_add_assign(&result.aggregate.stats)
                        .map_err(|error| CliError::caused(Kind::Internal, &error))?;
                    aggregate
                        .diagnostics
                        .extend(result.aggregate.diagnostics.iter().cloned());
                    traced = Some(result);
                }
                // The lookups' sends, bytes, and time count in this scan's
                // reported statistics.
                let (names, lookups) = reverse::names(
                    lookup,
                    &client,
                    &aggregate.hosts,
                    started,
                    reverse::last_transmission(
                        aggregate.stats.packets_attempted > 0,
                        scan_sent
                            .into_iter()
                            .chain(traced.as_ref().and_then(|traced| traced.last_sent)),
                    ),
                );
                aggregate
                    .stats
                    .checked_add_assign(&lookups.unwrap_or_default())
                    .map_err(|error| CliError::caused(Kind::Internal, &error))?;
                let traced = trace_plan
                    .zip(traced)
                    .map(|(plan, traced)| (plan, traced.aggregate));
                Ok((aggregate, names, traced))
            }),
            run_with_events: Box::new({
                let plan = plan.clone();
                let client = &client;
                let request = &request;
                move |emit| {
                    let started = Instant::now();
                    let emit = Arc::new(Mutex::new(emit));
                    // Events stream as they settle; the tracker keeps each
                    // attempt without its frame, for the endpoint inferences.
                    let tracker = packetcraftr::scan::Collector::default();
                    let mut tracked = tracker.clone();
                    // The tracker strips matched response frames, so the
                    // scan's retained evidence is counted as events publish.
                    let retained = Arc::new(Mutex::new(traceroute::Retained::default()));
                    let scan_emit = Arc::clone(&emit);
                    let observing = Arc::clone(&retained);
                    let mut report = client
                        .scan(request.clone(), move |event: packetcraftr::scan::Event| {
                            observing
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner)
                                .observe(&event);
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
                            publish(&scan_emit, Event::Scan(event))
                        })
                        .map_err(rendering::scan_error)?;
                    let aggregate = tracker
                        .finish(report.clone())
                        .map_err(rendering::scan_error)?;
                    let scan_sent = last_scan_transmission(&aggregate);
                    let mut traced = None;
                    if let Some((stage, trace_client)) = trace {
                        let retained = retained
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        let trace_emit = Arc::clone(&emit);
                        let result = stage.stream(
                            trace_client,
                            &aggregate,
                            *retained,
                            started,
                            scan_sent,
                            move |event| publish(&trace_emit, Event::Trace(event)),
                        )?;
                        report
                            .stats
                            .checked_add_assign(&result.report.stats)
                            .map_err(|error| CliError::caused(Kind::Internal, &error))?;
                        traced = Some(result);
                    }
                    // The lookups' sends, bytes, and time count in this
                    // scan's reported statistics.
                    let (reverse_dns, lookups) = reverse::names(
                        lookup,
                        client,
                        &report.hosts,
                        started,
                        reverse::last_transmission(
                            report.stats.packets_attempted > 0,
                            scan_sent
                                .into_iter()
                                .chain(traced.as_ref().and_then(|traced| traced.last_sent)),
                        ),
                    );
                    report
                        .stats
                        .checked_add_assign(&lookups.unwrap_or_default())
                        .map_err(|error| CliError::caused(Kind::Internal, &error))?;
                    let traceroute = trace_plan.zip(traced).map(|(plan, traced)| {
                        output::traceroute::hosts::Complete {
                            plan,
                            retained_evidence_bytes: traced.report.retained_evidence_bytes,
                        }
                    });
                    Ok(Streamed {
                        report,
                        endpoints: aggregate.endpoints,
                        plan,
                        reverse_dns,
                        traceroute,
                    })
                }
            }),
            on_event: rendering::emit_event,
            into_result: Box::new({
                let plan = plan.clone();
                move |(report, names, traced)| {
                    output::scan::Report::publish(
                        report,
                        plan,
                        names,
                        traced
                            .map(|(plan, aggregate)| {
                                output::traceroute::hosts::Report::new(plan, aggregate)
                            })
                            .transpose()
                            .map_err(CliError::classified)?,
                    )
                    .map_err(CliError::classified)
                }
            }),
            render_text: Box::new(move |(report, names, traced), _| {
                rendering::render_text(
                    output::scan::Report::publish(
                        report,
                        plan,
                        names,
                        traced
                            .map(|(plan, aggregate)| {
                                output::traceroute::hosts::Report::new(plan, aggregate)
                            })
                            .transpose()
                            .map_err(CliError::classified)?,
                    )
                    .map_err(CliError::classified)?,
                )
            }),
            complete: rendering::emit_complete,
        },
    )
}

/// What the command streams while it runs: the scan's events, then the trace
/// stage's.
pub(super) enum Event {
    Scan(packetcraftr::scan::Event),
    Trace(packetcraftr::traceroute::hosts::Event),
}

fn publish(
    emit: &Mutex<execution::Emit<Event>>,
    event: Event,
) -> Result<(), packetcraftr_core::error::BoundaryError> {
    let mut emit = emit.lock().unwrap_or_else(PoisonError::into_inner);
    emit(event)
}

/// When the scan last transmitted, or now when it sent at no known time.
fn last_scan_transmission(aggregate: &packetcraftr::scan::Aggregate) -> Option<SystemTime> {
    reverse::last_transmission(
        aggregate.stats.packets_attempted > 0,
        aggregate
            .discovery
            .iter()
            .chain(
                aggregate
                    .endpoints
                    .iter()
                    .flat_map(|endpoint| &endpoint.probes),
            )
            .map(|probe| probe.sent_at),
    )
}

pub(super) struct Streamed {
    pub(super) report: packetcraftr::scan::Report,
    pub(super) endpoints: Vec<packetcraftr::scan::Endpoint>,
    pub(super) plan: output::scan::plan::Plan,
    /// Each host's PTR lookup, by position; empty when none ran.
    pub(super) reverse_dns: Vec<Option<output::scan::host::ReverseDns>>,
    pub(super) traceroute: Option<output::traceroute::hosts::Complete>,
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
