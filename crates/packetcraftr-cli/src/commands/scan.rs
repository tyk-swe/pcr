// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

pub(super) mod arguments;
mod connect;
mod list;
mod rendering;
mod selection;
mod streaming;
mod traceroute;

use crate::output::contract::Format;

use crate::output;

use packetcraftr_core::error::Kind;

use std::time::Duration;

use packetcraftr::probe::Transport;
use packetcraftr::scan::{discovery, followup, method, profile::curated};

use self::arguments::Args;
use self::selection::{
    discovery_options, ingest_targets, load_udp_profiles, read_udp_payload, select_endpoints,
    transports,
};
use crate::command_options::parse_target;
use crate::errors::CliError;
use crate::input::manifest;
use crate::rendering::StreamEncoder;
use crate::system::{Runtime, collection, prepare_workflow};

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
        invocation: &crate::invocation::Invocation,
    ) -> Result<super::CommandExit, CliError> {
        run(invocation, self).map(|()| super::CommandExit::SUCCESS)
    }
}

pub(super) fn run(
    invocation: &crate::invocation::Invocation,
    arguments: Args,
) -> Result<(), CliError> {
    let format = invocation.format;
    let stream = &invocation.output;
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
        tcp_scan,
        tcp_flags,
        sctp_scan,
        udp_payload_hex,
        udp_payload_file,
        udp_profiles,
        family,
        ports,
        exclude_ports,
        ip_protocols,
        exclude_ip_protocols,
        discovery,
        discovery_probes,
        discovery_ports,
        discovery_ip_protocols,
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
    let tcp_scan = tcp_scan.resolve(tcp_flags)?;
    tcp_scan.validate().map_err(CliError::classified)?;
    let sctp_scan: packetcraftr::scan::SctpScan = sctp_scan.into();
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
        let (ports, ip_protocols) = list::Listing {
            requested,
            transports,
            tcp_scan,
            sctp_scan,
            ports,
            exclude_ports,
            ip_protocols,
            exclude_ip_protocols,
            max_ports,
        }
        .plan()?;
        return list::run(
            invocation,
            targets,
            list::Options {
                origins: selection.origins,
                ports,
                ip_protocols,
                family,
                max_targets,
                max_duration: duration.max_duration(),
                policy,
            },
            format,
            stream,
        );
    }
    let Built {
        request,
        excluded_endpoints,
        curated,
        discovery_excluded,
        queue_limits,
    } = build_request(RequestArgs {
        discovery,
        discovery_probes,
        discovery_ports,
        discovery_ip_protocols,
        unresponsive_hosts,
        ports,
        exclude_ports,
        ip_protocols,
        exclude_ip_protocols,
        transports,
        tcp_scan,
        sctp_scan,
        udp_payload_hex,
        udp_payload_file,
        udp_profiles,
        curated_udp_payloads,
        limits,
        max_prepared_bytes,
        max_targets,
        max_ports,
        max_probes,
        max_undecoded,
        duration,
        timeout,
        adaptive,
        attempts,
        rate,
        max_in_flight,
        family,
        targets,
        origins: selection.origins,
        route_options: packetcraftr::route::Options {
            link_mode: route.link_mode.into(),
            ..Default::default()
        },
    })?;
    let trace_stage = traceroute
        .then(|| -> Result<_, CliError> {
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
    let plan = publication_plan(
        selection,
        &request,
        excluded_endpoints,
        curated,
        discovery_excluded,
        &reverse_dns,
        reverse_dns_port,
    );
    let reverse_dns = reverse_dns.map(parse_target).transpose()?;
    if selected_method == method::Method::Connect {
        let reverse = reverse_dns
            .map(|server| {
                validated_reverse_dns(
                    followup::ReverseDns {
                        server,
                        server_port: reverse_dns_port,
                        transport: packetcraftr::dns::TransportMode::Tcp,
                    },
                    &request,
                )
            })
            .transpose()?;
        return connect::run(
            invocation,
            followup::ConnectRequest {
                scan: request,
                reverse_dns: reverse,
            },
            plan,
            policy,
            format,
            stream,
        );
    }
    run_raw(
        invocation,
        RawRun {
            request,
            plan,
            policy,
            route,
            queue_limits,
            trace_stage,
            reverse_dns,
            reverse_dns_port,
        },
        format,
        stream,
    )
}

struct RequestArgs {
    discovery: Option<arguments::Discovery>,
    discovery_probes: Vec<arguments::DiscoveryProbe>,
    discovery_ports: Vec<arguments::PortTerm>,
    discovery_ip_protocols: Vec<arguments::IpProtocolTerm>,
    unresponsive_hosts: Option<arguments::UnresponsiveHosts>,
    ports: Vec<arguments::PortTerm>,
    exclude_ports: Vec<arguments::PortTerm>,
    ip_protocols: Vec<arguments::IpProtocolTerm>,
    exclude_ip_protocols: Vec<arguments::IpProtocolTerm>,
    transports: Vec<Transport>,
    tcp_scan: packetcraftr::scan::TcpScan,
    sctp_scan: packetcraftr::scan::SctpScan,
    udp_payload_hex: Option<String>,
    udp_payload_file: Option<std::path::PathBuf>,
    udp_profiles: Option<std::path::PathBuf>,
    curated_udp_payloads: bool,
    limits: crate::command_options::CaptureLimitsArgs,
    max_prepared_bytes: usize,
    max_targets: usize,
    max_ports: usize,
    max_probes: usize,
    max_undecoded: usize,
    duration: crate::command_options::MaxDurationArgs,
    timeout: crate::command_options::TimeoutArgs,
    adaptive: arguments::AdaptiveArgs,
    attempts: u32,
    rate: Option<u32>,
    max_in_flight: usize,
    family: crate::command_options::AddressFamily,
    targets: packetcraftr::target::Selection,
    origins: Vec<manifest::Declaration>,
    route_options: packetcraftr::route::Options,
}

struct Built {
    request: packetcraftr::scan::Request,
    excluded_endpoints: usize,
    curated: Option<output::scan::plan::CuratedPayloads>,
    discovery_excluded: usize,
    queue_limits: packetcraftr_netio::capture::Limits,
}

fn build_request(arguments: RequestArgs) -> Result<Built, CliError> {
    let RequestArgs {
        discovery,
        discovery_probes,
        discovery_ports,
        discovery_ip_protocols,
        unresponsive_hosts,
        ports,
        exclude_ports,
        ip_protocols,
        exclude_ip_protocols,
        transports,
        tcp_scan,
        sctp_scan,
        udp_payload_hex,
        udp_payload_file,
        udp_profiles,
        curated_udp_payloads,
        limits,
        max_prepared_bytes,
        max_targets,
        max_ports,
        max_probes,
        max_undecoded,
        duration,
        timeout,
        adaptive,
        attempts,
        rate,
        max_in_flight,
        family,
        targets,
        origins,
        route_options,
    } = arguments;
    let (discovery, discovery_excluded) = discovery_options(
        discovery,
        &discovery_probes,
        discovery_ports,
        &exclude_ports,
        discovery_ip_protocols,
        &exclude_ip_protocols,
        unresponsive_hosts,
        max_ports,
    )?;
    let scanning = discovery.mode != discovery::Mode::Only;
    let exclude_ports = if discovery.runs() {
        exclude_ports
            .into_iter()
            .filter(|term| {
                let applies_to_scan = term.0.transport.map_or_else(
                    || {
                        transports.iter().any(|transport| {
                            matches!(transport, Transport::Tcp | Transport::Udp | Transport::Sctp)
                        })
                    },
                    |transport| transports.contains(&transport),
                );
                applies_to_scan
                    || !discovery_probes
                        .iter()
                        .filter_map(|probe| match probe {
                            arguments::DiscoveryProbe::Tcp | arguments::DiscoveryProbe::TcpAck => {
                                Some(Transport::Tcp)
                            }
                            arguments::DiscoveryProbe::Udp => Some(Transport::Udp),
                            arguments::DiscoveryProbe::Sctp => Some(Transport::Sctp),
                            _ => None,
                        })
                        .any(|transport| {
                            term.0
                                .transport
                                .is_none_or(|excluded| excluded == transport)
                        })
            })
            .collect()
    } else {
        exclude_ports
    };
    // Discovery has already consumed these shared exclusions. A port scan
    // must not reject exclusions that apply to its IP discovery stage.
    let exclude_ip_protocols = if transports != [Transport::Ip]
        && discovery.runs()
        && discovery
            .probes
            .iter()
            .any(|probe| matches!(probe, packetcraftr::probe::Endpoint::Ip { .. }))
    {
        Vec::new()
    } else {
        exclude_ip_protocols
    };
    let udp = (scanning && transports.contains(&Transport::Udp))
        || discovery
            .probes
            .iter()
            .any(|probe| probe.transport() == Transport::Udp);
    let udp_payload =
        read_udp_payload(udp, udp_payload_hex.as_deref(), udp_payload_file.as_deref())?;
    let operator_profiles = load_udp_profiles(udp_profiles.as_deref(), udp)?;
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
        evidence: packetcraftr::evidence::Limits {
            max_frames: queue_limits.max_frames,
            max_bytes: queue_limits.max_bytes,
            max_undecoded,
        },
    };
    scan_limits.validate().map_err(CliError::classified)?;
    let selected = if scanning {
        select_endpoints(
            &transports,
            ports,
            exclude_ports,
            ip_protocols,
            exclude_ip_protocols,
            max_ports,
        )?
    } else if !ports.is_empty() || !ip_protocols.is_empty() {
        return Err(CliError::new(
            Kind::Usage,
            "--discovery only probes no scan port; remove --ports and --ip-protocols",
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
        target_sources: origins.iter().map(ToString::to_string).collect(),
        udp_payload,
        udp_profiles,
        address_family: family.into(),
        endpoints: selected.endpoints,
        tcp_scan,
        sctp_scan,
        discovery,
        attempts,
        adaptive: adaptive.into_adaptive(timeout.timeout(), duration.max_duration(), max_in_flight),
        timeout: timeout.timeout(),
        probes_per_second: rate,
        limits: scan_limits,
        route: route_options,
        collection: collection(timeout.timeout(), queue_limits)?,
    };
    if !tcp_scan.is_syn() || !sctp_scan.is_init() {
        request.validate().map_err(CliError::classified)?;
    }
    Ok(Built {
        request,
        excluded_endpoints: selected.excluded,
        curated,
        discovery_excluded,
        queue_limits,
    })
}

fn publication_plan(
    selection: method::Selection,
    request: &packetcraftr::scan::Request,
    excluded_endpoints: usize,
    curated: Option<output::scan::plan::CuratedPayloads>,
    discovery_excluded: usize,
    reverse_dns: &Option<String>,
    reverse_dns_port: u16,
) -> output::scan::plan::Plan {
    let selected_method = selection.method;
    output::scan::plan::Plan {
        tcp_scan: (selected_method == method::Method::Raw
            && request
                .endpoints
                .iter()
                .any(|endpoint| endpoint.transport() == Transport::Tcp))
        .then(|| output::scan::plan::TcpScan::from(request.tcp_scan)),
        sctp_scan: (selected_method == method::Method::Raw
            && request
                .endpoints
                .iter()
                .any(|endpoint| endpoint.transport() == Transport::Sctp))
        .then(|| output::scan::plan::SctpScan::from(request.sctp_scan)),
        method: selection.into(),
        port_catalog: packetcraftr::scan::catalog::data_set().into(),
        excluded_endpoints,
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
    }
}

struct RawRun {
    request: packetcraftr::scan::Request,
    plan: output::scan::plan::Plan,
    policy: crate::command_options::HostnamePolicyArgs,
    route: crate::command_options::RouteSelectionArgs,
    queue_limits: packetcraftr_netio::capture::Limits,
    trace_stage: Option<traceroute::Stage>,
    reverse_dns: Option<packetcraftr::target::Target>,
    reverse_dns_port: u16,
}

fn run_raw(
    invocation: &crate::invocation::Invocation,
    run: RawRun,
    format: Format,
    stream: &StreamEncoder,
) -> Result<(), CliError> {
    let RawRun {
        request,
        plan,
        policy,
        route,
        queue_limits,
        trace_stage,
        reverse_dns,
        reverse_dns_port,
    } = run;
    let workflow = prepare_workflow(&route, policy.into_policy(), request.timeout, queue_limits)?;
    let client = workflow.client(invocation, Runtime::Workflow);
    let request = packetcraftr::scan::Request {
        route: workflow.route,
        collection: workflow.collection,
        ..request
    };
    // The finalized template is validated again before the scan runs, so a
    // queue configuration the trace stage cannot use fails before any probe.
    if let Some(stage) = &trace_stage {
        stage.revalidate(&request)?;
    }
    // DNS over TCP cannot follow a packet route override.
    let reverse = reverse_dns
        .map(|server| {
            let transport = if route.supports_kernel_tcp() {
                packetcraftr::dns::TransportMode::UdpThenTcp
            } else {
                packetcraftr::dns::TransportMode::Udp
            };
            validated_reverse_dns(
                followup::ReverseDns {
                    server,
                    server_port: reverse_dns_port,
                    transport,
                },
                &request,
            )
        })
        .transpose()?;
    let trace_plan = trace_stage.as_ref().map(traceroute::Stage::plan);
    let request = followup::Request {
        trace: trace_stage.as_ref().map(|stage| stage.trace(invocation)),
        reverse_dns: reverse,
        scan: request,
    };
    match format {
        Format::Ndjson => {
            let emit = crate::commands::execution::emitter(invocation, streaming::emit_event);
            let mut report = client
                .scan_with_followups(request, emit)
                .map_err(followup_error)?;
            report.scan.stats = report.stats;
            let traceroute = trace_plan.zip(report.trace).map(|(plan, traced)| {
                output::traceroute::hosts::Complete {
                    plan,
                    retained_evidence_bytes: traced.retained_evidence_bytes,
                }
            });
            let summary = Streamed {
                report: report.scan,
                endpoints: report.endpoints,
                plan,
                reverse_dns: reverse_dns_hosts(report.reverse_dns),
                traceroute,
            };
            invocation.check()?;
            streaming::emit_complete(summary, stream)
        }
        format => {
            let collector = followup::Collector::default();
            let report = client
                .scan_with_followups(request, collector.clone())
                .map_err(followup_error)?;
            let aggregate = collector.finish(report).map_err(followup_error)?;
            let followup::Aggregate {
                mut scan,
                trace,
                reverse_dns,
                stats,
            } = aggregate;
            scan.stats = stats;
            if let Some(trace) = &trace {
                scan.diagnostics.extend(trace.diagnostics.iter().cloned());
            }
            let traced = trace_plan.zip(trace);
            invocation.check()?;
            let published = output::scan::Report::publish(
                scan,
                plan,
                reverse_dns_hosts(reverse_dns),
                traced
                    .map(|(plan, aggregate)| {
                        output::traceroute::hosts::Report::new(plan, aggregate)
                    })
                    .transpose()
                    .map_err(CliError::classified)?,
            )
            .map_err(CliError::classified)?;
            if format == Format::Json {
                crate::rendering::emit_published(
                    invocation,
                    output::contract::Command::Scan,
                    published,
                )
            } else {
                rendering::render_text(invocation, published, stream.presentation())
            }
        }
    }
}

fn validated_reverse_dns(
    reverse: followup::ReverseDns,
    scan: &packetcraftr::scan::Request,
) -> Result<followup::ReverseDns, CliError> {
    reverse.validate(scan).map_err(followup_error)?;
    Ok(reverse)
}

/// A follow-up stage's failure, classified as the failing stage alone would
/// be; a scan failure keeps the partial evidence its pipeline retained.
pub(super) fn followup_error(error: followup::Error) -> CliError {
    match error {
        followup::Error::Scan(error) => scan_error(error),
        followup::Error::StatsOverflow(error) => CliError::caused(Kind::Internal, &error),
        error => CliError::classified(error),
    }
}

fn scan_error(error: packetcraftr::scan::Error) -> CliError {
    use packetcraftr_core::error::Classified;
    let mut cli =
        CliError::from_classification(error.classification(), error.to_string(), error.causes())
            .with_context(error.context());
    let mut source: Option<&(dyn std::error::Error + 'static)> = Some(&error);
    while let Some(error) = source {
        if let Some(pipeline) = error.downcast_ref::<packetcraftr::scan::PipelineFailure>() {
            match output::scan::Failure::try_from(pipeline) {
                Ok(partial) => cli = cli.with_scan(partial),
                Err(error) => cli
                    .causes
                    .push(format!("could not render pending scan evidence: {error}")),
            }
            break;
        }
        source = error.source();
    }
    cli
}

/// Each host's PTR lookup, by position; empty when no lookup was requested.
pub(super) fn reverse_dns_hosts(
    lookups: Option<followup::ReverseLookups>,
) -> Vec<Option<output::scan::host::ReverseDns>> {
    lookups
        .map(|lookups| {
            lookups
                .lookups
                .into_iter()
                .map(|lookup| lookup.map(Into::into))
                .collect()
        })
        .unwrap_or_default()
}

pub(super) struct Streamed {
    pub(super) report: packetcraftr::scan::Report,
    pub(super) endpoints: Vec<packetcraftr::scan::Endpoint>,
    pub(super) plan: output::scan::plan::Plan,
    /// Each host's PTR lookup, by position; empty when none ran.
    pub(super) reverse_dns: Vec<Option<output::scan::host::ReverseDns>>,
    pub(super) traceroute: Option<output::traceroute::hosts::Complete>,
}

/// Raw scans need packet capture and transmission in the requested link mode.
fn raw_capability(
    link_mode: packetcraftr_netio::link::Mode,
) -> Result<(), packetcraftr_netio::Unsupported> {
    use packetcraftr_netio::NativeCapability;
    NativeCapability::Capture.check()?;
    NativeCapability::Transmission(link_mode).check()
}
