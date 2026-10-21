// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Validate scan arguments and turn them into one typed execution request.
//! Selection and method checks stay here so list, connect, and raw modes share
//! their precedence and diagnostics.

use std::path::Path;
use std::time::Duration;

use packetcraftr::probe::Transport;
use packetcraftr::scan::{discovery, followup, method, profile::curated};
use packetcraftr_core::error::Kind;

use super::arguments::{
    self, AdaptiveArgs, Args, DiscoveryProbe, IpProtocolTerm, PortTerm, UnresponsiveHosts,
};
use super::selection::{
    DiscoveryRequest, EndpointRequest, ingest_targets, load_udp_profiles, read_udp_payload,
    transports,
};
use super::{connect, list, raw, traceroute};
use crate::command_options::{AddressFamily, CaptureLimitsArgs, MaxDurationArgs, TimeoutArgs};
use crate::errors::CliError;
use crate::input::manifest;
use crate::output;
use crate::system::collection;

pub(super) enum Planned {
    List(list::Request),
    Connect(connect::Request),
    Raw(raw::Request),
}

struct EndpointInputs {
    transports: Vec<Transport>,
    tcp_scan: packetcraftr::scan::TcpScan,
    sctp_scan: packetcraftr::scan::SctpScan,
    ports: Vec<PortTerm>,
    exclude_ports: Vec<PortTerm>,
    ip_protocols: Vec<IpProtocolTerm>,
    exclude_ip_protocols: Vec<IpProtocolTerm>,
}

struct DiscoveryInputs {
    mode: Option<arguments::Discovery>,
    probes: Vec<DiscoveryProbe>,
    ports: Vec<PortTerm>,
    ip_protocols: Vec<IpProtocolTerm>,
    unresponsive: Option<UnresponsiveHosts>,
}

struct UdpInputs {
    payload_hex: Option<String>,
    payload_file: Option<std::path::PathBuf>,
    profiles: Option<std::path::PathBuf>,
    curated: bool,
}

struct LimitInputs {
    capture: CaptureLimitsArgs,
    max_prepared_bytes: usize,
    max_targets: usize,
    max_ports: usize,
    max_probes: usize,
    max_undecoded: usize,
    duration: MaxDurationArgs,
}

struct ScheduleInputs {
    max_in_flight: usize,
    attempts: u32,
    adaptive: AdaptiveArgs,
    timeout: TimeoutArgs,
    rate: Option<u32>,
}

struct RequestInputs {
    endpoints: EndpointInputs,
    discovery: DiscoveryInputs,
    udp: UdpInputs,
    limits: LimitInputs,
    schedule: ScheduleInputs,
    family: AddressFamily,
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

pub(super) fn prepare(arguments: Args) -> Result<Planned, CliError> {
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
    validate_stdin_consumers(
        &targets_file,
        &exclude_file,
        udp_payload_file.as_deref(),
        udp_profiles.as_deref(),
    )?;
    let ingested = ingest_targets(
        &targets,
        &targets_file,
        &exclusions,
        &exclude_file,
        max_manifest_bytes,
        max_manifest_lines,
    )?;
    ingested.targets.validate().map_err(CliError::classified)?;
    let targets = ingested.targets;
    let origins = ingested.origins;

    if list {
        validate_list_options(list, discovery, &reverse_dns, traceroute)?;

        let diagnostic = !tcp_scan.is_syn();
        if diagnostic && requested == method::Requested::Connect {
            return Err(CliError::new(
                Kind::Usage,
                "--tcp-scan other than syn needs the raw method; drop --connect and --method tcp-connect",
            ));
        }
        let sctp_diagnostic = !sctp_scan.is_init();
        if sctp_diagnostic && requested == method::Requested::Connect {
            return Err(CliError::new(
                Kind::Usage,
                "--sctp-scan other than init needs the raw method; drop --connect and --method tcp-connect",
            ));
        }
        let ip_only = transports == [Transport::Ip];
        if ip_only && requested == method::Requested::Connect {
            return Err(CliError::new(
                Kind::Usage,
                "--transport ip needs the raw method; drop --connect and --method tcp-connect",
            ));
        }
        let selected = EndpointRequest {
            transports,
            ports,
            exclude_ports,
            ip_protocols,
            exclude_ip_protocols,
            max_ports,
        }
        .select_if_requested()?;
        let (ports, ip_protocols) = if ip_only {
            (
                None,
                selected.as_ref().map(output::scan::plan::IpProtocols::from),
            )
        } else {
            let ports = selected.as_ref().map(|selected| {
                let ports = output::scan::plan::Ports::from(selected);
                if requested == method::Requested::Connect {
                    ports
                } else {
                    ports.with_tcp_scan(tcp_scan).with_sctp_scan(sctp_scan)
                }
            });
            (ports, None)
        };
        if diagnostic && ports.as_ref().is_none_or(|ports| ports.tcp_scan.is_none()) {
            return Err(CliError::new(
                Kind::Usage,
                "--tcp-scan other than syn requires at least one TCP port endpoint",
            ));
        }
        if sctp_diagnostic && ports.as_ref().is_none_or(|ports| ports.sctp_scan.is_none()) {
            return Err(CliError::new(
                Kind::Usage,
                "--sctp-scan other than init requires at least one SCTP port endpoint",
            ));
        }
        return Ok(Planned::List(list::Request {
            selection: targets,
            origins,
            ports,
            ip_protocols,
            family,
            max_targets,
            max_duration: duration.max_duration(),
            policy,
        }));
    }

    let built = build_request(RequestInputs {
        endpoints: EndpointInputs {
            transports,
            tcp_scan,
            sctp_scan,
            ports,
            exclude_ports,
            ip_protocols,
            exclude_ip_protocols,
        },
        discovery: DiscoveryInputs {
            mode: discovery,
            probes: discovery_probes,
            ports: discovery_ports,
            ip_protocols: discovery_ip_protocols,
            unresponsive: unresponsive_hosts,
        },
        udp: UdpInputs {
            payload_hex: udp_payload_hex,
            payload_file: udp_payload_file,
            profiles: udp_profiles,
            curated: curated_udp_payloads,
        },
        limits: LimitInputs {
            capture: limits,
            max_prepared_bytes,
            max_targets,
            max_ports,
            max_probes,
            max_undecoded,
            duration,
        },
        schedule: ScheduleInputs {
            max_in_flight,
            attempts,
            adaptive,
            timeout,
            rate,
        },
        family,
        targets,
        origins,
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
                &built.request,
            )
        })
        .transpose()?;
    let selection = method::select(
        requested,
        &built.request,
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
        &built.request,
        built.excluded_endpoints,
        built.curated,
        built.discovery_excluded,
        &reverse_dns,
        reverse_dns_port,
    );
    let reverse_dns = reverse_dns
        .map(crate::command_options::parse_target)
        .transpose()?;
    if selected_method == method::Method::Connect {
        let reverse = reverse_dns
            .map(|server| {
                super::validated_reverse_dns(
                    followup::ReverseDns {
                        server,
                        server_port: reverse_dns_port,
                        transport: packetcraftr::dns::TransportMode::Tcp,
                    },
                    &built.request,
                )
            })
            .transpose()?;
        return Ok(Planned::Connect(connect::Request {
            followup: followup::ConnectRequest {
                scan: built.request,
                reverse_dns: reverse,
            },
            plan,
            policy,
        }));
    }
    Ok(Planned::Raw(raw::Request {
        request: built.request,
        plan,
        policy,
        route,
        queue_limits: built.queue_limits,
        trace_stage,
        reverse_dns,
        reverse_dns_port,
    }))
}

fn validate_stdin_consumers(
    targets_file: &[std::path::PathBuf],
    exclude_file: &[std::path::PathBuf],
    udp_payload_file: Option<&Path>,
    udp_profiles: Option<&Path>,
) -> Result<(), CliError> {
    let stdin_consumers = targets_file
        .iter()
        .chain(exclude_file)
        .filter(|path| manifest::is_stdin(path))
        .count()
        + usize::from(udp_payload_file.is_some_and(manifest::is_stdin))
        + usize::from(udp_profiles.is_some_and(manifest::is_stdin));
    if stdin_consumers > 1 {
        return Err(CliError::new(
            Kind::Usage,
            "stdin (`-`) can supply at most one of --targets-file, --exclude-file, --udp-payload-file, or --udp-profiles",
        ));
    }
    Ok(())
}

fn validate_list_options(
    list: bool,
    discovery: Option<arguments::Discovery>,
    reverse_dns: &Option<String>,
    traceroute: bool,
) -> Result<(), CliError> {
    if list && (discovery.is_some() || reverse_dns.is_some() || traceroute) {
        return Err(CliError::new(
            Kind::Usage,
            "--list sends no probe; remove --discovery, --reverse-dns, and --traceroute",
        ));
    }
    Ok(())
}

fn build_request(inputs: RequestInputs) -> Result<Built, CliError> {
    let RequestInputs {
        endpoints,
        discovery,
        udp,
        limits,
        schedule,
        family,
        targets,
        origins,
        route_options,
    } = inputs;
    let EndpointInputs {
        transports,
        tcp_scan,
        sctp_scan,
        ports,
        exclude_ports,
        ip_protocols,
        exclude_ip_protocols,
    } = endpoints;
    let prepared_discovery = DiscoveryRequest {
        mode: discovery.mode,
        probes: discovery.probes,
        ports: discovery.ports,
        exclude_ports: exclude_ports.clone(),
        ip_protocols: discovery.ip_protocols,
        exclude_ip_protocols: exclude_ip_protocols.clone(),
        unresponsive: discovery.unresponsive,
        max_ports: limits.max_ports,
    }
    .prepare()?;
    let scanning = prepared_discovery.options.mode != discovery::Mode::Only;
    let mut endpoint_request = EndpointRequest {
        transports: transports.clone(),
        ports,
        exclude_ports,
        ip_protocols,
        exclude_ip_protocols,
        max_ports: limits.max_ports,
    };
    if prepared_discovery.options.runs() {
        endpoint_request.retain_scan_exclusions(&prepared_discovery.port_transports);
    }
    // Discovery has already consumed these shared exclusions. A port scan
    // must not reject exclusions that apply to its IP discovery stage.
    if transports != [Transport::Ip]
        && prepared_discovery.options.runs()
        && prepared_discovery
            .options
            .probes
            .iter()
            .any(|probe| matches!(probe, packetcraftr::probe::Endpoint::Ip { .. }))
    {
        endpoint_request.clear_ip_exclusions();
    }
    let udp_required = (scanning && transports.contains(&Transport::Udp))
        || prepared_discovery
            .options
            .probes
            .iter()
            .any(|probe| probe.transport() == Transport::Udp);
    let udp_payload = read_udp_payload(
        udp_required,
        udp.payload_hex.as_deref(),
        udp.payload_file.as_deref(),
    )?;
    let operator_profiles = load_udp_profiles(udp.profiles.as_deref(), udp_required)?;
    if udp.curated && !udp_required {
        return Err(CliError::new(
            Kind::Usage,
            "--curated-udp-payloads requires UDP scan or discovery probes",
        ));
    }
    let queue_limits = limits.capture.into_limits();
    let max_duration = limits.duration.max_duration();
    let scan_limits = packetcraftr::scan::Limits {
        max_prepared_bytes: limits.max_prepared_bytes,
        max_targets: limits.max_targets,
        max_ports: limits.max_ports,
        max_probes: limits.max_probes,
        max_duration,
        evidence: packetcraftr::evidence::Limits {
            max_frames: queue_limits.max_frames,
            max_bytes: queue_limits.max_bytes,
            max_undecoded: limits.max_undecoded,
        },
    };
    scan_limits.validate().map_err(CliError::classified)?;
    let selected = if scanning {
        endpoint_request.select()?
    } else if endpoint_request.has_includes() {
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
    let (udp_profiles, curated) = if udp.curated {
        let mut planned = selected.endpoints.clone();
        for probe in &prepared_discovery.options.probes {
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
        max_in_flight: schedule.max_in_flight,
        targets,
        target_sources: origins.iter().map(ToString::to_string).collect(),
        udp_payload,
        udp_profiles,
        address_family: family.into(),
        endpoints: selected.endpoints,
        tcp_scan,
        sctp_scan,
        discovery: prepared_discovery.options,
        attempts: schedule.attempts,
        adaptive: schedule.adaptive.into_adaptive(
            schedule.timeout.timeout(),
            max_duration,
            schedule.max_in_flight,
        ),
        timeout: schedule.timeout.timeout(),
        probes_per_second: schedule.rate,
        limits: scan_limits,
        route: route_options,
        collection: collection(schedule.timeout.timeout(), queue_limits)?,
    };
    if !tcp_scan.is_syn() || !sctp_scan.is_init() {
        request.validate().map_err(CliError::classified)?;
    }
    Ok(Built {
        request,
        excluded_endpoints: selected.excluded,
        curated,
        discovery_excluded: prepared_discovery.excluded,
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

/// Raw scans need packet capture and transmission in the requested link mode.
fn raw_capability(
    link_mode: packetcraftr_netio::link::Mode,
) -> Result<(), packetcraftr_netio::Unsupported> {
    use packetcraftr_netio::NativeCapability;
    NativeCapability::Capture.check()?;
    NativeCapability::Transmission(link_mode).check()
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{validate_list_options, validate_stdin_consumers};
    use crate::commands::network::scan::arguments::Discovery;

    fn usage_message(error: crate::errors::CliError) -> String {
        assert_eq!(error.exit_code(), 2);
        error.to_string()
    }

    #[test]
    fn rejects_multiple_stdin_consumers() {
        let error =
            validate_stdin_consumers(&[PathBuf::from("-")], &[PathBuf::from("-")], None, None)
                .unwrap_err();
        assert_eq!(
            usage_message(error),
            "stdin (`-`) can supply at most one of --targets-file, --exclude-file, --udp-payload-file, or --udp-profiles"
        );
    }

    #[test]
    fn list_rejects_discovery() {
        let error = validate_list_options(true, Some(Discovery::Before), &None, false).unwrap_err();
        assert_eq!(
            usage_message(error),
            "--list sends no probe; remove --discovery, --reverse-dns, and --traceroute"
        );
    }

    #[test]
    fn list_rejects_reverse_dns() {
        let error =
            validate_list_options(true, None, &Some("192.0.2.53".to_owned()), false).unwrap_err();
        assert_eq!(
            usage_message(error),
            "--list sends no probe; remove --discovery, --reverse-dns, and --traceroute"
        );
    }

    #[test]
    fn list_rejects_traceroute() {
        let error = validate_list_options(true, None, &None, true).unwrap_err();
        assert_eq!(
            usage_message(error),
            "--list sends no probe; remove --discovery, --reverse-dns, and --traceroute"
        );
    }
}
