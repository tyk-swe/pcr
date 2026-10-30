// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Validate scan arguments and turn them into one typed execution request.
//! Selection and method checks stay here so list, connect, and raw modes share
//! their precedence and diagnostics.

mod request;

use crate::command_options::Bounded as _;
use std::path::Path;
use std::time::Duration;

use packetcraftr::probe::Transport;
use packetcraftr::scan::{followup, method};
use packetcraftr_core::error::Kind;

use super::arguments::{self, Args};
use super::inputs::ingest_targets;
use super::selection::{EndpointRequest, transports};
use super::{connect, list, raw, traceroute};
use crate::errors::CliError;
use crate::input::manifest;
use crate::output;
use request::{
    DiscoveryInputs, EndpointInputs, LimitInputs, RequestInputs, ScheduleInputs, UdpInputs,
    build_request,
};

pub(super) enum Planned {
    List(list::Request),
    Connect(connect::Request),
    Raw(raw::Request),
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
mod tests;
