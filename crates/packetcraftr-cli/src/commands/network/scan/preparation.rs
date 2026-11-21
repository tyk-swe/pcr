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
use request::{
    DiscoveryInputs, EndpointInputs, LimitInputs, RequestInputs, ScheduleInputs, UdpInputs,
    build_request,
};

pub(super) enum Planned {
    List(list::Request),
    Connect(connect::Request),
    Raw(raw::Request),
    PlanOnly {
        plan: crate::system::PlanSummary,
        preview_lines: Vec<String>,
    },
}

pub(super) fn prepare(
    invocation: &crate::invocation::Invocation,
    arguments: Args,
) -> Result<Planned, CliError> {
    let Args {
        connect,
        method,
        mut max_in_flight,
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
        mut attempts,
        adaptive,
        mut timeout,
        mut rate,
        timing,
        shuffle_seed,
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
        gate,
        preview,
    } = arguments;

    if let Some(preset) = timing {
        let schedule = preset.schedule();
        rate = Some(schedule.rate);
        timeout = crate::command_options::TimeoutArgs::from_millis(schedule.timeout_ms);
        attempts = schedule.attempts;
        max_in_flight = schedule.max_in_flight;
    }

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
        invocation,
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

    if preview && !list && !gate.plan_only {
        return Err(CliError::new(
            Kind::Usage,
            "--preview sends no probe; combine it with --list or --plan-only",
        ));
    }
    if gate.plan_only && invocation.format != crate::output::contract::Format::Text {
        return Err(CliError::new(
            Kind::Usage,
            format!(
                "--plan-only prints text only, not --output {}",
                invocation.format
            ),
        ));
    }
    let plan_only_needs_build =
        gate.plan_only && !list && (discovery.is_some() || reverse_dns.is_some() || traceroute);
    let gate_active = gate.plan_only || gate.plan_digest.is_some() || preview;
    let gate_plan = if gate_active {
        let schedule_lines = format!(
            "ports={ports:?}\nexclude_ports={exclude_ports:?}\nip_protocols={ip_protocols:?}\nexclude_ip_protocols={exclude_ip_protocols:?}\ndiscovery_probes={discovery_probes:?}\ndiscovery_ports={discovery_ports:?}\ndiscovery_ip_protocols={discovery_ip_protocols:?}\nunresponsive_hosts={unresponsive_hosts:?}\nadaptive={adaptive:?}\nlink_mode={:?}\nmax_targets={max_targets}\nmax_probes={max_probes}\nmax_prepared_bytes={max_prepared_bytes}\nmax_undecoded={max_undecoded}\nmax_duration_ms={}\ncapture_limits={limits:?}\n{}",
            route.link_mode,
            duration.max_duration().as_millis(),
            if traceroute {
                format!(
                    "traceroute_strategy={traceroute_strategy:?}\ntraceroute_port={traceroute_port:?}\ntraceroute_first_hop={traceroute_first_hop}\ntraceroute_max_hops={traceroute_max_hops}\ntraceroute_attempts={traceroute_attempts}\ntraceroute_max_probes={traceroute_max_probes}\ntraceroute_reuse_max_age_ms={traceroute_reuse_max_age_ms:?}\n"
                )
            } else {
                String::new()
            },
        );
        let udp_required = transports.contains(&Transport::Udp)
            || discovery_probes.contains(&arguments::DiscoveryProbe::Udp);
        let summary = scan_plan_summary(
            invocation,
            ScanPlanInputs {
                policy: &policy,
                targets: &targets,
                transports: &transports,
                ports: &ports,
                exclude_ports: &exclude_ports,
                ip_protocols: &ip_protocols,
                exclude_ip_protocols: &exclude_ip_protocols,
                max_ports,
                connect,
                method,
                tcp_scan: &tcp_scan,
                sctp_scan,
                family,
                attempts,
                rate,
                timeout: &timeout,
                max_in_flight,
                shuffle_seed,
                discovery,
                reverse_dns: &reverse_dns,
                reverse_dns_port,
                traceroute,
                udp_payload_hex: &udp_payload_hex,
                udp_payload_file: &udp_payload_file,
                udp_profiles: &udp_profiles,
                curated_udp_payloads,
                schedule_lines: &schedule_lines,
                udp_required,
                max_targets,
            },
        )?;
        if gate.plan_digest.is_some() {
            let check = crate::command_options::PlanGateArgs {
                plan_only: false,
                plan_digest: gate.plan_digest.clone(),
            };
            crate::system::enforce_plan_gate(invocation, &check, "scan", &summary)?;
        }
        Some(summary)
    } else {
        None
    };

    if list || (gate.plan_only && !plan_only_needs_build) {
        validate_list_options(true, discovery, &reverse_dns, traceroute)?;

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
        let portless_endpoints = usize::from(transports == [Transport::Icmp]);
        if ip_only && requested == method::Requested::Connect {
            return Err(CliError::new(
                Kind::Usage,
                "--transport ip needs the raw method; drop --connect and --method tcp-connect",
            ));
        }
        let mut selected = EndpointRequest {
            transports,
            ports,
            exclude_ports,
            ip_protocols,
            exclude_ip_protocols,
            max_ports,
        }
        .select_if_requested()?;
        if let (Some(seed), Some(selected)) = (shuffle_seed, selected.as_mut()) {
            packetcraftr::scan::shuffle_endpoints(&mut selected.endpoints, seed);
        }
        let (ports, ip_protocols) = if ip_only {
            (
                None,
                selected
                    .as_ref()
                    .map(super::output::plan::IpProtocols::from),
            )
        } else {
            let ports = selected.as_ref().map(|selected| {
                let ports = super::output::plan::Ports::from(selected);
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
            shuffle_seed,
            policy,
            plan: gate_plan,
            preview: preview.then_some(list::PreviewInputs {
                attempts,
                rate,
                timeout: timeout.timeout(),
                portless_endpoints,
            }),
        }));
    }

    let inputs = RequestInputs {
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
            shuffle_seed,
        },
        family,
        targets,
        origins,
        route_options: packetcraftr::route::Options {
            link_mode: route.link_mode.into(),
            ..Default::default()
        },
    };
    let built = build_request(invocation, inputs)?;
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
        PublicationInputs {
            timing,
            shuffle_seed,
            excluded_endpoints: built.excluded_endpoints,
            curated: built.curated,
            discovery_excluded: built.discovery_excluded,
            reverse_dns: &reverse_dns,
            reverse_dns_port,
        },
        &built.request,
    );
    let reverse_dns = reverse_dns
        .map(crate::command_options::parse_target)
        .transpose()?;
    if gate.plan_only {
        if selected_method == method::Method::Connect
            && let Some(server) = reverse_dns.clone()
        {
            super::validated_reverse_dns(
                followup::ReverseDns {
                    server,
                    server_port: reverse_dns_port,
                    transport: packetcraftr::dns::TransportMode::Tcp,
                },
                &built.request,
            )?;
        }
        let mut plan = gate_plan.ok_or_else(|| {
            CliError::new(Kind::Internal, "scan plan-only preparation lost its plan")
        })?;
        let candidates = candidate_upper_bound(
            &built.request.targets,
            &policy.clone().into_policy(),
            max_targets,
        );
        plan.packets = candidates
            .saturating_mul(built.request.endpoints.len() as u64)
            .saturating_mul(u64::from(built.request.attempts));
        let preview_lines = if preview {
            list::preview_lines(
                usize::try_from(candidates).unwrap_or(usize::MAX),
                built.request.endpoints.len(),
                list::PreviewInputs {
                    attempts: built.request.attempts,
                    rate: built.request.probes_per_second,
                    timeout: built.request.timeout,
                    portless_endpoints: 0,
                },
            )
        } else {
            Vec::new()
        };
        return Ok(Planned::PlanOnly {
            plan,
            preview_lines,
        });
    }
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

struct PublicationInputs<'a> {
    timing: Option<arguments::Timing>,
    shuffle_seed: Option<u64>,
    excluded_endpoints: usize,
    curated: Option<super::output::plan::CuratedPayloads>,
    discovery_excluded: usize,
    reverse_dns: &'a Option<String>,
    reverse_dns_port: u16,
}

fn publication_plan(
    selection: method::Selection,
    schedule: PublicationInputs<'_>,
    request: &packetcraftr::scan::Request,
) -> super::output::plan::Plan {
    let selected_method = selection.method;
    super::output::plan::Plan {
        tcp_scan: (selected_method == method::Method::Raw
            && request
                .endpoints
                .iter()
                .any(|endpoint| endpoint.transport() == Transport::Tcp))
        .then(|| super::output::plan::TcpScan::from(request.tcp_scan)),
        sctp_scan: (selected_method == method::Method::Raw
            && request
                .endpoints
                .iter()
                .any(|endpoint| endpoint.transport() == Transport::Sctp))
        .then(|| super::output::plan::SctpScan::from(request.sctp_scan)),
        method: selection.into(),
        timing: schedule.timing.map(arguments::Timing::as_str),
        shuffle_seed: schedule.shuffle_seed,
        port_catalog: packetcraftr::scan::catalog::data_set().into(),
        excluded_endpoints: schedule.excluded_endpoints,
        curated_udp_payloads: schedule.curated,
        discovery: super::output::plan::Discovery::new(
            &request.discovery,
            schedule.discovery_excluded,
            schedule
                .reverse_dns
                .as_ref()
                .map(|server| super::output::plan::ReverseDnsServer {
                    server: server.clone(),
                    port: schedule.reverse_dns_port,
                }),
        ),
    }
}

struct ScanPlanInputs<'a> {
    policy: &'a crate::command_options::HostnamePolicyArgs,
    targets: &'a packetcraftr::target::Selection,
    transports: &'a [Transport],
    ports: &'a [arguments::PortTerm],
    exclude_ports: &'a [arguments::PortTerm],
    ip_protocols: &'a [arguments::IpProtocolTerm],
    exclude_ip_protocols: &'a [arguments::IpProtocolTerm],
    max_ports: usize,
    connect: bool,
    method: arguments::Method,
    tcp_scan: &'a packetcraftr::scan::TcpScan,
    sctp_scan: packetcraftr::scan::SctpScan,
    family: crate::command_options::AddressFamily,
    attempts: u32,
    rate: Option<u32>,
    timeout: &'a crate::command_options::TimeoutArgs,
    max_in_flight: usize,
    shuffle_seed: Option<u64>,
    discovery: Option<arguments::Discovery>,
    reverse_dns: &'a Option<String>,
    reverse_dns_port: u16,
    traceroute: bool,
    udp_payload_hex: &'a Option<String>,
    udp_payload_file: &'a Option<std::path::PathBuf>,
    udp_profiles: &'a Option<std::path::PathBuf>,
    curated_udp_payloads: bool,
    schedule_lines: &'a str,
    udp_required: bool,
    max_targets: usize,
}

fn candidate_upper_bound(
    selection: &packetcraftr::target::Selection,
    policy: &packetcraftr::policy::Policy,
    max_targets: usize,
) -> u64 {
    use packetcraftr::target::{Specification, Target};
    use std::collections::HashSet;

    let mut seen = HashSet::new();
    let mut total: u64 = 0;
    for spec in &selection.include {
        if !seen.insert(spec) {
            continue;
        }
        let count = match spec {
            Specification::Target(Target::Hostname(_)) => policy.max_resolved_addresses as u64,
            Specification::Target(_) => 1,
            Specification::Network(network) => network
                .cardinality(max_targets)
                .map(|count| count as u64)
                .unwrap_or(max_targets as u64),
        };
        total = total.saturating_add(count);
        if total >= max_targets as u64 {
            return max_targets as u64;
        }
    }
    total.min(max_targets as u64)
}

fn scan_plan_summary(
    invocation: &crate::invocation::Invocation,
    inputs: ScanPlanInputs<'_>,
) -> Result<crate::system::PlanSummary, CliError> {
    use sha2::{Digest, Sha256};

    if inputs
        .udp_payload_file
        .as_deref()
        .is_some_and(|path| path == Path::new("-"))
        || inputs
            .udp_profiles
            .as_deref()
            .is_some_and(|path| path == Path::new("-"))
    {
        return Err(CliError::new(
            Kind::Usage,
            "the scan plan gate cannot bind stdin payload inputs; use files for --udp-payload-file and --udp-profiles",
        ));
    }
    let policy = inputs.policy.clone().into_policy();
    let policy_digest = policy.digest();
    let selected = EndpointRequest {
        transports: inputs.transports.to_vec(),
        ports: inputs.ports.to_vec(),
        exclude_ports: inputs.exclude_ports.to_vec(),
        ip_protocols: inputs.ip_protocols.to_vec(),
        exclude_ip_protocols: inputs.exclude_ip_protocols.to_vec(),
        max_ports: inputs.max_ports,
    }
    .select_if_requested()?;
    let endpoints: Vec<String> = match &selected {
        Some(selected) => selected.endpoints.iter().map(ToString::to_string).collect(),
        None if inputs.transports == [Transport::Icmp] => {
            vec![packetcraftr::probe::Endpoint::Icmp.to_string()]
        }
        None => Vec::new(),
    };
    let mut hasher = Sha256::new();
    hasher.update(
        format!(
            "packetcraftr.scan-plan/v1\npolicy={policy_digest}\nconnect={}\nmethod={:?}\ntcp_scan={:?}\nsctp_scan={:?}\nfamily={:?}\nattempts={}\nrate={}\ntimeout_ms={}\nmax_in_flight={}\nshuffle_seed={}\ndiscovery={:?}\nreverse_dns={}\nreverse_dns_port={}\ntraceroute={}\ncurated_udp_payloads={}\n",
            inputs.connect,
            inputs.method,
            inputs.tcp_scan,
            inputs.sctp_scan,
            inputs.family,
            inputs.attempts,
            inputs
                .rate
                .map_or_else(|| "-".to_owned(), |value| value.to_string()),
            inputs.timeout.timeout().as_millis(),
            inputs.max_in_flight,
            inputs
                .shuffle_seed
                .map_or_else(|| "-".to_owned(), |value| value.to_string()),
            inputs.discovery,
            inputs.reverse_dns.as_deref().unwrap_or("-"),
            inputs.reverse_dns_port,
            inputs.traceroute,
            inputs.curated_udp_payloads,
        )
        .as_bytes(),
    );
    hasher.update(inputs.schedule_lines.as_bytes());
    for spec in &inputs.targets.include {
        hasher.update(format!("include={spec}\n").as_bytes());
    }
    for network in &inputs.targets.exclude {
        hasher.update(format!("exclude={network}\n").as_bytes());
    }
    for endpoint in &endpoints {
        hasher.update(format!("endpoint={endpoint}\n").as_bytes());
    }
    if inputs.curated_udp_payloads && !inputs.udp_required {
        return Err(CliError::new(
            Kind::Usage,
            "--curated-udp-payloads requires UDP scan or discovery probes",
        ));
    }
    hasher.update(b"udp_payload=");
    if inputs.udp_payload_hex.is_some() || inputs.udp_payload_file.is_some() {
        let payload = super::inputs::read_udp_payload(
            invocation,
            inputs.udp_required,
            inputs.udp_payload_hex.as_deref(),
            inputs.udp_payload_file.as_deref(),
        )?;
        hasher.update((payload.len() as u64).to_be_bytes());
        hasher.update(&payload);
    } else {
        hasher.update(b"absent\n");
    }
    hasher.update(b"udp_profiles=");
    if let Some(profiles) = inputs.udp_profiles {
        if !inputs.udp_required {
            return Err(CliError::new(
                Kind::Usage,
                "--udp-profiles requires --transport udp",
            ));
        }
        let bytes = crate::input::read_document(
            &invocation.control,
            profiles,
            1024 * 1024,
            crate::input::InputKind::UdpProfiles,
        )?;
        hasher.update((bytes.len() as u64).to_be_bytes());
        hasher.update(&bytes);
    } else {
        hasher.update(b"absent\n");
    }
    let packets = candidate_upper_bound(inputs.targets, &policy, inputs.max_targets)
        .saturating_mul(endpoints.len() as u64)
        .saturating_mul(u64::from(inputs.attempts));
    Ok(crate::system::PlanSummary {
        digest: packetcraftr_core::field::hex::compact_hex(&hasher.finalize()),
        packets,
        wire_bytes: 0,
        destination: None,
        policy_digest,
    })
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
