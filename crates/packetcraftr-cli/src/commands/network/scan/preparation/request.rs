// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Turning the scan's grouped arguments into one validated scan request.

use packetcraftr::probe::Transport;
use packetcraftr::scan::{discovery, profile::curated};
use packetcraftr_core::error::Kind;

use super::super::arguments::{
    self, AdaptiveArgs, DiscoveryProbe, IpProtocolTerm, PortTerm, UnresponsiveHosts,
};
use super::super::inputs::{load_udp_profiles, read_udp_payload};
use super::super::selection::{DiscoveryRequest, EndpointRequest};
use crate::command_options::{AddressFamily, CaptureLimitsArgs, MaxDurationArgs, TimeoutArgs};
use crate::errors::CliError;
use crate::input::manifest;
use crate::output;
use crate::system::collection;

pub(super) struct EndpointInputs {
    pub(super) transports: Vec<Transport>,
    pub(super) tcp_scan: packetcraftr::scan::TcpScan,
    pub(super) sctp_scan: packetcraftr::scan::SctpScan,
    pub(super) ports: Vec<PortTerm>,
    pub(super) exclude_ports: Vec<PortTerm>,
    pub(super) ip_protocols: Vec<IpProtocolTerm>,
    pub(super) exclude_ip_protocols: Vec<IpProtocolTerm>,
}

pub(super) struct DiscoveryInputs {
    pub(super) mode: Option<arguments::Discovery>,
    pub(super) probes: Vec<DiscoveryProbe>,
    pub(super) ports: Vec<PortTerm>,
    pub(super) ip_protocols: Vec<IpProtocolTerm>,
    pub(super) unresponsive: Option<UnresponsiveHosts>,
}

pub(super) struct UdpInputs {
    pub(super) payload_hex: Option<String>,
    pub(super) payload_file: Option<std::path::PathBuf>,
    pub(super) profiles: Option<std::path::PathBuf>,
    pub(super) curated: bool,
}

pub(super) struct LimitInputs {
    pub(super) capture: CaptureLimitsArgs,
    pub(super) max_prepared_bytes: usize,
    pub(super) max_targets: usize,
    pub(super) max_ports: usize,
    pub(super) max_probes: usize,
    pub(super) max_undecoded: usize,
    pub(super) duration: MaxDurationArgs,
}

pub(super) struct ScheduleInputs {
    pub(super) max_in_flight: usize,
    pub(super) attempts: u32,
    pub(super) adaptive: AdaptiveArgs,
    pub(super) timeout: TimeoutArgs,
    pub(super) rate: Option<u32>,
}

pub(super) struct RequestInputs {
    pub(super) endpoints: EndpointInputs,
    pub(super) discovery: DiscoveryInputs,
    pub(super) udp: UdpInputs,
    pub(super) limits: LimitInputs,
    pub(super) schedule: ScheduleInputs,
    pub(super) family: AddressFamily,
    pub(super) targets: packetcraftr::target::Selection,
    pub(super) origins: Vec<manifest::Declaration>,
    pub(super) route_options: packetcraftr::route::Options,
}

pub(super) struct Built {
    pub(super) request: packetcraftr::scan::Request,
    pub(super) excluded_endpoints: usize,
    pub(super) curated: Option<output::scan::plan::CuratedPayloads>,
    pub(super) discovery_excluded: usize,
    pub(super) queue_limits: packetcraftr_netio::capture::Limits,
}

/// Builds and validates the scan request the grouped arguments describe.
pub(super) fn build_request(inputs: RequestInputs) -> Result<Built, CliError> {
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
