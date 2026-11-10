// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Convert one prepared endpoint plan and its remaining options into an executable request.

use crate::command_options::Bounded as _;
use packetcraftr::scan::{Base, Limits, Schedule, Targets, Udp, profile::curated};
use packetcraftr_core::error::Kind;

use super::super::arguments::AdaptiveArgs;
use super::super::inputs::{load_udp_profiles, read_udp_payload};
use crate::command_options::{AddressFamily, CaptureLimitsArgs, MaxDurationArgs, TimeoutArgs};
use crate::errors::CliError;
use crate::input::manifest;
use crate::system::collection;

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
    pub(super) selection: packetcraftr::scan::Prepared,
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
    pub(super) curated: Option<crate::commands::network::scan::output::plan::CuratedPayloads>,
    pub(super) queue_limits: packetcraftr_netio::capture::Limits,
}

pub(super) fn build_request(
    invocation: &crate::invocation::Invocation,
    inputs: RequestInputs,
) -> Result<Built, CliError> {
    let RequestInputs {
        selection,
        udp,
        limits,
        schedule,
        family,
        targets,
        origins,
        route_options,
    } = inputs;
    let udp_required = selection
        .endpoints()
        .iter()
        .chain(selection.discovery().probes())
        .any(|endpoint| endpoint.transport() == packetcraftr::probe::Transport::Udp);
    let udp_payload = read_udp_payload(
        invocation,
        udp_required,
        udp.payload_hex.as_deref(),
        udp.payload_file.as_deref(),
    )?;
    let operator_profiles = load_udp_profiles(invocation, udp.profiles.as_deref(), udp_required)?;
    if udp.curated && !udp_required {
        return Err(CliError::new(
            Kind::Usage,
            "--curated-udp-payloads requires UDP scan or discovery probes",
        ));
    }
    let queue_limits = limits.capture.into_limits();
    let scan_limits = Limits {
        max_prepared_bytes: limits.max_prepared_bytes,
        max_targets: limits.max_targets,
        max_ports: limits.max_ports,
        max_probes: limits.max_probes,
        max_duration: limits.duration.max_duration(),
        evidence: packetcraftr::evidence::Limits {
            max_frames: queue_limits.max_frames,
            max_bytes: queue_limits.max_bytes,
            max_undecoded: limits.max_undecoded,
        },
    };
    let (udp_profiles, curated) = if udp.curated {
        let mut planned = selection.endpoints().to_vec();
        for probe in selection.discovery().probes() {
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
    let timeout = schedule.timeout.timeout();
    let max_in_flight = schedule.max_in_flight;
    let request = packetcraftr::scan::Request::new(
        Base {
            targets: Targets {
                selection: targets,
                sources: origins.iter().map(ToString::to_string).collect(),
                family: family.into(),
            },
            selection,
            udp: Udp {
                payload: udp_payload,
                profiles: udp_profiles,
            },
            schedule: Schedule {
                max_in_flight,
                attempts: schedule.attempts,
                adaptive: schedule.adaptive.into_adaptive(
                    timeout,
                    scan_limits.max_duration,
                    max_in_flight,
                ),
                timeout,
                probes_per_second: schedule.rate,
            },
            limits: scan_limits,
        },
        route_options,
        collection(timeout, queue_limits)?,
    )
    .map_err(CliError::classified)?;
    Ok(Built {
        request,
        curated,
        queue_limits,
    })
}
