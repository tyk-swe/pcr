// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::IpAddr;
use std::time::Duration;

use packetcraftr_core::budget::Deadline;
use packetcraftr_netio::link::Mode;

use crate::engine::admission::{DeclaredTargets, FamilyGate, admit_selection, wire_limits};
use crate::engine::execution::rate_delay;
use crate::policy::Authorizer;
use crate::probe::{check_collection_evidence, check_probe_count, check_probe_duration};
use crate::target::ResolveTarget;
use crate::target::SelectedAddress;

use crate::neighbor::{needs_resolution, request_wire_bytes};
use crate::probe;
use crate::scan::Error;
use crate::scan::Request;
use crate::scan::error::probe_error;
use crate::scan::plan::{adaptive_worst_case_duration, ip_worst_case_duration, probe_count};
use crate::scan::{IPV4_PROBE_BYTES, IPV6_PROBE_BYTES};

pub(super) struct Approved {
    pub(super) planned_duration: std::time::Duration,
    pub(super) declared_target: String,
    pub(super) targets: Vec<SelectedAddress>,
    pub(super) duplicates: Vec<u32>,
    pub(super) endpoints: Vec<probe::Endpoint>,
    /// Discovery and scan probes, without neighbor requests.
    pub(super) total_probes: usize,
    /// Whether explicit discovery or any probe resolves a link-layer
    /// neighbor.
    pub(super) resolves_neighbors: bool,
}

impl Approved {
    pub(super) fn addresses(&self) -> Vec<IpAddr> {
        self.targets.iter().map(|target| target.address).collect()
    }
}

pub(super) struct Plan {
    pub(super) total_probes: usize,
    pub(super) resolves_neighbors: bool,
    pub(super) neighbor_requests: usize,
    pub(super) maximum_bytes: u64,
    pub(super) worst_case: Duration,
}

pub(super) fn approve<A: Authorizer + ResolveTarget>(
    request: &Request,
    authorizer: &mut A,
    deadline: &Deadline,
) -> Result<Approved, Error> {
    let endpoints = request.planned_endpoints()?.to_vec();
    // Only the serial path reuses `collection` to retain each exchange's frames.
    if request.max_in_flight == 1 {
        check_collection_evidence(probe_error, &request.collection, request.limits.evidence)?;
    }
    // Implementations must authorize the declared target before DNS and every
    // answer before anything below constructs a probe; `admit_selection` owns
    // that ordering.
    let (selected, plan) = admit_selection(
        authorizer,
        deadline,
        probe_error,
        DeclaredTargets {
            selection: &request.targets,
            family: FamilyGate::new(request.address_family, Error::family),
            max_targets: request.limits.max_targets,
            resolved: None,
        },
        Error::TargetSelection,
        |selected| plan(request, &selected.targets, &endpoints),
        |plan| {
            Ok(wire_limits(
                u64::try_from(plan.total_probes.saturating_add(plan.neighbor_requests))
                    .unwrap_or(u64::MAX),
                plan.maximum_bytes,
            ))
        },
    )?;
    if request.route.interface.is_some()
        && selected.targets.iter().any(|target| target.scope.is_some())
    {
        return Err(Error::InvalidLimit {
            field: "interface",
            value: 0,
            reason: "scoped targets cannot combine with an explicit --interface".to_owned(),
        });
    }
    if request.discovery.runs()
        && request.discovery.probes.iter().any(|probe| {
            matches!(
                probe,
                probe::Endpoint::IcmpTimestamp | probe::Endpoint::IcmpNetmask
            )
        })
        && selected
            .targets
            .iter()
            .any(|target| target.address.is_ipv6())
    {
        return Err(Error::InvalidDiscovery {
            message: "ICMP timestamp and netmask discovery probes are IPv4-only and cannot be used with IPv6 targets".to_owned(),
        });
    }

    Ok(Approved {
        planned_duration: plan.worst_case,
        declared_target: selected.declared,
        targets: selected.targets,
        duplicates: selected.duplicates,
        endpoints,
        total_probes: plan.total_probes,
        resolves_neighbors: plan.resolves_neighbors,
    })
}

/// Plans discovery and the scan as one budget: their probes, neighbor
/// requests, wire bytes, and worst-case durations must fit the request's
/// limits together, before discovery decides which hosts are scanned.
pub(super) fn plan(
    request: &Request,
    targets: &[SelectedAddress],
    endpoints: &[probe::Endpoint],
) -> Result<Plan, Error> {
    let overflow = || Error::InvalidLimit {
        field: "probes",
        value: u64::MAX,
        reason: "probe-count arithmetic overflowed".to_owned(),
    };
    let discovery = &request.discovery;
    let probes = if discovery.runs() {
        discovery.probes.as_slice()
    } else {
        &[]
    };
    let discovery_probes = probe_count(targets.len(), probes.len(), request.attempts)?;
    // A multicast or limited-broadcast target's link address follows from its
    // own, so neither discovery nor a stage asks for its neighbor.
    let resolvable: Vec<&SelectedAddress> = targets
        .iter()
        .filter(|target| needs_resolution(target.address))
        .collect();
    let explicit_requests = if discovery.runs() && discovery.neighbor {
        probe_count(resolvable.len(), 1, request.attempts)?
    } else {
        0
    };
    if explicit_requests > 0 {
        // Each attempt is one resolver request bounded like a probe.
        crate::neighbor::Options::default()
            .single_attempt(
                request.timeout,
                request.limits.evidence.max_frames,
                request.limits.evidence.max_bytes,
                request.collection.capture.snap_length,
            )
            .validate()
            .map_err(|source| Error::InvalidDiscovery {
                message: format!(
                    "neighbor discovery cannot use the scan timeout, snap length, and evidence limits: {source}"
                ),
            })?;
    }
    let scan_probes = probe_count(targets.len(), endpoints.len(), request.attempts)?;
    let total_probes = discovery_probes
        .checked_add(scan_probes)
        .ok_or_else(overflow)?;
    // Each stage resolves its probes' link-layer neighbors before sending
    // them: a fresh resolution asks for the target's neighbor, or its
    // gateway's, with at most one request each.
    let resolves_next_hops =
        total_probes > 0 && request.route.link_mode != Mode::Layer3 && !resolvable.is_empty();
    // Explicit neighbor discovery runs first and covers those requests: an
    // answer stays in the operation's cache, a silent target is sent nothing
    // more, and a routed target, which it sends nothing, needs at most one
    // request for its gateway within its `attempts`.
    let implicit_requests = if resolves_next_hops && explicit_requests == 0 {
        resolvable.len()
    } else {
        0
    };
    if resolves_next_hops {
        // Those requests capture within the evidence limits and snap length,
        // which must hold a decodable reply just as explicit neighbor
        // discovery requires.
        let snap_length = request.collection.capture.snap_length;
        let (field, value) = if snap_length < request.limits.evidence.max_bytes {
            ("snap_length", snap_length)
        } else {
            ("max_evidence_bytes", request.limits.evidence.max_bytes)
        };
        crate::neighbor::Options::default()
            .one_attempt(
                request.timeout,
                request.limits.evidence.max_frames,
                request.limits.evidence.max_bytes,
                snap_length,
            )
            .validate()
            .map_err(|source| Error::InvalidLimit {
                field,
                value: u64::try_from(value).unwrap_or(u64::MAX),
                reason: format!("cannot hold an implicit neighbor resolution: {source}"),
            })?;
    }
    let neighbor_requests = explicit_requests
        .checked_add(implicit_requests)
        .ok_or_else(overflow)?;
    check_probe_count(
        probe_error,
        total_probes
            .checked_add(neighbor_requests)
            .ok_or_else(overflow)?,
        request.limits.max_probes,
    )?;
    let neighbor_frames = resolvable.iter().try_fold(0u64, |total, target| {
        total.checked_add(request_wire_bytes(target.address))
    });
    // One target's neighbor bytes cover `attempts` discovery requests plus
    // at most one implicit request for its probes' neighbor.
    let neighbor_bytes = neighbor_frames
        .and_then(|per_target| {
            let explicit = if explicit_requests == 0 {
                Some(0)
            } else {
                per_target.checked_mul(u64::from(request.attempts))
            }?;
            explicit.checked_add(if implicit_requests == 0 {
                0
            } else {
                per_target
            })
        })
        .ok_or_else(overflow)?;
    let maximum_bytes = maximum_wire_bytes(targets, probes, request, false)?
        .checked_add(maximum_wire_bytes(targets, endpoints, request, true)?)
        .and_then(|bytes| bytes.checked_add(neighbor_bytes))
        .ok_or_else(overflow)?;
    let too_long = || Error::DurationLimit {
        actual: Duration::MAX,
        limit: request.limits.max_duration,
    };
    let pause = rate_delay(
        probe_error,
        "probes_per_second",
        1,
        request.probes_per_second,
    )?;
    // Every neighbor request waits its attempt timeout and paces like a probe,
    // except a last request no probe follows; a paced request's wait counts
    // toward its pause, so it holds the next transmission back by the longer.
    let neighbor_requests = explicit_requests
        .checked_add(implicit_requests)
        .ok_or_else(too_long)?;
    let neighbor_pauses = if total_probes == 0 {
        neighbor_requests.saturating_sub(1)
    } else {
        neighbor_requests
    };
    let neighbor_duration = u32::try_from(neighbor_requests - neighbor_pauses)
        .ok()
        .and_then(|unpaced| request.timeout.checked_mul(unpaced))
        .and_then(|waits| {
            u32::try_from(neighbor_pauses)
                .ok()
                .and_then(|paced| request.timeout.max(pause).checked_mul(paced))
                .and_then(|paced| paced.checked_add(waits))
        })
        .ok_or_else(too_long)?;
    let stage_pause = if discovery_probes > 0 && scan_probes > 0 {
        pause
    } else {
        Duration::ZERO
    };
    let stage_duration = |count, stage_endpoints: &[probe::Endpoint]| {
        request.adaptive.map_or_else(
            || ip_worst_case_duration(request, count, targets, stage_endpoints),
            |adaptive| adaptive_worst_case_duration(request, &adaptive, count),
        )
    };
    let worst_case = [
        stage_duration(discovery_probes, probes)?,
        neighbor_duration,
        stage_pause,
        stage_duration(scan_probes, endpoints)?,
    ]
    .into_iter()
    .try_fold(Duration::ZERO, Duration::checked_add)
    .ok_or_else(too_long)?;
    check_probe_duration(probe_error, worst_case, request.limits.max_duration)?;
    Ok(Plan {
        total_probes,
        resolves_neighbors: resolves_next_hops || explicit_requests > 0,
        neighbor_requests,
        maximum_bytes,
        worst_case,
    })
}

pub(super) fn maximum_wire_bytes(
    targets: &[SelectedAddress],
    endpoints: &[probe::Endpoint],
    request: &Request,
    scan_stage: bool,
) -> Result<u64, Error> {
    let overflow = || Error::InvalidLimit {
        field: "wire_bytes",
        value: u64::MAX,
        reason: "scan payload accounting overflowed".to_owned(),
    };
    let sctp_init_extra = if !scan_stage || request.sctp_scan.is_init() {
        12_u64
    } else {
        0_u64
    };
    let payload = endpoints.iter().try_fold(0u64, |total, endpoint| {
        let extra = match endpoint {
            probe::Endpoint::Udp { port } => request
                .udp_profiles
                .get(port)
                .map_or(request.udp_payload.len(), |profile| {
                    profile.payload_length()
                }) as u64,
            probe::Endpoint::Sctp { .. } => sctp_init_extra,
            probe::Endpoint::Tcp { .. }
            | probe::Endpoint::TcpAck { .. }
            | probe::Endpoint::Icmp
            | probe::Endpoint::IcmpTimestamp
            | probe::Endpoint::IcmpNetmask
            | probe::Endpoint::Ip { .. } => 0,
        };
        total.checked_add(extra).ok_or_else(overflow)
    })?;
    let endpoints = endpoints.len() as u64;
    targets.iter().try_fold(0u64, |total, target| {
        let header = if target.address.is_ipv4() {
            IPV4_PROBE_BYTES
        } else {
            IPV6_PROBE_BYTES
        };
        let bytes = header
            .checked_mul(endpoints)
            .and_then(|bytes| bytes.checked_add(payload))
            .and_then(|bytes| bytes.checked_mul(u64::from(request.attempts)))
            .ok_or_else(overflow)?;
        total.checked_add(bytes).ok_or_else(overflow)
    })
}
