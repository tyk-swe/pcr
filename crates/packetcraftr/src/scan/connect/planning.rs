// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! TCP target admission, preparation budgets, and per-stage endpoint plans.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use packetcraftr_core::budget::Deadline;
use packetcraftr_netio::tcp;

use super::super::error::Probes;
use super::super::plan::{adaptive_worst_case_duration, probe_count, worst_case_duration};
use super::super::{Error, Request, Stage};
use super::{execution, invalid};
use crate::execution::rate_delay;
use crate::policy::{Authorizer, Operation, SocketLimits, SocketOperation};
use crate::probe::ProbeEndpoint;
use crate::target::{DeclaredTargets, FamilyGate, ResolveTarget, SelectedAddress, admit_selection};

pub(super) struct Planned {
    /// Discovery ports, probed on every target before the scan stage.
    discovery: Vec<u16>,
    /// Scan ports, probed on the targets discovery leaves to the scan.
    ports: Vec<u16>,
    pub(super) diagnostics: Vec<packetcraftr_core::diagnostic::Diagnostic>,
    delay: Duration,
    limits: SocketLimits,
    pub(super) planned_duration: Duration,
}

pub(super) fn planned<A: Authorizer + ResolveTarget>(
    request: &Request,
    authorizer: &mut A,
    deadline: &Deadline,
    active_size: usize,
) -> Result<(Vec<SelectedAddress>, Planned), Error> {
    let tcp_ports = |endpoints: &[ProbeEndpoint]| -> Vec<u16> {
        endpoints
            .iter()
            .filter_map(|endpoint| endpoint.port())
            .collect()
    };
    let ports = tcp_ports(request.planned_endpoints()?);
    if let Some(probe) = super::super::method::unconnectable(request) {
        return Err(Error::MethodProbe {
            method: super::super::method::Method::Connect.as_str(),
            probe,
        });
    }
    let discovery = if request.discovery.runs() {
        tcp_ports(&request.discovery.probes)
    } else {
        Vec::new()
    };
    if request.route.requires_packet_route() {
        return Err(Error::UnsupportedTcpRoute);
    }
    if ports.contains(&0) || discovery.contains(&0) {
        return Err(invalid("port", 0, "TCP connect requires nonzero ports"));
    }
    let (selected, (planned, _)) = admit_selection(
        authorizer,
        deadline,
        &Probes,
        DeclaredTargets {
            selection: &request.targets,
            family: FamilyGate::new(request.address_family, Error::family),
            max_targets: request.limits.max_targets,
        },
        Error::TargetSelection,
        |selected| {
            let targets = selected.targets.len();
            let discovery_count = probe_count(targets, discovery.len(), request.attempts)?;
            let scan_count = probe_count(targets, ports.len(), request.attempts)?;
            let count = discovery_count.checked_add(scan_count).ok_or_else(|| {
                invalid("probes", usize::MAX, "probe-count arithmetic overflowed")
            })?;
            crate::probe::check_probe_count(&Probes, count, request.limits.max_probes)?;
            let delay = rate_delay(&Probes, "probes_per_second", 1, request.probes_per_second)?;
            let stage_pause = if discovery_count > 0 && scan_count > 0 {
                delay
            } else {
                Duration::ZERO
            };
            let stage_duration = |probes| {
                request.adaptive.map_or_else(
                    || worst_case_duration(request, probes),
                    |adaptive| adaptive_worst_case_duration(request, &adaptive, probes),
                )
            };
            let planned_duration = [
                stage_duration(discovery_count)?,
                stage_pause,
                stage_duration(scan_count)?,
            ]
            .into_iter()
            .try_fold(Duration::ZERO, Duration::checked_add)
            .ok_or(Error::DurationLimit {
                actual: Duration::MAX,
                limit: request.limits.max_duration,
            })?;
            crate::probe::check_probe_duration(
                &Probes,
                planned_duration,
                request.limits.max_duration,
            )?;
            // Discovery may leave any target to the scan stage, so the
            // operation covers every target on every port of either stage.
            let mut every_port = discovery.clone();
            every_port.extend(ports.iter().filter(|port| !discovery.contains(port)));
            let effective = request.max_in_flight.min(tcp::MAX_PENDING_CONNECTIONS);
            let charge = request
                .adaptive
                .map(|_| {
                    super::super::adaptive::state_charge(
                        targets,
                        every_port.len(),
                        effective,
                        super::super::adaptive::scoped_bytes(&selected.targets),
                        0,
                    )
                })
                .unwrap_or(0)
                .saturating_add(
                    targets
                        .saturating_mul(every_port.len())
                        .saturating_mul(std::mem::size_of::<SocketAddr>()),
                )
                .saturating_add(
                    targets
                        .saturating_mul(std::mem::size_of::<SelectedAddress>())
                        .saturating_mul(2),
                )
                .saturating_add(
                    (discovery.len().saturating_add(ports.len()))
                        .saturating_mul(std::mem::size_of::<u16>()),
                )
                .saturating_add(effective.saturating_mul(active_size));
            if charge > request.limits.max_prepared_bytes {
                return Err(Error::PipelineExecution {
                    source: crate::scan::executor::limit(
                        "prepared descriptions",
                        request.limits.max_prepared_bytes,
                    ),
                });
            }
            let endpoints = selected
                .targets
                .iter()
                .flat_map(|target| {
                    every_port
                        .iter()
                        .map(move |port| socket_endpoint(target, *port))
                })
                .collect::<Vec<_>>();
            Ok((
                Planned {
                    discovery: discovery.clone(),
                    ports: ports.clone(),
                    diagnostics: selected
                        .duplicates
                        .iter()
                        .map(|duplicate| request.duplicate_diagnostic(*duplicate))
                        .collect(),
                    delay,
                    limits: SocketLimits::new(count as u64, 0, 0),
                    planned_duration,
                },
                endpoints,
            ))
        },
        |(planned, endpoints)| {
            SocketOperation::new(endpoints, planned.limits)
                .map(Operation::Socket)
                .map_err(|source| execution(0, source))
        },
    )?;
    Ok((selected.targets, planned))
}

pub(super) struct StagePlan<'a> {
    pub(super) stage: Stage,
    pub(super) targets: &'a [SelectedAddress],
    pub(super) ports: &'a [u16],
    pub(super) first_sequence: u64,
    pub(super) count: usize,
    pub(super) delay: Duration,
    pub(super) limits: &'a SocketLimits,
}

impl<'a> StagePlan<'a> {
    pub(super) fn new(
        request: &Request,
        planned: &'a Planned,
        stage: Stage,
        targets: &'a [SelectedAddress],
        first_sequence: u64,
    ) -> Result<Self, Error> {
        let ports = match stage {
            Stage::Discovery => planned.discovery.as_slice(),
            Stage::Scan => planned.ports.as_slice(),
        };
        Ok(Self {
            stage,
            count: probe_count(
                targets.len().saturating_mul(ports.len()),
                1,
                request.attempts,
            )?,
            targets,
            ports,
            first_sequence,
            delay: planned.delay,
            limits: &planned.limits,
        })
    }

    pub(super) fn endpoint(
        &self,
        position: usize,
    ) -> (SocketAddr, Option<crate::target::ResolvedZone>) {
        let target = &self.targets[position / self.ports.len()];
        (
            socket_endpoint(target, self.ports[position % self.ports.len()]),
            target.scope.clone(),
        )
    }
}

fn socket_endpoint(selected: &crate::target::SelectedAddress, port: u16) -> SocketAddr {
    match (selected.address, &selected.scope) {
        (IpAddr::V6(address), Some(scope)) => SocketAddr::V6(std::net::SocketAddrV6::new(
            address,
            port,
            0,
            scope.interface.index,
        )),
        (address, _) => SocketAddr::new(address, port),
    }
}
