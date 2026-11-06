// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! TCP target admission, preparation budgets, and per-stage endpoint plans.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use packetcraftr_core::budget::Deadline;
use packetcraftr_netio::tcp;

use super::super::plan::{adaptive_worst_case_duration, probe_count, worst_case_duration};
use super::super::{Error, Request, Stage};
use super::{execution, invalid};
use crate::client::admission::{DeclaredTargets, FamilyGate, admit_selection};
use crate::engine::execution::rate_delay;
use crate::policy::{Authorizer, Operation, SocketLimits, SocketOperation};
use crate::probe;
use crate::target::{ResolveTarget, SelectedAddress};

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
    let tcp_ports = |endpoints: &[probe::Endpoint]| -> Vec<u16> {
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
        DeclaredTargets {
            selection: &request.targets,
            family: FamilyGate::new(request.address_family, Error::family),
            max_targets: request.limits.max_targets,
            resolved: None,
        },
        Error::TargetSelection,
        |selected| {
            let targets = selected.targets.len();
            let discovery_count = probe_count(targets, discovery.len(), request.attempts)?;
            let scan_count = probe_count(targets, ports.len(), request.attempts)?;
            let count = discovery_count.checked_add(scan_count).ok_or_else(|| {
                invalid("probes", usize::MAX, "probe-count arithmetic overflowed")
            })?;
            crate::probe::check_probe_count::<Error>(count, request.limits.max_probes)?;
            let delay = rate_delay::<Error>("probes_per_second", 1, request.probes_per_second)?;
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
            crate::probe::check_probe_duration::<Error>(
                planned_duration,
                request.limits.max_duration,
            )?;
            // Discovery may leave any target to the scan stage, so the
            // operation covers every target on every port of either stage.
            let every_port = authorization_ports(&discovery, &ports);
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

fn authorization_ports(discovery: &[u16], ports: &[u16]) -> Vec<u16> {
    let mut discovery_membership = [0_u64; 1024];
    for &port in discovery {
        discovery_membership[usize::from(port) / 64] |= 1 << (port % 64);
    }
    let mut every_port = discovery.to_vec();
    every_port.extend(
        ports.iter().filter(|&&port| {
            discovery_membership[usize::from(port) / 64] & (1 << (port % 64)) == 0
        }),
    );
    every_port
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::target::{Authorized, Target};
    use packetcraftr_core::error::BoundaryError;

    #[derive(Default)]
    struct RecordingAuthorizer {
        endpoints: Vec<SocketAddr>,
        connections: u64,
    }

    impl Authorizer for RecordingAuthorizer {
        fn authorize_operation(&mut self, request: Operation<'_>) -> Result<(), BoundaryError> {
            if let Operation::Socket(socket) = request {
                self.endpoints = socket.endpoints().to_vec();
                self.connections = socket.sockets().connections();
            }
            Ok(())
        }
    }

    impl ResolveTarget for RecordingAuthorizer {
        fn resolve_and_authorize(
            &mut self,
            target: &Target,
            _: &Deadline,
        ) -> Result<Authorized, BoundaryError> {
            let Target::Address(address) = target else {
                unreachable!()
            };
            Ok(Authorized {
                declared: target.clone(),
                selected: vec![SelectedAddress::new(*address)],
            })
        }
    }

    fn request() -> Request {
        Request {
            tcp_scan: Default::default(),
            sctp_scan: Default::default(),
            target_sources: Vec::new(),
            max_in_flight: 1,
            targets: "192.0.2.1".parse::<Target>().unwrap().into(),
            udp_payload: Default::default(),
            udp_profiles: Default::default(),
            address_family: crate::target::Family::Any,
            endpoints: [1, 443, 65, u16::MAX]
                .into_iter()
                .map(|port| probe::Endpoint::Tcp { port })
                .collect(),
            discovery: super::super::super::discovery::Options {
                mode: super::super::super::discovery::Mode::Before,
                probes: [u16::MAX, 443, 64]
                    .into_iter()
                    .map(|port| probe::Endpoint::Tcp { port })
                    .collect(),
                ..Default::default()
            },
            attempts: 2,
            adaptive: None,
            timeout: Duration::from_millis(1),
            probes_per_second: None,
            limits: Default::default(),
            route: Default::default(),
            collection: Default::default(),
        }
    }

    #[test]
    fn discovery_precedes_probes_within_limits() {
        let request = request();
        let deadline = Deadline::new(Duration::from_secs(5));
        let mut authorizer = RecordingAuthorizer::default();
        let (targets, plan) = planned(&request, &mut authorizer, &deadline, 0).unwrap();
        assert_eq!(
            authorizer
                .endpoints
                .iter()
                .map(SocketAddr::port)
                .collect::<Vec<_>>(),
            [u16::MAX, 443, 64, 1, 65]
        );
        assert_eq!(authorizer.connections, 14);
        assert_eq!(plan.discovery, [u16::MAX, 443, 64]);
        assert_eq!(plan.ports, [1, 443, 65, u16::MAX]);
        assert_eq!(targets.len(), 1);
        for limits in [
            super::super::super::Limits {
                max_probes: 13,
                ..request.limits
            },
            super::super::super::Limits {
                max_prepared_bytes: 1,
                ..request.limits
            },
        ] {
            let mut authorizer = RecordingAuthorizer::default();
            let limited = Request {
                limits,
                ..request.clone()
            };
            assert!(planned(&limited, &mut authorizer, &deadline, 0).is_err());
            assert!(authorizer.endpoints.is_empty());
        }
    }

    #[test]
    fn overlapping_ports_preserve_duplicates_and_order() {
        let discovery = [u16::MAX, 64, 64, 1];
        let ports = [65, u16::MAX, 65, 63, 64, 1, 63];
        assert_eq!(
            authorization_ports(&discovery, &ports),
            [u16::MAX, 64, 64, 1, 65, 65, 63, 63]
        );
        assert_eq!(authorization_ports(&[], &ports), ports);
    }
}
