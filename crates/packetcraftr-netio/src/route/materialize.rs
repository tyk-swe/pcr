// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Neighbor resolution materialization for planned routes.

#![forbid(unsafe_code)]

use std::net::IpAddr;

use thiserror::Error;

use crate::{Error as LiveIoError, capture::Statistics};
use packetcraftr_core::error::{Classification, Classified, Kind};
use packetcraftr_core::frame::Frame;

use crate::link::Mode;
use crate::neighbor::{Request as NeighborRequest, Resolution as NeighborResolution};

use super::models::PlannedRoute;

/// Materialize a planned route, invoking neighbor resolution when required.
pub fn materialize<N: NeighborResolver>(
    mut plan: PlannedRoute,
    resolver: &N,
) -> Result<MaterializedRoute, NeighborError> {
    let mut neighbor_resolution = None;
    if plan.needs_neighbor_resolution() {
        let target = plan
            .neighbor_target
            .ok_or_else(|| NeighborError::MissingNeighborTarget {
                interface: plan.route.interface.name.clone(),
            })?;
        let source = plan
            .neighbor_source
            .ok_or_else(|| NeighborError::MissingNeighborSource {
                interface: plan.route.interface.name.clone(),
            })?;
        let interface_mac =
            plan.route
                .source_mac
                .ok_or_else(|| NeighborError::MissingSourceMac {
                    interface: plan.route.interface.name.clone(),
                })?;
        let resolution = resolver.resolve_request(&NeighborRequest {
            interface: plan.route.interface.clone(),
            interface_source: source,
            interface_mac,
            target,
            vlan_tags: plan.neighbor_vlan_tags.clone(),
            mtu: plan.route.mtu,
            link_type: plan.route.link_type,
        })?;
        plan.destination_mac = Some(resolution.mac_address);
        neighbor_resolution = Some(resolution);
    }
    if plan.mode == Mode::Layer2 && plan.source_mac.is_none() {
        return Err(NeighborError::MissingSourceMac {
            interface: plan.route.interface.name.clone(),
        });
    }
    Ok(MaterializedRoute {
        plan,
        neighbor_resolution,
    })
}

pub trait NeighborResolver: Send + Sync {
    fn resolve_request(
        &self,
        request: &NeighborRequest,
    ) -> Result<NeighborResolution, NeighborError>;
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum NeighborError {
    #[error("neighbor resolution for {target} on {interface} failed: {message}")]
    Resolution {
        interface: String,
        target: IpAddr,
        message: String,
    },
    #[error(
        "neighbor resolution returned no address for {target} on {interface} after {attempts} attempt(s)"
    )]
    NotFound {
        interface: String,
        target: IpAddr,
        attempts: u32,
        captured: Vec<Frame>,
        evidence_truncated: bool,
        capture_statistics: Statistics,
    },
    #[error("interface {interface} has no source MAC for Layer 2 transmission")]
    MissingSourceMac { interface: String },
    #[error("Layer 2 plan on {interface} has no neighbor target")]
    MissingNeighborTarget { interface: String },
    #[error("Layer 2 plan on {interface} has no interface-owned neighbor source address")]
    MissingNeighborSource { interface: String },
    #[error("neighbor request is invalid: {message}")]
    InvalidRequest { message: String },
    #[error("neighbor resolver configuration is invalid: {message}")]
    InvalidConfiguration { message: String },
    #[error("neighbor resolver state failed: {message}")]
    State { message: String },
    #[error("neighbor resolution for {target} on {interface} failed while {operation}: {source}")]
    Io {
        interface: String,
        target: IpAddr,
        operation: &'static str,
        source: LiveIoError,
    },
    #[error(
        "neighbor resolution for {target} on {interface} completed but capture cleanup failed: {source}"
    )]
    Cleanup {
        interface: String,
        target: IpAddr,
        source: LiveIoError,
    },
    #[error(
        "neighbor resolution for {target} on {interface} failed and capture cleanup also failed: operation={operation}; cleanup={cleanup}"
    )]
    OperationAndCleanup {
        interface: String,
        target: IpAddr,
        operation: Box<NeighborError>,
        cleanup: LiveIoError,
    },
}

impl Classified for NeighborError {
    fn classification(&self) -> Classification {
        match self {
            Self::Io { source, .. } => source.classification(),
            Self::Cleanup { source, .. } => source.classification(),
            Self::OperationAndCleanup { operation, .. } => operation.classification(),
            Self::NotFound { .. } => Classification::new(
                "io.neighbor_timeout",
                Kind::Io,
                Some(
                    "inspect the selected gateway, VLAN, and interface; the finite neighbor-resolution budget was exhausted",
                ),
            ),
            Self::Resolution { .. } => Classification::new(
                "io.neighbor",
                Kind::Io,
                Some(
                    "inspect the correlated ARP/NDP evidence and selected logical link before retrying",
                ),
            ),
            Self::InvalidConfiguration { .. } => Classification::new(
                "cli.neighbor_limit",
                Kind::Cli,
                Some(
                    "use finite non-zero neighbor attempts, timeouts, cache limits, and capture bounds",
                ),
            ),
            Self::MissingSourceMac { .. }
            | Self::MissingNeighborTarget { .. }
            | Self::MissingNeighborSource { .. }
            | Self::InvalidRequest { .. }
            | Self::State { .. } => Classification::new(
                "internal.neighbor_invariant",
                Kind::Internal,
                Some(
                    "do not transmit with the incomplete neighbor request or inconsistent resolver state",
                ),
            ),
        }
    }

    fn causes(&self) -> Vec<String> {
        match self {
            Self::Io { source, .. } | Self::Cleanup { source, .. } => {
                vec![source.to_string()]
            }
            Self::OperationAndCleanup {
                operation, cleanup, ..
            } => vec![operation.to_string(), cleanup.to_string()],
            _ => Vec::new(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MaterializedRoute {
    pub plan: PlannedRoute,
    pub neighbor_resolution: Option<NeighborResolution>,
}

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr},
        sync::Mutex,
    };

    use packetcraftr_core::frame::LinkType;

    use super::*;
    use crate::{
        interface::Id as InterfaceId,
        link::{Capability, MacAddress},
        neighbor::{VlanKind, VlanTag},
        route::{DestinationScope, RouteDecision, RouteSelectionReason},
    };

    const INTERFACE_MAC: MacAddress = MacAddress([0x02, 0, 0, 0, 0, 1]);
    const RESOLVED_MAC: MacAddress = MacAddress([0x02, 0, 0, 0, 0, 9]);

    fn address(last_octet: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, last_octet))
    }

    fn unresolved_plan() -> PlannedRoute {
        PlannedRoute {
            route: RouteDecision {
                interface: InterfaceId {
                    name: "fixture0".to_owned(),
                    index: 7,
                },
                source_mac: Some(INTERFACE_MAC),
                selected_address: Some(address(2)),
                preferred_source: None,
                next_hop: Some(address(1)),
                selection_reason: RouteSelectionReason::Gateway,
                destination_scope: DestinationScope::Global,
                mtu: 1_400,
                capability: Capability::Layer2And3,
                link_type: LinkType::ETHERNET,
            },
            mode: Mode::Layer2,
            lookup_destination: Some(address(9)),
            final_destination: Some(address(9)),
            visited_destinations: vec![address(9)],
            packet_source: Some(address(2)),
            neighbor_source: Some(address(2)),
            neighbor_target: Some(address(1)),
            destination_mac: None,
            source_mac: Some(INTERFACE_MAC),
            neighbor_vlan_tags: vec![VlanTag {
                kind: VlanKind::Ieee8021Q,
                priority: 3,
                drop_eligible: true,
                vlan_id: 42,
            }],
            synthesized_ethernet: true,
        }
    }

    #[derive(Default)]
    struct RecordingResolver {
        requests: Mutex<Vec<NeighborRequest>>,
    }

    impl NeighborResolver for RecordingResolver {
        fn resolve_request(
            &self,
            request: &NeighborRequest,
        ) -> Result<NeighborResolution, NeighborError> {
            self.requests
                .lock()
                .expect("request recorder lock")
                .push(request.clone());
            Ok(NeighborResolution {
                mac_address: RESOLVED_MAC,
                attempts: 2,
                cache_hit: false,
                captured: Vec::new(),
                evidence_truncated: false,
                capture_statistics: Statistics::default(),
            })
        }
    }

    #[test]
    fn materialize_resolves_with_the_complete_planned_link_context() {
        let plan = unresolved_plan();
        let expected_request = NeighborRequest {
            interface: plan.route.interface.clone(),
            interface_source: address(2),
            interface_mac: INTERFACE_MAC,
            target: address(1),
            vlan_tags: plan.neighbor_vlan_tags.clone(),
            mtu: 1_400,
            link_type: LinkType::ETHERNET,
        };
        let resolver = RecordingResolver::default();

        let materialized = materialize(plan, &resolver).expect("complete plan must materialize");

        assert_eq!(materialized.plan.destination_mac, Some(RESOLVED_MAC));
        assert_eq!(
            materialized
                .neighbor_resolution
                .as_ref()
                .map(|resolution| resolution.mac_address),
            Some(RESOLVED_MAC)
        );
        assert_eq!(
            *resolver.requests.lock().expect("request recorder lock"),
            [expected_request]
        );
    }

    #[test]
    fn materialize_skips_resolution_when_the_plan_already_has_a_link_destination() {
        let mut plan = unresolved_plan();
        plan.destination_mac = Some(RESOLVED_MAC);
        let resolver = RecordingResolver::default();

        let materialized = materialize(plan.clone(), &resolver).expect("resolved plan");

        assert_eq!(materialized.plan, plan);
        assert_eq!(materialized.neighbor_resolution, None);
        assert!(
            resolver
                .requests
                .lock()
                .expect("request recorder lock")
                .is_empty()
        );
    }

    #[test]
    fn materialize_makes_no_resolver_request_for_ipv4_broadcast() {
        let mut plan = unresolved_plan();
        plan.lookup_destination = Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 255)));
        plan.final_destination = plan.lookup_destination;
        plan.visited_destinations = vec![plan.lookup_destination.expect("broadcast destination")];
        plan.route.next_hop = None;
        plan.route.selection_reason = RouteSelectionReason::Broadcast;
        plan.neighbor_target = None;
        plan.destination_mac = Some(MacAddress([0xff; 6]));
        let resolver = RecordingResolver::default();

        let materialized = materialize(plan.clone(), &resolver).expect("broadcast plan");

        assert_eq!(materialized.plan, plan);
        assert_eq!(materialized.neighbor_resolution, None);
        assert!(
            resolver
                .requests
                .lock()
                .expect("request recorder lock")
                .is_empty()
        );
    }

    #[test]
    fn materialize_rejects_each_missing_layer2_input_before_resolution() {
        type InvalidCase = (fn(&mut PlannedRoute), NeighborError);
        let cases: [InvalidCase; 4] = [
            (
                |plan| plan.neighbor_target = None,
                NeighborError::MissingNeighborTarget {
                    interface: "fixture0".to_owned(),
                },
            ),
            (
                |plan| plan.neighbor_source = None,
                NeighborError::MissingNeighborSource {
                    interface: "fixture0".to_owned(),
                },
            ),
            (
                |plan| plan.route.source_mac = None,
                NeighborError::MissingSourceMac {
                    interface: "fixture0".to_owned(),
                },
            ),
            (
                |plan| {
                    plan.destination_mac = Some(RESOLVED_MAC);
                    plan.source_mac = None;
                },
                NeighborError::MissingSourceMac {
                    interface: "fixture0".to_owned(),
                },
            ),
        ];

        for (remove_input, expected) in cases {
            let mut plan = unresolved_plan();
            remove_input(&mut plan);
            let resolver = RecordingResolver::default();

            assert_eq!(materialize(plan, &resolver), Err(expected));
            assert!(
                resolver
                    .requests
                    .lock()
                    .expect("request recorder lock")
                    .is_empty()
            );
        }
    }
}
