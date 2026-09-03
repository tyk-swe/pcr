// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Neighbor resolution materialization for planned routes.

use std::time::Instant;

use packetcraftr_core::frame::LinkType;

use crate::interface::Id as InterfaceId;
use crate::link::{Capability, MacAddress, Mode};
use crate::neighbor::{Request as NeighborRequest, Resolution as NeighborResolution};

use super::error::Error;
use super::models::{Decision, Plan, Scope, SelectionReason};

/// Materialize a planned route, invoking neighbor resolution when required.
///
/// Neighbor discovery is the one step here that waits on the network, so
/// `deadline` is handed to the resolver rather than checked afterwards: the
/// calling operation's budget bounds every attempt, not only the result.
pub fn materialize<N: crate::neighbor::Resolver>(
    mut plan: Plan,
    resolver: &N,
    deadline: Option<Instant>,
) -> Result<Materialized, Error> {
    let mut neighbor_resolution = None;
    if plan.needs_neighbor_resolution() {
        let target = plan
            .neighbor_target
            .ok_or_else(|| Error::MissingNeighborTarget {
                interface: plan.decision.interface.name.clone(),
            })?;
        let source = plan
            .neighbor_source
            .ok_or_else(|| Error::MissingNeighborSource {
                interface: plan.decision.interface.name.clone(),
            })?;
        let interface_mac = plan
            .decision
            .source_mac
            .ok_or_else(|| Error::MissingSourceMac {
                interface: plan.decision.interface.name.clone(),
            })?;
        let resolution = resolver.resolve(&NeighborRequest {
            interface: plan.decision.interface.clone(),
            interface_source: source,
            interface_mac,
            target,
            vlan_tags: plan.neighbor_vlan_tags.clone(),
            mtu: plan.decision.mtu,
            link_type: plan.decision.link_type,
            deadline,
        })?;
        plan.destination_mac = Some(resolution.mac_address);
        neighbor_resolution = Some(resolution);
    }
    if plan.mode == Mode::Layer2 && plan.source_mac.is_none() {
        return Err(Error::MissingSourceMac {
            interface: plan.decision.interface.name.clone(),
        });
    }
    Ok(Materialized {
        plan,
        neighbor_resolution,
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Materialized {
    pub plan: Plan,
    pub neighbor_resolution: Option<NeighborResolution>,
}

impl Materialized {
    /// Route for a complete Layer 2 frame whose interface and link-layer
    /// envelope the caller already fixed, so no lookup or neighbor resolution
    /// can change them.
    ///
    /// Only the interface identity and the Layer 2 mode reach the transmission
    /// boundary; every field a route lookup would have decided stays empty
    /// rather than being invented.
    pub fn for_prepared_layer2_frame(
        interface: InterfaceId,
        source_mac: MacAddress,
        destination_mac: MacAddress,
        mtu: u32,
        link_type: LinkType,
    ) -> Self {
        Self {
            plan: Plan {
                decision: Decision {
                    interface,
                    source_mac: Some(source_mac),
                    selected_source: None,
                    preferred_source: None,
                    next_hop: None,
                    selection_reason: SelectionReason::InterfaceOnly,
                    destination_scope: Scope::Unspecified,
                    mtu,
                    capability: Capability::Layer2,
                    link_type,
                },
                mode: Mode::Layer2,
                lookup_destination: None,
                final_destination: None,
                visited_destinations: Vec::new(),
                packet_source: None,
                neighbor_source: None,
                neighbor_target: None,
                destination_mac: Some(destination_mac),
                source_mac: Some(source_mac),
                neighbor_vlan_tags: Vec::new(),
                synthesized_ethernet: false,
            },
            neighbor_resolution: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr},
        sync::Mutex,
    };

    use packetcraftr_core::frame::LinkType;

    use packetcraftr_core::error::Classified;

    use super::*;
    use crate::{
        capture::Statistics,
        link::{VlanKind, VlanTag},
    };

    const INTERFACE_MAC: MacAddress = MacAddress([0x02, 0, 0, 0, 0, 1]);
    const RESOLVED_MAC: MacAddress = MacAddress([0x02, 0, 0, 0, 0, 9]);

    fn address(last_octet: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, last_octet))
    }

    fn unresolved_plan() -> Plan {
        Plan {
            decision: Decision {
                interface: InterfaceId {
                    name: "fixture0".to_owned(),
                    index: 7,
                },
                source_mac: Some(INTERFACE_MAC),
                selected_source: Some(address(2)),
                preferred_source: None,
                next_hop: Some(address(1)),
                selection_reason: SelectionReason::Gateway,
                destination_scope: Scope::Global,
                mtu: 1_400,
                capability: Capability::Layer2AndLayer3,
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

    impl crate::neighbor::Resolver for RecordingResolver {
        fn resolve(
            &self,
            request: &NeighborRequest,
        ) -> Result<NeighborResolution, crate::neighbor::Error> {
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
            interface: plan.decision.interface.clone(),
            interface_source: address(2),
            interface_mac: INTERFACE_MAC,
            target: address(1),
            vlan_tags: plan.neighbor_vlan_tags.clone(),
            mtu: 1_400,
            link_type: LinkType::ETHERNET,
            deadline: None,
        };
        let resolver = RecordingResolver::default();

        let materialized =
            materialize(plan, &resolver, None).expect("complete plan must materialize");

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

        let materialized = materialize(plan.clone(), &resolver, None).expect("resolved plan");

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
        plan.decision.next_hop = None;
        plan.decision.selection_reason = SelectionReason::Broadcast;
        plan.neighbor_target = None;
        plan.destination_mac = Some(MacAddress([0xff; 6]));
        let resolver = RecordingResolver::default();

        let materialized = materialize(plan.clone(), &resolver, None).expect("broadcast plan");

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
    fn materialize_reports_each_missing_layer2_input_as_a_route_defect() {
        type InvalidCase = (fn(&mut Plan), fn(&Error) -> bool);
        let cases: [InvalidCase; 4] = [
            (
                |plan| plan.neighbor_target = None,
                |error| matches!(error, Error::MissingNeighborTarget { .. }),
            ),
            (
                |plan| plan.neighbor_source = None,
                |error| matches!(error, Error::MissingNeighborSource { .. }),
            ),
            (
                |plan| plan.decision.source_mac = None,
                |error| matches!(error, Error::MissingSourceMac { .. }),
            ),
            (
                |plan| {
                    plan.destination_mac = Some(RESOLVED_MAC);
                    plan.source_mac = None;
                },
                |error| matches!(error, Error::MissingSourceMac { .. }),
            ),
        ];

        for (remove_input, expected) in cases {
            let mut plan = unresolved_plan();
            remove_input(&mut plan);
            let resolver = RecordingResolver::default();

            let error = materialize(plan, &resolver, None).expect_err("incomplete Layer 2 plan");
            assert!(expected(&error), "{error}");
            assert_eq!(
                error.classification().code,
                "internal.route_contract",
                "{error}"
            );
            assert!(
                resolver
                    .requests
                    .lock()
                    .expect("request recorder lock")
                    .is_empty()
            );
        }
    }

    #[test]
    fn a_prepared_layer2_route_invents_no_route_lookup_field() {
        let route = Materialized::for_prepared_layer2_frame(
            InterfaceId {
                name: "fixture0".to_owned(),
                index: 7,
            },
            INTERFACE_MAC,
            RESOLVED_MAC,
            1_400,
            LinkType::ETHERNET,
        );

        assert_eq!(route.plan.mode, Mode::Layer2);
        assert_eq!(route.plan.decision.interface.name, "fixture0");
        assert_eq!(route.plan.source_mac, Some(INTERFACE_MAC));
        assert_eq!(route.plan.destination_mac, Some(RESOLVED_MAC));
        assert_eq!(route.plan.decision.selected_source, None);
        assert_eq!(route.plan.lookup_destination, None);
        assert_eq!(route.plan.final_destination, None);
        assert_eq!(route.plan.packet_source, None);
        assert_eq!(route.plan.neighbor_source, None);
        assert_eq!(route.plan.neighbor_target, None);
        assert!(route.plan.visited_destinations.is_empty());
        assert!(route.plan.neighbor_vlan_tags.is_empty());
        assert_eq!(route.neighbor_resolution, None);
        assert!(!route.plan.needs_neighbor_resolution());
    }
}
