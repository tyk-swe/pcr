// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Neighbor resolution materialization for planned routes.

#![forbid(unsafe_code)]

use crate::link::Mode;
use crate::neighbor::{Request as NeighborRequest, Resolution as NeighborResolution};

use super::model::Plan;

/// Materialize a planned route, invoking neighbor resolution when required.
pub fn materialize<N: crate::neighbor::Resolver>(
    mut plan: Plan,
    resolver: &N,
) -> Result<Materialized, crate::neighbor::Error> {
    let mut neighbor_resolution = None;
    if plan.needs_neighbor_resolution() {
        let target =
            plan.neighbor_target
                .ok_or_else(|| crate::neighbor::Error::MissingNeighborTarget {
                    interface: plan.decision.interface.name.clone(),
                })?;
        let source =
            plan.neighbor_source
                .ok_or_else(|| crate::neighbor::Error::MissingNeighborSource {
                    interface: plan.decision.interface.name.clone(),
                })?;
        let interface_mac =
            plan.decision
                .source_mac
                .ok_or_else(|| crate::neighbor::Error::MissingSourceMac {
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
        })?;
        plan.destination_mac = Some(resolution.mac_address);
        neighbor_resolution = Some(resolution);
    }
    if plan.mode == Mode::Layer2 && plan.source_mac.is_none() {
        return Err(crate::neighbor::Error::MissingSourceMac {
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

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr},
        sync::Mutex,
    };

    use packetcraftr_core::frame::LinkType;

    use super::*;
    use crate::{
        capture::Statistics,
        interface::Id as InterfaceId,
        link::{Capability, MacAddress},
        neighbor::{VlanKind, VlanTag},
        route::{Decision, Scope, SelectionReason},
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
        plan.decision.next_hop = None;
        plan.decision.selection_reason = SelectionReason::Broadcast;
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
        type InvalidCase = (fn(&mut Plan), crate::neighbor::Error);
        let cases: [InvalidCase; 4] = [
            (
                |plan| plan.neighbor_target = None,
                crate::neighbor::Error::MissingNeighborTarget {
                    interface: "fixture0".to_owned(),
                },
            ),
            (
                |plan| plan.neighbor_source = None,
                crate::neighbor::Error::MissingNeighborSource {
                    interface: "fixture0".to_owned(),
                },
            ),
            (
                |plan| plan.decision.source_mac = None,
                crate::neighbor::Error::MissingSourceMac {
                    interface: "fixture0".to_owned(),
                },
            ),
            (
                |plan| {
                    plan.destination_mac = Some(RESOLVED_MAC);
                    plan.source_mac = None;
                },
                crate::neighbor::Error::MissingSourceMac {
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
