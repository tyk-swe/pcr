// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr_core::budget::Deadline;

use crate::neighbor::{self, Request as NeighborRequest, Resolution as NeighborResolution};
use packetcraftr_netio::link::Mode;
use packetcraftr_netio::transmit;

use super::error::Error;
use super::model::Plan;

/// Materializes a route, passing `deadline` to neighbor resolution so the
/// operation budget bounds every discovery attempt.
pub(crate) fn materialize<N: neighbor::Resolver>(
    mut plan: Plan,
    resolver: &N,
    deadline: &Deadline,
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
        let resolution = resolver.resolve(
            &NeighborRequest {
                interface: plan.decision.interface.clone(),
                interface_source: source,
                interface_mac,
                target,
                vlan_tags: plan.neighbor_vlan_tags.clone(),
                mtu: plan.decision.mtu,
                link_type: plan.decision.link_type,
            },
            deadline,
        )?;
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
    /// The route facts a transmission backend checks before sending this
    /// route's frame.
    pub fn transmit_route(&self) -> transmit::Route<'_> {
        transmit::Route {
            decision: &self.plan.decision,
            mode: self.plan.mode,
            lookup_destination: self.plan.lookup_destination,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::live;
    use std::{
        net::{IpAddr, Ipv4Addr},
        sync::Mutex,
    };

    use packetcraftr_core::budget::Deadline;
    use packetcraftr_core::error::Classified;
    use packetcraftr_core::frame::LinkType;
    use packetcraftr_core::packet::{MacAddress, VlanKind, VlanTag};
    use packetcraftr_netio::capture::Stats;
    use packetcraftr_netio::interface::Id as InterfaceId;
    use packetcraftr_netio::link::Capability;
    use packetcraftr_netio::route::{Decision, Scope, SelectionReason};

    use super::*;

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

    impl neighbor::Resolver for RecordingResolver {
        fn resolve(
            &self,
            request: &NeighborRequest,
            _deadline: &Deadline,
        ) -> Result<NeighborResolution, neighbor::Error> {
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
                capture_statistics: Stats::default(),
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

        let materialized =
            materialize(plan, &resolver, &live()).expect("complete plan must materialize");

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

        let materialized = materialize(plan.clone(), &resolver, &live()).expect("resolved plan");

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

        let materialized = materialize(plan.clone(), &resolver, &live()).expect("broadcast plan");

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

            let error = materialize(plan, &resolver, &live()).expect_err("incomplete Layer 2 plan");
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
    fn the_transmit_route_carries_the_planned_interface_mode_and_lookup_destination() {
        let mut plan = unresolved_plan();
        plan.destination_mac = Some(RESOLVED_MAC);
        let materialized = materialize(plan.clone(), &RecordingResolver::default(), &live())
            .expect("resolved plan");

        let route = materialized.transmit_route();

        assert_eq!(route.decision, &plan.decision);
        assert_eq!(route.mode, Mode::Layer2);
        assert_eq!(route.lookup_destination, Some(address(9)));
    }
}
