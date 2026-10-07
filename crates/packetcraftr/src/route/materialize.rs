// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr_core::budget::Deadline;

use crate::neighbor::{self, Request as NeighborRequest, Resolution as NeighborResolution};
use packetcraftr_netio::link::Mode;
use packetcraftr_netio::transmit;

use super::error::Error;
use super::model::Plan;

pub(crate) fn materialize<N: neighbor::Resolver>(
    mut plan: Plan,
    resolver: &N,
    deadline: &Deadline,
) -> Result<Materialized, Error> {
    let mut neighbor_resolution = None;
    if plan.needs_neighbor_resolution() {
        let resolution = resolver.resolve(&neighbor_request(&plan)?, deadline)?;
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

/// The request that resolves the neighbor `plan` sends its frames to.
pub(crate) fn neighbor_request(plan: &Plan) -> Result<NeighborRequest, Error> {
    let interface = || plan.decision.interface.name.clone();
    let target = plan
        .neighbor_target
        .ok_or_else(|| Error::MissingNeighborTarget {
            interface: interface(),
        })?;
    let interface_source = plan
        .neighbor_source
        .ok_or_else(|| Error::MissingNeighborSource {
            interface: interface(),
        })?;
    let interface_mac = plan
        .decision
        .source_mac
        .ok_or_else(|| Error::MissingSourceMac {
            interface: interface(),
        })?;
    Ok(NeighborRequest {
        interface: plan.decision.interface.clone(),
        interface_source,
        interface_mac,
        target,
        vlan_tags: plan.neighbor_vlan_tags.clone(),
        mtu: plan.decision.mtu,
        link_type: plan.decision.link_type,
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Materialized {
    pub plan: Plan,
    pub neighbor_resolution: Option<NeighborResolution>,
}

impl Materialized {
    pub fn transmit_route(&self) -> transmit::Route<'_> {
        transmit::Route {
            decision: &self.plan.decision,
            mode: self.plan.mode,
            lookup_destination: self.plan.lookup_destination,
        }
    }
}
