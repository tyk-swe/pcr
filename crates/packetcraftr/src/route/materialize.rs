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
    if let Some(request) = plan.neighbor_request()? {
        let resolution = resolver.resolve(&request, deadline)?;
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

impl Plan {
    pub(crate) fn neighbor_request(&self) -> Result<Option<NeighborRequest>, Error> {
        if !self.needs_neighbor_resolution() {
            return Ok(None);
        }
        let target = self
            .neighbor_target
            .ok_or_else(|| Error::MissingNeighborTarget {
                interface: self.decision.interface.name.clone(),
            })?;
        let source = self
            .neighbor_source
            .ok_or_else(|| Error::MissingNeighborSource {
                interface: self.decision.interface.name.clone(),
            })?;
        let interface_mac = self
            .decision
            .source_mac
            .ok_or_else(|| Error::MissingSourceMac {
                interface: self.decision.interface.name.clone(),
            })?;
        Ok(Some(NeighborRequest {
            interface: self.decision.interface.clone(),
            interface_source: source,
            interface_mac,
            target,
            vlan_tags: self.neighbor_vlan_tags.clone(),
            mtu: self.decision.mtu,
            link_type: self.decision.link_type,
        }))
    }
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
