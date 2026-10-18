// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Neighbor materialization and fresh-route checks for already admitted packets.

use super::admission::{Admitted, AdmittedCost, AuthorizedRoute, Retained, RetainedAdmission};
use super::construction::PreparedPacket;
#[cfg(test)]
use super::work;
use super::{
    Clock, Deadline, Error, Packet, PacketProviders, Policy, RebuildError, Stages,
    TransmitProviders, changed_preparation, route,
};
use crate::{execution::NeighborMode, mtu::validate_mtu};
use std::sync::Arc;

impl<P: TransmitProviders, K: Clock> Stages<'_, P, K> {
    /// Spaces a packet from the neighbor request its route just sent, within
    /// the preparation deadline.
    fn pace_neighbor_request(&self, spent: std::time::Duration) -> Result<(), Error> {
        // The resolution's own wait already spaced its request from the packet.
        let pause = self.operation.neighbor_pause.saturating_sub(spent);
        if pause.is_zero() {
            return Ok(());
        }
        self.check()?;
        self.within(packetcraftr_netio::deadline::MAX_WAIT, |deadline| {
            let pause = pause.min(deadline.remaining().unwrap_or_default());
            self.client
                .clock
                .sleep(pause, deadline)
                .map_err(|source| Error::Clock {
                    source: Box::new(source),
                })
        })?;
        self.check()
    }

    pub(super) fn materialize_using(
        &self,
        admitted: Admitted,
        resolve: impl FnOnce(route::Plan, &Deadline) -> Result<route::Materialized, route::Error>,
    ) -> Result<PreparedPacket, Error> {
        let Admitted {
            packet,
            plan,
            build_context,
            preliminary_build,
            admission,
            declared: _,
        } = admitted;
        if !Arc::ptr_eq(&self.admission, &admission) {
            return Err(changed_preparation("packet belongs to another admission"));
        }
        self.check()?;
        // Only a request about to be sent is checked: a cached answer sends
        // nothing to the neighbor.
        if self.operation.neighbor_mode != NeighborMode::Ordinary
            && plan.needs_neighbor_resolution()
        {
            let request = route::neighbor_request(&plan)?;
            let cached = self
                .operation
                .neighbors
                .cached(&request)
                .map_err(route::Error::from)?
                .is_some();
            if !cached && self.operation.neighbor_mode == NeighborMode::Cached {
                return Err(Error::UnresolvedNeighbor {
                    target: request.target,
                    interface: request.interface.name,
                });
            }
            if !cached {
                authorize_neighbor_request(&self.policy, &request, &plan)?;
            }
        }
        // The resolver stops at the deadline on its own; a failure it reports
        // after the deadline passed is the deadline, not a neighbor verdict.
        let request = plan
            .needs_neighbor_resolution()
            .then(|| route::neighbor_request(&plan))
            .transpose()?;
        let began = self.client.now();
        let route = match self.within(packetcraftr_netio::deadline::MAX_WAIT, |deadline| {
            resolve(plan, deadline)
        }) {
            Ok(route) => route,
            Err(error) => {
                let spent = unanswered(&error, request.as_ref());
                let error = self.check().err().unwrap_or_else(|| error.into());
                return Err(error.after_neighbor_requests(spent));
            }
        };
        // Whatever fails after the route's requests went out still reports
        // them.
        let spent = route.neighbor_stats()?;
        let built = (|| {
            if spent.packets_attempted > 0 {
                self.pace_neighbor_request(self.client.now().saturating_duration_since(began))?;
            }
            let built = self.materializer().link(
                packet,
                &route,
                build_context,
                preliminary_build,
                || self.check(),
            )?;
            self.check()?;
            self.authorize_built(&built, &route.plan)?;
            Ok(built)
        })()
        .map_err(|error: Error| error.after_neighbor_requests(spent))?;
        Ok(PreparedPacket { built, route })
    }
}

impl<P: PacketProviders, K: Clock> Stages<'_, P, K> {
    pub(super) fn materialize(&self, admitted: Admitted) -> Result<PreparedPacket, Error> {
        let providers = &self.client.providers;
        let neighbors = self.operation.neighbors.over(
            PacketProviders::transmit(providers.as_ref()),
            providers.capture(),
        );
        self.materialize_using(admitted, |plan, deadline| {
            route::materialize(plan, &neighbors, deadline)
        })
    }

    pub(super) fn rebuild(
        &self,
        packet: Packet,
        route: &AuthorizedRoute,
        cost: AdmittedCost,
    ) -> Result<PreparedPacket, RebuildError> {
        self.check()?;
        self.check_cost(&cost)?;
        let fresh = self.fresh_plan(&packet, route)?;
        let admitted = self.build_and_authorize(packet, fresh)?;
        self.materialize_cost(admitted, cost)
    }

    pub(super) fn materialize_retained(
        &self,
        retained: RetainedAdmission,
        route: &AuthorizedRoute,
        cost: AdmittedCost,
    ) -> Result<PreparedPacket, RebuildError> {
        self.check()?;
        self.check_cost(&cost)?;
        let Retained { declared, admitted } = *retained.0;
        if !Arc::ptr_eq(&self.admission, &admitted.admission) {
            return Err(changed_preparation("preview belongs to another admission").into());
        }
        let fresh = self.fresh_plan(&declared, route)?;
        let admitted = if fresh == admitted.plan {
            #[cfg(test)]
            work::reuse();
            self.check()?;
            validate_mtu(&admitted.preliminary_build, fresh.decision.mtu)?;
            self.authorize_built(&admitted.preliminary_build, &fresh)?;
            admitted
        } else {
            // Release the obsolete preview before constructing its replacement.
            drop(admitted);
            self.build_and_authorize(declared, fresh)?
        };
        self.materialize_cost(admitted, cost)
    }

    fn check_cost(&self, cost: &AdmittedCost) -> Result<(), Error> {
        if !Arc::ptr_eq(&self.admission, &cost.admission) {
            return Err(changed_preparation("cost belongs to another admission"));
        }
        Ok(())
    }

    fn fresh_plan(
        &self,
        packet: &Packet,
        expected: &AuthorizedRoute,
    ) -> Result<route::Plan, Error> {
        let scoped;
        let options = if self.options.plan.interface.is_none()
            && let Some(interface) = &expected.scoped_interface
        {
            scoped = route::Options {
                interface: Some(interface.clone().into()),
                ..self.options.plan.clone()
            };
            &scoped
        } else {
            &self.options.plan
        };
        // A name/index memo from preparation is not proof that the selector
        // still names the device whose capture was armed. Resolve it afresh.
        let fresh = self.plan_with_interfaces(
            packet,
            Some(expected.destination),
            options,
            self.client.providers.route_provider(),
            &route::ResolvedInterface::default(),
        )?;
        if fresh.decision.interface != expected.plan.decision.interface {
            return Err(route::Error::InterfaceMismatch {
                requested: expected.plan.decision.interface.name.clone(),
                requested_index: expected.plan.decision.interface.index,
                selected: fresh.decision.interface.name.clone(),
                selected_index: fresh.decision.interface.index,
            }
            .into());
        }
        if fresh.mode != expected.plan.mode
            || fresh.decision.link_type != expected.plan.decision.link_type
        {
            return Err(changed_preparation(
                "route link mode or capture link type changed",
            ));
        }
        Ok(fresh)
    }

    fn materialize_cost(
        &self,
        admitted: Admitted,
        cost: AdmittedCost,
    ) -> Result<PreparedPacket, RebuildError> {
        if admitted.wire_len() != cost.wire_len {
            return Err(RebuildError::Changed {
                admitted: cost.wire_len,
            });
        }
        Ok(self.materialize(admitted)?)
    }
}

/// The requests a resolution that `request` asked for sent before it failed,
/// unanswered or while its capture was cleaned up.
fn unanswered(error: &route::Error, request: Option<&crate::neighbor::Request>) -> crate::Stats {
    let (route::Error::Neighbor(neighbor), Some(request)) = (error, request) else {
        return crate::Stats::default();
    };
    let (attempts, capture) = requests_sent(neighbor);
    let frame_bytes = crate::neighbor::request_frame(request).map_or(0, |frame| frame.len());
    crate::neighbor::stats(attempts, frame_bytes, std::time::Duration::ZERO, capture)
}

/// The requests a failed resolution sent, with its capture's counters when
/// they were settled.
fn requests_sent(error: &crate::neighbor::Error) -> (u32, packetcraftr_netio::capture::Stats) {
    use crate::neighbor::Error;
    match error {
        Error::NotFound {
            attempts,
            capture_statistics,
            ..
        } => (*attempts, *capture_statistics),
        // A failed shutdown leaves the capture's counters unsettled.
        Error::Cleanup { attempts, .. } => (*attempts, Default::default()),
        Error::OperationAndCleanup { operation, .. } => requests_sent(operation),
        _ => (0, Default::default()),
    }
}

/// Authorizes the neighbor request `plan` resolves before the resolver sends
/// it: the address it asks for and every source of the exact frame. An NDP
/// solicitation goes to the target's solicited-node group, so the address it
/// asks for is authorized rather than the group.
pub(crate) fn authorize_neighbor_request(
    policy: &Policy,
    request: &crate::neighbor::Request,
    plan: &route::Plan,
) -> Result<(), Error> {
    let frame = crate::neighbor::request_frame(request).map_err(route::Error::from)?;
    let decoded = crate::policy::decode_wire(request.link_type, &frame)?;
    policy.authorize_destination(request.target)?;
    Ok(policy.authorize_packet_sources(&decoded.packet, plan)?)
}
