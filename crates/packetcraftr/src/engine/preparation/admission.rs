// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Admission tokens, cumulative accounting, and passive route/build authorization.

#[cfg(test)]
use super::work;
use super::{
    Clock, Error, Packet, PacketProviders, Policy, PreparedPacket, RebuildError, Stages,
    TransmitProviders, route,
};
use crate::{
    engine::mtu::validate_mtu,
    engine::planning::RouteLookup,
    policy::{Operation, WireLimits},
};
use packetcraftr_core::{build::BuiltPacket, codec};
use packetcraftr_netio::{interface, route::Provider as RouteProvider};
use std::{net::IpAddr, sync::Arc};

#[derive(Clone)]
pub(crate) struct AuthorizedRoute {
    pub(super) plan: route::Plan,
    pub(super) destination: IpAddr,
    pub(super) scoped_interface: Option<interface::Id>,
}

impl AuthorizedRoute {
    pub(crate) fn interface(&self) -> &interface::Id {
        &self.plan.decision.interface
    }

    pub(crate) fn plan(&self) -> &route::Plan {
        &self.plan
    }

    pub(crate) fn retained_name_bytes(&self) -> usize {
        self.plan.decision.interface.name.capacity().saturating_add(
            self.scoped_interface
                .as_ref()
                .map_or(0, |interface| interface.name.capacity()),
        )
    }

    pub(crate) fn scoped_name_bytes(&self) -> usize {
        self.scoped_interface
            .as_ref()
            .map_or(0, |interface| interface.name.len())
    }
}

/// The exact wire bytes one admitted packet charged to the cumulative budget.
/// It is neither `Clone` nor `Copy`: [`Admitting::rebuild`] consumes it, so
/// each admission pays for exactly one rebuild.
#[derive(Debug)]
pub(crate) struct AdmittedCost {
    pub(super) wire_len: usize,
    pub(super) admission: Arc<()>,
}

pub(crate) struct Admitted {
    pub(super) packet: Packet,
    pub(super) plan: route::Plan,
    pub(super) build_context: codec::Addresses,
    pub(super) preliminary_build: BuiltPacket,
    pub(super) admission: Arc<()>,
    pub(super) declared: Option<Packet>,
}

/// One immutable declaration and preview owned by the admission that built it.
/// The preview is an optimization, never authority to reuse an old route or to
/// send another declaration. Callers must charge its resident packet/build
/// memory and retain only a bounded preparation window.
pub(crate) struct RetainedAdmission(pub(super) Box<Retained>);

pub(super) struct Retained {
    pub(super) declared: Packet,
    pub(super) admitted: Admitted,
}

impl Admitted {
    pub(crate) fn packet(&self) -> &Packet {
        &self.packet
    }

    pub(crate) fn wire_len(&self) -> usize {
        self.preliminary_build.bytes.len()
    }

    pub(crate) fn retained_route_name_bytes(&self) -> usize {
        self.plan.decision.interface.name.capacity()
    }

    pub(crate) fn shares_route_with(&self, other: &Self) -> bool {
        self.plan.decision.interface == other.plan.decision.interface
            && self.plan.mode == other.plan.mode
    }

    /// Keep only spend-once accounting when no preview residency is available.
    /// This path drops the declaration/build without allocating a preview box.
    pub(crate) fn into_cost(self) -> AdmittedCost {
        AdmittedCost {
            wire_len: self.wire_len(),
            admission: self.admission,
        }
    }

    pub(crate) fn into_parts(mut self) -> (AdmittedCost, Option<RetainedAdmission>) {
        let cost = AdmittedCost {
            wire_len: self.wire_len(),
            admission: Arc::clone(&self.admission),
        };
        let retained = self.declared.take().map(|declared| {
            RetainedAdmission(Box::new(Retained {
                declared,
                admitted: self,
            }))
        });
        (cost, retained)
    }
}

#[derive(Debug)]
pub(super) struct Budget {
    pub(super) packets: u64,
    pub(super) wire_bytes: u64,
}

impl Budget {
    pub(super) fn open(policy: &Policy, packets: u64) -> Result<Self, Error> {
        policy.authorize(Operation::Wire(WireLimits::new(packets, 0)))?;
        Ok(Self {
            packets,
            wire_bytes: 0,
        })
    }

    /// Arithmetic overflow is itself a byte-limit denial.
    fn charge(&mut self, policy: &Policy, wire_len: usize) -> Result<(), Error> {
        let wire_bytes = u64::try_from(wire_len)
            .ok()
            .and_then(|bytes| self.wire_bytes.checked_add(bytes))
            .ok_or(crate::policy::Error::ByteLimit {
                actual: u64::MAX,
                limit: policy.max_bytes_per_operation,
            })?;
        policy.authorize(Operation::Wire(WireLimits::new(self.packets, wire_bytes)))?;
        self.wire_bytes = wire_bytes;
        Ok(())
    }
}

pub(crate) struct Admitting<'c, P, K> {
    pub(super) stages: Stages<'c, P, K>,
    pub(super) budget: Budget,
}

impl<'c, P: PacketProviders, K: Clock> Admitting<'c, P, K> {
    pub(crate) fn check(&self) -> Result<(), Error> {
        self.stages.check()
    }

    pub(crate) fn admit<R: RouteProvider>(
        &mut self,
        packet: Packet,
        routes: &R,
    ) -> Result<Admitted, Error> {
        self.stages.admit(&mut self.budget, packet, routes)
    }

    pub(crate) fn route_on(
        &self,
        packet: &Packet,
        destination: IpAddr,
        interface: Option<&interface::Id>,
    ) -> Result<AuthorizedRoute, Error> {
        let route_options;
        let options = match interface {
            Some(id) => {
                let conflicts = match self.stages.options.plan.interface.as_ref() {
                    Some(route::Interface::Id(requested)) => *requested != *id,
                    Some(route::Interface::Name(name)) => *name != id.name,
                    Some(route::Interface::Index(index)) => index.get() != id.index,
                    None => false,
                };
                if conflicts {
                    let requested = self
                        .stages
                        .options
                        .plan
                        .interface
                        .as_ref()
                        .expect("conflicting interface")
                        .clone();
                    let (name, index) = match &requested {
                        route::Interface::Id(id) => (id.name.clone(), id.index),
                        route::Interface::Name(name) => (name.clone(), 0),
                        route::Interface::Index(index) => (index.to_string(), index.get()),
                    };
                    return Err(Error::Plan(route::Error::InterfaceMismatch {
                        requested: name,
                        requested_index: index,
                        selected: id.name.clone(),
                        selected_index: id.index,
                    }));
                }
                route_options = route::Options {
                    interface: Some(route::Interface::Id(id.clone())),
                    ..self.stages.options.plan.clone()
                };
                &route_options
            }
            None => &self.stages.options.plan,
        };
        let plan = self.stages.plan_with(
            packet,
            Some(destination),
            options,
            TransmitProviders::route_provider(self.stages.client.providers.as_ref()),
        )?;
        if let Some(expected) = interface
            && plan.decision.interface != *expected
        {
            return Err(Error::Plan(route::Error::InterfaceMismatch {
                requested: expected.name.clone(),
                requested_index: expected.index,
                selected: plan.decision.interface.name.clone(),
                selected_index: plan.decision.interface.index,
            }));
        }
        Ok(AuthorizedRoute {
            plan,
            destination,
            scoped_interface: interface.cloned(),
        })
    }

    pub(crate) fn admit_on(
        &mut self,
        packet: Packet,
        route: &AuthorizedRoute,
    ) -> Result<Admitted, Error> {
        self.stages.check()?;
        let admitted = self
            .stages
            .build_and_authorize(packet, route.plan.clone())?;
        self.stages.charge(&mut self.budget, admitted)
    }

    pub(crate) fn admit_retained_on(
        &mut self,
        packet: Packet,
        route: &AuthorizedRoute,
    ) -> Result<Admitted, Error> {
        let declared = packet.clone();
        let mut admitted = self.admit_on(packet, route)?;
        admitted.declared = Some(declared);
        Ok(admitted)
    }

    /// Materialize an already-admitted item without closing this cumulative
    /// budget. The workflow must complete its whole-request preflight before
    /// invoking any materialization that can perform neighbor discovery.
    pub(crate) fn materialize_retained(
        &self,
        retained: RetainedAdmission,
        route: &AuthorizedRoute,
        cost: AdmittedCost,
    ) -> Result<PreparedPacket, RebuildError> {
        self.stages.materialize_retained(retained, route, cost)
    }

    pub(crate) fn rebuild(
        &self,
        packet: Packet,
        route: &AuthorizedRoute,
        cost: AdmittedCost,
    ) -> Result<PreparedPacket, RebuildError> {
        self.stages.rebuild(packet, route, cost)
    }

    pub(crate) fn wire_bytes(&self) -> u64 {
        self.budget.wire_bytes
    }

    pub(crate) fn discover(self) -> Discovery<'c, P, K> {
        Discovery {
            stages: self.stages,
        }
    }
}

pub(crate) struct Discovery<'c, P, K> {
    pub(super) stages: Stages<'c, P, K>,
}

impl<P: PacketProviders, K: Clock> Discovery<'_, P, K> {
    pub(crate) fn materialize(&self, admitted: Admitted) -> Result<PreparedPacket, Error> {
        self.stages.materialize(admitted)
    }
}

impl<P: TransmitProviders, K: Clock> Stages<'_, P, K> {
    fn plan<R: RouteProvider>(
        &self,
        packet: &Packet,
        destination: Option<IpAddr>,
        routes: &R,
    ) -> Result<route::Plan, Error> {
        self.plan_with(packet, destination, &self.options.plan, routes)
    }

    fn plan_with<R: RouteProvider>(
        &self,
        packet: &Packet,
        destination: Option<IpAddr>,
        route_options: &route::Options,
        routes: &R,
    ) -> Result<route::Plan, Error> {
        self.plan_with_interfaces(
            packet,
            destination,
            route_options,
            routes,
            &self.operation.interfaces,
        )
    }

    pub(super) fn plan_with_interfaces<R: RouteProvider>(
        &self,
        packet: &Packet,
        destination: Option<IpAddr>,
        route_options: &route::Options,
        routes: &R,
        interfaces: &route::ResolvedInterface,
    ) -> Result<route::Plan, Error> {
        self.check()?;
        let plan = self.within(crate::deadline::PASSIVE_LOOKUP_TIMEOUT, |deadline| {
            self.client.authorize_and_plan(
                packet,
                destination,
                route_options,
                RouteLookup {
                    routes,
                    interfaces,
                    deadline,
                },
                || self.check(),
            )
        })?;
        self.check()?;
        Ok(plan)
    }

    pub(super) fn admit<R: RouteProvider>(
        &self,
        budget: &mut Budget,
        packet: Packet,
        routes: &R,
    ) -> Result<Admitted, Error> {
        let plan = self.plan(&packet, self.options.destination, routes)?;
        self.charge(budget, self.build_and_authorize(packet, plan)?)
    }

    fn charge(&self, budget: &mut Budget, admitted: Admitted) -> Result<Admitted, Error> {
        budget.charge(&self.policy, admitted.wire_len())?;
        Ok(admitted)
    }

    pub(super) fn authorize_built(
        &self,
        built: &BuiltPacket,
        plan: &route::Plan,
    ) -> Result<(), Error> {
        let policy = &self.policy;
        policy.authorize_built_packet(built, self.options.allow_permissive_live)?;
        crate::policy::authorize_wire(policy, plan.wire_link_type()?, &built.bytes, plan)?;
        Ok(())
    }

    pub(super) fn build_and_authorize(
        &self,
        mut packet: Packet,
        plan: route::Plan,
    ) -> Result<Admitted, Error> {
        #[cfg(test)]
        work::prepare();
        let (build_context, preliminary_build) =
            self.materializer()
                .preliminary(&mut packet, &plan, || self.check())?;
        self.check()?;
        validate_mtu(&preliminary_build, plan.decision.mtu)?;
        self.authorize_built(&preliminary_build, &plan)?;
        Ok(Admitted {
            packet,
            plan,
            build_context,
            preliminary_build,
            admission: Arc::clone(&self.admission),
            declared: None,
        })
    }
}
