// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Staged preparation: the one path from an expanded packet to the wire.
//!
//! Every live packet passes the same stages in the same order:
//!
//! 1. the operation's count-only budget, before any provider call;
//! 2. passive route planning with destination and source authorization;
//! 3. the preliminary build, MTU, packet and wire authorization;
//! 4. the cumulative wire-byte budget;
//! 5. materialization, which may emit neighbor discovery traffic;
//! 6. the final endpoint and bytes authorization;
//! 7. transmission and [`SentPacket`] construction.

mod materialize;

use std::net::IpAddr;
use std::sync::Arc;

use bytes::Bytes;
use packetcraftr_core::budget::Deadline;
use packetcraftr_core::build::{self, Builder, BuiltPacket};
use packetcraftr_core::codec;
use packetcraftr_core::packet::Packet;
use packetcraftr_netio::route::Provider as RouteProvider;
use packetcraftr_netio::{Error as LiveIoError, interface, transmit};

use crate::clock::Clock;
use crate::execution::{NeighborMode, Operation as Execution};
use crate::mtu::validate_mtu;
use crate::planning::ensure_preparation_deadline;
use crate::policy::{Operation, Policy, WireLimits};
use crate::providers::{PacketProviders, TransmitProviders};
use crate::route;
use crate::{Client, Error, evidence::SentPacket, send};
use materialize::{
    build_context, materialize_link_fields, materialize_link_structure, materialize_network_fields,
    require_fixed_width_link_materialization,
};

#[derive(Clone)]
pub(crate) struct AuthorizedRoute {
    plan: route::Plan,
    destination: IpAddr,
    scoped_interface: Option<interface::Id>,
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
    wire_len: usize,
    admission: Arc<()>,
}

pub(crate) struct Admitted {
    packet: Packet,
    plan: route::Plan,
    build_context: codec::Addresses,
    preliminary_build: BuiltPacket,
    admission: Arc<()>,
    declared: Option<Packet>,
}

/// One immutable declaration and preview owned by the admission that built it.
/// The preview is an optimization, never authority to reuse an old route or to
/// send another declaration. Callers must charge its resident packet/build
/// memory and retain only a bounded preparation window.
pub(crate) struct RetainedAdmission(Box<Retained>);

struct Retained {
    declared: Packet,
    admitted: Admitted,
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

pub(crate) struct PreparedPacket {
    built: BuiltPacket,
    route: route::Materialized,
}

impl PreparedPacket {
    pub(crate) fn built(&self) -> &BuiltPacket {
        &self.built
    }

    pub(crate) fn route(&self) -> &route::Materialized {
        &self.route
    }

    pub(crate) fn transmit<I, E>(
        self,
        io: &I,
        check: impl FnOnce() -> Result<(), E>,
    ) -> Result<SentPacket, E>
    where
        I: transmit::Provider + ?Sized,
        E: From<LiveIoError>,
    {
        let report = {
            let frame =
                transmit::Outbound::try_new(&self.built.bytes, self.route.transmit_route())?;
            check()?;
            io.send(frame)?
        };
        Ok(SentPacket::try_new(self.built, self.route, report)?)
    }
}

/// Deterministic: no provider is consulted and nothing is authorized, so the
/// result is only a reference for bytes that were prepared elsewhere.
pub(crate) fn exact_bytes(
    builder: &Builder,
    options: &build::Options,
    mut packet: Packet,
    route: &route::Materialized,
) -> Result<Bytes, Error> {
    let rules = Materializer { builder, options };
    let unchecked = || Ok(());
    let (context, preliminary) = rules.preliminary(&mut packet, &route.plan, unchecked)?;
    let built = rules.link(packet, route, context, preliminary, unchecked)?;
    Ok(built.bytes)
}

struct Materializer<'a> {
    builder: &'a Builder,
    options: &'a build::Options,
}

impl Materializer<'_> {
    fn preliminary(
        &self,
        packet: &mut Packet,
        plan: &route::Plan,
        check: impl Fn() -> Result<(), Error>,
    ) -> Result<(codec::Addresses, BuiltPacket), Error> {
        materialize_network_fields(packet, plan)?;
        materialize_link_structure(packet, plan)?;
        check()?;
        let context = build_context(plan);
        #[cfg(test)]
        work::build();
        let built = self
            .builder
            .build(packet.clone(), context.clone(), self.options.clone())?;
        Ok((context, built))
    }

    fn link(
        &self,
        mut packet: Packet,
        route: &route::Materialized,
        context: codec::Addresses,
        preliminary: BuiltPacket,
        check: impl Fn() -> Result<(), Error>,
    ) -> Result<BuiltPacket, Error> {
        let preliminary_len = preliminary.bytes.len();
        let built = if materialize_link_fields(&mut packet, route)? {
            check()?;
            #[cfg(test)]
            work::build();
            self.builder.build(packet, context, self.options.clone())?
        } else {
            preliminary
        };
        require_fixed_width_link_materialization(preliminary_len, built.bytes.len())?;
        Ok(built)
    }
}

#[derive(Debug)]
struct Budget {
    packets: u64,
    wire_bytes: u64,
}

impl Budget {
    fn open(policy: &Policy, packets: u64) -> Result<Self, Error> {
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

struct Stages<'c, P, K> {
    client: &'c Client<P, K>,
    policy: Policy,
    operation: Execution,
    builder: Builder,
    options: &'c send::Options,
    deadline: Option<&'c Deadline>,
    admission: Arc<()>,
}

impl<'c, P: TransmitProviders, K: Clock> Stages<'c, P, K> {
    fn new(
        client: &'c Client<P, K>,
        options: &'c send::Options,
        deadline: Option<&'c Deadline>,
        operation: &Execution,
    ) -> Self {
        Self {
            client,
            policy: operation.policy(&client.policy),
            operation: operation.clone(),
            builder: Builder::new(operation.registry.clone()),
            options,
            deadline,
            admission: Arc::new(()),
        }
    }

    fn materializer(&self) -> Materializer<'_> {
        Materializer {
            builder: &self.builder,
            options: &self.options.build,
        }
    }

    fn within<T>(&self, limit: std::time::Duration, lookup: impl FnOnce(&Deadline) -> T) -> T {
        match self.deadline {
            Some(deadline) => lookup(deadline),
            None => lookup(&self.operation.deadline(self.client, limit)),
        }
    }

    fn check(&self) -> Result<(), Error> {
        self.client.check_cancelled()?;
        self.operation.deadline.check_cancelled()?;
        ensure_preparation_deadline(&self.operation.deadline)?;
        if let Some(deadline) = self.deadline {
            deadline.check_cancelled()?;
            ensure_preparation_deadline(deadline)?;
        }
        Ok(())
    }

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

    fn plan_with_interfaces<R: RouteProvider>(
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
                routes,
                deadline,
                interfaces,
                || self.check(),
            )
        })?;
        self.check()?;
        Ok(plan)
    }

    fn admit<R: RouteProvider>(
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

    fn authorize_built(&self, built: &BuiltPacket, plan: &route::Plan) -> Result<(), Error> {
        let policy = &self.policy;
        policy.authorize_built_packet(built, self.options.allow_permissive_live)?;
        crate::policy::authorize_wire(policy, plan.wire_link_type()?, &built.bytes, plan)?;
        Ok(())
    }

    fn build_and_authorize(
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

    fn materialize_using(
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
    fn materialize(&self, admitted: Admitted) -> Result<PreparedPacket, Error> {
        let providers = &self.client.providers;
        let neighbors = self.operation.neighbors.over(
            PacketProviders::transmit(providers.as_ref()),
            providers.capture(),
        );
        self.materialize_using(admitted, |plan, deadline| {
            route::materialize(plan, &neighbors, deadline)
        })
    }

    fn rebuild(
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

    fn materialize_retained(
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

pub(crate) struct Admitting<'c, P, K> {
    stages: Stages<'c, P, K>,
    budget: Budget,
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
    stages: Stages<'c, P, K>,
}

impl<P: PacketProviders, K: Clock> Discovery<'_, P, K> {
    pub(crate) fn materialize(&self, admitted: Admitted) -> Result<PreparedPacket, Error> {
        self.stages.materialize(admitted)
    }
}

fn changed_preparation(message: &str) -> Error {
    Error::PacketMaterialization {
        layer: 0,
        field: "preparation",
        message: message.to_owned(),
        source: None,
    }
}

#[cfg(test)]
mod work {
    std::thread_local! {
        static COUNTS: std::cell::Cell<(usize, usize, usize)> = const { std::cell::Cell::new((0, 0, 0)) };
    }
    pub(super) fn build() {
        COUNTS.with(|counts| {
            let (builds, preparations, reused) = counts.get();
            counts.set((builds + 1, preparations, reused));
        });
    }
    pub(super) fn prepare() {
        COUNTS.with(|counts| {
            let (builds, preparations, reused) = counts.get();
            counts.set((builds, preparations + 1, reused));
        });
    }
    pub(super) fn reuse() {
        COUNTS.with(|counts| {
            let (builds, preparations, reused) = counts.get();
            counts.set((builds, preparations, reused + 1));
        });
    }
    pub(super) fn take() -> (usize, usize, usize) {
        COUNTS.replace((0, 0, 0))
    }
}

#[cfg(test)]
pub(crate) mod tests;

#[derive(Debug)]
pub(crate) enum RebuildError {
    Changed { admitted: usize },
    Preparation(Error),
}

impl From<Error> for RebuildError {
    fn from(source: Error) -> Self {
        Self::Preparation(source)
    }
}

pub(crate) struct Streaming<'c, P, K> {
    stages: Stages<'c, P, K>,
    budget: Budget,
}

impl<P: TransmitProviders, K: Clock> Streaming<'_, P, K> {
    pub(crate) fn check(&self) -> Result<(), Error> {
        self.stages.check()
    }

    pub(crate) fn prepare_layer3(&mut self, packet: Packet) -> Result<PreparedPacket, Error> {
        let admitted = self.stages.admit(
            &mut self.budget,
            packet,
            self.stages.client.providers.route_provider(),
        )?;
        self.stages.materialize_using(admitted, |plan, _| {
            if plan.mode != packetcraftr_netio::link::Mode::Layer3
                || plan.needs_neighbor_resolution()
            {
                return Err(route::Error::Layer3Unsupported);
            }
            Ok(route::Materialized {
                plan,
                neighbor_resolution: None,
            })
        })
    }

    pub(crate) fn transmit(&self, packet: PreparedPacket) -> Result<SentPacket, Error> {
        packet.transmit(self.stages.client.providers.transmit_provider(), || {
            self.stages.check()
        })
    }
}

impl<P: PacketProviders, K: Clock> Streaming<'_, P, K> {
    pub(crate) fn prepare(&mut self, packet: Packet) -> Result<PreparedPacket, Error> {
        let admitted = self.stages.admit(
            &mut self.budget,
            packet,
            TransmitProviders::route_provider(self.stages.client.providers.as_ref()),
        )?;
        self.stages.materialize(admitted)
    }
}

impl<P: TransmitProviders, K: Clock> Client<P, K> {
    pub(crate) fn admitting_in<'c>(
        &'c self,
        options: &'c send::Options,
        packets: u64,
        deadline: &'c Deadline,
        operation: &Execution,
    ) -> Result<Admitting<'c, P, K>, Error> {
        let (stages, budget) = self.open_stages(options, packets, Some(deadline), operation)?;
        Ok(Admitting { stages, budget })
    }

    pub(crate) fn streaming_in<'c>(
        &'c self,
        options: &'c send::Options,
        packets: u64,
        operation: &Execution,
    ) -> Result<Streaming<'c, P, K>, Error> {
        let (stages, budget) = self.open_stages(options, packets, None, operation)?;
        Ok(Streaming { stages, budget })
    }

    fn open_stages<'c>(
        &'c self,
        options: &'c send::Options,
        packets: u64,
        deadline: Option<&'c Deadline>,
        operation: &Execution,
    ) -> Result<(Stages<'c, P, K>, Budget), Error> {
        let stages = Stages::new(self, options, deadline, operation);
        stages.check()?;
        let budget = Budget::open(&stages.policy, packets)?;
        Ok((stages, budget))
    }
}
