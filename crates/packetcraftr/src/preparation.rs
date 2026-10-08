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

use bytes::Bytes;
use packetcraftr_core::budget::Deadline;
use packetcraftr_core::build::{self, Builder, BuiltPacket};
use packetcraftr_core::codec;
use packetcraftr_core::packet::Packet;
use packetcraftr_netio::route::Provider as RouteProvider;
use packetcraftr_netio::{Error as LiveIoError, interface, transmit};

use crate::clock::Clock;
use crate::mtu::validate_mtu;
use crate::planning::ensure_preparation_deadline;
use crate::policy::{Operation, Policy, WireLimits};
use crate::providers::PacketProviders;
use crate::route;
use crate::{Client, Error, evidence::SentPacket, send};
use materialize::{
    build_context, materialize_link_fields, materialize_link_structure, materialize_network_fields,
    require_fixed_width_link_materialization,
};

#[derive(Clone)]
pub(crate) struct AuthorizedRoute {
    plan: route::Plan,
}

impl AuthorizedRoute {
    pub(crate) fn interface(&self) -> &interface::Id {
        &self.plan.decision.interface
    }

    pub(crate) fn plan(&self) -> &route::Plan {
        &self.plan
    }
}

/// The exact wire bytes one admitted packet charged to the cumulative budget.
/// It is neither `Clone` nor `Copy`: [`Discovery::rebuild`] consumes it, so
/// each admission pays for exactly one rebuild.
#[derive(Debug)]
pub(crate) struct AdmittedCost {
    wire_len: usize,
}

pub(crate) struct Admitted {
    packet: Packet,
    plan: route::Plan,
    build_context: codec::Context,
    preliminary_build: BuiltPacket,
}

impl Admitted {
    pub(crate) fn packet(&self) -> &Packet {
        &self.packet
    }

    pub(crate) fn wire_len(&self) -> usize {
        self.preliminary_build.bytes.len()
    }

    pub(crate) fn shares_route_with(&self, other: &Self) -> bool {
        self.plan.decision.interface == other.plan.decision.interface
            && self.plan.mode == other.plan.mode
    }

    pub(crate) fn into_cost(self) -> AdmittedCost {
        AdmittedCost {
            wire_len: self.wire_len(),
        }
    }
}

#[derive(Clone)]
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

    #[cfg(test)]
    pub(crate) fn fixture(built: BuiltPacket, route: route::Materialized) -> Self {
        Self { built, route }
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
    ) -> Result<(codec::Context, BuiltPacket), Error> {
        materialize_network_fields(packet, plan)?;
        materialize_link_structure(packet, plan)?;
        check()?;
        let context = build_context(plan);
        let built = self
            .builder
            .build(packet.clone(), context.clone(), self.options.clone())?;
        Ok((context, built))
    }

    fn link(
        &self,
        mut packet: Packet,
        route: &route::Materialized,
        context: codec::Context,
        preliminary: BuiltPacket,
        check: impl Fn() -> Result<(), Error>,
    ) -> Result<BuiltPacket, Error> {
        let preliminary_len = preliminary.bytes.len();
        let built = if materialize_link_fields(&mut packet, route)? {
            check()?;
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
    policy: &'c Policy,
    builder: Builder,
    options: &'c send::Options,
    deadline: Option<&'c Deadline>,
}

impl<'c, P: PacketProviders, K: Clock> Stages<'c, P, K> {
    fn new(
        client: &'c Client<P, K>,
        options: &'c send::Options,
        deadline: Option<&'c Deadline>,
    ) -> Self {
        Self {
            client,
            policy: client.policy.as_ref(),
            builder: Builder::new(client.registry.clone()),
            options,
            deadline,
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
            None => lookup(&self.client.deadline(limit)),
        }
    }

    fn check(&self) -> Result<(), Error> {
        self.client.check_cancelled()?;
        if let Some(deadline) = self.deadline {
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
        self.check()?;
        let plan = self.within(crate::deadline::PASSIVE_LOOKUP_TIMEOUT, |deadline| {
            self.client.authorize_and_plan(
                packet,
                destination,
                route_options,
                routes,
                deadline,
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
        budget.charge(self.policy, admitted.wire_len())?;
        Ok(admitted)
    }

    fn authorize_built(&self, built: &BuiltPacket, plan: &route::Plan) -> Result<(), Error> {
        let policy = &self.client.policy;
        policy.authorize_built_packet(built, self.options.allow_permissive_live)?;
        crate::policy::authorize_wire(policy, plan.wire_link_type()?, &built.bytes, plan)?;
        Ok(())
    }

    fn build_and_authorize(
        &self,
        mut packet: Packet,
        plan: route::Plan,
    ) -> Result<Admitted, Error> {
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
        })
    }

    /// Spaces a packet from the neighbor request its route just sent, within
    /// the preparation deadline.
    fn pace_neighbor_request(&self) -> Result<(), Error> {
        let pause = self.client.neighbor_pause;
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

    fn materialize(&self, admitted: Admitted) -> Result<PreparedPacket, Error> {
        let Admitted {
            packet,
            plan,
            build_context,
            preliminary_build,
        } = admitted;
        self.check()?;
        // Only a request about to be sent is checked: a cached answer sends
        // nothing to the neighbor.
        if (self.client.neighbors_resolved_ahead || self.client.authorize_neighbor_requests)
            && plan.needs_neighbor_resolution()
        {
            let request = route::neighbor_request(&plan)?;
            let cached = self
                .client
                .neighbors
                .cached(&request)
                .map_err(route::Error::from)?
                .is_some();
            if !cached && self.client.neighbors_resolved_ahead {
                return Err(Error::UnresolvedNeighbor {
                    target: request.target,
                    interface: request.interface.name,
                });
            }
            if !cached {
                authorize_neighbor_request(&self.client.policy, &request, &plan)?;
            }
        }
        // The resolver stops at the deadline on its own; a failure it reports
        // after the deadline passed is the deadline, not a neighbor verdict.
        let providers = &self.client.providers;
        let neighbors = self
            .client
            .neighbors
            .over(providers.transmit(), providers.capture());
        let request = plan
            .needs_neighbor_resolution()
            .then(|| route::neighbor_request(&plan))
            .transpose()?;
        let route = match self.within(packetcraftr_netio::deadline::MAX_WAIT, |deadline| {
            route::materialize(plan, &neighbors, deadline)
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
                self.pace_neighbor_request()?;
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

/// The requests a resolution that `request` asked for sent before it failed
/// unanswered.
fn unanswered(error: &route::Error, request: Option<&crate::neighbor::Request>) -> crate::Stats {
    let (route::Error::Neighbor(neighbor), Some(request)) = (error, request) else {
        return crate::Stats::default();
    };
    let crate::neighbor::Error::NotFound {
        attempts,
        capture_statistics,
        ..
    } = &**neighbor
    else {
        return crate::Stats::default();
    };
    let attempts = u64::from(*attempts);
    let frame_bytes = crate::neighbor::request_frame(request).map_or(0, |frame| frame.len() as u64);
    crate::Stats {
        packets_attempted: attempts,
        packets_completed: attempts,
        bytes: attempts.saturating_mul(frame_bytes),
        capture: *capture_statistics,
        ..crate::Stats::default()
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

    #[cfg(test)]
    pub(crate) fn route(
        &self,
        packet: &Packet,
        destination: IpAddr,
    ) -> Result<AuthorizedRoute, Error> {
        self.route_on(packet, destination, None)
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
            self.stages.client.providers.route(),
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
        Ok(AuthorizedRoute { plan })
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

    pub(crate) fn rebuild(
        &self,
        packet: Packet,
        route: &AuthorizedRoute,
        cost: AdmittedCost,
    ) -> Result<PreparedPacket, RebuildError> {
        self.stages.check()?;
        let admitted = self
            .stages
            .build_and_authorize(packet, route.plan.clone())?;
        if admitted.wire_len() != cost.wire_len {
            return Err(RebuildError::Changed {
                admitted: cost.wire_len,
            });
        }
        Ok(self.stages.materialize(admitted)?)
    }
}

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

impl<P: PacketProviders, K: Clock> Streaming<'_, P, K> {
    pub(crate) fn check(&self) -> Result<(), Error> {
        self.stages.check()
    }

    pub(crate) fn prepare(&mut self, packet: Packet) -> Result<PreparedPacket, Error> {
        let admitted = self.stages.admit(
            &mut self.budget,
            packet,
            self.stages.client.providers.route(),
        )?;
        self.stages.materialize(admitted)
    }

    pub(crate) fn transmit(&self, packet: PreparedPacket) -> Result<SentPacket, Error> {
        packet.transmit(self.stages.client.providers.transmit(), || {
            self.stages.check()
        })
    }
}

impl<P: PacketProviders, K: Clock> Client<P, K> {
    pub(crate) fn admitting<'c>(
        &'c self,
        options: &'c send::Options,
        packets: u64,
        deadline: &'c Deadline,
    ) -> Result<Admitting<'c, P, K>, Error> {
        let (stages, budget) = self.open_stages(options, packets, Some(deadline))?;
        Ok(Admitting { stages, budget })
    }

    pub(crate) fn streaming<'c>(
        &'c self,
        options: &'c send::Options,
        packets: u64,
    ) -> Result<Streaming<'c, P, K>, Error> {
        let (stages, budget) = self.open_stages(options, packets, None)?;
        Ok(Streaming { stages, budget })
    }

    fn open_stages<'c>(
        &'c self,
        options: &'c send::Options,
        packets: u64,
        deadline: Option<&'c Deadline>,
    ) -> Result<(Stages<'c, P, K>, Budget), Error> {
        let stages = Stages::new(self, options, deadline);
        stages.check()?;
        let budget = Budget::open(stages.policy, packets)?;
        Ok((stages, budget))
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::time::Duration;

    use bytes::Bytes;
    use packetcraftr_core::layer::Raw;
    use packetcraftr_core::protocol::network::Ipv4;
    use packetcraftr_core::protocol::transport::Udp;
    use packetcraftr_netio::link::Mode;

    use super::*;
    use crate::test_support::{Call, fake_client};

    const DESTINATION: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 2);

    fn datagram(payload: &'static [u8]) -> Packet {
        let mut packet = Packet::new();
        packet
            .push(Ipv4 {
                destination: DESTINATION,
                ..Ipv4::default()
            })
            .push(Udp {
                source_port: 40_000,
                destination_port: 9,
                ..Udp::default()
            })
            .push(Raw::new(Bytes::from_static(payload)));
        packet
    }

    #[test]
    fn a_rebuild_must_match_the_wire_bytes_its_admission_charged() {
        let (client, providers) = fake_client();
        let mut options = send::Options::default();
        options.plan.link_mode = Mode::Layer3;
        let deadline = client.deadline(Duration::from_secs(5));
        let admitted_packet = datagram(b"four");
        let mut admission = client
            .admitting(&options, 2, &deadline)
            .expect("two packets fit the default budget");
        let route = admission
            .route(&admitted_packet, IpAddr::V4(DESTINATION))
            .expect("documentation destination is authorized");
        let unchanged = admission
            .admit_on(admitted_packet.clone(), &route)
            .expect("first packet is admitted")
            .into_cost();
        let changed = admission
            .admit_on(admitted_packet.clone(), &route)
            .expect("second packet is admitted")
            .into_cost();
        let admitted_len = unchanged.wire_len;
        let discovery = admission.discover();

        let prepared = discovery
            .rebuild(admitted_packet, &route, unchanged)
            .expect("an identical rebuild keeps its admitted cost");
        assert_eq!(prepared.built().bytes.len(), admitted_len);

        let Err(error) = discovery.rebuild(datagram(b"fives"), &route, changed) else {
            panic!("a rebuild with a different wire length must be rejected");
        };
        assert!(
            matches!(
                error,
                RebuildError::Changed { admitted } if admitted == admitted_len
            ),
            "{error:?}"
        );
        assert!(
            !providers
                .calls()
                .iter()
                .any(|call| matches!(call, Call::Transmit(_))),
            "preparation never transmits on its own"
        );
    }

    #[test]
    fn cumulative_byte_overflow_is_a_byte_limit_denial() {
        let policy = Policy::default();
        let mut budget = Budget::open(&policy, 1).expect("one packet fits");
        budget.wire_bytes = u64::MAX - 1;

        let error = budget
            .charge(&policy, 2)
            .expect_err("overflowing the cumulative total must be denied");

        assert!(
            matches!(
                error,
                Error::Policy(crate::policy::Error::ByteLimit { actual, limit })
                    if actual == u64::MAX && limit == policy.max_bytes_per_operation
            ),
            "{error:?}"
        );
        assert_eq!(
            budget.wire_bytes,
            u64::MAX - 1,
            "a denied charge is not kept"
        );
    }
}
