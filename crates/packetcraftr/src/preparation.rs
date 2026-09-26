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
//!
//! The types enforce the order. An [`Admitted`] packet exists only after
//! stages 2–4, a [`PreparedPacket`] only after stage 6, and only a
//! `PreparedPacket` can be transmitted. Its bytes and route are immutable, so
//! the final check covers exactly what reaches the wire.
//!
//! Two orders are available:
//!
//! - **All-before-discovery** ([`Admitting`] then [`Discovery`]): every
//!   packet is admitted before any is materialized. [`Admitting::discover`]
//!   consumes the admission, so no packet can be admitted once discovery
//!   traffic may have been emitted. Exchange keeps its admitted packets and
//!   materializes them. The scan pipeline keeps only each packet's
//!   [`AdmittedCost`] and rebuilds the packet at send time with
//!   [`Discovery::rebuild`], which rejects a rebuild whose exact wire length
//!   differs from the admitted one.
//! - **Streaming** ([`Streaming`]): each packet is admitted, materialized,
//!   and transmitted before the next one is planned, so frames are confirmed
//!   as they go and large sets are never held in memory. Send uses it.
//!
//! [`exact_bytes`] applies the same materialization rules to a packet and an
//! already materialized route, without providers or authorization, so a
//! workflow can check what an executor transmitted.

mod materialize;

use std::net::IpAddr;

use bytes::Bytes;
use packetcraftr_core::budget::Deadline;
use packetcraftr_core::build::{self, Builder, BuiltPacket};
use packetcraftr_core::codec;
use packetcraftr_core::packet::Packet;
use packetcraftr_netio::route::Provider as RouteProvider;
use packetcraftr_netio::{Error as LiveIoError, capture, interface, transmit};

use crate::clock::Clock;
use crate::execution::Admission;
use crate::mtu::validate_mtu;
use crate::planning::ensure_preparation_deadline;
use crate::policy::{Operation, WireLimits};
use crate::providers::Providers;
use crate::route;
use crate::{Client, Error, SentPacket, send};
use materialize::{
    build_context, materialize_link_fields, materialize_link_structure, materialize_network_fields,
    require_fixed_width_link_materialization,
};

/// A route planned for one destination after the destination and the
/// planning packet's declared endpoints were authorized. Only
/// [`Admitting::route`] creates one, so every packet admitted or rebuilt on it
/// leaves on a planned route. Each packet's own endpoints and bytes are still
/// authorized when it is built.
#[derive(Clone)]
pub(crate) struct AuthorizedRoute {
    plan: route::Plan,
}

impl AuthorizedRoute {
    /// The interface the route leaves through.
    pub(crate) fn interface(&self) -> &interface::Id {
        &self.plan.decision.interface
    }
}

/// The exact wire bytes one admitted packet charged to the cumulative budget.
/// It is neither `Clone` nor `Copy`: [`Discovery::rebuild`] consumes it, so
/// each admission pays for exactly one rebuild.
#[derive(Debug)]
pub(crate) struct AdmittedCost {
    wire_len: usize,
}

/// A packet whose route is planned and whose preliminary build passed the MTU,
/// packet, wire, and cumulative budget checks. Neighbor discovery has not run
/// for it yet.
pub(crate) struct Admitted {
    packet: Packet,
    plan: route::Plan,
    build_context: codec::Context,
    preliminary_build: BuiltPacket,
}

impl Admitted {
    /// The packet description after network-field materialization.
    pub(crate) fn packet(&self) -> &Packet {
        &self.packet
    }

    /// Exact wire bytes charged to the cumulative budget.
    pub(crate) fn wire_len(&self) -> usize {
        self.preliminary_build.bytes.len()
    }

    /// Whether both packets leave through the same interface in the same link
    /// mode.
    pub(crate) fn shares_route_with(&self, other: &Self) -> bool {
        self.plan.decision.interface == other.plan.decision.interface
            && self.plan.mode == other.plan.mode
    }

    /// Drops the prepared packet and keeps only what it charged, for a caller
    /// that rebuilds it at send time instead of holding it.
    pub(crate) fn into_cost(self) -> AdmittedCost {
        AdmittedCost {
            wire_len: self.wire_len(),
        }
    }
}

/// The exact bytes and the materialized route of one transmission, after both
/// passed the final endpoint and bytes authorization together.
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

    /// Hands the authorized bytes to `io` and records the confirmed
    /// transmission. `check` runs immediately before the provider call, after
    /// the typed frame is selected.
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

    /// Fixture constructor for tests that exercise evidence handling without
    /// a preparation run.
    #[cfg(test)]
    pub(crate) fn fixture(built: BuiltPacket, route: route::Materialized) -> Self {
        Self { built, route }
    }
}

/// The exact bytes preparation produces for `packet` on the materialized
/// `route`: route-dependent network fields and link structure, the
/// preliminary build, then link fields, rebuilt at the planned width when they
/// changed.
///
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

/// The materialization rules shared by live preparation and [`exact_bytes`].
/// `check` runs between steps that may take time.
struct Materializer<'a> {
    builder: &'a Builder,
    options: &'a build::Options,
}

impl Materializer<'_> {
    /// Fills route-dependent network fields and link structure into `packet`,
    /// then builds it with the route's checksum endpoints.
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

    /// Fills the materialized route's link fields and rebuilds when they
    /// changed. The final bytes must keep the preliminary build's width.
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

/// The operation's running wire budget: its declared packet count and the
/// exact wire bytes charged so far, each authorized against policy limits.
#[derive(Debug)]
struct Budget {
    packets: u64,
    wire_bytes: u64,
}

impl Budget {
    /// Authorizes the count-only budget before any provider is consulted.
    fn open(admission: &Admission<'_>, packets: u64) -> Result<Self, Error> {
        admission.authorize(Operation::Wire(WireLimits::new(packets, 0)))?;
        Ok(Self {
            packets,
            wire_bytes: 0,
        })
    }

    /// Adds one packet's exact wire bytes and authorizes the new total.
    /// Arithmetic overflow is itself a byte-limit denial.
    fn charge(&mut self, admission: &Admission<'_>, wire_len: usize) -> Result<(), Error> {
        let wire_bytes = u64::try_from(wire_len)
            .ok()
            .and_then(|bytes| self.wire_bytes.checked_add(bytes))
            .ok_or(crate::policy::Error::ByteLimit {
                actual: u64::MAX,
                limit: admission.policy().max_bytes_per_operation,
            })?;
        admission.authorize(Operation::Wire(WireLimits::new(self.packets, wire_bytes)))?;
        self.wire_bytes = wire_bytes;
        Ok(())
    }
}

/// State shared by both orders: the client and its admission, one builder,
/// the per-packet send options, and the operation's deadline.
struct Stages<'c, P, K> {
    client: &'c Client<P, K>,
    admission: Admission<'c>,
    builder: Builder,
    options: &'c send::Options,
    /// The operation's deadline, when it has one. It carries the client's
    /// cancellation.
    deadline: Option<&'c Deadline>,
}

impl<'c, P: Providers, K: Clock> Stages<'c, P, K> {
    fn new(
        client: &'c Client<P, K>,
        options: &'c send::Options,
        deadline: Option<&'c Deadline>,
    ) -> Self {
        Self {
            client,
            admission: client.admission(),
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

    /// Runs `lookup` under the operation deadline, or with none, under a
    /// fresh client deadline of `limit`.
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

    /// Stage 2: plans `packet` toward `destination` through `routes`,
    /// authorizing the destination and the packet's endpoints before the
    /// interface selector is resolved or a route is looked up. A lookup
    /// without an operation deadline gets
    /// [`PASSIVE_LOOKUP_TIMEOUT`](crate::deadline::PASSIVE_LOOKUP_TIMEOUT).
    fn plan<R: RouteProvider>(
        &self,
        packet: &Packet,
        destination: Option<IpAddr>,
        routes: &R,
    ) -> Result<route::Plan, Error> {
        self.check()?;
        let plan = self.within(crate::deadline::PASSIVE_LOOKUP_TIMEOUT, |deadline| {
            self.client.authorize_and_plan(
                packet,
                destination,
                &self.options.plan,
                routes,
                deadline,
                || self.check(),
            )
        })?;
        self.check()?;
        Ok(plan)
    }

    /// Stages 2–4 for one packet, planning its route through `routes`.
    fn admit<R: RouteProvider>(
        &self,
        budget: &mut Budget,
        packet: Packet,
        routes: &R,
    ) -> Result<Admitted, Error> {
        let plan = self.plan(&packet, self.options.destination, routes)?;
        self.charge(budget, self.build_and_authorize(packet, plan)?)
    }

    /// Stage 4: charges an admitted packet's exact wire bytes.
    fn charge(&self, budget: &mut Budget, admitted: Admitted) -> Result<Admitted, Error> {
        budget.charge(&self.admission, admitted.wire_len())?;
        Ok(admitted)
    }

    /// Authorizes a build's declared destinations and permissive-live
    /// approvals, then the exact bytes that would reach the wire on `plan`,
    /// decoded with the trusted registry.
    fn authorize_built(&self, built: &BuiltPacket, plan: &route::Plan) -> Result<(), Error> {
        let policy = &self.client.policy;
        policy.authorize_built_packet(built, self.options.allow_permissive_live)?;
        crate::policy::authorize_wire(policy, plan.wire_link_type()?, &built.bytes, Some(plan))?;
        Ok(())
    }

    /// Stage 3: materializes route-dependent network fields and authorizes
    /// the preliminary build without traffic.
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

    /// Stages 5–6: resolves link fields (which may emit discovery traffic),
    /// rebuilds a changed packet at the planned width, and authorizes the
    /// final bytes and route together.
    fn materialize(&self, admitted: Admitted) -> Result<PreparedPacket, Error> {
        let Admitted {
            packet,
            plan,
            build_context,
            preliminary_build,
        } = admitted;
        self.check()?;
        // The resolver stops at the deadline on its own; a failure it reports
        // after the deadline passed is the deadline, not a neighbor verdict.
        // Without an operation deadline, the longest wait a provider accepts
        // leaves the resolver's own options as the bound.
        let providers = &self.client.providers;
        let neighbors = self
            .client
            .neighbors
            .over(providers.transmit(), providers.capture());
        let route = match self.within(capture::MAX_TIMEOUT, |deadline| {
            route::materialize(plan, &neighbors, deadline)
        }) {
            Ok(route) => route,
            Err(error) => {
                self.check()?;
                return Err(error.into());
            }
        };
        let built =
            self.materializer()
                .link(packet, &route, build_context, preliminary_build, || {
                    self.check()
                })?;
        self.check()?;
        self.authorize_built(&built, &route.plan)?;
        Ok(PreparedPacket { built, route })
    }
}

/// All-before-discovery order, admission phase: packets are planned,
/// preliminarily authorized, and charged, and none is materialized.
pub(crate) struct Admitting<'c, P, K> {
    stages: Stages<'c, P, K>,
    budget: Budget,
}

impl<'c, P: Providers, K: Clock> Admitting<'c, P, K> {
    /// Checks cancellation and the operation deadline between packets.
    pub(crate) fn check(&self) -> Result<(), Error> {
        self.stages.check()
    }

    /// Plans `packet` through `routes`, checks its preliminary build, and
    /// charges its exact wire bytes to the cumulative budget.
    pub(crate) fn admit<R: RouteProvider>(
        &mut self,
        packet: Packet,
        routes: &R,
    ) -> Result<Admitted, Error> {
        self.stages.admit(&mut self.budget, packet, routes)
    }

    /// Plans `packet` toward `destination` through the client's routes, for a
    /// caller that shares one route among the packets it sends to the same
    /// destination.
    pub(crate) fn route(
        &self,
        packet: &Packet,
        destination: IpAddr,
    ) -> Result<AuthorizedRoute, Error> {
        let plan = self.stages.plan(
            packet,
            Some(destination),
            self.stages.client.providers.route(),
        )?;
        Ok(AuthorizedRoute { plan })
    }

    /// Checks `packet`'s preliminary build on an already planned `route` and
    /// charges its exact wire bytes to the cumulative budget.
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

    /// Cumulative exact wire bytes admitted so far.
    pub(crate) fn wire_bytes(&self) -> u64 {
        self.budget.wire_bytes
    }

    /// Ends admission. Discovery traffic can be emitted only from here on,
    /// and no further packet can be admitted into this operation.
    pub(crate) fn discover(self) -> Discovery<'c, P, K> {
        Discovery {
            stages: self.stages,
        }
    }
}

/// All-before-discovery order, discovery phase: admitted packets are
/// materialized and finally authorized.
pub(crate) struct Discovery<'c, P, K> {
    stages: Stages<'c, P, K>,
}

impl<P: Providers, K: Clock> Discovery<'_, P, K> {
    pub(crate) fn materialize(&self, admitted: Admitted) -> Result<PreparedPacket, Error> {
        self.stages.materialize(admitted)
    }

    /// Prepares a packet admitted earlier whose preparation was dropped to
    /// bound memory. The preliminary checks run again without a second
    /// budget charge, and a build whose exact wire length differs from
    /// `cost` is rejected before any discovery traffic for it.
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

/// Why [`Discovery::rebuild`] refused a packet. The caller names a changed
/// build in its own error, because only it knows why it rebuilds.
#[derive(Debug)]
pub(crate) enum RebuildError {
    /// The rebuild's exact wire length differs from the `admitted` one.
    Changed { admitted: usize },
    /// A preparation stage refused the rebuilt packet.
    Preparation(Error),
}

impl From<Error> for RebuildError {
    fn from(source: Error) -> Self {
        Self::Preparation(source)
    }
}

/// Streaming order: each packet is admitted, materialized, and finally
/// authorized by [`prepare`](Self::prepare), then sent by
/// [`transmit`](Self::transmit), before the next packet is planned.
pub(crate) struct Streaming<'c, P, K> {
    stages: Stages<'c, P, K>,
    budget: Budget,
}

impl<P: Providers, K: Clock> Streaming<'_, P, K> {
    /// Checks the client's cancellation signal.
    pub(crate) fn check(&self) -> Result<(), Error> {
        self.stages.check()
    }

    /// Runs every stage up to the final authorization for one packet. Its
    /// neighbor discovery runs only after its own preliminary checks and
    /// budget charge pass.
    pub(crate) fn prepare(&mut self, packet: Packet) -> Result<PreparedPacket, Error> {
        let admitted = self.stages.admit(
            &mut self.budget,
            packet,
            self.stages.client.providers.route(),
        )?;
        self.stages.materialize(admitted)
    }

    /// Transmits a finally authorized packet through the client's transmit
    /// provider.
    pub(crate) fn transmit(&self, packet: PreparedPacket) -> Result<SentPacket, Error> {
        packet.transmit(self.stages.client.providers.transmit(), || {
            self.stages.check()
        })
    }
}

impl<P: Providers, K: Clock> Client<P, K> {
    /// Starts an all-before-discovery preparation of `packets` packets under
    /// `deadline`, authorizing the count-only budget first.
    pub(crate) fn admitting<'c>(
        &'c self,
        options: &'c send::Options,
        packets: u64,
        deadline: &'c Deadline,
    ) -> Result<Admitting<'c, P, K>, Error> {
        let (stages, budget) = self.open_stages(options, packets, Some(deadline))?;
        Ok(Admitting { stages, budget })
    }

    /// Starts a streaming preparation of `packets` packets, authorizing the
    /// count-only budget first.
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
        let budget = Budget::open(&stages.admission, packets)?;
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
    use crate::policy::Policy;
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
        let providers = crate::test_support::FakeProviders::default();
        let admission = Admission::new(&policy, &providers);
        let mut budget = Budget::open(&admission, 1).expect("one packet fits");
        budget.wire_bytes = u64::MAX - 1;

        let error = budget
            .charge(&admission, 2)
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
