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
//! - **All-before-discovery** ([`Admission`] then [`Discovery`]): every
//!   packet is admitted before any is materialized. [`Admission::discover`]
//!   consumes the admission, so no packet can be admitted once discovery
//!   traffic may have been emitted. Exchange uses it.
//! - **Streaming** ([`Streaming`]): each packet is admitted, materialized,
//!   and transmitted before the next one is planned, so frames are confirmed
//!   as they go and large sets are never held in memory. `send_set` uses it;
//!   single send is streaming with one packet.

use std::time::Instant;

use packetcraftr_core::budget::Cancellation;
use packetcraftr_core::build::{Builder, BuiltPacket};
use packetcraftr_core::codec;
use packetcraftr_core::packet::Packet;
use packetcraftr_netio::{Error as LiveIoError, neighbor, route, transmit};

use crate::materialize::{
    build_context, materialize_link_fields, materialize_link_structure, materialize_network_fields,
    require_fixed_width_link_materialization,
};
use crate::mtu::validate_mtu;
use crate::planning::ensure_preparation_deadline;
use crate::policy::{Operation, Policy, WireBudget};
use crate::{Client, Error, SentPacket, send};

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
    /// The passive route plan the packet was admitted on.
    pub(crate) fn plan(&self) -> &route::Plan {
        &self.plan
    }

    /// The packet description after network-field materialization.
    pub(crate) fn packet(&self) -> &Packet {
        &self.packet
    }

    /// Exact wire bytes charged to the cumulative budget.
    pub(crate) fn wire_len(&self) -> usize {
        self.preliminary_build.bytes.len()
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
        I: transmit::Sender + ?Sized,
        E: From<LiveIoError>,
    {
        let report = {
            let frame = transmit::Frame::try_new(&self.built.bytes, &self.route)?;
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

/// The operation's packet count and cumulative exact wire bytes.
#[derive(Debug)]
struct Budget {
    packets: u64,
    wire_bytes: u64,
}

impl Budget {
    /// Authorizes the count-only budget before any provider is consulted.
    fn open(policy: &Policy, packets: u64) -> Result<Self, Error> {
        policy.authorize(Operation::Budgeted(WireBudget::new(packets, 0)))?;
        Ok(Self {
            packets,
            wire_bytes: 0,
        })
    }

    /// Adds one packet's exact wire bytes and authorizes the new total.
    /// Arithmetic overflow is itself a byte-limit denial.
    fn charge(&mut self, policy: &Policy, wire_len: usize) -> Result<(), Error> {
        let wire_bytes = u64::try_from(wire_len)
            .ok()
            .and_then(|bytes| self.wire_bytes.checked_add(bytes))
            .ok_or(crate::policy::Error::ByteLimit {
                actual: u64::MAX,
                limit: policy.max_bytes_per_operation,
            })?;
        policy.authorize(Operation::Budgeted(WireBudget::new(
            self.packets,
            wire_bytes,
        )))?;
        self.wire_bytes = wire_bytes;
        Ok(())
    }
}

/// State shared by both orders: the client, one builder, the per-packet send
/// options, and the operation's stop conditions.
struct Stages<'c, R, N, I> {
    client: &'c Client<R, N, I>,
    builder: Builder,
    options: &'c send::Options,
    deadline: Option<Instant>,
    /// A signal checked in addition to the client's own.
    cancellation: Option<Cancellation>,
}

impl<'c, R, N, I> Stages<'c, R, N, I>
where
    R: route::Provider,
    N: neighbor::Resolver,
    I: transmit::Sender,
{
    fn new(
        client: &'c Client<R, N, I>,
        options: &'c send::Options,
        deadline: Option<Instant>,
        cancellation: Option<Cancellation>,
    ) -> Self {
        Self {
            client,
            builder: Builder::new(client.registry.clone()),
            options,
            deadline,
            cancellation,
        }
    }

    fn check(&self) -> Result<(), Error> {
        self.client.check_cancelled()?;
        if let Some(signal) = &self.cancellation {
            signal.check()?;
        }
        if let Some(deadline) = self.deadline {
            ensure_preparation_deadline(deadline)?;
        }
        Ok(())
    }

    /// Stages 2–4 for one packet, planning its route through `routes`.
    fn admit<P: route::Provider>(
        &self,
        budget: &mut Budget,
        packet: Packet,
        routes: &P,
    ) -> Result<Admitted, Error> {
        self.check()?;
        let plan = self.client.plan_with_provider(
            &packet,
            self.options.destination,
            &self.options.plan,
            routes,
            self.deadline,
        )?;
        self.check()?;
        let admitted = self.build_and_authorize(packet, plan)?;
        budget.charge(&self.client.policy, admitted.wire_len())?;
        Ok(admitted)
    }

    /// Stage 3: materializes route-dependent network fields and authorizes
    /// the preliminary build without traffic.
    fn build_and_authorize(
        &self,
        mut packet: Packet,
        plan: route::Plan,
    ) -> Result<Admitted, Error> {
        let policy = &self.client.policy;
        materialize_network_fields(&mut packet, &plan)?;
        materialize_link_structure(&mut packet, &plan)?;
        self.check()?;
        let build_context = build_context(&plan);
        let preliminary_build = self.builder.build(
            packet.clone(),
            build_context.clone(),
            self.options.build.clone(),
        )?;
        self.check()?;
        validate_mtu(&preliminary_build, plan.decision.mtu)?;
        policy.authorize_built_packet(&preliminary_build, self.options.allow_permissive_live)?;
        policy.authorize_built_wire(&preliminary_build, &plan)?;
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
            mut packet,
            plan,
            build_context,
            preliminary_build,
        } = admitted;
        let policy = &self.client.policy;
        let preliminary_len = preliminary_build.bytes.len();
        self.check()?;
        // The resolver stops at the deadline on its own; a failure it reports
        // after the deadline passed is the deadline, not a neighbor verdict.
        let route = match route::materialize(plan, &self.client.neighbors, self.deadline) {
            Ok(route) => route,
            Err(error) => {
                self.check()?;
                return Err(error.into());
            }
        };
        let link_changed = materialize_link_fields(&mut packet, &route)?;
        let built = if link_changed {
            self.check()?;
            self.builder
                .build(packet, build_context, self.options.build.clone())?
        } else {
            preliminary_build
        };
        require_fixed_width_link_materialization(preliminary_len, built.bytes.len())?;
        self.check()?;
        policy.authorize_built_packet(&built, self.options.allow_permissive_live)?;
        policy.authorize_built_wire(&built, &route.plan)?;
        Ok(PreparedPacket { built, route })
    }
}

/// All-before-discovery order, admission phase: packets are planned,
/// preliminarily authorized, and charged, and none is materialized.
pub(crate) struct Admission<'c, R, N, I> {
    stages: Stages<'c, R, N, I>,
    budget: Budget,
}

impl<'c, R, N, I> Admission<'c, R, N, I>
where
    R: route::Provider,
    N: neighbor::Resolver,
    I: transmit::Sender,
{
    /// Checks cancellation and the operation deadline between packets.
    pub(crate) fn check(&self) -> Result<(), Error> {
        self.stages.check()
    }

    /// Plans `packet` through `routes`, checks its preliminary build, and
    /// charges its exact wire bytes to the cumulative budget.
    pub(crate) fn admit<P: route::Provider>(
        &mut self,
        packet: Packet,
        routes: &P,
    ) -> Result<Admitted, Error> {
        self.stages.admit(&mut self.budget, packet, routes)
    }

    /// Cumulative exact wire bytes admitted so far.
    pub(crate) fn wire_bytes(&self) -> u64 {
        self.budget.wire_bytes
    }

    /// Ends admission. Discovery traffic can be emitted only from here on,
    /// and no further packet can be admitted into this operation.
    pub(crate) fn discover(self) -> Discovery<'c, R, N, I> {
        Discovery {
            stages: self.stages,
        }
    }
}

/// All-before-discovery order, discovery phase: admitted packets are
/// materialized and finally authorized.
pub(crate) struct Discovery<'c, R, N, I> {
    stages: Stages<'c, R, N, I>,
}

impl<R, N, I> Discovery<'_, R, N, I>
where
    R: route::Provider,
    N: neighbor::Resolver,
    I: transmit::Sender,
{
    pub(crate) fn materialize(&self, admitted: Admitted) -> Result<PreparedPacket, Error> {
        self.stages.materialize(admitted)
    }
}

/// Streaming order: each packet is admitted, materialized, and finally
/// authorized by [`prepare`](Self::prepare), then sent by
/// [`transmit`](Self::transmit), before the next packet is planned.
pub(crate) struct Streaming<'c, R, N, I> {
    stages: Stages<'c, R, N, I>,
    budget: Budget,
}

impl<R, N, I> Streaming<'_, R, N, I>
where
    R: route::Provider,
    N: neighbor::Resolver,
    I: transmit::Sender,
{
    /// Checks the client's and the operation's cancellation signals.
    pub(crate) fn check(&self) -> Result<(), Error> {
        self.stages.check()
    }

    /// Runs every stage up to the final authorization for one packet. Its
    /// neighbor discovery runs only after its own preliminary checks and
    /// budget charge pass.
    pub(crate) fn prepare(&mut self, packet: Packet) -> Result<PreparedPacket, Error> {
        let admitted = self
            .stages
            .admit(&mut self.budget, packet, &self.stages.client.routes)?;
        self.stages.materialize(admitted)
    }

    /// Transmits a finally authorized packet through the client's sender.
    pub(crate) fn transmit(&self, packet: PreparedPacket) -> Result<SentPacket, Error> {
        packet.transmit(&self.stages.client.io, || self.stages.check())
    }
}

impl<R, N, I> Client<R, N, I>
where
    R: route::Provider,
    N: neighbor::Resolver,
    I: transmit::Sender,
{
    /// Starts an all-before-discovery preparation of `packets` packets,
    /// authorizing the count-only budget first.
    pub(crate) fn admission<'c>(
        &'c self,
        options: &'c send::Options,
        packets: u64,
        deadline: Instant,
    ) -> Result<Admission<'c, R, N, I>, Error> {
        let stages = Stages::new(self, options, Some(deadline), None);
        stages.check()?;
        let budget = Budget::open(&self.policy, packets)?;
        Ok(Admission { stages, budget })
    }

    /// Starts a streaming preparation of `packets` packets, authorizing the
    /// count-only budget first. `cancellation` is checked alongside the
    /// client's own signal.
    pub(crate) fn streaming<'c>(
        &'c self,
        options: &'c send::Options,
        packets: u64,
        cancellation: Option<Cancellation>,
    ) -> Result<Streaming<'c, R, N, I>, Error> {
        let stages = Stages::new(self, options, None, cancellation);
        stages.check()?;
        let budget = Budget::open(&self.policy, packets)?;
        Ok(Streaming { stages, budget })
    }

    /// Stage 3 on a caller-planned route, without a budget charge.
    ///
    /// Transitional: the scan pipeline still sequences its own chain until it
    /// moves onto [`Admission`].
    pub(crate) fn plan_and_authorize(
        &self,
        packet: Packet,
        plan: route::Plan,
        builder: &Builder,
        options: &send::Options,
        deadline: Option<Instant>,
    ) -> Result<Admitted, Error> {
        self.detached_stages(builder, options, deadline)
            .build_and_authorize(packet, plan)
    }

    /// Stages 5–6 for a packet admitted by
    /// [`plan_and_authorize`](Self::plan_and_authorize).
    ///
    /// Transitional: see [`plan_and_authorize`](Self::plan_and_authorize).
    pub(crate) fn materialize_and_authorize(
        &self,
        admitted: Admitted,
        builder: &Builder,
        options: &send::Options,
        deadline: Option<Instant>,
    ) -> Result<PreparedPacket, Error> {
        self.detached_stages(builder, options, deadline)
            .materialize(admitted)
    }

    fn detached_stages<'c>(
        &'c self,
        builder: &Builder,
        options: &'c send::Options,
        deadline: Option<Instant>,
    ) -> Stages<'c, R, N, I> {
        Stages {
            client: self,
            builder: builder.clone(),
            options,
            deadline,
            cancellation: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
