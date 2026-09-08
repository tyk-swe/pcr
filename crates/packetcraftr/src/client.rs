// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;

use crate::progress::Runtime;
use packetcraftr_core::registry::Registry;
use packetcraftr_netio::transmit::Sender as PacketIo;

use crate::Error;
use crate::materialize::{
    PlannedPacket, PreparedPacket, build_context, materialize_link_fields,
    materialize_link_structure, materialize_network_fields,
    require_fixed_width_link_materialization,
};
use crate::mtu::validate_mtu;
use crate::planning::ensure_preparation_deadline;
use crate::policy::Policy;
use packetcraftr_core::Packet;
use packetcraftr_core::build::Builder;
use packetcraftr_netio::{neighbor, route, transmit};
use std::time::Instant;

/// High-level composition of packet construction, passive route planning,
/// explicit neighbor materialization, policy, and packet I/O.
#[derive(Debug)]
pub struct Client<R, N, I> {
    pub(crate) registry: Arc<Registry>,
    pub(crate) routes: R,
    pub(crate) neighbors: N,
    pub(crate) io: I,
    pub(crate) policy: Arc<Policy>,
    /// Owns the worker budget behind
    /// [`exchange_with_events`](Self::exchange_with_events). It starts no
    /// thread until an exchange actually publishes events, and scoping it here
    /// keeps one client's publication failures out of every other client.
    pub(crate) runtime: Runtime,
    pub(crate) cancellation: Option<packetcraftr_core::budget::Cancellation>,
}

impl<R, N, I> Client<R, N, I>
where
    R: packetcraftr_netio::route::Provider,
    N: packetcraftr_netio::neighbor::Resolver,
    I: PacketIo,
{
    pub fn new(
        registry: Arc<Registry>,
        routes: R,
        neighbors: N,
        io: I,
        policy: impl Into<Arc<Policy>>,
    ) -> Self {
        Self {
            registry,
            routes,
            neighbors,
            io,
            policy: policy.into(),
            runtime: Runtime::default(),
            cancellation: None,
        }
    }

    #[must_use]
    pub fn with_cancellation(
        mut self,
        cancellation: packetcraftr_core::budget::Cancellation,
    ) -> Self {
        self.cancellation = Some(cancellation);
        self
    }

    pub fn registry(&self) -> &Arc<Registry> {
        &self.registry
    }
}

impl<R, N, I> Client<R, N, I> {
    pub(crate) fn check_cancelled(&self) -> Result<(), Error> {
        if let Some(signal) = &self.cancellation {
            signal.check()?;
        }
        Ok(())
    }

    pub fn policy(&self) -> &Policy {
        &self.policy
    }
}

impl<R, N, I> Client<R, N, I>
where
    R: route::Provider,
    N: neighbor::Resolver,
    I: transmit::Sender,
{
    /// Shared send/exchange preparation: materialize route-dependent fields,
    /// build the exact
    /// bytes, and authorize them against the selected route. Nothing here may
    /// emit traffic — neighbor discovery is deliberately still ahead.
    ///
    /// `deadline` is checked between the steps that can allocate, and is
    /// `None` for the single-packet path that has no bounded preparation
    /// window.
    pub(crate) fn plan_and_authorize(
        &self,
        mut packet: Packet,
        plan: route::Plan,
        builder: &Builder,
        options: &crate::send::Options,
        deadline: Option<Instant>,
    ) -> Result<PlannedPacket, Error> {
        // Route selection precedes all route-dependent materialization.
        materialize_network_fields(&mut packet, &plan)?;
        materialize_link_structure(&mut packet, &plan)?;
        self.check_cancelled()?;
        ensure_deadline(deadline)?;
        let build_context = build_context(&plan);
        let preliminary_build =
            builder.build(packet.clone(), build_context.clone(), options.build.clone())?;
        self.check_cancelled()?;
        ensure_deadline(deadline)?;
        validate_mtu(&preliminary_build, plan.decision.mtu)?;
        self.policy
            .authorize_built_packet(&preliminary_build, options.allow_permissive_live)?;
        self.policy
            .authorize_built_wire(&preliminary_build, &plan)?;
        Ok(PlannedPacket {
            packet,
            plan,
            build_context,
            preliminary_build,
        })
    }

    /// Materializes the route — the only step that resolves link
    /// fields, and the first that may emit traffic — rebuild if that changed
    /// the packet, require the planned frame width, then re-authorize the
    /// exact final bytes against the final route.
    ///
    /// The re-authorization is unconditional: it is the last gate before
    /// capture arming and transmission can observe these bytes.
    pub(crate) fn materialize_and_authorize(
        &self,
        planned: PlannedPacket,
        builder: &Builder,
        options: &crate::send::Options,
        deadline: Option<Instant>,
    ) -> Result<PreparedPacket, Error> {
        let PlannedPacket {
            mut packet,
            plan,
            build_context,
            preliminary_build,
        } = planned;
        let preliminary_len = preliminary_build.bytes.len();
        // The resolver stops at the deadline on its own; a failure it reports
        // after the deadline passed is the deadline, not a neighbor verdict.
        self.check_cancelled()?;
        let route = match route::materialize(plan, &self.neighbors, deadline) {
            Ok(route) => route,
            Err(error) => {
                self.check_cancelled()?;
                ensure_deadline(deadline)?;
                return Err(error.into());
            }
        };
        let link_changed = materialize_link_fields(&mut packet, &route)?;
        let built = if link_changed {
            self.check_cancelled()?;
            ensure_deadline(deadline)?;
            builder.build(packet, build_context, options.build.clone())?
        } else {
            preliminary_build
        };
        require_fixed_width_link_materialization(preliminary_len, built.bytes.len())?;
        self.check_cancelled()?;
        ensure_deadline(deadline)?;
        self.policy
            .authorize_built_packet(&built, options.allow_permissive_live)?;
        // Every final materialized destination is authorized immediately
        // before capture arming and transmission can observe it.
        self.policy.authorize_built_wire(&built, &route.plan)?;
        Ok(PreparedPacket { built, route })
    }
}

fn ensure_deadline(deadline: Option<Instant>) -> Result<(), Error> {
    match deadline {
        Some(deadline) => ensure_preparation_deadline(deadline),
        None => Ok(()),
    }
}
