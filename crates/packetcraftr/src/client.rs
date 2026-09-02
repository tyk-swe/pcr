// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;

use crate::progress::Runtime;
use packetcraftr_core::build::BuiltPacket;
use packetcraftr_core::frame::LinkType;
use packetcraftr_core::registry::Registry;
use packetcraftr_netio::transmit::Sender as PacketIo;
use packetcraftr_netio::{Error as LiveIoError, link::Mode as LinkMode};

use crate::Error;
use crate::authorization::{WireAuthorizationError, authorize_permissive_live, authorize_wire};
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
    pub(crate) policy: Policy,
    /// Owns the worker budget behind
    /// [`exchange_with_events`](Self::exchange_with_events). It starts no
    /// thread until an exchange actually publishes events, and scoping it here
    /// keeps one client's publication failures out of every other client.
    pub(crate) runtime: Runtime,
}

impl<R, N, I> Client<R, N, I>
where
    R: packetcraftr_netio::route::Provider,
    N: packetcraftr_netio::neighbor::Resolver,
    I: PacketIo,
{
    pub fn new(registry: Arc<Registry>, routes: R, neighbors: N, io: I, policy: Policy) -> Self {
        Self {
            registry,
            routes,
            neighbors,
            io,
            policy,
            runtime: Runtime::default(),
        }
    }

    pub fn registry(&self) -> &Arc<Registry> {
        &self.registry
    }
}

/// The client's own authorization seam.
///
/// `send`, `exchange`, and `plan` never take an injected
/// [`Authorizer`](crate::authorization::Authorizer); they apply the [`Policy`]
/// this client owns through the two methods below.
impl<R, N, I> Client<R, N, I> {
    /// The traffic policy this client applies to every operation it runs.
    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    /// Authorizes the destinations a built packet declares, plus the two
    /// permissive-live approvals when the build needed them.
    pub(crate) fn authorize_built_packet(
        &self,
        built: &BuiltPacket,
        allow_permissive_live: bool,
    ) -> Result<(), Error> {
        self.policy.authorize_packet_destinations(&built.packet)?;
        if built.requires_live_opt_in {
            authorize_permissive_live(&self.policy, allow_permissive_live)?;
        }
        Ok(())
    }

    /// Authorizes the exact bytes that would reach the wire against the route
    /// that was selected for them, decoding them with the trusted registry.
    pub(crate) fn authorize_built_wire(
        &self,
        built: &BuiltPacket,
        route: &packetcraftr_netio::route::Plan,
    ) -> Result<(), Error> {
        let link_type = match route.mode {
            LinkMode::Layer2 => route.decision.link_type,
            LinkMode::Layer3 => LinkType::RAW,
            LinkMode::Auto => return Err(LiveIoError::UnresolvedLinkMode.into()),
        };
        authorize_wire(&self.policy, link_type, &built.bytes, Some(route)).map_err(
            |error| -> Error {
                match error {
                    WireAuthorizationError::Decode(error) => {
                        crate::policy::Error::InvalidPacketSemantics {
                            reason: error.to_string(),
                        }
                    }
                    WireAuthorizationError::Policy(error) => error,
                }
                .into()
            },
        )
    }
}

impl<R, N, I> Client<R, N, I>
where
    R: route::Provider,
    N: neighbor::Resolver,
    I: transmit::Sender,
{
    /// Steps 1-6 of the transmission pipeline, shared by `send` and the
    /// exchange: materialize the route-dependent fields, build the exact
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
        ensure_deadline(deadline)?;
        let build_context = build_context(&plan);
        let preliminary_build =
            builder.build(packet.clone(), build_context.clone(), options.build.clone())?;
        ensure_deadline(deadline)?;
        validate_mtu(&preliminary_build, plan.decision.mtu)?;
        self.authorize_built_packet(&preliminary_build, options.allow_permissive_live)?;
        self.authorize_built_wire(&preliminary_build, &plan)?;
        Ok(PlannedPacket {
            packet,
            plan,
            build_context,
            preliminary_build,
        })
    }

    /// Steps 7-11: materialize the route — the only step that resolves link
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
        let route = route::materialize(plan, &self.neighbors)?;
        ensure_deadline(deadline)?;
        let link_changed = materialize_link_fields(&mut packet, &route)?;
        let built = if link_changed {
            ensure_deadline(deadline)?;
            builder.build(packet, build_context, options.build.clone())?
        } else {
            preliminary_build
        };
        require_fixed_width_link_materialization(preliminary_len, built.bytes.len())?;
        ensure_deadline(deadline)?;
        self.authorize_built_packet(&built, options.allow_permissive_live)?;
        // Every final materialized destination is authorized immediately
        // before capture arming and transmission can observe it.
        self.authorize_built_wire(&built, &route.plan)?;
        Ok(PreparedPacket { built, route })
    }
}

fn ensure_deadline(deadline: Option<Instant>) -> Result<(), Error> {
    match deadline {
        Some(deadline) => ensure_preparation_deadline(deadline),
        None => Ok(()),
    }
}
