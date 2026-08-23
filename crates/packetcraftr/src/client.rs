// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;

use packetcraftr_core::build::BuiltPacket;
use packetcraftr_core::frame::LinkType;
use packetcraftr_core::registry::Registry;
use packetcraftr_netio::transmit::Sender as PacketIo;
use packetcraftr_netio::{Error as LiveIoError, link::Mode as LinkMode};

use crate::Error;
use crate::policy::Policy;

/// High-level composition of packet construction, passive route planning,
/// explicit neighbor materialization, policy, and packet I/O.
#[derive(Debug)]
pub struct Client<R, N, I> {
    pub(crate) registry: Arc<Registry>,
    pub(crate) routes: R,
    pub(crate) neighbors: N,
    pub(crate) io: I,
    pub(crate) policy: Policy,
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
        }
    }

    pub fn registry(&self) -> &Arc<Registry> {
        &self.registry
    }

    pub(crate) fn authorize_built(
        &self,
        built: &BuiltPacket,
        allow_permissive_live: bool,
    ) -> Result<(), Error> {
        self.policy.authorize_packet_destinations(&built.packet)?;
        self.policy
            .authorize_permissive(built.requires_live_opt_in, allow_permissive_live)?;
        Ok(())
    }

    pub(crate) fn authorize_final_wire(
        &self,
        built: &BuiltPacket,
        route: &packetcraftr_netio::route::Plan,
    ) -> Result<(), Error> {
        let link_type = match route.mode {
            LinkMode::Layer2 => route.decision.link_type,
            LinkMode::Layer3 => LinkType::RAW,
            LinkMode::Auto => return Err(LiveIoError::UnresolvedLinkMode.into()),
        };
        self.policy
            .authorize_final_wire(built.bytes.to_vec(), link_type, route)?;
        Ok(())
    }
}
