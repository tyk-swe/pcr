// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;

use packetcraftr_core::registry::Registry;
use packetcraftr_netio::transmit::Sender as PacketIo;
use packetcraftr_netio::{
    neighbor::Resolver as NeighborResolver, route::Provider as RouteProvider,
};

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
    R: RouteProvider,
    N: NeighborResolver,
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
}
