// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;

use crate::progress::Runtime;
use packetcraftr_core::registry::Registry;
use packetcraftr_netio::transmit::Sender as PacketIo;

use crate::Error;
use crate::neighbor;
use crate::policy::Policy;

/// High-level composition of packet construction, passive route planning,
/// neighbor resolution, policy, and packet I/O.
///
/// The client resolves neighbors itself, over the transmit and capture
/// providers of `io`, and only for routes that policy has already admitted.
#[derive(Debug)]
pub struct Client<R, I> {
    pub(crate) registry: Arc<Registry>,
    pub(crate) routes: R,
    pub(crate) io: I,
    /// Neighbor-resolution bounds and the cache every operation shares.
    pub(crate) neighbors: neighbor::State,
    pub(crate) policy: Arc<Policy>,
    /// Owns the worker budget behind
    /// [`exchange_with_events`](Self::exchange_with_events). It starts no
    /// thread until an exchange actually publishes events, and scoping it here
    /// keeps one client's publication failures out of every other client.
    pub(crate) runtime: Runtime,
    pub(crate) cancellation: Option<packetcraftr_core::budget::Cancellation>,
}

impl<R, I> Client<R, I>
where
    R: packetcraftr_netio::route::Provider,
    I: PacketIo,
{
    /// Composes a client with default [`neighbor::Options`].
    pub fn new(registry: Arc<Registry>, routes: R, io: I, policy: impl Into<Arc<Policy>>) -> Self {
        Self {
            registry,
            routes,
            io,
            neighbors: neighbor::State::default(),
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

impl<R, I> Client<R, I> {
    /// Replaces the neighbor-resolution bounds, validating them first, and
    /// starts a fresh neighbor cache under them.
    pub fn with_neighbor_options(
        mut self,
        options: neighbor::Options,
    ) -> Result<Self, neighbor::Error> {
        self.neighbors = neighbor::State::try_new(options)?;
        Ok(self)
    }

    /// Selects a shared callback admission budget. The default constructor
    /// creates an isolated runtime; cloning a supplied runtime shares it.
    #[must_use]
    pub fn with_progress_runtime(mut self, runtime: Runtime) -> Self {
        self.runtime = runtime;
        self
    }

    pub fn progress_runtime(&self) -> &Runtime {
        &self.runtime
    }

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
