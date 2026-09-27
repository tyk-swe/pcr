// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;
use std::time::{Duration, Instant};

use packetcraftr_core::budget::{Cancellation, Deadline};
use packetcraftr_core::registry::Registry;

use crate::clock::{Clock, SystemClock};
use crate::execution::Admission;
use crate::policy::Policy;
use crate::providers::Providers;
use crate::runtime::Runtime;
use crate::{Error, neighbor, route};

/// The single entry point for live workflows.
///
/// A client holds the policy, the protocol registry, the clock, the runtime
/// that admits event workers, and the [`Providers`] every workflow reaches the
/// network through. Each workflow is a method that takes the workflow's
/// request and a [`Sink`](crate::Sink) for its events and returns its report.
///
/// Every workflow is admitted first: the operation's limits and declared
/// destinations are authorized before any provider is consulted, and an
/// interface selector is resolved only after that. The client resolves
/// neighbors itself, over its transmit and capture providers, and only for
/// routes that policy has already admitted.
#[derive(Debug)]
pub struct Client<P, K = SystemClock> {
    pub(crate) registry: Arc<Registry>,
    pub(crate) policy: Arc<Policy>,
    /// Shared so an operation-local view, or a worker that outlives one call,
    /// holds the same providers.
    pub(crate) providers: Arc<P>,
    pub(crate) clock: K,
    /// Owns the worker budget event sinks run on. It starts no thread until
    /// a workflow publishes events, and scoping it here keeps one client's
    /// publication failures out of every other client.
    pub(crate) runtime: Runtime,
    /// Neighbor-resolution bounds and the cache every operation shares.
    pub(crate) neighbors: neighbor::State,
    /// The interface selector resolved last, shared like the neighbor cache.
    pub(crate) interfaces: route::ResolvedInterface,
    pub(crate) cancellation: Option<Cancellation>,
}

impl<P: Providers> Client<P> {
    /// Composes a client on the system clock, with default
    /// [`neighbor::Options`] and an isolated [`Runtime`].
    pub fn new(registry: Arc<Registry>, policy: impl Into<Arc<Policy>>, providers: P) -> Self {
        Self {
            registry,
            policy: policy.into(),
            providers: Arc::new(providers),
            clock: SystemClock,
            runtime: Runtime::default(),
            neighbors: neighbor::State::default(),
            interfaces: route::ResolvedInterface::default(),
            cancellation: None,
        }
    }
}

impl<P: Providers, K: Clock> Client<P, K> {
    /// Replaces the clock every deadline and send schedule is anchored on.
    #[must_use]
    pub fn with_clock<C: Clock>(self, clock: C) -> Client<P, C> {
        Client {
            registry: self.registry,
            policy: self.policy,
            providers: self.providers,
            clock,
            runtime: self.runtime,
            neighbors: self.neighbors,
            interfaces: self.interfaces,
            cancellation: self.cancellation,
        }
    }

    /// Selects the worker budget event sinks run on. Cloning a runtime shares
    /// it between clients.
    #[must_use]
    pub fn with_runtime(mut self, runtime: Runtime) -> Self {
        self.runtime = runtime;
        self
    }

    /// Shares a cooperative stop signal with every workflow this client runs.
    #[must_use]
    pub fn with_cancellation(mut self, cancellation: Cancellation) -> Self {
        self.cancellation = Some(cancellation);
        self
    }

    /// Replaces the neighbor-resolution bounds, validating them first, and
    /// starts a fresh neighbor cache under them.
    ///
    /// # Errors
    ///
    /// Returns the invalid bound.
    pub fn with_neighbor_options(
        mut self,
        options: neighbor::Options,
    ) -> Result<Self, neighbor::Error> {
        self.neighbors = neighbor::State::try_new(options)?;
        Ok(self)
    }

    pub fn registry(&self) -> &Arc<Registry> {
        &self.registry
    }

    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    pub fn runtime(&self) -> &Runtime {
        &self.runtime
    }

    pub fn providers(&self) -> &P {
        &self.providers
    }

    /// The one admission path every workflow authorizes through: the
    /// client's policy, resolving declared targets with the client's resolver.
    pub(crate) fn admission(&self) -> Admission<'_> {
        Admission::new(&self.policy, self.providers.resolver())
    }

    /// A deadline of `limit` anchored on the client's clock and carrying the
    /// client's cancellation.
    pub(crate) fn deadline(&self, limit: Duration) -> Deadline {
        let clock = self.clock.clone();
        Deadline::with_time_source(limit, move || clock.now())
            .with_cancellation(self.cancellation.clone())
    }

    /// The current time on the client's clock.
    pub(crate) fn now(&self) -> Instant {
        self.clock.now()
    }

    /// A view of this client that builds and decodes with `registry` and
    /// shares everything else, including the neighbor and interface caches.
    pub(crate) fn view_with_registry(&self, registry: Arc<Registry>) -> Self {
        Self {
            registry,
            policy: Arc::clone(&self.policy),
            providers: Arc::clone(&self.providers),
            clock: self.clock.clone(),
            runtime: self.runtime.clone(),
            neighbors: self.neighbors.clone(),
            interfaces: self.interfaces.clone(),
            cancellation: self.cancellation.clone(),
        }
    }

    pub(crate) fn check_cancelled(&self) -> Result<(), Error> {
        if let Some(signal) = &self.cancellation {
            signal.check()?;
        }
        Ok(())
    }
}
