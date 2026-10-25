// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;
use std::time::{Duration, Instant};

pub(crate) mod admission;
pub(crate) mod planning;

use packetcraftr_core::budget::{Cancellation, Deadline};
use packetcraftr_core::registry::Registry;

use crate::clock::{Clock, SystemClock};
use crate::policy::Policy;
use crate::runtime::Runtime;
use crate::{Error, neighbor, route};

/// The single entry point for live workflows.
#[derive(Debug)]
pub struct Client<P, K = SystemClock> {
    pub(crate) registry: Arc<Registry>,
    pub(crate) policy: Arc<Policy>,
    pub(crate) providers: Arc<P>,
    pub(crate) clock: K,
    /// Scoping it here keeps one client's publication failures out of every other client.
    pub(crate) runtime: Runtime,
    pub(crate) neighbors: neighbor::State,
    pub(crate) interfaces: route::ResolvedInterface,
    pub(crate) cancellation: Option<Cancellation>,
    /// An optional absolute deadline a containing operation already set: the
    /// client's operation deadlines attach it as a parent so cooperative
    /// boundaries enforce it, and a blocked provider may still overrun the
    /// deadline it could not check.
    pub(crate) deadline_ceiling: Option<Arc<Deadline>>,
}

impl<P> Client<P> {
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
            deadline_ceiling: None,
        }
    }
}

impl<P, K: Clock> Client<P, K> {
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
            deadline_ceiling: self.deadline_ceiling,
        }
    }

    #[must_use]
    pub fn with_runtime(mut self, runtime: Runtime) -> Self {
        self.runtime = runtime;
        self
    }

    #[must_use]
    pub fn with_cancellation(mut self, cancellation: Cancellation) -> Self {
        self.cancellation = Some(cancellation);
        self
    }

    /// Replaces the neighbor-resolution bounds and starts a fresh neighbor cache under them.
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

    pub(crate) fn deadline(&self, limit: Duration) -> Deadline {
        let clock = self.clock.clone();
        Deadline::with_time_source(limit, move || clock.now())
            .with_cancellation(self.cancellation.clone())
            .with_parent(self.deadline_ceiling.clone())
    }

    pub(crate) fn now(&self) -> Instant {
        self.clock.now()
    }

    /// Narrows the absolute ceiling shared by this client's future operations.
    /// An existing ceiling stays attached, so this cannot extend its expiry.
    #[must_use]
    pub fn with_deadline(mut self, deadline: Deadline) -> Self {
        self.deadline_ceiling = Some(Arc::new(deadline.with_parent(self.deadline_ceiling.take())));
        self
    }

    pub(crate) fn check_cancelled(&self) -> Result<(), Error> {
        if let Some(signal) = &self.cancellation {
            signal.check()?;
        }
        Ok(())
    }
}
