// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;
use std::time::{Duration, Instant};

use packetcraftr_core::budget::{Cancellation, Deadline};
use packetcraftr_core::registry::Registry;

use crate::clock::{Clock, SystemClock};
use crate::execution::Admission;
use crate::policy::Policy;
use crate::providers::TargetProviders;
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
    /// Whether materialization authorizes each neighbor request like a
    /// prepared packet before resolving it, so a next hop the policy denies
    /// is never sent one.
    pub(crate) authorize_neighbor_requests: bool,
    /// Whether every neighbor a packet's route needs was resolved, accounted,
    /// before preparation, which then sends no request of its own: a route
    /// needing another neighbor changed after its resolution.
    pub(crate) neighbors_resolved_ahead: bool,
    /// How long a packet waits behind a neighbor request its own route just
    /// sent, so the request spends the workflow's rate like a packet.
    pub(crate) neighbor_pause: Duration,
    pub(crate) interfaces: route::ResolvedInterface,
    pub(crate) cancellation: Option<Cancellation>,
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
            authorize_neighbor_requests: false,
            neighbors_resolved_ahead: false,
            neighbor_pause: Duration::ZERO,
            interfaces: route::ResolvedInterface::default(),
            cancellation: None,
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
            authorize_neighbor_requests: self.authorize_neighbor_requests,
            neighbors_resolved_ahead: self.neighbors_resolved_ahead,
            neighbor_pause: self.neighbor_pause,
            interfaces: self.interfaces,
            cancellation: self.cancellation,
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

    /// Authorizes every neighbor request a workflow's route resolves, such
    /// as a gateway's, against the destination allowlist and the route's
    /// sources before sending it, as scans always do.
    #[must_use]
    pub fn with_neighbor_request_authorization(mut self) -> Self {
        self.authorize_neighbor_requests = true;
        self
    }

    /// Bounds every neighbor resolution as a scan of `request` does: one
    /// request per fresh answer, within the scan's timeout and evidence
    /// limits, with each answer kept while this client lives, and each
    /// request paced like a probe at the scan's rate. Lookups after a scan on
    /// this client, such as its reverse-DNS names, then reuse the scan's
    /// answers and stay within its bounds.
    pub fn with_scan_neighbors(
        mut self,
        request: &crate::scan::Request,
    ) -> Result<Self, neighbor::Error> {
        self.neighbors = crate::scan::NeighborBounds::of(request).narrow(&self.neighbors)?;
        self.neighbor_pause = request
            .probes_per_second
            .and_then(|rate| Duration::from_secs(1).checked_div(rate))
            .unwrap_or_default();
        Ok(self)
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

    pub(crate) fn admission(&self) -> Admission<'_>
    where
        P: TargetProviders,
    {
        Admission::new(&self.policy, self.providers.resolver())
    }

    pub(crate) fn deadline(&self, limit: Duration) -> Deadline {
        let clock = self.clock.clone();
        Deadline::with_time_source(limit, move || clock.now())
            .with_cancellation(self.cancellation.clone())
    }

    pub(crate) fn now(&self) -> Instant {
        self.clock.now()
    }

    pub(crate) fn view_with_registry(&self, registry: Arc<Registry>) -> Self {
        Self {
            registry,
            policy: Arc::clone(&self.policy),
            providers: Arc::clone(&self.providers),
            clock: self.clock.clone(),
            runtime: self.runtime.clone(),
            neighbors: self.neighbors.clone(),
            authorize_neighbor_requests: self.authorize_neighbor_requests,
            neighbors_resolved_ahead: self.neighbors_resolved_ahead,
            neighbor_pause: self.neighbor_pause,
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
